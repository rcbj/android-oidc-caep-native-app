// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.util.UUID

/**
 * Caches token sets per key and keeps them fresh.
 *
 * - [getTokenSet] always returns tokens valid for at least `refreshSkew`, refreshing on demand.
 * - With `autoRefresh` (the default), a timer refreshes each key's tokens `refreshSkew` before they expire.
 * - Concurrent refreshes of one key are merged into one token-endpoint call, and a refresh and a delete of one key
 *   never interleave, so a rotating refresh token is never presented twice and revoked tokens are never written back.
 * - [set] with `schedule = false`, and [unschedule], keep a key's tokens without refreshing them.
 */
public class TokenManager(
    public val client: OIDCClient,
    internal val store: TokenStore = MemoryTokenStore(),
    internal val refreshSkew: Double = 60.0,
    internal val autoRefresh: Boolean = true,
    internal val minRefreshDelay: Double = 1.0,
    internal val retryDelay: Double = 5.0,
) {
    public sealed class Event {
        /** New tokens obtained with the refresh token. */
        public data class Refreshed(val key: String, val tokenSet: TokenSet) : Event()
        /** A refresh failed (the tokens are dropped when the grant is invalid). */
        public data class RefreshError(val key: String, val error: OIDCError) : Event()
        /** The key's tokens could not be renewed and were removed. */
        public data class Expired(val key: String) : Event()
        /** The key's tokens were deleted with [delete]. */
        public data class Removed(val key: String) : Event()
    }

    public val events: EventHub<Event> = EventHub()

    private val dispatcher = actorDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val timers = HashMap<String, Pair<UUID, Job>>()
    private val wanted = HashSet<String>()
    private val inflight = HashMap<String, CompletableDeferred<TokenSet>>()
    private val locks = KeyedMutex()

    private val now: Instant get() = client.options.now()

    private suspend fun <T> serial(body: suspend () -> T): T = withContext(dispatcher) { body() }

    /** Stores tokens for a key and (unless [schedule] is false) schedules their proactive refresh. */
    public suspend fun set(key: String, tokenSet: TokenSet, schedule: Boolean = true): TokenSet = serial {
        store.setJSON(key, tokenSet.json)
        if (schedule) wanted.add(key) else unscheduleNow(key)
        scheduleTimer(key, tokenSet)
        tokenSet
    }

    /** Schedules the proactive refresh of the tokens already stored for [key]. */
    public suspend fun schedule(key: String): Unit = serial {
        wanted.add(key)
        runCatching { get(key) }.getOrNull()?.let { scheduleTimer(key, it) }
    }

    /** Stops refreshing [key]'s tokens in the background; they stay stored. */
    public suspend fun unschedule(key: String): Unit = serial { unscheduleNow(key) }

    private fun unscheduleNow(key: String) {
        wanted.remove(key)
        timers.remove(key)?.second?.cancel()
    }

    /** The cached tokens (possibly expired) for [key]. */
    public suspend fun get(key: String): TokenSet? {
        val json = store.getJSON(key) ?: return null
        return try { TokenSet.fromJson(json) } catch (e: OIDCError) { null }
    }

    /** A usable access token for [key]. Prefer [getTokenSet] when the token may be DPoP-bound: its `tokenType` decides the header. */
    public suspend fun getAccessToken(key: String, forceRefresh: Boolean = false): String = getTokenSet(key, forceRefresh).accessToken

    /** The cached token set for [key], refreshed first if the access token is (nearly) expired. */
    public suspend fun getTokenSet(key: String, forceRefresh: Boolean = false): TokenSet = serial {
        var ts = get(key) ?: throw OIDCError(OIDCError.Kind.GENERAL, "No tokens cached for $key", code = "no_tokens")
        if (forceRefresh || ts.isExpired(refreshSkew, now)) {
            if (ts.refreshToken != null) {
                ts = refresh(key)
            } else if (ts.isExpired(now = now)) {
                drop(key, Event.Expired(key))
                throw OIDCError(OIDCError.Kind.GENERAL, "Access token expired and no refresh_token is available", code = "token_expired")
            }
        }
        ts
    }

    /** Refreshes the tokens for [key] now. Concurrent calls share one request. */
    public suspend fun refresh(key: String): TokenSet {
        val (deferred, owner) = serial {
            inflight[key]?.let { it to false } ?: CompletableDeferred<TokenSet>().also { inflight[key] = it }.let { it to true }
        }
        if (!owner) return deferred.await()
        // Cleared before the awaiters resume: a refresh asked for after this one finished is a new refresh.
        val result = runCatching { performRefresh(key) }
        serial { inflight.remove(key) }
        result.fold({ deferred.complete(it) }, { deferred.completeExceptionally(it) })
        return result.getOrThrow()
    }

    private suspend fun performRefresh(key: String): TokenSet {
        val before = get(key) ?: throw OIDCError(OIDCError.Kind.GENERAL, "No tokens cached for $key", code = "no_tokens")
        try {
            return locks.withLock(lockName(key)) { refreshHoldingLock(key, before) }
        } catch (error: Throwable) {
            if (error is kotlinx.coroutines.CancellationException) throw error
            val e = OIDCError.wrap(error)
            events.emit(Event.RefreshError(key, e))
            if (e.kind == OIDCError.Kind.OAUTH && (e.code == "invalid_grant" || e.code == "invalid_client")) serial { drop(key, Event.Expired(key)) }
            throw e
        }
    }

    private suspend fun refreshHoldingLock(key: String, before: TokenSet): TokenSet {
        val current = get(key) ?: throw OIDCError(OIDCError.Kind.GENERAL, "Tokens for $key were removed", code = "no_tokens")
        // Another refresh may have finished while this one waited for the lock.
        if (current.accessToken != before.accessToken && !current.isExpired(refreshSkew, now)) {
            serial { scheduleTimer(key, current) }
            return current
        }
        val next = client.refresh(current)
        // The key may have been deleted while the request was in flight. Its new tokens are revoked rather than left valid at the OP.
        if (store.get(key) == null) {
            client.revokeQuietly(next.accessToken, next.refreshToken)
            throw OIDCError(OIDCError.Kind.GENERAL, "Tokens for $key were removed during refresh", code = "no_tokens")
        }
        set(key, next, schedule = serial { key in wanted })
        events.emit(Event.Refreshed(key, next))
        return next
    }

    /**
     * Removes the tokens for [key], optionally revoking them at the OP (RFC 7009). A refresh in flight finishes first,
     * so it cannot write its tokens back after they were removed (e.g. on a CAEP session-revoked).
     */
    public suspend fun delete(key: String, revoke: Boolean = false): TokenSet? {
        val held = locks.withLock(lockName(key)) {
            val held = get(key)
            serial { drop(key, Event.Removed(key)) }
            held
        }
        if (revoke && held != null) client.revokeQuietly(held.accessToken, held.refreshToken)
        return held
    }

    /** Cancels every refresh timer (call on shutdown). */
    public suspend fun close(): Unit = serial {
        for (t in timers.values) t.second.cancel()
        timers.clear()
        wanted.clear()
    }

    private suspend fun drop(key: String, event: Event) {
        unscheduleNow(key)
        runCatching { store.delete(key) }
        events.emit(event)
    }

    private fun scheduleTimer(key: String, ts: TokenSet) {
        timers.remove(key)?.second?.cancel()
        val expiresAt = ts.expiresAt
        if (!autoRefresh || key !in wanted || expiresAt == null || ts.refreshToken == null) return
        val due = expiresAt - ts.effectiveSkew(refreshSkew) - now.seconds
        startTimer(key, maxOf(minRefreshDelay, due))
    }

    private fun startTimer(key: String, delaySeconds: Double) {
        val id = UUID.randomUUID()
        val job = scope.launch {
            delay((minOf(delaySeconds, 86_400.0 * 30) * 1000).toLong())
            timerFired(key, id)
        }
        timers[key] = id to job
    }

    private suspend fun timerFired(key: String, id: UUID) {
        if (timers[key]?.first != id) return
        timers.remove(key)
        try { refresh(key) } catch (e: Exception) { retry(key) }
    }

    /** After a transient background-refresh failure (already reported as RefreshError), try again later. */
    private suspend fun retry(key: String) = serial {
        val ts = runCatching { get(key) }.getOrNull()
        if (ts == null || timers[key] != null || key !in wanted) return@serial
        if (ts.isExpired(now = now)) {
            drop(key, Event.Expired(key))
            return@serial
        }
        startTimer(key, retryDelay)
    }

    /** Cancels the manager's timers for good. */
    internal fun shutdown() = scope.cancel()

    private fun lockName(key: String) = "refresh:$key"
}
