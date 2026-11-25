// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.time.Instant

/** ID token claims an account record keeps, for display and for naming the account to the OP. No tokens. */
internal val profileClaims = setOf("iss", "sub", "sid", "name", "given_name", "family_name", "preferred_username", "email",
    "email_verified", "phone_number", "phone_number_verified", "picture", "acr", "amr", "auth_time")

/** One person signed in through this client in this app. Holds no token. */
public data class Account(
    /** Stable id derived from `iss` and `sub` ([accountKey]). */
    public val key: String,
    public val status: Status,
    public val endedReason: String? = null,
    public val addedAt: Instant,
    public val lastUsedAt: Instant,
    /** When the status last left `signed-in`. */
    public val changedAt: Instant? = null,
    /** The profile claims of its latest validated ID token. */
    public val claims: JsonObject = emptyJsonObject,
) {
    public enum class Status(public val value: String) {
        /** Its tokens are in the cache. */
        SIGNED_IN("signed-in"),
        /** Not signed out, but its cached tokens could not be used; [AccountManager.resume] asks the OP for new ones. */
        TOKENS_MISSING("tokens-missing"),
        SIGNED_OUT("signed-out"),
        /** Ended by the OP, a security event or a refused refresh; see [endedReason]. */
        ENDED("ended"),
    }

    val iss: String get() = claims.string("iss") ?: ""
    val sub: String get() = claims.string("sub") ?: ""
    /** The OP session (OpenID Connect Front-/Back-Channel Logout `sid`). */
    val sid: String? get() = claims.string("sid")
    val name: String? get() = claims.string("name")
    val email: String? get() = claims.string("email")
    val preferredUsername: String? get() = claims.string("preferred_username")

    /** What [subjectMatches] compares a security event's subject with. */
    val identity: SubjectIdentity
        get() = SubjectIdentity(iss, sub, sid, email, claims["email_verified"].boolValue == true, claims.string("phone_number"),
            claims["phone_number_verified"].boolValue == true)

    internal fun toJson(): JsonObject = jsonObjectOf("key" to key, "status" to status.value, "endedReason" to endedReason,
        "addedAt" to addedAt.toEpochMilli() / 1000.0, "lastUsedAt" to lastUsedAt.toEpochMilli() / 1000.0,
        "changedAt" to changedAt?.let { it.toEpochMilli() / 1000.0 }, "claims" to claims)

    internal companion object {
        fun fromJson(o: JsonObject): Account? {
            val key = o.string("key") ?: return null
            val status = Status.entries.firstOrNull { it.value == o.string("status") } ?: return null
            fun instant(name: String) = o[name].doubleValue?.let { Instant.ofEpochMilli((it * 1000).toLong()) }
            return Account(key, status, o.string("endedReason"), instant("addedAt") ?: return null, instant("lastUsedAt") ?: return null,
                instant("changedAt"), o["claims"].objectValue ?: emptyJsonObject)
        }
    }
}

/** Reaches one account's tokens from inside a hook (and, for `onActivate`, for as long as it stays active). */
public class AccountAccess internal constructor(private val fetch: suspend (Boolean) -> TokenSet) {
    public suspend fun getTokenSet(forceRefresh: Boolean = false): TokenSet = fetch(forceRefresh)
}

public data class AccountManagerOptions(
    /**
     * The account list and each account's tokens. Default: memory. On Android, pass [KeystoreTokenStore] to keep them
     * across launches (encrypted at rest). A persistent store without DPoP logs a warning, since a refresh token at
     * rest is best bound to a key (RFC 9700 §2.2.2).
     */
    public val store: TokenStore = MemoryTokenStore(),
    /** The key the account list is stored under (and, with `active:` before it, the active account). */
    public val storeKey: String = "accounts",
    public val refreshSkew: Double = 60.0,
    /** Past it, the account that left longest ago is forgotten; when every place is held by a signed-in account, a further sign-in is refused (`too_many_accounts`). */
    public val maxAccounts: Int = 10,
    /** How long a signed-out account stays listed (days). */
    public val rememberSignedOutDays: Double = 30.0,
    /** What names an account to the OP in `login_hint`. Default: `preferred_username`, else `email`. */
    public val loginHint: (Account) -> String? = { it.preferredUsername ?: it.email },
    /**
     * Runs when an account is about to become the active account, after its tokens are refreshed if due and before
     * `Activated` is emitted: e.g. to poll its CAEP stream and act on the signals queued while it was dormant.
     * Throwing aborts the activation.
     */
    public val onActivate: (suspend (Account, AccountAccess) -> Unit)? = null,
    /** Runs when an account stops being the active account (e.g. to stop polling its stream). */
    public val onDeactivate: (suspend (Account) -> Unit)? = null,
    /** Runs before an account's tokens are deleted by sign-out or [AccountManager.end] (e.g. to delete its CAEP stream while its tokens still work). */
    public val onLeave: (suspend (Account, AccountAccess) -> Unit)? = null,
)

/** What a completed sign-in did. */
public data class SignInResult(
    public val account: Account,
    public val tokenSet: TokenSet,
    /** `sign-in`, `choose`, `add`, `resume` or `reauth`. */
    public val intent: String,
    /** The account is new to this app (rather than signed in again). */
    public val added: Boolean,
)

/**
 * Every account signed in through one client in this app, with ONE active account, for an OP that keeps several
 * signed-in accounts per browser (e.g. iya-sts `authn.multipleAccounts`).
 *
 * - **One cache.** Each account's tokens are kept until it is signed out or its session ends, so any signed-in
 *   account can be made active with no trip to the OP.
 * - **One active account.** Only its tokens are reachable ([getTokenSet]), and only its tokens are refreshed in the
 *   background. The others are dormant. [activate] refreshes a dormant account's tokens if they are due and runs
 *   `onActivate` before it becomes active.
 *
 * Signing in: [signIn] lets the OP decide (its account picker when several are signed in there); [chooseAccount]
 * always shows the picker (`prompt=select_account`); [addAccount] is a fresh sign-in (`prompt=login`). [resume] and
 * [reauthenticate] name the account and refuse anybody else. [signOut] revokes that account's tokens and names its ID
 * token at logout, so the OP ends that account's session only.
 *
 * Use one `AccountManager` per store.
 */
public class AccountManager(public val client: OIDCClient, internal val options: AccountManagerOptions = AccountManagerOptions()) {
    public sealed class Event {
        public data class Added(val account: Account) : Event()
        public data class Updated(val account: Account) : Event()
        /** The active account changed (to null: none is active). */
        public data class Activated(val account: Account?, val previous: Account?) : Event()
        /** The active account's tokens were refreshed. */
        public data class Refreshed(val account: Account) : Event()
        public data class SignedOut(val account: Account) : Event()
        public data class Ended(val account: Account, val reason: String?) : Event()
        public data class Forgotten(val account: Account) : Event()
        public data class ActivationError(val account: Account?, val error: OIDCError) : Event()
        /** After any of the above. */
        public object Change : Event()
    }

    public val events: EventHub<Event> = EventHub()
    public val tokens: TokenManager = TokenManager(client, options.store, options.refreshSkew)

    private val dispatcher = actorDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val accounts = LinkedHashMap<String, Account>()
    private var activeKeyValue: String? = null
    private var activating: String? = null
    private var subscription: EventSubscription? = null
    private var restored = false
    private val persistLock = KeyedMutex()

    init {
        if (options.store.isPersistent && client.dpopKey == null) {
            OIDCLog.log(OIDCLog.Level.WARNING, "AccountManager: tokens are kept in persistent storage without DPoP. Anything that can read the store can use them anywhere; turn on DPoP or use MemoryTokenStore.")
        }
    }

    private val now: Instant get() = client.options.now()

    private suspend fun <T> serial(body: suspend () -> T): T = withContext(dispatcher) { body() }

    /**
     * Loads the account list and reactivates the account that was active (refreshing its tokens if due and running
     * `onActivate`). A failed reactivation leaves no active account and is emitted as ActivationError.
     */
    public suspend fun restore(): AccountManager = serial {
        if (subscription == null) {
            subscription = tokens.events.subscribe { event -> scope.launch { handleTokenEvent(event) } }
        }
        if (!restored) {
            restored = true
            options.store.getJSON(options.storeKey)?.get("accounts").arrayValue?.let { list ->
                accounts.clear()
                for (item in list) item.objectValue?.let(Account::fromJson)?.let { accounts[it.key] = it }
            }
            val forgetBefore = now.plusSeconds(-options.rememberSignedOutDays * 86_400)
            accounts.entries.removeAll { it.value.status == Account.Status.SIGNED_OUT && (it.value.changedAt ?: Instant.EPOCH).isBefore(forgetBefore) }
            persist()
        }
        val remembered = options.store.get(activeStoreKey)?.decodeToString()
        if (remembered != null && accounts.containsKey(remembered)) {
            try { activateInternal(remembered) } catch (e: Exception) {
                events.emit(Event.ActivationError(accounts[remembered], OIDCError.wrap(e)))
            }
        }
        this
    }

    /** Every account in this app, in the order added. */
    public suspend fun list(): List<Account> = serial { listNow() }
    private fun listNow() = accounts.values.sortedBy { it.addedAt }
    public suspend fun get(key: String): Account? = serial { accounts[key] }
    /** The active account (whatever its status). */
    public suspend fun active(): Account? = serial { activeKeyValue?.let { accounts[it] } }
    public suspend fun activeKey(): String? = serial { activeKeyValue }

    /** The identity [subjectMatches] compares a security event's subject with. */
    public suspend fun identity(key: String): SubjectIdentity? = serial { accounts[key]?.identity }

    /** The accounts a security event's subject (`sub_id`) is about. */
    public suspend fun accountsForSubject(subId: JsonObject): List<Account> = serial { listNow().filter { subjectMatches(subId, it.identity) } }

    // MARK: The active account's tokens: the only ones reachable

    /** The active account's tokens, refreshed first when (nearly) expired. A dormant account's tokens cannot be reached. */
    public suspend fun getTokenSet(forceRefresh: Boolean = false): TokenSet = tokensFor(serial { activeKeyValue }, forceRefresh)

    /** Refreshes the active account's tokens now. */
    public suspend fun refresh(): TokenSet = getTokenSet(forceRefresh = true)

    private suspend fun tokensFor(key: String?, forceRefresh: Boolean): TokenSet {
        serial {
            if (key == null || (key != activeKeyValue && key != activating)) {
                throw OIDCError(OIDCError.Kind.GENERAL, "Only the active account's tokens can be used; activate the account first", code = "not_active")
            }
            if (accounts[key]?.status != Account.Status.SIGNED_IN) throw OIDCError(OIDCError.Kind.GENERAL, "The active account is not signed in", code = "no_tokens")
        }
        return tokens.getTokenSet(key!!, forceRefresh)
    }

    private fun access(key: String) = AccountAccess { force -> tokensFor(key, force) }

    // MARK: Signing in (building the requests)

    /** A sign-in that leaves the choice to the OP: with several accounts signed in there, it shows its account picker. */
    public suspend fun signIn(opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest =
        client.createAuthorizationRequest(opts.copy(context = context(opts.context, jsonObjectOf("intent" to "sign-in"))))

    /** A sign-in that always shows the OP's account picker (`prompt=select_account`). */
    public suspend fun chooseAccount(opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest =
        client.createAuthorizationRequest(opts.copy(prompt = "select_account", context = context(opts.context, jsonObjectOf("intent" to "choose"))))

    /** A fresh sign-in (`prompt=login`), never the OP's picker: whoever signs in is added as an account. */
    public suspend fun addAccount(opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest =
        client.createAuthorizationRequest(opts.copy(prompt = "login", context = context(opts.context, jsonObjectOf("intent" to "add"))))

    /**
     * Asks the OP for this account's tokens again without showing a screen (`prompt=none`, naming the account with
     * `login_hint` and, where cached, `id_token_hint`). Fails with an error for which [needsInteraction] is true when
     * the account's session at the OP has ended; reauthenticate then.
     */
    public suspend fun resume(key: String, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest =
        accountRequest(key, "resume", opts.copy(prompt = opts.prompt ?: "none"))

    /** Signs this account's person in again at the OP (`prompt=login` by default), e.g. for step-up. A sign-in as anybody else is refused (`account_mismatch`). */
    public suspend fun reauthenticate(key: String, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest =
        accountRequest(key, "reauth", opts.copy(prompt = opts.prompt ?: "login"))

    private suspend fun accountRequest(key: String, intent: String, opts: AuthorizationRequestOptions): AuthorizationRequest {
        val a = serial { mustGet(key) }
        val cached = runCatching { tokens.get(key) }.getOrNull()
        val o = opts.copy(
            loginHint = opts.loginHint ?: options.loginHint(a),
            idTokenHint = opts.idTokenHint ?: cached?.idToken,
            expectedSub = a.sub,
            context = context(opts.context, jsonObjectOf("intent" to intent, "key" to key)),
        )
        return client.createAuthorizationRequest(o)
    }

    /**
     * Completes any of the requests above from the redirect. The account signed in is added to the cache (or, when
     * already listed, signed in again) and becomes the active account.
     *
     * An error the OP returned is thrown with [OIDCError.context] (`{ intent, key? }`) and, for `resume`/`reauth`,
     * [OIDCError.account].
     */
    public suspend fun handleCallback(callbackURL: URI): SignInResult {
        val result = try {
            client.completeAuthorization(callbackURL)
        } catch (e: OIDCError) {
            e.context["key"].stringValue?.let { key -> e.account = serial { accounts[key] } }
            throw e
        }
        return serial {
            val tokenSet = result.tokenSet
            val claims = tokenSet.claims ?: emptyJsonObject
            val key = accountKey(claims.string("iss") ?: "", claims.string("sub") ?: "")
            val existing = accounts[key]
            val added = existing == null
            if (added) makeRoom(tokenSet)
            val account = (existing ?: Account(key, Account.Status.SIGNED_IN, addedAt = now, lastUsedAt = now)).copy(
                claims = JsonObject(claims.filterKeys { it in profileClaims }), status = Account.Status.SIGNED_IN, lastUsedAt = now,
                endedReason = null, changedAt = null)
            accounts[key] = account
            tokens.set(key, tokenSet, schedule = false)
            persist()
            events.emit(if (added) Event.Added(account) else Event.Updated(account))
            activateInternal(key)
            SignInResult(accounts[key] ?: account, tokenSet, result.context["intent"].stringValue ?: "sign-in", added)
        }
    }

    // MARK: Activating

    /**
     * Makes a listed account the active account; the previous one becomes dormant. Nothing is sent to the OP unless
     * the account's tokens are due for a refresh. When the refresh or `onActivate` fails, the previously active
     * account is reactivated and the error thrown.
     */
    public suspend fun activate(key: String): Account? = serial {
        mustGet(key)
        val previous = activeKeyValue
        try {
            activateInternal(key)
        } catch (e: Exception) {
            if (previous != null && previous != key && activeKeyValue != previous) runCatching { activateInternal(previous) }
            throw e
        }
        activeKeyValue?.let { accounts[it] }
    }

    private suspend fun activateInternal(key: String) {
        val previous = activeKeyValue
        if (previous != null && previous != key) deactivate()
        mustGet(key)
        if (accounts[key]?.status == Account.Status.SIGNED_IN) {
            var ts = tokens.get(key)
            if (ts != null && ts.isExpired(options.refreshSkew, now)) {
                ts = if (ts.refreshToken != null) tokens.refresh(key) else null
            }
            val account = accounts[key]
            val onActivate = options.onActivate
            if (ts == null) {
                runCatching { tokens.delete(key) }
                setStatus(key, Account.Status.TOKENS_MISSING)
                persist()
            } else if (onActivate != null && account != null) {
                activating = key
                try { onActivate(account, access(key)) } finally { activating = null }
                // A signal acted on during onActivate may have ended the account: its status says so.
            }
        }
        activeKeyValue = key
        options.store.set(activeStoreKey, key.encodeToByteArray())
        if (accounts[key]?.status == Account.Status.SIGNED_IN) {
            accounts[key] = accounts[key]!!.copy(lastUsedAt = now)
            persist()
            tokens.schedule(key)
        }
        if (previous != key) events.emit(Event.Activated(accounts[key], previous?.let { accounts[it] }))
        events.emit(Event.Change)
    }

    private suspend fun deactivate() {
        val key = activeKeyValue ?: return
        tokens.unschedule(key)
        activeKeyValue = null
        runCatching { options.store.delete(activeStoreKey) }
        val a = accounts[key]
        val hook = options.onDeactivate
        if (a != null && hook != null) hook(a)
    }

    // MARK: Signing out, ending, forgetting

    /**
     * Signs one account out of this app: `onLeave` runs, its tokens are revoked (with [revoke]) and removed from the
     * cache, and it stays listed as `signed-out`. When it was the active account, the most recently added signed-in
     * account becomes active. Returns an RP-Initiated Logout request naming that account's ID token, so the OP ends
     * that account's session only (or null: no end_session_endpoint, or `endSession = false`).
     */
    public suspend fun signOut(key: String? = null, revoke: Boolean = true, endSession: Boolean = true, postLogoutRedirectURI: URI? = null): EndSessionRequest? {
        val (account, idToken, k) = serial {
            val k = key ?: activeKeyValue ?: throw OIDCError(OIDCError.Kind.GENERAL, "No account to sign out", code = "no_account")
            val (account, idToken) = leave(k, Account.Status.SIGNED_OUT, revoke, null)
            afterLeaving(k)
            events.emit(Event.SignedOut(account))
            events.emit(Event.Change)
            Triple(account, idToken, k)
        }
        if (!endSession) return null
        return client.createEndSessionRequest(idToken, postLogoutRedirectURI, if (idToken == null) options.loginHint(account) else null, jsonObjectOf("key" to k))
    }

    /** Signs every account out of this app. Returns one logout request that names nobody, so an OP holding several accounts asks the person which to end. */
    public suspend fun signOutAll(revoke: Boolean = true, endSession: Boolean = true, postLogoutRedirectURI: URI? = null): EndSessionRequest? {
        serial {
            val previous = activeKeyValue?.let { accounts[it] }
            for (a in listNow()) {
                if (a.status == Account.Status.SIGNED_IN || a.status == Account.Status.TOKENS_MISSING) {
                    events.emit(Event.SignedOut(leave(a.key, Account.Status.SIGNED_OUT, revoke, null).first))
                }
            }
            if (activeKeyValue != null) deactivate()
            if (previous != null) events.emit(Event.Activated(null, accounts[previous.key]))
            events.emit(Event.Change)
        }
        if (!endSession) return null
        return client.createEndSessionRequest(postLogoutRedirectURI = postLogoutRedirectURI, context = jsonObjectOf("all" to true))
    }

    /**
     * Ends an account's session in this app because the OP or a security event says it has ended: `onLeave` runs, its
     * tokens are removed from the cache (not revoked: the OP already knows), and it stays listed as `ended` with the
     * reason. Does nothing for an account that is not signed in.
     */
    public suspend fun end(key: String, reason: String? = null): Account? = serial {
        val a = accounts[key]
        if (a == null || (a.status != Account.Status.SIGNED_IN && a.status != Account.Status.TOKENS_MISSING)) return@serial a
        val (account, _) = leave(key, Account.Status.ENDED, false, reason)
        // During its onActivate the account is not active yet; activation sees the status when the hook returns.
        if (activating != key) afterLeaving(key)
        events.emit(Event.Ended(account, reason))
        events.emit(Event.Change)
        accounts[key]
    }

    /** Removes an account that is not signed in from the list. A signed-in account must be signed out first. */
    public suspend fun forget(key: String): Unit = serial {
        val a = mustGet(key)
        if (a.status == Account.Status.SIGNED_IN) throw OIDCError(OIDCError.Kind.GENERAL, "Sign the account out before forgetting it", code = "account_signed_in")
        accounts.remove(key)
        persist()
        runCatching { tokens.delete(key) }
        if (activeKeyValue == key) {
            activeKeyValue = null
            runCatching { options.store.delete(activeStoreKey) }
            events.emit(Event.Activated(null, a))
        }
        events.emit(Event.Forgotten(a))
        events.emit(Event.Change)
    }

    /** Cancels refresh timers (call on shutdown). */
    public suspend fun close() {
        tokens.close()
        serial {
            subscription?.cancel()
            subscription = null
        }
    }

    // MARK: Internals

    private val activeStoreKey: String get() = "active:${options.storeKey}"

    /** The request's context: the manager's `intent` (and `key`), added to an object the caller passed, or kept beside any other value as `app`. */
    private fun context(given: JsonElement?, ours: JsonObject): JsonElement = when {
        given == null -> ours
        given is JsonObject -> given + ours
        else -> ours + mapOf("app" to given)
    }

    private fun mustGet(key: String): Account = accounts[key] ?: throw OIDCError(OIDCError.Kind.GENERAL, "No account $key", code = "no_account")

    /** Runs onLeave, drops the tokens and records the new status. */
    private suspend fun leave(key: String, status: Account.Status, revoke: Boolean, reason: String?): Pair<Account, String?> {
        val a = mustGet(key)
        val cached = runCatching { tokens.get(key) }.getOrNull()
        val onLeave = options.onLeave
        if (cached != null && onLeave != null) onLeave(a, AccountAccess { force -> tokens.getTokenSet(key, force) })
        runCatching { tokens.delete(key, revoke) }
        setStatus(key, status)
        if (reason != null) accounts[key]?.let { accounts[key] = it.copy(endedReason = reason) }
        persist()
        return (accounts[key] ?: a).copy(status = status) to cached?.idToken
    }

    /** When the account that left was the active one, the most recently added signed-in account takes over. */
    private suspend fun afterLeaving(key: String) {
        if (activeKeyValue != key) return
        deactivate()
        val next = accounts.values.filter { it.status == Account.Status.SIGNED_IN }.maxByOrNull { it.addedAt }
        if (next != null) {
            try { activateInternal(next.key) } catch (e: Exception) { events.emit(Event.ActivationError(accounts[next.key], OIDCError.wrap(e))) }
        } else {
            events.emit(Event.Activated(null, accounts[key]))
        }
    }

    private fun setStatus(key: String, status: Account.Status) {
        val a = accounts[key] ?: return
        accounts[key] = a.copy(status = status, changedAt = now, endedReason = if (status != Account.Status.ENDED) null else a.endedReason)
    }

    /** Before adding an account at the limit: forget the account that left longest ago, or refuse. */
    private suspend fun makeRoom(tokenSet: TokenSet) {
        if (accounts.size < options.maxAccounts) return
        val oldest = accounts.values.filter { it.status != Account.Status.SIGNED_IN }.minByOrNull { it.changedAt ?: it.lastUsedAt }
        if (oldest == null) {
            scope.launch { client.revokeQuietly(tokenSet.accessToken, tokenSet.refreshToken) }
            throw OIDCError(OIDCError.Kind.GENERAL, "${options.maxAccounts} accounts are signed in already; sign one out first", code = "too_many_accounts")
        }
        accounts.remove(oldest.key)
        runCatching { tokens.delete(oldest.key) }
        events.emit(Event.Forgotten(oldest))
    }

    private suspend fun handleTokenEvent(event: TokenManager.Event) {
        when (event) {
            is TokenManager.Event.Refreshed -> serial {
                val claims = event.tokenSet.claims ?: return@serial
                val a = accounts[event.key] ?: return@serial
                accounts[event.key] = a.copy(claims = a.claims + claims.filterKeys { it in profileClaims })
                runCatching { persist() }
                if (event.key == activeKeyValue) events.emit(Event.Refreshed(accounts[event.key]!!))
                events.emit(Event.Change)
            }
            is TokenManager.Event.Expired -> runCatching { end(event.key, "Its tokens could not be renewed.") }
            else -> {}
        }
    }

    /** Writes the account list. The snapshot is taken under the lock, so the last write is the latest list. */
    private suspend fun persist() {
        persistLock.withLock("accounts") {
            val snapshot = serial { listNow() }
            options.store.setJSON(options.storeKey, jsonObjectOf("accounts" to JsonArray(snapshot.map { it.toJson() })))
        }
    }
}

/** The account key for an `iss` and `sub`: stable, opaque, and safe in a storage key or a URL. */
public fun accountKey(iss: String, sub: String): String = "acct-" + Base64URL.encode(sha256("$iss\n$sub")).take(22)
