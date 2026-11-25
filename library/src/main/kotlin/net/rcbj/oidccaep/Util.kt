// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** base64url without padding (RFC 4648 §5), as JOSE uses it. */
public object Base64URL {
    public fun encode(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /** Decodes base64url. Padding, whitespace and the standard alphabet's `+` and `/` are refused. */
    public fun decode(string: String): ByteArray? {
        if (!string.all { it.code < 128 && (it.isLetterOrDigit() || it == '-' || it == '_') }) return null
        if (string.length % 4 == 1) return null
        return try { Base64.getUrlDecoder().decode(string) } catch (e: IllegalArgumentException) { null }
    }
}

private val secureRandom = SecureRandom()

/** A cryptographically random base64url string (default 256 bits). */
public fun randomToken(bytes: Int = 32): String = Base64URL.encode(ByteArray(bytes).also { secureRandom.nextBytes(it) })

internal fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
internal fun sha256(string: String): ByteArray = sha256(string.encodeToByteArray())

/**
 * Compares two strings in time independent of where they differ, so a response's `state` cannot be guessed byte
 * by byte from timing. Both sides are hashed first so their lengths match.
 */
internal fun timingSafeEqual(a: String, b: String): Boolean = MessageDigest.isEqual(sha256(a), sha256(b))

internal fun parseURI(value: String?): URI? = try { value?.let { URI(it) } } catch (e: Exception) { null }

/** Loopback hosts, where plain http is acceptable (RFC 8252 §7.3, RFC 9700 §2.6). */
internal fun isLoopback(url: URI): Boolean {
    var host = url.host?.lowercase() ?: return false
    if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length - 1)
    if (host == "localhost" || host.endsWith(".localhost") || host == "::1") return true
    val parts = host.split(".")
    return parts.size == 4 && parts[0] == "127" && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255 }
}

/** https, or plain http to a loopback host. Anything unparseable is not secure. */
internal fun isSecureURL(value: String?): Boolean {
    val url = parseURI(value) ?: return false
    val scheme = url.scheme?.lowercase() ?: return false
    if (url.host == null) return false
    return scheme == "https" || (scheme == "http" && isLoopback(url))
}

/**
 * A private-use URI scheme for a native app's redirect URI (RFC 8252 §7.1): a reverse domain name such as
 * `com.example.app`, so it contains a period, with no fragment.
 */
internal fun isPrivateUseRedirect(url: URI): Boolean {
    val scheme = url.scheme?.lowercase() ?: return false
    if (!scheme.contains('.') || url.rawFragment != null) return false
    return Regex("^[a-z][a-z0-9+.-]*$").matches(scheme)
}

/** Where a native app may receive a redirect: https, loopback http, or a private-use scheme. */
internal fun isAcceptableRedirect(url: URI): Boolean = isSecureURL(url.toString()) || isPrivateUseRedirect(url)

/** The origin (`scheme://host[:port]`) of a URL, with the default port left out. */
internal fun originOf(url: URI): String? {
    val scheme = url.scheme?.lowercase() ?: return null
    val host = url.host?.lowercase() ?: return null
    val defaultPort = when (scheme) { "https" -> 443; "http" -> 80; else -> -1 }
    val hostPart = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
    return if (url.port != -1 && url.port != defaultPort) "$scheme://$hostPart:${url.port}" else "$scheme://$hostPart"
}

internal fun originOf(string: String?): String? = parseURI(string)?.let(::originOf)

internal fun nowSeconds(now: Instant): Long = now.epochSecond

/** Seconds since 1970 as a Double, for comparisons with JSON numbers. */
internal val Instant.seconds: Double get() = epochSecond + nano / 1e9

internal fun Instant.plusSeconds(seconds: Double): Instant = plusMillis((seconds * 1000).toLong())

// MARK: - Concurrency

/**
 * A serial executor for one object's state: what a Swift `actor` is. Every member that touches the state runs on
 * it, one at a time, and (as with an actor) others may run while one is suspended.
 */
internal fun actorDispatcher(): CoroutineDispatcher = Dispatchers.Default.limitedParallelism(1)

/**
 * A mutex keyed by name: a refresh and a delete of one key's tokens never interleave, and two refreshes never
 * present the same rotating refresh token.
 */
internal class KeyedMutex {
    private val mutexes = HashMap<String, Mutex>()
    private fun mutex(name: String): Mutex = synchronized(mutexes) { mutexes.getOrPut(name) { Mutex() } }
    suspend fun <T> withLock(name: String, body: suspend () -> T): T = mutex(name).withLock { body() }
}

/** A subscription made with [EventHub.subscribe]. Cancel it to stop receiving events. */
public class EventSubscription internal constructor(private val onCancel: () -> Unit) {
    private val cancelled = AtomicBoolean(false)
    public fun cancel() {
        if (cancelled.compareAndSet(false, true)) onCancel()
    }
}

/** Delivers a component's events to any number of listeners, as callbacks or as a [Flow]. */
public class EventHub<E> {
    private val listeners = LinkedHashMap<UUID, (E) -> Unit>()

    /** Calls [listener] with every event until the returned subscription is cancelled. */
    public fun subscribe(listener: (E) -> Unit): EventSubscription {
        val id = UUID.randomUUID()
        synchronized(listeners) { listeners[id] = listener }
        return EventSubscription { synchronized(listeners) { listeners.remove(id) } }
    }

    /** A flow of every event from the moment it is collected. */
    public fun flow(): Flow<E> = callbackFlow {
        val subscription = subscribe { trySend(it) }
        awaitClose { subscription.cancel() }
    }

    internal fun emit(event: E) {
        val current = synchronized(listeners) { listeners.values.toList() }
        for (listener in current) listener(event)
    }
}

// MARK: - Logging

/**
 * Where the library writes its few log lines (a received CAEP event, a warning about token storage, an SSF error
 * nobody handles). Replace [handler] to route them elsewhere (the default writes to Logcat on Android, else to
 * standard output and error), or set it to a no-op.
 */
public object OIDCLog {
    public enum class Level { INFO, WARNING, ERROR }

    @Volatile
    public var handler: (Level, String) -> Unit = { level, message -> defaultLog(level, message) }

    internal fun log(level: Level, message: String) = handler(level, message)

    private fun defaultLog(level: Level, message: String) {
        // android.util.Log on a device; plain output in JVM unit tests (where android.jar's stubs do nothing).
        val logged = try {
            when (level) {
                Level.INFO -> android.util.Log.i("OIDCCAEPClient", message)
                Level.WARNING -> android.util.Log.w("OIDCCAEPClient", message)
                Level.ERROR -> android.util.Log.e("OIDCCAEPClient", message)
            }
            System.getProperty("java.vendor")?.contains("Android", ignoreCase = true) == true
        } catch (e: Throwable) {
            false
        }
        if (!logged) {
            val line = "[OIDCCAEPClient] $message"
            if (level == Level.INFO) println(line) else System.err.println(line)
        }
    }
}
