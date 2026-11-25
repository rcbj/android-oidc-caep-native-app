// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.time.Instant

/**
 * The tokens one token endpoint response issued, with the claims of the ID token this client validated.
 *
 * Stored as the token response's own JSON (snake_case), plus `expires_at`, `issued_at` and `claims`.
 */
public data class TokenSet(
    val accessToken: String,
    /** `Bearer` or `DPoP`. */
    val tokenType: String = "Bearer",
    val refreshToken: String? = null,
    val idToken: String? = null,
    val scope: String? = null,
    /** Epoch seconds when the access token expires. */
    val expiresAt: Long? = null,
    /** Epoch seconds when the tokens were issued. */
    val issuedAt: Long? = null,
    /**
     * The validated ID token's claims. Only claims this client validated: an ID token is never decoded here
     * unverified, because code that trusts `claims` (UserInfo's `sub` check, account keys) must not be handed claims
     * nobody checked.
     */
    val claims: JsonObject? = null,
    /** Every other member of the token response. */
    val additional: JsonObject = emptyJsonObject,
) {
    /** The tokens are bound to a DPoP key (`token_type` DPoP). */
    val isDPoPBound: Boolean get() = tokenType.equals("DPoP", ignoreCase = true)

    /** Seconds until the access token expires. */
    public fun expiresIn(now: Instant = Instant.now()): Long? = expiresAt?.let { maxOf(0, it - nowSeconds(now)) }

    /**
     * Skew to apply for early renewal, capped at half the token lifetime so that short-lived tokens are not considered
     * expired the moment they are issued.
     */
    public fun effectiveSkew(skew: Double): Double {
        val i = issuedAt ?: return skew
        val e = expiresAt ?: return skew
        return minOf(skew, (e - i) / 2.0)
    }

    /** Whether the access token has expired, or will within [skew] seconds (see [effectiveSkew]). */
    public fun isExpired(skew: Double = 0.0, now: Instant = Instant.now()): Boolean {
        val e = expiresAt ?: return false
        return e - effectiveSkew(skew) <= nowSeconds(now).toDouble()
    }

    /** The token set as stored: the response's members, `expires_at`, `issued_at` and `claims`. */
    val json: JsonObject get() {
        val o = LinkedHashMap<String, JsonElement>(additional)
        o["access_token"] = jsonOf(accessToken)
        o["token_type"] = jsonOf(tokenType)
        refreshToken?.let { o["refresh_token"] = jsonOf(it) }
        idToken?.let { o["id_token"] = jsonOf(it) }
        scope?.let { o["scope"] = jsonOf(it) }
        expiresAt?.let { o["expires_at"] = jsonOf(it) }
        issuedAt?.let { o["issued_at"] = jsonOf(it) }
        claims?.let { o["claims"] = it }
        return JsonObject(o)
    }

    public companion object {
        private val known = setOf("access_token", "token_type", "refresh_token", "id_token", "scope", "expires_in", "expires_at", "issued_at", "claims")

        /** From a token endpoint response. `expires_in` becomes `expires_at`; the response cannot set `expires_at`, `issued_at` or `claims`. */
        internal fun fromResponse(response: JsonObject, claims: JsonObject?, now: Instant): TokenSet {
            val expiresIn = response["expires_in"]?.let { it.doubleValue ?: it.stringValue?.toDoubleOrNull() }
            return TokenSet(
                accessToken = response.string("access_token") ?: "",
                tokenType = response.string("token_type") ?: "Bearer",
                refreshToken = response.string("refresh_token"),
                idToken = response.string("id_token"),
                scope = response.string("scope"),
                expiresAt = expiresIn?.let { nowSeconds(now) + it.toLong() },
                issuedAt = expiresIn?.let { nowSeconds(now) },
                claims = claims,
                additional = JsonObject(response.filterKeys { it !in known }),
            )
        }

        /** A token set as stored ([json]). */
        public fun fromJson(o: JsonObject): TokenSet {
            val access = o.string("access_token") ?: throw OIDCError.validation("Stored tokens have no access_token")
            return TokenSet(access, o.string("token_type") ?: "Bearer", o.string("refresh_token"), o.string("id_token"), o.string("scope"),
                o["expires_at"].longValue, o["issued_at"].longValue, o["claims"].objectValue, JsonObject(o.filterKeys { it !in known }))
        }
    }
}

/**
 * Where tokens (and an [AccountManager]'s account list) are kept: opaque values by key.
 *
 * [MemoryTokenStore] keeps nothing past the process. [KeystoreTokenStore] (Android) encrypts the values with a key in
 * the Android Keystore and keeps them in the app's private storage, so a relaunch keeps every signed-in account.
 */
public interface TokenStore {
    public suspend fun get(key: String): ByteArray?
    public suspend fun set(key: String, value: ByteArray)
    public suspend fun delete(key: String)
    /** Whether values outlive the process. A persistent store without DPoP logs a warning. */
    public val isPersistent: Boolean get() = true
}

internal suspend fun TokenStore.getJSON(key: String): JsonObject? {
    val data = get(key) ?: return null
    return try { parseJson(data) as? JsonObject } catch (e: Exception) { null }
}

internal suspend fun TokenStore.setJSON(key: String, value: JsonObject) = set(key, value.jsonBytes())

/** Tokens in memory only: a relaunch means signing in again (or resuming silently with `prompt=none`). */
public class MemoryTokenStore : TokenStore {
    private val mutex = Mutex()
    private val values = HashMap<String, ByteArray>()
    override suspend fun get(key: String): ByteArray? = mutex.withLock { values[key] }
    override suspend fun set(key: String, value: ByteArray): Unit = mutex.withLock { values[key] = value }
    override suspend fun delete(key: String): Unit = mutex.withLock { values.remove(key) }
    public suspend fun keys(): List<String> = mutex.withLock { values.keys.toList() }
    override val isPersistent: Boolean get() = false
}

/** One authorization request in progress: what the callback needs to check the response and redeem the code. */
public data class AuthorizationTransaction(
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectURI: String,
    val maxAge: Int?,
    val acrValues: String?,
    val expectedSub: String?,
    val context: JsonElement?,
    val issuer: String,
    val clientID: String,
    /** When the request was created (seconds since 1970). */
    val createdAt: Double,
) {
    internal fun toJson(): JsonObject = jsonObjectOf("state" to state, "nonce" to nonce, "codeVerifier" to codeVerifier, "redirectURI" to redirectURI,
        "maxAge" to maxAge, "acrValues" to acrValues, "expectedSub" to expectedSub, "context" to context, "issuer" to issuer,
        "clientID" to clientID, "createdAt" to createdAt)

    internal companion object {
        fun fromJson(o: JsonObject): AuthorizationTransaction? = try {
            AuthorizationTransaction(o.string("state")!!, o.string("nonce")!!, o.string("codeVerifier")!!, o.string("redirectURI")!!,
                o["maxAge"].longValue?.toInt(), o.string("acrValues"), o.string("expectedSub"), o["context"], o.string("issuer")!!,
                o.string("clientID")!!, o["createdAt"].doubleValue!!)
        } catch (e: NullPointerException) {
            null
        }
    }
}

/** A logout request in progress (RP-Initiated Logout), kept to check the `state` it returns with. */
public data class LogoutTransaction(val state: String, val context: JsonElement?, val createdAt: Double) {
    internal fun toJson(): JsonObject = jsonObjectOf("state" to state, "context" to context, "createdAt" to createdAt)

    internal companion object {
        fun fromJson(o: JsonObject): LogoutTransaction? {
            val state = o.string("state") ?: return null
            val at = o["createdAt"].doubleValue ?: return null
            return LogoutTransaction(state, o["context"], at)
        }
    }
}

/**
 * Authorization and logout transactions between the request and its callback, keyed by `state`. [take] removes the
 * entry as it reads it, so each transaction (and therefore each response) is used once.
 *
 * A native app receives the callback in the process that made the request, so the default,
 * [MemoryTransactionStore], is enough.
 */
public interface TransactionStore {
    public suspend fun set(id: String, value: ByteArray)
    /** Reads and removes a transaction. */
    public suspend fun take(id: String): ByteArray?
    /** Removes transactions created before [cutoff] (abandoned sign-ins). */
    public suspend fun sweep(cutoff: Instant)
}

/** Transactions in memory. */
public class MemoryTransactionStore : TransactionStore {
    private val mutex = Mutex()
    private val values = HashMap<String, Pair<ByteArray, Instant>>()
    override suspend fun set(id: String, value: ByteArray): Unit = mutex.withLock { values[id] = value to Instant.now() }
    override suspend fun take(id: String): ByteArray? = if (id.isEmpty()) null else mutex.withLock { values.remove(id)?.first }
    override suspend fun sweep(cutoff: Instant): Unit = mutex.withLock { values.entries.removeAll { it.value.second.isBefore(cutoff) } }
}
