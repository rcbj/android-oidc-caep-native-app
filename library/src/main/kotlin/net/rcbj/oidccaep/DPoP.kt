// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.time.Instant
import java.util.UUID

/** DPoP proof algorithms this library can create, in preference order. */
public val dpopAlgorithms: List<String> = listOf("ES256", "ES384", "ES512")

/**
 * Where a DPoP key pair is kept between launches.
 *
 * - [MemoryKeyStore]: a software key in memory (a new key every launch).
 * - [AndroidKeystoreKeyStore]: a P-256 key generated in the Android Keystore (StrongBox or the TEE). Its private
 *   key can never be read out, by this app or anything else, so a stolen access or refresh token is useless
 *   elsewhere: the counterpart of the Secure Enclave on Apple platforms.
 */
public interface DPoPKeyStore {
    /** The key kept for [alg], if any. */
    public suspend fun load(alg: String): JWSSigner?
    /** Creates a key for [alg], keeps it (replacing any other), and returns it. */
    public suspend fun create(alg: String): JWSSigner
    /** Forgets the key. */
    public suspend fun delete()
    /** The algorithms this store can create keys for, in preference order. */
    public val supportedAlgorithms: List<String>
    /** Whether the private key can be read out of the store (a software key) or not (hardware-backed). */
    public val isExtractable: Boolean
}

/** A software key in memory: a new one after every launch. */
public class MemoryKeyStore : DPoPKeyStore {
    private val mutex = Mutex()
    private var signer: JWSSigner? = null
    override suspend fun load(alg: String): JWSSigner? = mutex.withLock { signer?.takeIf { it.alg == alg } }
    override suspend fun create(alg: String): JWSSigner = mutex.withLock { SoftwareECSigner.generate(alg).also { signer = it } }
    override suspend fun delete(): Unit = mutex.withLock { signer = null }
    override val supportedAlgorithms: List<String> get() = dpopAlgorithms
    override val isExtractable: Boolean get() = true
}

/**
 * A DPoP key pair (RFC 9449) and the proofs made with it.
 *
 * Keep the same key for the lifetime of the tokens it binds: a refresh token bound to a key is useless with any other.
 */
public class DPoPKey(public val signer: JWSSigner) {
    public val alg: String get() = signer.alg
    public val publicJWK: JsonObject get() = signer.publicJWK
    /** RFC 7638 SHA-256 thumbprint of the public key (the `jkt`). */
    public val thumbprint: String = jwkThumbprint(signer.publicJWK)

    /** A DPoP proof JWT (RFC 9449 §4.2) for one request. */
    public fun proof(method: String, url: URI, nonce: String? = null, accessToken: String? = null, now: Instant = Instant.now()): String {
        val claims = jsonObjectOf(
            "htm" to method.uppercase(),
            "htu" to htuOf(url),
            "jti" to UUID.randomUUID().toString().lowercase(),
            "iat" to nowSeconds(now),
            "nonce" to nonce,
            "ath" to accessToken?.let { Base64URL.encode(sha256(it)) },
        )
        return signJWS(jsonObjectOf("typ" to "dpop+jwt", "jwk" to publicJWK), claims, signer)
    }

    public companion object {
        /** Loads the key held in [store] for [alg], or creates one there. */
        public suspend fun loadOrCreate(store: DPoPKeyStore, alg: String = "ES256"): DPoPKey =
            DPoPKey(store.load(alg) ?: store.create(alg))
    }
}

/** The `htu` of a request: its URL without query and fragment (RFC 9449 §4.2). */
public fun htuOf(url: URI): String {
    val scheme = url.scheme?.lowercase() ?: return url.toString()
    val host = url.host?.lowercase() ?: return url.toString()
    val port = url.port.takeUnless { (scheme == "https" && it == 443) || (scheme == "http" && it == 80) } ?: -1
    val path = url.rawPath?.ifEmpty { "/" } ?: "/"
    val hostPart = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
    return "$scheme://$hostPart${if (port != -1) ":$port" else ""}$path"
}

/** Remembers the most recent `DPoP-Nonce` each server origin handed out (RFC 9449 §8, §9). */
internal class DPoPNonceCache {
    private val nonces = HashMap<String, String>()

    fun get(url: URI): String? = originOf(url)?.let { o -> synchronized(nonces) { nonces[o] } }

    /** Records the nonce a response carries, if any, and returns it. */
    fun update(url: URI, response: HttpResponse): String? {
        val nonce = response.header("dpop-nonce")?.takeIf { it.isNotEmpty() } ?: return null
        val o = originOf(url) ?: return null
        synchronized(nonces) { nonces[o] = nonce }
        return nonce
    }
}

/** Whether a resource server's 401 asks for a (new) DPoP nonce (RFC 9449 §9). */
internal fun wantsDPoPNonce(response: HttpResponse): Boolean {
    if (response.status != 401) return false
    val www = response.header("www-authenticate") ?: ""
    return Regex("\\bdpop\\b", RegexOption.IGNORE_CASE).containsMatchIn(www) && www.contains("error=\"use_dpop_nonce\"") &&
        response.header("dpop-nonce") != null
}
