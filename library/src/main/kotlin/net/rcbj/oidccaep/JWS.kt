// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import java.math.BigInteger
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant

/** Asymmetric JWS algorithms this library can verify. A public client has no secret, so HS* is not among them. */
public val asymmetricJWSAlgorithms: List<String> = listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519")

/** ID token algorithms this library can verify. */
public val supportedIDTokenAlgorithms: List<String> = asymmetricJWSAlgorithms

/** Why a JWS or JWT was not accepted, in the terms of the `jose` library the JavaScript client uses. */
internal sealed class JOSEError(message: String) : Exception(message) {
    class Invalid(m: String) : JOSEError(m)
    class NotSupported(m: String) : JOSEError(m)
    class AlgNotAllowed(m: String) : JOSEError(m)
    class SignatureFailed : JOSEError("signature verification failed")
    class ClaimFailed(val claim: String, m: String) : JOSEError(m)
    class Expired(val claim: String, m: String) : JOSEError(m)
    /** May pass after the JWKS is fetched again. */
    class NoMatchingKey : JOSEError("no applicable key found in the JSON Web Key Set")
    /** The JWKS could not be fetched or read: may pass later. */
    class JwksUnavailable(m: String) : JOSEError(m)

    override fun toString(): String = message ?: ""
}

/** A compact JWS, split and decoded (signature not yet verified). */
internal class CompactJWS(token: String) {
    val header: JsonObject
    val payload: ByteArray
    val signingInput: ByteArray
    val signature: ByteArray

    init {
        val parts = token.split(".")
        if (parts.size != 3) throw JOSEError.Invalid("Invalid Compact JWS")
        val h = Base64URL.decode(parts[0]) ?: throw JOSEError.Invalid("Invalid JWS Protected Header")
        header = (try { parseJson(h) } catch (e: Exception) { null }) as? JsonObject ?: throw JOSEError.Invalid("Invalid JWS Protected Header")
        payload = Base64URL.decode(parts[1]) ?: throw JOSEError.Invalid("Invalid Compact JWS encoding")
        signature = Base64URL.decode(parts[2]) ?: throw JOSEError.Invalid("Invalid Compact JWS encoding")
        signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray()
    }

    val alg: String? get() = header.string("alg")
}

/** Decodes a JWS's protected header without verifying anything. */
public fun decodeProtectedHeader(token: String): JsonObject =
    try { CompactJWS(token).header } catch (e: Exception) { throw OIDCError.validation("Not a valid compact JWS") }

/** Decodes a JWT's payload without verifying anything. For display only: never trust what it returns. */
public fun decodeUnverifiedJWTPayload(token: String): JsonObject? {
    val parts = token.split(".")
    if (parts.size != 3) return null
    val data = Base64URL.decode(parts[1]) ?: return null
    return try { parseJson(data) as? JsonObject } catch (e: Exception) { null }
}

// MARK: - Keys

private val curves = mapOf("P-256" to ("secp256r1" to 32), "P-384" to ("secp384r1" to 48), "P-521" to ("secp521r1" to 66))

internal fun ecParameters(curveName: String): ECParameterSpec =
    AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(curveName)) }.getParameterSpec(ECParameterSpec::class.java)

/** A public key from a JWK (RFC 7517), ready to verify signatures. */
internal class VerificationKey(jwk: JsonObject) {
    private val key: PublicKey
    private val kty: String
    private val crv: String?

    init {
        fun bytes(name: String): ByteArray {
            val d = jwk.string(name)?.let(Base64URL::decode)
            if (d == null || d.isEmpty()) throw JOSEError.Invalid("JWK member $name is missing or invalid")
            return d
        }
        kty = jwk.string("kty") ?: throw JOSEError.NotSupported("Unsupported key type (none)")
        crv = jwk.string("crv")
        key = when (kty) {
            "RSA" -> {
                val n = BigInteger(1, bytes("n"))
                val e = BigInteger(1, bytes("e"))
                if (n.bitLength() < 2048) throw JOSEError.Invalid("Unusable RSA key (RSA keys must be at least 2048 bits)")
                try { KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e)) } catch (x: Exception) {
                    throw JOSEError.Invalid("Unusable RSA key (RSA keys must be at least 2048 bits)")
                }
            }
            "EC" -> {
                val (name, size) = curves[crv] ?: throw JOSEError.NotSupported("Unsupported EC curve ${crv ?: "(none)"}")
                val x = bytes("x")
                val y = bytes("y")
                if (x.size != size || y.size != size) throw JOSEError.Invalid("Invalid EC public key")
                try {
                    KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), ecParameters(name)))
                } catch (e: Exception) {
                    throw JOSEError.Invalid("Invalid EC public key")
                }
            }
            "OKP" -> {
                if (crv != "Ed25519") throw JOSEError.NotSupported("Unsupported OKP curve ${crv ?: "(none)"}")
                val x = bytes("x")
                if (x.size != 32) throw JOSEError.Invalid("Invalid Ed25519 public key")
                // SubjectPublicKeyInfo for Ed25519 (RFC 8410): the OID 1.3.101.112 and the raw key.
                val spki = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + x
                try { KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki)) } catch (e: Exception) {
                    throw JOSEError.NotSupported("Ed25519 is not available on this platform")
                }
            }
            else -> throw JOSEError.NotSupported("Unsupported key type $kty")
        }
    }

    /** Verifies [signature] over [input] with [alg]. A key of the wrong type for [alg] fails. */
    fun verify(alg: String, signature: ByteArray, input: ByteArray): Boolean = try {
        when {
            kty == "RSA" && alg in setOf("RS256", "RS384", "RS512") ->
                Signature.getInstance("SHA${alg.takeLast(3)}withRSA").run { initVerify(key); update(input); verify(signature) }
            kty == "RSA" && alg in setOf("PS256", "PS384", "PS512") -> pss(alg.takeLast(3)).run { initVerify(key); update(input); verify(signature) }
            kty == "EC" && alg == "ES256" && crv == "P-256" -> ecdsa("SHA256withECDSA", signature, 32, input)
            kty == "EC" && alg == "ES384" && crv == "P-384" -> ecdsa("SHA384withECDSA", signature, 48, input)
            kty == "EC" && alg == "ES512" && crv == "P-521" -> ecdsa("SHA512withECDSA", signature, 66, input)
            kty == "OKP" && (alg == "EdDSA" || alg == "Ed25519") ->
                Signature.getInstance("Ed25519").run { initVerify(key); update(input); verify(signature) }
            else -> false
        }
    } catch (e: Exception) {
        false
    }

    private fun ecdsa(name: String, signature: ByteArray, size: Int, input: ByteArray): Boolean {
        if (signature.size != 2 * size) return false
        return Signature.getInstance(name).run { initVerify(key); update(input); verify(rawToDer(signature)) }
    }
}

/** An RSASSA-PSS verifier or signer for SHA-256/384/512, with MGF1 over the same hash and a salt of the hash's size. */
internal fun pss(bits: String): Signature {
    val hash = "SHA-$bits"
    val spec = PSSParameterSpec(hash, "MGF1", MGF1ParameterSpec(hash), bits.toInt() / 8, 1)
    return try {
        Signature.getInstance("RSASSA-PSS").apply { setParameter(spec) }
    } catch (e: Exception) {
        // Android's Conscrypt names it by digest.
        Signature.getInstance("SHA${bits}withRSA/PSS")
    }
}

/** JWS ECDSA `r || s` to the DER `SEQUENCE { INTEGER r, INTEGER s }` the platform verifies. */
internal fun rawToDer(raw: ByteArray): ByteArray {
    val half = raw.size / 2
    fun integer(bytes: ByteArray): ByteArray {
        val v = BigInteger(1, bytes).toByteArray() // minimal, with a leading 0 when the high bit is set
        return byteArrayOf(0x02) + derLength(v.size) + v
    }
    val body = integer(raw.copyOfRange(0, half)) + integer(raw.copyOfRange(half, raw.size))
    return byteArrayOf(0x30) + derLength(body.size) + body
}

private fun derLength(n: Int): ByteArray = when {
    n < 0x80 -> byteArrayOf(n.toByte())
    n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
    else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
}

/** A DER ECDSA signature to JWS `r || s`, each [size] bytes. */
internal fun derToRaw(der: ByteArray, size: Int): ByteArray {
    var i = 0
    fun readLength(): Int {
        val first = der[i++].toInt() and 0xff
        if (first < 0x80) return first
        var n = 0
        repeat(first and 0x7f) { n = (n shl 8) or (der[i++].toInt() and 0xff) }
        return n
    }
    require(der[i++] == 0x30.toByte()) { "Not a DER signature" }
    readLength()
    fun readInt(): ByteArray {
        require(der[i++] == 0x02.toByte()) { "Not a DER signature" }
        val len = readLength()
        val v = der.copyOfRange(i, i + len)
        i += len
        val unsigned = BigInteger(1, v).toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        require(unsigned.size <= size) { "Signature integer too long" }
        return ByteArray(size - unsigned.size) + unsigned
    }
    return readInt() + readInt()
}

/** Whether a JWK can be used to verify a signature made with [alg] (its `kty`, `crv`, `use`, `alg` and `key_ops`). */
internal fun jwkIsUsableFor(jwk: JsonObject, alg: String): Boolean {
    jwk.string("use")?.let { if (it != "sig") return false }
    jwk["key_ops"].stringArrayValue?.let { if ("verify" !in it) return false }
    jwk.string("alg")?.let { if (it != alg) return false }
    val kty = jwk.string("kty")
    val crv = jwk.string("crv")
    return when (alg) {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> kty == "RSA"
        "ES256" -> kty == "EC" && crv == "P-256"
        "ES384" -> kty == "EC" && crv == "P-384"
        "ES512" -> kty == "EC" && crv == "P-521"
        "EdDSA", "Ed25519" -> kty == "OKP" && crv == "Ed25519"
        else -> false
    }
}

/** RFC 7638 JWK SHA-256 thumbprint of a public key. */
public fun jwkThumbprint(jwk: JsonObject): String {
    val members = when (jwk.string("kty")) {
        "EC" -> listOf("crv", "kty", "x", "y")
        "RSA" -> listOf("e", "kty", "n")
        "OKP" -> listOf("crv", "kty", "x")
        else -> emptyList()
    }
    val json = "{" + members.joinToString(",") { "\"$it\":\"${jwk.string(it) ?: ""}\"" } + "}"
    return Base64URL.encode(sha256(json))
}

// MARK: - Key sets

/**
 * A JSON Web Key Set fetched from a `jwks_uri`, cached, and fetched again when a token names a key it does not
 * hold (a rotation), at most once per cooldown: the behaviour of `jose`'s `createRemoteJWKSet`.
 */
internal class RemoteJWKSet(
    val url: URI,
    private val http: HttpClient,
    private val cooldownSeconds: Double = 30.0,
    private val cacheMaxAgeSeconds: Double = 600.0,
    private val now: () -> Instant,
) {
    private val mutex = Mutex()
    private var keys: List<JsonObject>? = null
    private var fetchedAt: Instant? = null
    private var inflight: CompletableDeferred<List<JsonObject>>? = null

    /** The keys that may have signed a token with this header. */
    suspend fun candidates(header: JsonObject): List<JsonObject> {
        val alg = header.string("alg") ?: throw JOSEError.Invalid("JWS header has no alg")
        val kid = header.string("kid")
        fun matching(list: List<JsonObject>) = list.filter { (kid == null || it.string("kid") == kid) && jwkIsUsableFor(it, alg) }
        val (held, at) = mutex.withLock { keys to fetchedAt }
        val fresh = at?.let { now().seconds - it.seconds < cacheMaxAgeSeconds } ?: false
        var list = if (held == null || !fresh) reload() else held
        var found = matching(list)
        val fetched = mutex.withLock { fetchedAt }
        if (found.isEmpty() && fetched != null && now().seconds - fetched.seconds >= cooldownSeconds) {
            list = reload()
            found = matching(list)
        }
        if (found.isEmpty()) throw JOSEError.NoMatchingKey()
        return found
    }

    private suspend fun reload(): List<JsonObject> {
        val (deferred, owner) = mutex.withLock {
            inflight?.let { it to false } ?: CompletableDeferred<List<JsonObject>>().also { inflight = it }.let { it to true }
        }
        if (!owner) return deferred.await()
        try {
            val res = try { http.get(url, mapOf("accept" to "application/json, application/jwk-set+json")) } catch (e: Exception) {
                throw JOSEError.JwksUnavailable("Could not fetch the JWKS at $url: ${e.message}")
            }
            val doc = if (res.isOK) (try { parseJson(res.body) } catch (e: Exception) { null }) as? JsonObject else null
            val list = doc?.get("keys").arrayValue ?: throw JOSEError.JwksUnavailable("The JWKS at $url is not a JSON Web Key Set (HTTP ${res.status})")
            val fetched = list.mapNotNull { it.objectValue }
            mutex.withLock {
                keys = fetched
                fetchedAt = now()
                inflight = null
            }
            deferred.complete(fetched)
            return fetched
        } catch (e: Throwable) {
            mutex.withLock { inflight = null }
            deferred.completeExceptionally(e)
            throw e
        }
    }
}

// MARK: - Verifying JWTs

internal class JWTVerifyOptions(
    val algorithms: List<String>,
    val issuer: String? = null,
    /** The token's `aud` must contain one of these. */
    val audience: List<String>? = null,
    val clockTolerance: Double = 0.0,
    /** Refuse a token whose `iat` is older than this (seconds). */
    val maxTokenAge: Double? = null,
    val requiredClaims: List<String> = emptyList(),
    val now: Instant,
)

/** Verifies a compact JWS JWT's signature against [keys] and its registered claims. Returns the header and the claims. */
internal suspend fun verifyJWT(token: String, keys: RemoteJWKSet, o: JWTVerifyOptions): Pair<JsonObject, JsonObject> {
    val jws = CompactJWS(token)
    val alg = jws.alg ?: throw JOSEError.Invalid("JWS header has no alg")
    if (alg !in o.algorithms) throw JOSEError.AlgNotAllowed("\"alg\" (Algorithm) Header Parameter value not allowed")
    if (jws.header["crit"] != null) throw JOSEError.NotSupported("Extension Header Parameter in crit is not recognized")
    if (jws.header["b64"] != null) throw JOSEError.NotSupported("b64 is not supported")

    val candidates = keys.candidates(jws.header)
    val verified = candidates.any { jwk ->
        val key = try { VerificationKey(jwk) } catch (e: JOSEError) { null }
        key?.verify(alg, jws.signature, jws.signingInput) == true
    }
    if (!verified) throw JOSEError.SignatureFailed()

    val claims = (try { parseJson(jws.payload) } catch (e: Exception) { null }) as? JsonObject
        ?: throw JOSEError.Invalid("JWT Claims Set must be a top-level JSON object")
    validateClaims(claims, o)
    return jws.header to claims
}

internal fun validateClaims(claims: JsonObject, o: JWTVerifyOptions) {
    for (name in o.requiredClaims) if (claims[name] == null) throw JOSEError.ClaimFailed(name, "missing required \"$name\" claim")
    if (o.issuer != null && claims.string("iss") != o.issuer) throw JOSEError.ClaimFailed("iss", "unexpected \"iss\" claim value")
    if (o.audience != null) {
        val aud = claims["aud"].stringValue?.let { listOf(it) } ?: claims["aud"].stringArrayValue ?: emptyList()
        if (aud.none { it in o.audience }) throw JOSEError.ClaimFailed("aud", "unexpected \"aud\" claim value")
    }
    val now = o.now.epochSecond.toDouble()
    val tol = o.clockTolerance
    claims["iat"]?.let { if (it.doubleValue == null) throw JOSEError.ClaimFailed("iat", "\"iat\" claim must be a number") }
    claims["nbf"]?.let {
        val v = it.doubleValue ?: throw JOSEError.ClaimFailed("nbf", "\"nbf\" claim must be a number")
        if (v > now + tol) throw JOSEError.ClaimFailed("nbf", "\"nbf\" claim timestamp check failed")
    }
    claims["exp"]?.let {
        val v = it.doubleValue ?: throw JOSEError.ClaimFailed("exp", "\"exp\" claim must be a number")
        if (v <= now - tol) throw JOSEError.Expired("exp", "\"exp\" claim timestamp check failed")
    }
    o.maxTokenAge?.let { max ->
        val iat = claims["iat"].doubleValue ?: throw JOSEError.ClaimFailed("iat", "missing required \"iat\" claim")
        val age = now - iat
        if (age - tol > max) throw JOSEError.Expired("iat", "\"iat\" claim timestamp check failed (too far in the past)")
        if (age < 0 - tol) throw JOSEError.ClaimFailed("iat", "\"iat\" claim timestamp check failed (it should be in the past)")
    }
}

// MARK: - Signing (DPoP proofs)

/** Creates compact JWS tokens with a private key (DPoP proofs, and test fixtures). */
public interface JWSSigner {
    /** The JWS `alg` this key signs with. */
    public val alg: String
    /** The public key, as a JWK (no private members). */
    public val publicJWK: JsonObject
    /** The JWS signature over [data] (for ECDSA, `r || s`). */
    public fun sign(data: ByteArray): ByteArray
}

/** Signs [claims] as a compact JWS with [signer], under [header] (its `alg` is set from the signer). */
public fun signJWS(header: JsonObject, claims: JsonObject, signer: JWSSigner): String {
    val h = header.with("alg", signer.alg)
    val input = Base64URL.encode(h.jsonBytes()) + "." + Base64URL.encode(claims.jsonBytes())
    return input + "." + Base64URL.encode(signer.sign(input.encodeToByteArray()))
}

/** The public JWK of an EC public key. */
internal fun ecPublicJWK(key: ECPublicKey, crv: String, size: Int): JsonObject {
    fun fixed(v: BigInteger): ByteArray {
        val b = v.toByteArray().let { if (it.size > size) it.copyOfRange(it.size - size, it.size) else it }
        return ByteArray(size - b.size) + b
    }
    return jsonObjectOf("kty" to "EC", "crv" to crv, "x" to Base64URL.encode(fixed(key.w.affineX)), "y" to Base64URL.encode(fixed(key.w.affineY)))
}

/** The public JWK of an RSA public key. */
internal fun rsaPublicJWK(key: RSAPublicKey): JsonObject {
    fun unsigned(v: BigInteger) = v.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
    return jsonObjectOf("kty" to "RSA", "n" to Base64URL.encode(unsigned(key.modulus)), "e" to Base64URL.encode(unsigned(key.publicExponent)))
}

/** An ES256 / ES384 / ES512 signer with a software key. */
public class SoftwareECSigner private constructor(override val alg: String, private val privateKey: PrivateKey, publicKey: ECPublicKey) : JWSSigner {
    private val size = ecSizes[alg]!!.second
    override val publicJWK: JsonObject = ecPublicJWK(publicKey, ecSizes[alg]!!.first, size)

    /** The private key, PKCS #8 encoded, for a store that keeps it. */
    public val pkcs8PrivateKey: ByteArray get() = privateKey.encoded

    override fun sign(data: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA${alg.takeLast(3)}withECDSA").run { initSign(privateKey); update(data); sign() }
        return derToRaw(der, size)
    }

    public companion object {
        private val ecSizes = mapOf("ES256" to ("P-256" to 32), "ES384" to ("P-384" to 48), "ES512" to ("P-521" to 66))
        private val curveNames = mapOf("ES256" to "secp256r1", "ES384" to "secp384r1", "ES512" to "secp521r1")

        /** A new key for [alg] (ES256, ES384 or ES512). */
        public fun generate(alg: String = "ES256"): SoftwareECSigner {
            val curve = curveNames[alg] ?: throw OIDCError.usage("Unsupported EC algorithm $alg")
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
            return SoftwareECSigner(alg, pair.private, pair.public as ECPublicKey)
        }

        /** A key restored from [pkcs8PrivateKey] and its public JWK. */
        public fun restore(alg: String, pkcs8: ByteArray, publicJWK: JsonObject): SoftwareECSigner {
            if (alg !in curveNames) throw OIDCError.usage("Unsupported EC algorithm $alg")
            val factory = KeyFactory.getInstance("EC")
            val priv = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val x = BigInteger(1, Base64URL.decode(publicJWK.string("x") ?: "") ?: ByteArray(0))
            val y = BigInteger(1, Base64URL.decode(publicJWK.string("y") ?: "") ?: ByteArray(0))
            val pub = factory.generatePublic(ECPublicKeySpec(ECPoint(x, y), ecParameters(curveNames[alg]!!))) as ECPublicKey
            return SoftwareECSigner(alg, priv, pub)
        }
    }
}
