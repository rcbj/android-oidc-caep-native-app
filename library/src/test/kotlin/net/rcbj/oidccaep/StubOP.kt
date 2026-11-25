// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A strict in-memory OpenID Provider and SSF transmitter, injected as the library's HttpTransport. It enforces public
// clients, PKCE, PAR, and DPoP (proof signature, htm/htu/ath, key binding, nonces), and keeps a poll stream of SETs
// with acknowledgements. Ported from the Swift library's Tests/OIDCCAEPClientTests/StubOP.swift.

package net.rcbj.oidccaep

import kotlinx.coroutines.delay
import kotlinx.coroutines.yield
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import java.net.URI
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.UUID

const val ISSUER = "https://op.example.test"
const val CLIENT_ID = "native-demo"
val REDIRECT: URI = URI("net.example.app:/callback")
val POST_LOGOUT: URI = URI("net.example.app:/logged-out")

data class IssuedCode(val clientID: String, val redirectURI: String, val challenge: String, val nonce: String?, val jkt: String?, val scope: String, val sub: String)

data class Grant(val sub: String, val jkt: String?, val scope: String, val sid: String)

class StubError(message: String) : Exception(message)

fun nowEpoch(): Long = System.currentTimeMillis() / 1000

class StubOP : HttpTransport {
    // Settings a test may change.
    @Volatile var idTokenAlg = "ES256"
    @Volatile var signer: JWSSigner = SoftwareECSigner.generate("ES256")
    @Volatile var rsaKey: Pair<PrivateKey, RSAPublicKey>? = null
    @Volatile var metadataOverrides: JsonObject = emptyJsonObject
    @Volatile var metadataRemovals: Set<String> = emptySet()
    @Volatile var sub = "user-1"
    @Volatile var email = "alice@example.test"
    @Volatile var emailVerified = true
    @Volatile var sid = "sid-1"
    @Volatile var expiresIn = 300
    @Volatile var issueRefreshTokens = true
    @Volatile var rotateRefreshTokens = true
    @Volatile var forceTokenType: String? = null
    @Volatile var requireDPoPNonce = false
    @Volatile var dpopNonce = "nonce-1"
    @Volatile var authorizeError: String? = null
    @Volatile var mutateIDToken: ((MutableMap<String, JsonElement>) -> Unit)? = null
    @Volatile var refreshIDToken = true
    @Volatile var userinfoSub: String? = null
    /** Milliseconds the token endpoint waits before answering. */
    @Volatile var tokenDelay: Long = 0
    /** Like iya-sts's ssf.maxStreams: a create past it is refused with 403 access_denied. */
    @Volatile var maxStreams = 25

    // What happened.
    var tokenRequests = 0; private set
    var refreshRequests = 0; private set
    val revoked = mutableListOf<String>()
    val parRequests = mutableListOf<FormParameters>()
    var lastAuthorizeParams = FormParameters(); private set
    val acks = mutableListOf<String>()
    val setErrs = LinkedHashMap<String, JsonElement>()
    val subjectsAdded = mutableListOf<JsonObject>()
    var streamDeletes = 0; private set

    private val codes = HashMap<String, IssuedCode>()
    private val parRequestsByURI = HashMap<String, FormParameters>()
    private val refreshTokens = HashMap<String, Grant>()
    private val accessTokens = HashMap<String, Grant>()
    private val streams = LinkedHashMap<String, JsonObject>()
    private val queued = mutableListOf<Pair<String, String>>()

    // SSF
    @Volatile var ssfSigner: JWSSigner = SoftwareECSigner.generate("ES256")
    val ssfKid = "ssf-1"

    private val lock = Any()

    fun useRSA(alg: String) {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        rsaKey = pair.private to (pair.public as RSAPublicKey)
        idTokenAlg = alg
    }

    val metadata: JsonObject
        get() {
            val m = LinkedHashMap<String, JsonElement>(jsonObjectOf(
                "issuer" to ISSUER,
                "authorization_endpoint" to "$ISSUER/authorize",
                "token_endpoint" to "$ISSUER/token",
                "jwks_uri" to "$ISSUER/jwks",
                "userinfo_endpoint" to "$ISSUER/userinfo",
                "revocation_endpoint" to "$ISSUER/revoke",
                "end_session_endpoint" to "$ISSUER/logout",
                "pushed_authorization_request_endpoint" to "$ISSUER/par",
                "registration_endpoint" to "$ISSUER/register",
                "response_types_supported" to listOf("code"),
                "subject_types_supported" to listOf("public"),
                "id_token_signing_alg_values_supported" to listOf("RS256", "PS256", "ES256"),
                "code_challenge_methods_supported" to listOf("S256"),
                "token_endpoint_auth_methods_supported" to listOf("none"),
                "dpop_signing_alg_values_supported" to listOf("ES256"),
                "scopes_supported" to listOf("openid", "profile", "email", "offline_access"),
                "authorization_response_iss_parameter_supported" to true,
            ))
            m.putAll(metadataOverrides)
            for (k in metadataRemovals) m.remove(k)
            return JsonObject(m)
        }

    val jwks: JsonObject
        get() {
            val keys = mutableListOf<JsonElement>()
            rsaKey?.let { keys.add(rsaPublicJWK(it.second).with("kid", "rsa-1")) }
            keys.add(signer.publicJWK.with("kid", "ec-1"))
            return jsonObjectOf("keys" to JsonArray(keys))
        }

    // MARK: Signing

    fun signIDToken(claims: JsonObject): String {
        val rsa = rsaKey
        if (rsa != null && (idTokenAlg.startsWith("RS") || idTokenAlg.startsWith("PS"))) {
            val header = jsonObjectOf("alg" to idTokenAlg, "kid" to "rsa-1", "typ" to "JWT")
            val input = Base64URL.encode(header.jsonBytes()) + "." + Base64URL.encode(claims.jsonBytes())
            val sig = (if (idTokenAlg.startsWith("PS")) pss("256") else Signature.getInstance("SHA256withRSA"))
                .run { initSign(rsa.first); update(input.encodeToByteArray()); sign() }
            return input + "." + Base64URL.encode(sig)
        }
        return signJWS(jsonObjectOf("kid" to "ec-1", "typ" to "JWT"), claims, signer)
    }

    fun makeSET(type: String, payload: JsonObject = emptyJsonObject, subId: JsonObject? = null, aud: String = CLIENT_ID, iat: Long? = null,
                jti: String = UUID.randomUUID().toString(), typ: String = "secevent+jwt", signer: JWSSigner? = null,
                extraEvents: JsonObject = emptyJsonObject): String {
        val events = jsonObjectOf(type to payload) + extraEvents
        val claims = jsonObjectOf("iss" to ISSUER, "aud" to aud, "iat" to (iat ?: nowEpoch()), "jti" to jti, "events" to events, "sub_id" to subId)
        return signJWS(jsonObjectOf("kid" to ssfKid, "typ" to typ), claims, signer ?: ssfSigner)
    }

    fun queueSET(type: String, payload: JsonObject = emptyJsonObject, subId: JsonObject? = null, jti: String = UUID.randomUUID().toString(),
                 token: String? = null): String {
        val t = token ?: makeSET(type, payload, subId, jti = jti)
        synchronized(lock) { queued.add(jti to t) }
        return jti
    }

    val queuedCount: Int get() = synchronized(lock) { queued.size }
    val streamCount: Int get() = synchronized(lock) { streams.size }
    fun stream(id: String): JsonObject? = synchronized(lock) { streams[id] }

    // MARK: The browser's part

    /** What the browser does: follows the authorization request and returns the redirect it ends at. */
    fun authorize(url: URI): URI = synchronized(lock) {
        var p = OIDCClient.responseParameters(url)
        p.get("request_uri")?.let { uri ->
            val pushed = parRequestsByURI.remove(uri) ?: throw StubError("unknown request_uri")
            if (pushed.get("client_id") != p.get("client_id")) throw StubError("client_id differs from PAR")
            p = pushed
        }
        lastAuthorizeParams = p
        val challenge = p.get("code_challenge")
        val redirect = p.get("redirect_uri")
        val clientID = p.get("client_id")
        if (p.get("response_type") != "code" || p.get("code_challenge_method") != "S256" || challenge == null || redirect == null || clientID == null) {
            throw StubError("bad authorization request")
        }
        val out = FormParameters()
        val error = authorizeError
        if (error != null) {
            out.append("error", error)
        } else {
            val code = randomToken()
            codes[code] = IssuedCode(clientID, redirect, challenge, p.get("nonce"), p.get("dpop_jkt"), p.get("scope") ?: "openid", sub)
            out.append("code", code)
        }
        p.get("state")?.let { out.append("state", it) }
        out.append("iss", ISSUER)
        URI(redirect + "?" + out.encoded)
    }

    // MARK: HTTP

    override suspend fun send(request: HttpRequest, timeoutSeconds: Double): HttpResponse {
        // The Swift StubOP is an actor, so every request suspends the caller (an actor hop); so does this one.
        yield()
        if (request.method == "POST" && request.url.path == "/token" && tokenDelay > 0) {
            synchronized(lock) { tokenRequests += 1 }
            delay(tokenDelay)
            return synchronized(lock) { handle(request, countedToken = true) }
        }
        return synchronized(lock) { handle(request, countedToken = false) }
    }

    private fun handle(request: HttpRequest, countedToken: Boolean): HttpResponse {
        val url = request.url
        val path = url.path
        fun json(v: JsonElement, status: Int = 200, headers: Map<String, String> = emptyMap()) =
            HttpResponse(url, status, headers + ("content-type" to "application/json"), v.jsonBytes())
        fun oauthError(error: String, status: Int = 400) = json(jsonObjectOf("error" to error), status)
        val form = FormParameters.parse(request.body?.decodeToString() ?: "")
        val body = request.body?.let { try { parseJson(it) as? JsonObject } catch (e: Exception) { null } } ?: emptyJsonObject
        val query = FormParameters.parse(url.rawQuery ?: "")

        when (request.method to path) {
            "GET" to "/.well-known/openid-configuration" -> return json(metadata)
            "GET" to "/jwks" -> return json(jwks)
            "GET" to "/.well-known/ssf-configuration" -> return json(jsonObjectOf(
                "issuer" to ISSUER, "jwks_uri" to "$ISSUER/ssf/jwks",
                "configuration_endpoint" to "$ISSUER/ssf/streams", "status_endpoint" to "$ISSUER/ssf/status",
                "add_subject_endpoint" to "$ISSUER/ssf/subjects:add", "remove_subject_endpoint" to "$ISSUER/ssf/subjects:remove",
                "verification_endpoint" to "$ISSUER/ssf/verify", "delivery_methods_supported" to listOf(Delivery.POLL)))
            "GET" to "/ssf/jwks" -> return json(jsonObjectOf("keys" to listOf(ssfSigner.publicJWK.with("kid", ssfKid))))
            "POST" to "/par" -> {
                if (form.get("client_id") != CLIENT_ID) return oauthError("invalid_client", 401)
                checkDPoP(request, "POST")?.let { return it }
                parRequests.add(form)
                val uri = "urn:ietf:params:oauth:request_uri:${randomToken()}"
                parRequestsByURI[uri] = form
                return json(jsonObjectOf("request_uri" to uri, "expires_in" to 60), 201)
            }
            "POST" to "/token" -> {
                if (!countedToken) tokenRequests += 1
                if (form.get("client_id") != CLIENT_ID) return oauthError("invalid_client", 401)
                checkDPoP(request, "POST")?.let { return it }
                val jkt = request.headers["dpop"]?.let { proofJkt(it) }
                when (form.get("grant_type")) {
                    "authorization_code" -> {
                        val code = form.get("code")
                        val issued = code?.let { codes.remove(it) } ?: return oauthError("invalid_grant")
                        val verifier = form.get("code_verifier")
                        if (issued.redirectURI != form.get("redirect_uri") || verifier == null || codeChallengeS256(verifier) != issued.challenge) {
                            return oauthError("invalid_grant")
                        }
                        if (issued.jkt != null && issued.jkt != jkt) return oauthError("invalid_dpop_proof")
                        return json(issueTokens(issued.sub, issued.nonce, jkt, issued.scope, true))
                    }
                    "refresh_token" -> {
                        refreshRequests += 1
                        val rt = form.get("refresh_token")
                        val grant = rt?.let { refreshTokens[it] } ?: return oauthError("invalid_grant")
                        if (grant.jkt != null && grant.jkt != jkt) return oauthError("invalid_dpop_proof")
                        if (rotateRefreshTokens) refreshTokens.remove(rt)
                        var out = issueTokens(grant.sub, null, grant.jkt, grant.scope, refreshIDToken)
                        if (!rotateRefreshTokens) out = out.with("refresh_token", null)
                        return json(out)
                    }
                    else -> return oauthError("unsupported_grant_type")
                }
            }
            "GET" to "/userinfo" -> {
                val (_, grant) = authorizedGrant(request) ?: return HttpResponse(url, 401, mapOf("www-authenticate" to "DPoP error=\"invalid_token\""))
                return json(jsonObjectOf("sub" to (userinfoSub ?: grant.sub), "email" to email, "name" to "Alice Example"))
            }
            "POST" to "/revoke" -> {
                form.get("token")?.let { t ->
                    revoked.add(t)
                    refreshTokens.remove(t)
                    accessTokens.remove(t)
                }
                return HttpResponse(url, 200)
            }
            "POST" to "/register" -> return json(body.with("client_id", CLIENT_ID), 201)
            "POST" to "/ssf/streams" -> {
                authorizedGrant(request) ?: return oauthError("invalid_token", 401)
                if (streams.size >= maxStreams) return oauthError("access_denied", 403)
                val id = "stream-${streams.size + 1}"
                val s = body.with("stream_id", id).with("aud", CLIENT_ID)
                    .with("delivery", jsonObjectOf("method" to Delivery.POLL, "endpoint_url" to "$ISSUER/ssf/poll/$id"))
                streams[id] = s
                return json(s, 201)
            }
            "GET" to "/ssf/streams" -> {
                authorizedGrant(request) ?: return oauthError("invalid_token", 401)
                query.get("stream_id")?.let { id ->
                    val s = streams[id] ?: return oauthError("not_found", 404)
                    return json(s)
                }
                return json(JsonArray(streams.values.toList()))
            }
            "PATCH" to "/ssf/streams" -> {
                val id = body.string("stream_id")
                val s = id?.let { streams[it] } ?: return oauthError("not_found", 404)
                val merged = s + body
                streams[id] = merged
                return json(merged)
            }
            "DELETE" to "/ssf/streams" -> {
                streamDeletes += 1
                streams.remove(query.get("stream_id") ?: "")
                return HttpResponse(url, 204)
            }
            "POST" to "/ssf/subjects:add" -> {
                body["subject"].objectValue?.let { subjectsAdded.add(it) }
                return HttpResponse(url, 200)
            }
            "POST" to "/ssf/verify" -> {
                val state = body.string("state") ?: ""
                val t = makeSET(SSF.VERIFICATION, jsonObjectOf("state" to state), Subject.opaque(body.string("stream_id") ?: ""))
                queued.add(UUID.randomUUID().toString() to t)
                return HttpResponse(url, 204)
            }
        }
        if (request.method == "POST" && path.startsWith("/ssf/poll/")) {
            authorizedGrant(request) ?: return oauthError("invalid_token", 401)
            val ack = body["ack"].stringArrayValue ?: emptyList()
            acks.addAll(ack)
            val errs = body["setErrs"].objectValue ?: emptyJsonObject
            setErrs.putAll(errs)
            queued.removeAll { it.first in ack || errs[it.first] != null }
            val max = body["maxEvents"].longValue?.toInt() ?: 25
            val batch = queued.take(max)
            val sets = JsonObject(batch.associate { it.first to jsonOf(it.second) })
            return json(jsonObjectOf("sets" to sets, "moreAvailable" to (queued.size > batch.size)))
        }
        return HttpResponse(url, 404)
    }

    private fun issueTokens(sub: String, nonce: String?, jkt: String?, scope: String, withIDToken: Boolean): JsonObject {
        val access = randomToken()
        val grant = Grant(sub, jkt, scope, sid)
        accessTokens[access] = grant
        var out = jsonObjectOf("access_token" to access, "token_type" to (forceTokenType ?: if (jkt != null) "DPoP" else "Bearer"),
            "expires_in" to expiresIn, "scope" to scope)
        if (issueRefreshTokens) {
            val rt = randomToken()
            refreshTokens[rt] = grant
            out = out.with("refresh_token", rt)
        }
        if (withIDToken) {
            val now = nowEpoch()
            val claims = LinkedHashMap<String, JsonElement>(jsonObjectOf("iss" to ISSUER, "sub" to sub, "aud" to CLIENT_ID, "iat" to now,
                "exp" to now + 300, "auth_time" to 1_700_000_000, "sid" to sid, "email" to email, "email_verified" to emailVerified,
                "preferred_username" to "alice", "at_hash" to tokenHash(access, idTokenAlg)))
            if (nonce != null) claims["nonce"] = jsonOf(nonce)
            mutateIDToken?.invoke(claims)
            out = out.with("id_token", signIDToken(JsonObject(claims)))
        }
        return out
    }

    /** The grant behind the request's access token, with its DPoP proof checked when it is DPoP-bound. */
    private fun authorizedGrant(request: HttpRequest): Pair<String, Grant>? {
        val auth = request.headers["authorization"] ?: ""
        val parts = auth.split(" ", limit = 2)
        if (parts.size != 2) return null
        val grant = accessTokens[parts[1]] ?: return null
        if (grant.jkt != null) {
            val proof = request.headers["dpop"]
            if (parts[0] != "DPoP" || proof == null || proofJkt(proof) != grant.jkt) return null
            val claims = verifyProof(proof, request.method, request.url)
            if (claims.string("ath") != Base64URL.encode(sha256(parts[1]))) return null
        } else if (parts[0] != "Bearer") {
            return null
        }
        return parts[1] to grant
    }

    private fun checkDPoP(request: HttpRequest, htm: String): HttpResponse? {
        val proof = request.headers["dpop"] ?: return null
        val claims = verifyProof(proof, htm, request.url)
        if (requireDPoPNonce && claims.string("nonce") != dpopNonce) {
            return HttpResponse(request.url, 400, mapOf("dpop-nonce" to dpopNonce, "content-type" to "application/json"),
                "{\"error\":\"use_dpop_nonce\"}".encodeToByteArray())
        }
        return null
    }

    private fun verifyProof(proof: String, htm: String, url: URI): JsonObject {
        val jws = CompactJWS(proof)
        val jwk = jws.header["jwk"].objectValue
        if (jws.header.string("typ") != "dpop+jwt" || jwk == null) throw StubError("bad proof header")
        if (!VerificationKey(jwk).verify(jws.alg ?: "", jws.signature, jws.signingInput)) throw StubError("bad proof signature")
        val claims = parseJsonObject(jws.payload)
        if (claims.string("htm") != htm || claims.string("htu") != htuOf(url) || claims.string("jti") == null) throw StubError("bad proof claims")
        return claims
    }

    private fun proofJkt(proof: String): String = jwkThumbprint(CompactJWS(proof).header["jwk"].objectValue ?: throw StubError("no jwk"))
}

/** A WebAuthenticator that plays the browser against the stub. */
class StubBrowser(private val op: StubOP) : WebAuthenticator {
    override suspend fun authenticate(url: URI, callback: URI): URI {
        if (url.path == "/logout") {
            val p = OIDCClient.responseParameters(url)
            val out = FormParameters()
            p.get("state")?.let { out.append("state", it) }
            return URI((p.get("post_logout_redirect_uri") ?: callback.toString()) + "?" + out.encoded)
        }
        return op.authorize(url)
    }
}

suspend fun makeClient(op: StubOP, dpop: Boolean = true, configure: (OIDCClientOptions) -> OIDCClientOptions = { it }): OIDCClient {
    clearDiscoveryCache()
    val o = OIDCClientOptions(clientID = CLIENT_ID, redirectURI = REDIRECT, postLogoutRedirectURI = POST_LOGOUT,
        idTokenSignedResponseAlg = op.idTokenAlg, dpop = if (dpop) DPoPOptions() else null, transport = op)
    return OIDCClient.discover(URI("$ISSUER/.well-known/openid-configuration"), configure(o))
}

/** The Swift suite's XCTAssertThrowsCode: [body] must throw an [OIDCError] with [code]. */
suspend fun <T> assertThrowsCode(code: String, body: suspend () -> T) {
    try {
        body()
    } catch (e: OIDCError) {
        assertEquals(e.message, code, e.code)
        return
    } catch (e: Throwable) {
        fail("expected OIDCError $code, got $e")
    }
    fail("expected $code, got success")
}
