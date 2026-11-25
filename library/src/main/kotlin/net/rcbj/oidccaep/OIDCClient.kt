// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.MessageDigest
import java.time.Instant

/** Pushed Authorization Requests (RFC 9126). */
public enum class PARMode {
    /** Used when the provider advertises a PAR endpoint (and required when it sets `require_pushed_authorization_requests`). */
    AUTO,
    /** Always; fails when the provider has no PAR endpoint. */
    ALWAYS,
    /** Never; fails when the provider requires PAR. */
    NEVER,
}

/** DPoP (RFC 9449) settings. */
public class DPoPOptions(
    /** Where the key is kept. Default: memory (a new key every launch). */
    public val keyStore: DPoPKeyStore = MemoryKeyStore(),
    /** The proof algorithm. Default: the first of the store's algorithms the provider accepts. */
    public val alg: String? = null,
    /** A key to use as is, instead of one from [keyStore]. */
    public val key: DPoPKey? = null,
)

/** How an [OIDCClient] behaves. Only [clientID] is required; every default is the safe one. */
public data class OIDCClientOptions(
    /** A PUBLIC client (`token_endpoint_auth_method` none). There is no client secret. */
    public val clientID: String,
    /**
     * Where the provider returns the authorization response. For a native app (RFC 8252): a private-use scheme such
     * as `com.example.app:/callback`, or loopback `http://127.0.0.1:port/…` (which needs [LoopbackWebAuthenticator]).
     */
    public val redirectURI: URI? = null,
    public val postLogoutRedirectURI: URI? = null,
    /** Default `openid profile email`, plus `offline_access` when the provider supports it. */
    public val scope: String? = null,
    /** RFC 8707 resource indicators: audience-restrict the tokens. */
    public val resource: List<String> = emptyList(),
    /** The ID token `alg` this client accepts (one only). Default RS256. */
    public val idTokenSignedResponseAlg: String = "RS256",
    public val par: PARMode = PARMode.AUTO,
    /** DPoP (RFC 9449). Off when null. */
    public val dpop: DPoPOptions? = null,
    /** With DPoP on, refuse a token response whose `token_type` is Bearer. Default true. A refresh of DPoP-bound tokens never accepts Bearer. */
    public val requireDPoP: Boolean? = null,
    /** The only `alg` a signed UserInfo response may use. Default: any asymmetric algorithm. */
    public val userinfoSignedResponseAlg: String? = null,
    /** Where state, nonce and the PKCE verifier wait for the callback. */
    public val transactionStore: TransactionStore = MemoryTransactionStore(),
    /** How long an authorization request stays redeemable (seconds). */
    public val transactionTTL: Double = 600.0,
    /** Refuse ID tokens whose `iat` is older than this (seconds; 0 for no limit). */
    public val maxIDTokenAge: Double = 600.0,
    /** When `acr_values` were requested, require the ID token's `acr` to be one of them. */
    public val enforceACR: Boolean = true,
    /** Require `auth_time` in every ID token. */
    public val requireAuthTime: Boolean = false,
    /** Allow non-TLS endpoints other than loopback. Never in production. */
    public val allowInsecureRequests: Boolean = false,
    /** Allowed clock skew (seconds). */
    public val clockTolerance: Double = 30.0,
    /** Per-request timeout (seconds). */
    public val httpTimeout: Double = 10.0,
    /** How long discovered metadata is cached (seconds). */
    public val discoveryCacheTTL: Double = 3600.0,
    public val transport: HttpTransport = OkHttpTransport(),
    /** The clock (for tests). */
    public val now: () -> Instant = { Instant.now() },
)

/** Options for one authorization request. */
public data class AuthorizationRequestOptions(
    public val scope: String? = null,
    public val redirectURI: URI? = null,
    /** `none`, `login`, `consent`, `select_account` (space-separated for several). */
    public val prompt: String? = null,
    public val maxAge: Int? = null,
    public val loginHint: String? = null,
    /** A previously issued ID token naming the account (and session) meant. */
    public val idTokenHint: String? = null,
    /** Space-separated; with `enforceACR`, the ID token's `acr` must be one of these. */
    public val acrValues: String? = null,
    /** The callback refuses an ID token about anybody else (`account_mismatch`). */
    public val expectedSub: String? = null,
    /** Kept with the transaction and handed back by [OIDCClient.completeAuthorization] (and on an OAuth error as [OIDCError.context]). */
    public val context: JsonElement? = null,
    /** Further parameters (`claims`, `ui_locales` …). They may not replace the ones the client sets. */
    public val extraParameters: Map<String, String> = emptyMap(),
)

/** An authorization request, ready to open in the system browser. */
public data class AuthorizationRequest(public val url: URI, public val state: String)

/** A completed sign-in. */
public data class AuthorizationResult(public val tokenSet: TokenSet, public val context: JsonElement?)

/** An RP-Initiated Logout request. */
public data class EndSessionRequest(public val url: URI, public val state: String)

/** The DPoP key in use. */
public data class DPoPFeature(public val alg: String, public val jkt: String, public val extractable: Boolean)

/** Which protections are in effect, for display and audit. */
public data class SecurityFeatures(
    public val pkce: String,
    public val state: String,
    public val nonce: Boolean,
    public val issuerIdentification: String,
    public val par: Boolean,
    /** The DPoP algorithm and key thumbprint, when DPoP is on. */
    public val dpop: DPoPFeature?,
    public val resourceIndicators: List<String>,
    public val tlsEnforced: Boolean,
    public val idToken: String,
)

/** Authorization request parameters `extraParameters` may not set: the client sets them, and the callback relies on them. */
private val reservedAuthorizationParameters = setOf("response_type", "response_mode", "client_id", "redirect_uri", "state", "nonce",
    "code_challenge", "code_challenge_method", "dpop_jkt", "request", "request_uri", "resource")

/** JWT `typ` values that mark a token as something other than an ID token (RFC 8725 §3.11). */
private val notIDTokenTypes = setOf("at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt", "token-introspection+jwt",
    "software-statement+jwt", "jwt-bearer")

/** Parameters that must never arrive at a code-flow redirect URI (tokens in the front channel). */
private val frontChannelTokens = listOf("access_token", "id_token", "refresh_token", "token_type")

/** Endpoints whose URLs must use TLS. */
private val tlsEndpoints = listOf("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint",
    "end_session_endpoint", "pushed_authorization_request_endpoint", "registration_endpoint")

/**
 * OpenID Connect Relying Party for a PUBLIC client (a native app): Authorization Code + PKCE, with the protections
 * RFC 9700 (OAuth 2.0 Security Best Current Practice), RFC 8252 (OAuth 2.0 for Native Apps) and OpenID Connect call
 * for. It holds no client secret and supports no confidential-client authentication.
 *
 * Create one with [discover], [discoverIssuer] or [fromMetadata].
 */
public class OIDCClient private constructor(
    public val metadata: ProviderMetadata,
    public val options: OIDCClientOptions,
    /** The DPoP key, when DPoP is on. */
    public val dpopKey: DPoPKey?,
    private val dpopExtractable: Boolean,
    /** Whether authorization requests are pushed (PAR). */
    public val usesPAR: Boolean,
) {
    /** The scope requested when a request names none. */
    public val scope: String = options.scope
        ?: ("openid profile email" + if (metadata.scopesSupported?.contains("offline_access") == true) " offline_access" else "")

    /** Every token set the token endpoint issues (sign-in and refresh). */
    public val tokenEvents: EventHub<TokenSet> = EventHub()

    internal val http = HttpClient(options.transport, options.httpTimeout)
    internal val jwks = RemoteJWKSet(parseURI(metadata.jwksURI) ?: throw OIDCError.validation("jwks_uri is not a URL"), http, now = options.now)

    // RFC 9449 §8 and §9: the authorization server's nonce and a resource server's are separate, even on one origin.
    private val asNonces = DPoPNonceCache()
    private val rsNonces = DPoPNonceCache()
    private val usedStates = HashMap<String, Instant>()

    public val issuer: String get() = metadata.issuer
    public val clientID: String get() = options.clientID
    internal val now: Instant get() = options.now()

    public companion object {
        /** Loads the provider's metadata from its metadata URL (`…/.well-known/openid-configuration`) and creates a client. */
        public suspend fun discover(metadataURL: URI, options: OIDCClientOptions): OIDCClient =
            create(discoverOpenIDProvider(metadataURL, options.transport, options.httpTimeout, options.discoveryCacheTTL), options)

        /** Loads the provider's metadata from `<issuer>/.well-known/openid-configuration` and creates a client. */
        public suspend fun discoverIssuer(issuer: String, options: OIDCClientOptions): OIDCClient =
            create(discoverOpenIDProvider(issuer, options.transport, options.httpTimeout, options.discoveryCacheTTL), options)

        /** Creates a client from a provider metadata document already in hand (validated as if discovered). */
        public suspend fun fromMetadata(metadata: JsonObject, options: OIDCClientOptions): OIDCClient =
            create(validateOpenIDProviderMetadata(metadata), options)

        /**
         * Registers a new PUBLIC client (OpenID Connect Dynamic Client Registration 1.0) and returns a client configured
         * from the registration. `token_endpoint_auth_method` is always `none`. `options.clientID` is replaced.
         */
        public suspend fun register(metadata: JsonObject, clientMetadata: JsonObject, initialAccessToken: String? = null,
                                    options: OIDCClientOptions): Pair<OIDCClient, JsonObject> {
            val provider = validateOpenIDProviderMetadata(metadata)
            var request = clientMetadata.with("token_endpoint_auth_method", "none")
            if (options.dpop != null && request["dpop_bound_access_tokens"] == null) request = request.with("dpop_bound_access_tokens", true)
            val registration = ClientRegistration.register(provider, request, initialAccessToken, options.allowInsecureRequests, options.transport, options.httpTimeout)
            if (registration["client_secret"] != null) {
                // A confidential registration is not what was asked for, and this client would ignore the secret.
                throw OIDCError.validation("The OP registered a confidential client (it issued a client_secret); only public clients are supported",
                    code = "registration_mismatch", response = registration)
            }
            fun firstURI(key: String) = (registration[key].stringArrayValue?.firstOrNull() ?: request[key].stringArrayValue?.firstOrNull())?.let(::parseURI)
            val o = options.copy(
                clientID = registration.string("client_id") ?: "",
                redirectURI = options.redirectURI ?: firstURI("redirect_uris"),
                postLogoutRedirectURI = options.postLogoutRedirectURI ?: firstURI("post_logout_redirect_uris"),
                idTokenSignedResponseAlg = registration.string("id_token_signed_response_alg") ?: request.string("id_token_signed_response_alg") ?: "RS256",
            )
            return fromMetadata(metadata, o) to registration
        }

        private suspend fun create(m: ProviderMetadata, o: OIDCClientOptions): OIDCClient {
            if (o.clientID.isEmpty()) throw OIDCError.usage("clientID is required")
            // TLS for every endpoint and redirect URI (RFC 9700 §2.6, OIDC Core §16.17), loopback excepted. A native
            // app's redirect URI may also be a private-use scheme (RFC 8252 §7.1).
            if (!o.allowInsecureRequests) {
                for (key in tlsEndpoints) {
                    val value = m[key].stringValue ?: continue
                    if (!isSecureURL(value)) throw OIDCError.validation("$key must use https: $value", code = "insecure_endpoint")
                }
            }
            for ((name, uri) in listOf("redirectURI" to o.redirectURI, "postLogoutRedirectURI" to o.postLogoutRedirectURI)) {
                if (uri != null && !o.allowInsecureRequests && !isAcceptableRedirect(uri)) {
                    throw OIDCError.validation("$name must use https, loopback http, or a private-use scheme such as com.example.app:/callback: $uri",
                        code = "insecure_redirect_uri")
                }
            }
            // PKCE downgrade protection (RFC 9700 §2.1.1): refuse an OP that says it does not do S256.
            m.codeChallengeMethodsSupported?.let { if ("S256" !in it) throw OIDCError.validation("The OP does not support PKCE with S256", code = "pkce_not_supported") }
            // A public client authenticates with "none" only.
            m.tokenEndpointAuthMethodsSupported?.let {
                if ("none" !in it) throw OIDCError.validation("The OP does not accept public clients (token_endpoint_auth_method \"none\")", code = "public_client_not_supported")
            }
            if (o.idTokenSignedResponseAlg !in supportedIDTokenAlgorithms) {
                throw OIDCError.validation("ID token alg ${o.idTokenSignedResponseAlg} cannot be verified by this library (supported: ${supportedIDTokenAlgorithms.joinToString(", ")})")
            }
            if (o.idTokenSignedResponseAlg !in m.idTokenSigningAlgValuesSupported) {
                throw OIDCError.validation("OP does not support ID token alg ${o.idTokenSignedResponseAlg}")
            }

            // PAR (RFC 9126).
            val parEndpoint = m.pushedAuthorizationRequestEndpoint
            if (m.requirePushedAuthorizationRequests && parEndpoint == null) {
                throw OIDCError.validation("The OP requires PAR but advertises no pushed_authorization_request_endpoint")
            }
            if (o.par == PARMode.ALWAYS && parEndpoint == null) throw OIDCError.validation("par is ALWAYS but the OP has no pushed_authorization_request_endpoint")
            if (o.par == PARMode.NEVER && m.requirePushedAuthorizationRequests) throw OIDCError.validation("The OP requires PAR (require_pushed_authorization_requests)")
            val usesPAR = parEndpoint != null && (o.par != PARMode.NEVER || m.requirePushedAuthorizationRequests)

            // DPoP (RFC 9449).
            var dpopKey: DPoPKey? = null
            var extractable = false
            o.dpop?.let { d ->
                if (d.key != null) {
                    dpopKey = d.key
                    extractable = true
                } else {
                    val offered = m.dpopSigningAlgValuesSupported
                    val creatable = d.keyStore.supportedAlgorithms
                    val alg = d.alg ?: (if (offered != null) creatable.firstOrNull { it in offered } else creatable.firstOrNull())
                        ?: throw OIDCError.validation("The OP accepts no DPoP algorithm this key store creates (${creatable.joinToString(", ")})", code = "dpop_not_supported")
                    dpopKey = DPoPKey.loadOrCreate(d.keyStore, alg)
                    extractable = d.keyStore.isExtractable
                }
            }
            if (parseURI(m.jwksURI) == null) throw OIDCError.validation("jwks_uri is not a URL")
            val client = OIDCClient(m, o, dpopKey, extractable, usesPAR)
            o.transactionStore.sweep(o.now().plusSeconds(-o.transactionTTL))
            return client
        }

        /** The parameters of an authorization response: the query, plus any fragment, so that tokens injected in a fragment are caught. */
        internal fun responseParameters(url: URI): FormParameters {
            val all = FormParameters()
            url.rawQuery?.let { for ((n, v) in FormParameters.parse(it)) all.append(n, v) }
            url.rawFragment?.takeIf { it.isNotEmpty() }?.let { for ((n, v) in FormParameters.parse(it)) all.append(n, v) }
            return all
        }
    }

    /** Which security features are active, for display and audit. */
    public val securityFeatures: SecurityFeatures
        get() = SecurityFeatures(
            pkce = "S256",
            state = "random 256-bit, single use, expiring, issuer-bound, constant-time compared",
            nonce = true,
            issuerIdentification = if (metadata.authorizationResponseIssParameterSupported) "required (RFC 9207)" else "checked when present (RFC 9207)",
            par = usesPAR,
            dpop = dpopKey?.let { DPoPFeature(it.alg, it.thumbprint, dpopExtractable) },
            resourceIndicators = options.resource,
            tlsEnforced = !options.allowInsecureRequests,
            idToken = "alg ${options.idTokenSignedResponseAlg}, typ checked, iat ≤ ${options.maxIDTokenAge.toInt()}s, at_hash, acr ${if (options.enforceACR) "enforced" else "not enforced"}",
        )

    // MARK: Authorization request

    /**
     * Starts an Authorization Code + PKCE (S256) sign-in. The transaction (state, nonce, code verifier) is kept in the
     * transaction store under its `state`, and [completeAuthorization] consumes it. Uses PAR when enabled, and binds
     * the authorization code to the DPoP key (`dpop_jkt`).
     *
     * Open the returned URL in the system browser ([WebAuthenticator]), or use [authorize], which does both steps.
     */
    public suspend fun createAuthorizationRequest(opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationRequest {
        val redirectURI = opts.redirectURI ?: options.redirectURI ?: throw OIDCError.usage("redirectURI is required")
        if (!options.allowInsecureRequests && !isAcceptableRedirect(redirectURI)) {
            throw OIDCError.validation("redirectURI must use https, loopback http, or a private-use scheme: $redirectURI", code = "insecure_redirect_uri")
        }
        val reserved = opts.extraParameters.keys.filter { it in reservedAuthorizationParameters }.sorted()
        if (reserved.isNotEmpty()) throw OIDCError.usage("extraParameters may not set ${reserved.joinToString(", ")}: the client sets them itself")

        val state = randomToken()
        val nonce = randomToken()
        val codeVerifier = generateCodeVerifier()
        val scope = opts.scope ?: this.scope
        var prompt = opts.prompt
        // offline_access requires prompt=consent per OIDC Core §11 unless the caller chose otherwise.
        if (prompt == null && "offline_access" in scope.split(" ")) prompt = "consent"

        val query = FormParameters()
        query.append("response_type", "code")
        query.append("client_id", options.clientID)
        query.append("redirect_uri", redirectURI.toString())
        query.append("scope", scope)
        query.append("state", state)
        query.append("nonce", nonce)
        query.append("code_challenge", codeChallengeS256(codeVerifier))
        query.append("code_challenge_method", "S256")
        prompt?.let { query.append("prompt", it) }
        opts.maxAge?.let { query.append("max_age", it.toString()) }
        opts.loginHint?.let { query.append("login_hint", it) }
        opts.idTokenHint?.let { query.append("id_token_hint", it) }
        opts.acrValues?.let { query.append("acr_values", it) }
        for ((k, v) in opts.extraParameters.toSortedMap()) query.set(k, v)
        dpopKey?.let { query.append("dpop_jkt", it.thumbprint) }
        for (r in options.resource) query.append("resource", r)

        val authorizationEndpoint = parseURI(metadata.authorizationEndpoint) ?: throw OIDCError.validation("authorization_endpoint is not a URL")
        val parEndpoint = parseURI(metadata.pushedAuthorizationRequestEndpoint)
        val url = if (usesPAR && parEndpoint != null) {
            val par = postForm(parEndpoint, query)
            val requestURI = par.string("request_uri") ?: throw OIDCError.validation("PAR response has no request_uri", code = "invalid_par_response")
            authorizationEndpoint.appendingQuery(FormParameters(listOf("client_id" to options.clientID, "request_uri" to requestURI)))
        } else {
            authorizationEndpoint.appendingQuery(query)
        }

        val transaction = AuthorizationTransaction(state, nonce, codeVerifier, redirectURI.toString(), opts.maxAge, opts.acrValues, opts.expectedSub,
            opts.context, metadata.issuer, options.clientID, now.seconds)
        options.transactionStore.set(state, transaction.toJson().jsonBytes())
        return AuthorizationRequest(url, state)
    }

    /**
     * Completes the sign-in from the redirect URL: consumes the stored transaction for the returned `state` (single
     * use), checks it, redeems the code with the PKCE verifier (and a DPoP proof) and validates the ID token. An error
     * the OP returned (e.g. `login_required` to a `prompt=none` request) is thrown as an [OIDCError] of kind OAUTH
     * carrying the request's context.
     */
    public suspend fun completeAuthorization(callbackURL: URI): AuthorizationResult = completeAuthorization(responseParameters(callbackURL))

    /** [completeAuthorization] with the response's parameters. */
    public suspend fun completeAuthorization(p: FormParameters): AuthorizationResult {
        // Front-channel token injection: a code-flow redirect never carries tokens (RFC 9700 §4.5, §2.1.2).
        val injected = frontChannelTokens.filter { p.has(it) }
        if (injected.isNotEmpty()) {
            throw OIDCError.validation("Authorization response carries ${injected.joinToString(", ")}; tokens never arrive in the front channel", code = "front_channel_token")
        }
        // Parameter pollution: every response parameter appears at most once (RFC 6749 §3.1).
        for (name in p.names) if (p.getAll(name).size > 1) throw OIDCError.validation("Authorization response repeats \"$name\"", code = "duplicate_parameter")

        // STATE: look up and REMOVE the transaction (single use), then check it thoroughly.
        val returned = p.get("state")?.takeIf { it.isNotEmpty() } ?: throw OIDCError.validation("state missing from authorization response", code = "state_missing")
        val transaction = options.transactionStore.take(returned)?.let { data ->
            (try { parseJson(data) } catch (e: Exception) { null } as? JsonObject)?.let(AuthorizationTransaction::fromJson)
        }
        if (transaction == null) {
            val reused = synchronized(usedStates) { usedStates.containsKey(returned) }
            throw OIDCError.validation(
                if (reused) "This authorization response was already used (state replayed)"
                else "No sign-in in progress for this state (unknown, already used, or from another app instance)",
                code = if (reused) "state_reused" else "state_mismatch")
        }
        rememberState(returned)
        if (!timingSafeEqual(returned, transaction.state)) throw OIDCError.validation("state mismatch", code = "state_mismatch")
        if (now.seconds - transaction.createdAt > options.transactionTTL) {
            throw OIDCError.validation("The sign-in took longer than ${options.transactionTTL.toInt()}s; start again", code = "transaction_expired")
        }
        // The transaction belongs to this OP and this client (mix-up defence when several are configured).
        if (transaction.issuer != metadata.issuer || transaction.clientID != options.clientID) {
            throw OIDCError.validation("This sign-in was started with a different identity provider or client", code = "issuer_mismatch")
        }

        // RFC 9207 issuer identification.
        p.get("iss")?.let { if (it != metadata.issuer) throw OIDCError.validation("iss mismatch in authorization response: $it", code = "issuer_mismatch") }
        if (p.get("iss") == null && metadata.authorizationResponseIssParameterSupported) {
            throw OIDCError.validation("iss missing from authorization response", code = "issuer_missing")
        }
        p.get("error")?.takeIf { it.isNotEmpty() }?.let { error ->
            val e = OIDCError.oauth(error, p.get("error_description"), p.get("error_uri"))
            e.context = transaction.context
            throw e
        }
        val code = p.get("code")?.takeIf { it.isNotEmpty() } ?: throw OIDCError.validation("code missing from authorization response", code = "code_missing")

        val body = FormParameters()
        body.append("grant_type", "authorization_code")
        body.append("code", code)
        body.append("redirect_uri", transaction.redirectURI)
        body.append("code_verifier", transaction.codeVerifier)
        for (r in options.resource) body.append("resource", r)
        val tokens = tokenRequest(body)
        val idToken = tokens.string("id_token") ?: throw OIDCError.validation("Token response did not include an id_token", code = "id_token_missing")

        val claims = validateIDToken(idToken, transaction.nonce, transaction.maxAge, transaction.acrValues, tokens.string("access_token"))
        // The request named an account; a sign-in as somebody else is not that account.
        if (transaction.expectedSub != null && claims.string("sub") != transaction.expectedSub) {
            revokeQuietly(tokens.string("access_token"), tokens.string("refresh_token"))
            throw OIDCError.validation("The identity provider signed in a different account from the one requested", code = "account_mismatch",
                response = jsonObjectOf("expected" to transaction.expectedSub, "sub" to (claims["sub"] ?: JsonNull)))
        }
        val tokenSet = TokenSet.fromResponse(tokens, claims, now)
        tokenEvents.emit(tokenSet)
        return AuthorizationResult(tokenSet, transaction.context)
    }

    private fun rememberState(state: String) {
        val at = now
        val cutoff = at.plusSeconds(-options.transactionTTL)
        synchronized(usedStates) {
            usedStates[state] = at
            if (usedStates.size > 1000 || usedStates.values.any { it.isBefore(cutoff) }) {
                usedStates.entries.removeAll { it.value.isBefore(cutoff) }
                while (usedStates.size > 1000) usedStates.remove(usedStates.minByOrNull { it.value }!!.key)
            }
        }
    }

    // MARK: Refresh

    /**
     * Refresh Token grant (OIDC Core §12). Keeps the previous refresh token when the OP doesn't rotate it, validates
     * any new ID token against the previous claims (§12.2), and sends a DPoP proof with the same key when the tokens
     * are DPoP-bound.
     */
    public suspend fun refresh(previous: TokenSet, scope: String? = null): TokenSet = refresh(previous.refreshToken, previous, previous.claims, scope)

    /** Refresh with a bare refresh token. Without [previousClaims], a response that carries an ID token is refused. */
    public suspend fun refresh(refreshToken: String, previousClaims: JsonObject? = null, scope: String? = null): TokenSet =
        refresh(refreshToken, null, previousClaims, scope)

    private suspend fun refresh(refreshToken: String?, previous: TokenSet?, previousClaims: JsonObject?, scope: String?): TokenSet {
        if (refreshToken.isNullOrEmpty()) throw OIDCError(OIDCError.Kind.GENERAL, "No refresh_token available", code = "no_refresh_token")
        val body = FormParameters()
        body.append("grant_type", "refresh_token")
        body.append("refresh_token", refreshToken)
        scope?.let { body.append("scope", it) }
        for (r in options.resource) body.append("resource", r)

        var tokens = tokenRequest(body)
        val tokenType = tokens.string("token_type") ?: ""
        // A DPoP-bound grant must stay bound: a Bearer reply to it is a downgrade (RFC 9449 §5).
        if (previous?.isDPoPBound == true && !tokenType.equals("DPoP", ignoreCase = true)) {
            throw OIDCError.validation("Refresh of DPoP-bound tokens returned token_type $tokenType", code = "dpop_downgrade")
        }
        var claims = previousClaims
        tokens.string("id_token")?.let { idToken ->
            if (previousClaims == null) {
                throw OIDCError.validation("The refresh returned an ID token, and there are no previous ID token claims to check it against (OIDC Core §12.2); pass a TokenSet or previousClaims",
                    code = "invalid_id_token")
            }
            claims = validateIDToken(idToken, accessToken = tokens.string("access_token"), previousClaims = previousClaims)
        }
        if (tokens["refresh_token"] == null) tokens = tokens.with("refresh_token", refreshToken)
        if (tokens["id_token"] == null && previous?.idToken != null) tokens = tokens.with("id_token", previous.idToken)
        val tokenSet = TokenSet.fromResponse(tokens, claims, now)
        tokenEvents.emit(tokenSet)
        return tokenSet
    }

    // MARK: Calling protected resources (UserInfo, SSF, APIs)

    /** The `authorization` (and `dpop`) headers for a request to a resource server. A DPoP-bound token gets a fresh proof. */
    public fun resourceHeaders(accessToken: String, tokenType: String = "Bearer", method: String = "GET", url: URI, nonce: String? = null): Map<String, String> {
        if (tokenType.equals("DPoP", ignoreCase = true)) {
            val key = dpopKey ?: throw OIDCError(OIDCError.Kind.GENERAL, "A DPoP-bound token needs the DPoP key it was issued to", code = "dpop_key_missing")
            return mapOf("authorization" to "DPoP $accessToken", "dpop" to key.proof(method, url, nonce ?: rsNonces.get(url), accessToken, now))
        }
        return mapOf("authorization" to "Bearer $accessToken")
    }

    /** [resourceHeaders] for a token set. */
    public fun resourceHeaders(tokenSet: TokenSet, method: String = "GET", url: URI, nonce: String? = null): Map<String, String> =
        resourceHeaders(tokenSet.accessToken, tokenSet.tokenType, method, url, nonce)

    /** Sends a request to a protected resource with an access token, retrying once when the resource server asks for a DPoP nonce (RFC 9449 §9). */
    public suspend fun fetchResource(tokenSet: TokenSet, url: URI, method: String = "GET", headers: Map<String, String> = emptyMap(), body: ByteArray? = null): HttpResponse {
        suspend fun send(nonce: String?): HttpResponse =
            http.send(HttpRequest(url, method, headers.mapKeys { it.key.lowercase() } + resourceHeaders(tokenSet, method, url, nonce), body))
        var res = send(null)
        val nonce = rsNonces.update(url, res)
        if (wantsDPoPNonce(res)) {
            res = send(nonce)
            rsNonces.update(url, res)
        }
        return res
    }

    /**
     * Calls the UserInfo endpoint (OIDC Core §5.3). The response must be about the person the ID token is about
     * (§5.3.2): its `sub` is checked against [expectedSub], or else the token set's ID token `sub`.
     */
    public suspend fun userinfo(tokenSet: TokenSet, expectedSub: String? = null): JsonObject {
        val expected = expectedSub ?: tokenSet.claims?.string("sub")
            ?: throw OIDCError.validation("UserInfo needs the ID token sub to check the response against (OIDC Core §5.3.2): pass a TokenSet with an ID token, or expectedSub",
                code = "sub_mismatch")
        val endpoint = parseURI(metadata.userinfoEndpoint) ?: throw OIDCError(OIDCError.Kind.GENERAL, "OP has no userinfo_endpoint")
        val res = fetchResource(tokenSet, endpoint, headers = mapOf("accept" to "application/json, application/jwt"))
        if (res.status == 401) {
            val www = res.header("www-authenticate") ?: ""
            val error = Regex("error=\"([^\"]+)\"").find(www)?.groupValues?.get(1) ?: "invalid_token"
            throw OIDCError.oauth(error, www, status = 401)
        }
        val claims: JsonObject = if ((res.header("content-type") ?: "").contains("application/jwt")) {
            try {
                verifyJWT(res.text.trim(), jwks, JWTVerifyOptions(
                    algorithms = options.userinfoSignedResponseAlg?.let { listOf(it) } ?: asymmetricJWSAlgorithms,
                    issuer = metadata.issuer, audience = listOf(options.clientID), clockTolerance = options.clockTolerance, now = now)).second
            } catch (e: JOSEError) {
                throw OIDCError.validation("UserInfo response validation failed: $e", code = "invalid_userinfo")
            }
        } else {
            readJSON(res) as? JsonObject ?: throw OIDCError.validation("UserInfo response is not a JSON object", code = "invalid_userinfo")
        }
        if (claims.string("sub") != expected) throw OIDCError.validation("UserInfo sub does not match ID token sub", code = "sub_mismatch")
        return claims
    }

    /** Token revocation (RFC 7009), as a public client. Returns false when the OP has no revocation endpoint. */
    public suspend fun revoke(token: String, hint: String? = null): Boolean {
        val endpoint = parseURI(metadata.revocationEndpoint) ?: return false
        if (token.isEmpty()) return false
        val body = FormParameters()
        body.append("token", token)
        body.append("client_id", options.clientID)
        hint?.let { body.append("token_type_hint", it) }
        val res = http.send(HttpRequest(endpoint, "POST", mapOf("content-type" to "application/x-www-form-urlencoded", "accept" to "application/json"),
            body.encoded.encodeToByteArray()))
        if (!res.isOK) readJSON(res)
        return true
    }

    /** Revokes a token set's refresh and access tokens, ignoring failures. */
    internal suspend fun revokeQuietly(accessToken: String?, refreshToken: String?) {
        coroutineScope {
            val r = async { refreshToken?.let { runCatching { revoke(it, "refresh_token") } } }
            val a = async { accessToken?.let { runCatching { revoke(it, "access_token") } } }
            r.await()
            a.await()
        }
    }

    // MARK: Logout

    /**
     * Builds an RP-Initiated Logout 1.0 request with a fresh `state`, kept for [completeEndSession]. Returns null when
     * the OP has no end_session_endpoint. [context] is kept with the state and handed back when the logout completes.
     */
    public suspend fun createEndSessionRequest(idTokenHint: String? = null, postLogoutRedirectURI: URI? = null, logoutHint: String? = null,
                                               context: JsonElement? = null): EndSessionRequest? {
        val endpoint = parseURI(metadata.endSessionEndpoint) ?: return null
        val state = randomToken()
        val redirect = postLogoutRedirectURI ?: options.postLogoutRedirectURI
        if (redirect != null && !options.allowInsecureRequests && !isAcceptableRedirect(redirect)) {
            throw OIDCError.validation("postLogoutRedirectURI must use https, loopback http, or a private-use scheme: $redirect", code = "insecure_redirect_uri")
        }
        val params = FormParameters()
        if (!idTokenHint.isNullOrEmpty()) params.append("id_token_hint", idTokenHint)
        redirect?.let { params.append("post_logout_redirect_uri", it.toString()) }
        params.append("client_id", options.clientID)
        if (!logoutHint.isNullOrEmpty()) params.append("logout_hint", logoutHint)
        if (redirect != null) {
            params.append("state", state)
            options.transactionStore.set("logout:$state", LogoutTransaction(state, context, now.seconds).toJson().jsonBytes())
        }
        return EndSessionRequest(endpoint.appendingQuery(params), state)
    }

    /**
     * Checks the `state` the OP returned to the post-logout redirect URI, and returns the context the logout request
     * was created with. Throws when the state is missing, unknown, reused or expired.
     */
    public suspend fun completeEndSession(callbackURL: URI): JsonElement? {
        val returned = responseParameters(callbackURL).get("state")?.takeIf { it.isNotEmpty() }
            ?: throw OIDCError.validation("state missing from logout response", code = "state_missing")
        val held = options.transactionStore.take("logout:$returned")?.let { data ->
            (try { parseJson(data) } catch (e: Exception) { null } as? JsonObject)?.let(LogoutTransaction::fromJson)
        }
        if (held == null || !timingSafeEqual(returned, held.state)) throw OIDCError.validation("Unknown or already-used logout state", code = "state_mismatch")
        if (now.seconds - held.createdAt > options.transactionTTL) throw OIDCError.validation("The logout took too long", code = "transaction_expired")
        return held.context
    }

    // MARK: ID token validation (OIDC Core §3.1.3.7, §12.2; RFC 8725)

    /** Validates an ID token and returns its claims. */
    public suspend fun validateIDToken(idToken: String, nonce: String? = null, maxAge: Int? = null, acrValues: String? = null,
                                       accessToken: String? = null, previousClaims: JsonObject? = null): JsonObject {
        val expectedAlg = options.idTokenSignedResponseAlg
        val header = try { CompactJWS(idToken).header } catch (e: Exception) {
            throw OIDCError.validation("ID token is not a valid JWS", code = "invalid_id_token")
        }
        if (header.string("alg") != expectedAlg) {
            throw OIDCError.validation("Unexpected ID token alg ${header.string("alg") ?: "(none)"}; expected $expectedAlg", code = "invalid_id_token")
        }
        header["typ"]?.let { typ ->
            val t = typ.stringValue ?: typ.jsonString()
            if (t.lowercase() in notIDTokenTypes) throw OIDCError.validation("A \"$t\" token is not an ID token", code = "invalid_id_token")
        }
        if (header["crit"] != null) throw OIDCError.validation("ID token has critical header parameters this client does not understand", code = "invalid_id_token")

        val claims = try {
            verifyJWT(idToken, jwks, JWTVerifyOptions(
                algorithms = listOf(expectedAlg), issuer = metadata.issuer, audience = listOf(options.clientID), clockTolerance = options.clockTolerance,
                maxTokenAge = if (options.maxIDTokenAge > 0) options.maxIDTokenAge else null, requiredClaims = listOf("iss", "sub", "aud", "exp", "iat"), now = now)).second
        } catch (e: JOSEError) {
            throw OIDCError.validation("ID token validation failed: $e", code = "invalid_id_token")
        }

        val aud = claims["aud"].arrayValue ?: listOf(claims["aud"] ?: JsonNull)
        if (aud.size > 1 && claims["azp"] == null) throw OIDCError.validation("ID token has multiple audiences but no azp", code = "invalid_id_token")
        claims["azp"]?.let { if (it.stringValue != options.clientID) throw OIDCError.validation("ID token azp does not match client_id", code = "invalid_id_token") }
        if (nonce != null && !timingSafeEqual(claims.string("nonce") ?: "", nonce)) throw OIDCError.validation("ID token nonce mismatch", code = "nonce_mismatch")
        if ((maxAge != null || options.requireAuthTime) && claims["auth_time"].doubleValue == null) {
            throw OIDCError.validation("ID token has no auth_time", code = "invalid_id_token")
        }
        val authTime = claims["auth_time"].doubleValue
        if (maxAge != null && authTime != null && authTime + maxAge + options.clockTolerance < nowSeconds(now).toDouble()) {
            throw OIDCError.validation("auth_time is older than max_age; re-authentication required", code = "max_age_exceeded")
        }
        if (!acrValues.isNullOrEmpty() && options.enforceACR) {
            val wanted = acrValues.split(" ")
            if ((claims.string("acr") ?: "\u0000") !in wanted) {
                throw OIDCError.validation("ID token acr \"${claims.string("acr") ?: "(none)"}\" is not one of the requested acr_values ($acrValues)", code = "acr_mismatch")
            }
        }
        if (accessToken != null) {
            claims["at_hash"]?.let { if (it.stringValue != tokenHash(accessToken, expectedAlg)) throw OIDCError.validation("ID token at_hash does not match access token", code = "invalid_id_token") }
        }
        if (previousClaims != null) {
            // OIDC Core §12.2: iss, sub and azp the same (azp absent if it was absent), aud the same.
            for (claim in listOf("iss", "sub", "azp")) {
                if (claims[claim] != previousClaims[claim]) throw OIDCError.validation("Refreshed ID token $claim changed", code = "invalid_id_token")
            }
            fun audOf(v: JsonElement?) = (v.stringValue?.let { listOf(it) } ?: v.stringArrayValue ?: emptyList()).toSortedSet().toList()
            if (audOf(claims["aud"]) != audOf(previousClaims["aud"])) throw OIDCError.validation("Refreshed ID token aud changed", code = "invalid_id_token")
            // §12.2 lets a refreshed ID token leave auth_time out; one it carries must be the original time.
            val was = previousClaims["auth_time"]
            val isNow = claims["auth_time"]
            if (was != null && isNow != null && was != isNow) throw OIDCError.validation("Refreshed ID token auth_time changed", code = "invalid_id_token")
        }
        return claims
    }

    // MARK: Internals

    /**
     * POSTs a form to an authorization-server endpoint as this public client, with a DPoP proof when enabled, retrying
     * once when the AS demands a DPoP nonce (RFC 9449 §8).
     */
    internal suspend fun postForm(endpoint: URI, form: FormParameters): JsonObject {
        val f = FormParameters(form.pairs)
        f.set("client_id", options.clientID)
        val body = f.encoded.encodeToByteArray()
        suspend fun send(nonce: String?): HttpResponse {
            val headers = mutableMapOf("content-type" to "application/x-www-form-urlencoded", "accept" to "application/json")
            dpopKey?.let { headers["dpop"] = it.proof("POST", endpoint, nonce ?: asNonces.get(endpoint), now = now) }
            return http.send(HttpRequest(endpoint, "POST", headers, body))
        }
        var res = send(null)
        val nonce = asNonces.update(endpoint, res)
        if (dpopKey != null && res.status == 400 && nonce != null && Regex("\"error\"\\s*:\\s*\"use_dpop_nonce\"").containsMatchIn(res.text)) {
            res = send(nonce)
            asNonces.update(endpoint, res)
        }
        return readJSON(res) as? JsonObject ?: throw OIDCError.validation("Expected a JSON object from $endpoint")
    }

    private suspend fun tokenRequest(form: FormParameters): JsonObject {
        val endpoint = parseURI(metadata.tokenEndpoint) ?: throw OIDCError.validation("token_endpoint is not a URL")
        val tokens = postForm(endpoint, form)
        if (tokens.string("access_token").isNullOrEmpty()) throw OIDCError.validation("Token response missing access_token", code = "invalid_token_response")
        val type = tokens.string("token_type") ?: ""
        val isDPoP = type.equals("DPoP", ignoreCase = true)
        if (!isDPoP && !type.equals("Bearer", ignoreCase = true)) throw OIDCError.validation("Unsupported token_type $type", code = "invalid_token_response")
        if (isDPoP && dpopKey == null) throw OIDCError.validation("The OP issued a DPoP-bound token but DPoP is not enabled", code = "invalid_token_response")
        if (dpopKey != null && (options.requireDPoP ?: true) && !isDPoP) {
            throw OIDCError.validation("DPoP is required, and the OP issued token_type $type", code = "dpop_downgrade")
        }
        tokens["expires_in"]?.let { e ->
            val n = e.doubleValue ?: e.stringValue?.toDoubleOrNull()
            if (n == null || !n.isFinite() || n < 0) throw OIDCError.validation("Invalid expires_in ${e.jsonString()}", code = "invalid_token_response")
        }
        // expires_at, issued_at and claims are this client's own fields, computed from what it validated.
        return JsonObject(tokens.filterKeys { it !in setOf("expires_at", "issued_at", "claims") })
    }
}

/** at_hash: left-most half of the hash of the ASCII value, base64url encoded (OIDC Core §3.1.3.6). */
internal fun tokenHash(value: String, alg: String): String {
    val bits = if (alg == "EdDSA" || alg == "Ed25519") "512" else alg.takeLast(3)
    val digest = MessageDigest.getInstance(when (bits) { "384" -> "SHA-384"; "512" -> "SHA-512"; else -> "SHA-256" }).digest(value.encodeToByteArray())
    return Base64URL.encode(digest.copyOf(digest.size / 2))
}

// MARK: - PKCE

/** RFC 7636 §4.1: 43–128 characters; 32 random bytes are 43 base64url characters. */
public fun generateCodeVerifier(): String = randomToken(32)

/** RFC 7636 §4.2 S256 transformation. */
public fun codeChallengeS256(verifier: String): String = Base64URL.encode(sha256(verifier))
