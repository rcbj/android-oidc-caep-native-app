// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Ported from the Swift library's Tests/OIDCCAEPClientTests/OIDCClientTests.swift.

package net.rcbj.oidccaep

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.URI
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

class OIDCClientTests {
    private suspend fun signIn(client: OIDCClient, op: StubOP, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): TokenSet =
        client.authorize(StubBrowser(op), opts).tokenSet

    // MARK: Discovery and setup

    @Test fun testDiscoversFromMetadataURLAndSignsInWithPARAndDPoP() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        assertTrue(client.usesPAR)
        assertNotNull(client.dpopKey)
        assertEquals("openid profile email offline_access", client.scope)
        val ts = signIn(client, op)
        assertEquals("DPoP", ts.tokenType)
        assertEquals("user-1", ts.claims?.string("sub"))
        assertNotNull(ts.refreshToken)
        val pushed = op.parRequests
        assertEquals(1, pushed.size)
        assertEquals(client.dpopKey?.thumbprint, pushed[0].get("dpop_jkt"))
        assertEquals("S256", pushed[0].get("code_challenge_method"))
        assertEquals("offline_access asks for consent (OIDC Core §11)", "consent", pushed[0].get("prompt"))
    }

    @Test fun testMetadataURLMustNameItsIssuer() = runBlocking {
        val op = StubOP()
        op.metadataOverrides = jsonObjectOf("issuer" to "https://other.example.test")
        assertThrowsCode("issuer_mismatch") { makeClient(op) }
    }

    @Test fun testRefusesOPWithoutS256OrPublicClients() = runBlocking {
        val op = StubOP()
        op.metadataOverrides = jsonObjectOf("code_challenge_methods_supported" to listOf("plain"))
        assertThrowsCode("pkce_not_supported") { makeClient(op) }
        op.metadataOverrides = jsonObjectOf("token_endpoint_auth_methods_supported" to listOf("client_secret_basic"))
        assertThrowsCode("public_client_not_supported") { makeClient(op) }
    }

    @Test fun testRefusesInsecureEndpointsAndRedirects() = runBlocking {
        val op = StubOP()
        op.metadataOverrides = jsonObjectOf("token_endpoint" to "http://op.example.test/token")
        assertThrowsCode("insecure_endpoint") { makeClient(op) }
        op.metadataOverrides = emptyJsonObject
        assertThrowsCode("insecure_redirect_uri") { makeClient(op) { it.copy(redirectURI = URI("http://example.test/cb")) } }
        assertThrowsCode("insecure_redirect_uri") { makeClient(op) { it.copy(redirectURI = URI("myapp:/cb")) } }
        makeClient(op) { it.copy(redirectURI = URI("http://127.0.0.1:8123/cb")) }
        Unit
    }

    // The Swift suite reads a property list here; the Android library reads the same keys from JSON.
    @Test fun testAppConfigurationFromJSON() {
        val json = """
        {
          "MetadataURL": "https://op.example.test/.well-known/openid-configuration",
          "ClientID": "native-demo",
          "Scopes": ["openid", "email", "ssf.read"],
          "RedirectURI": "net.example.app:/callback",
          "PAR": "always",
          "DPoP": false
        }
        """
        val c = OIDCAppConfiguration.fromJson(json)
        assertEquals("native-demo", c.clientID)
        assertEquals("openid email ssf.read", c.scope)
        assertEquals(PARMode.ALWAYS, c.par)
        assertFalse(c.dpop)
        assertNull(c.clientOptions().dpop)
        assertThrowsSync { OIDCAppConfiguration.fromObject(jsonObjectOf("MetadataURL" to "https://op.example.test/", "ClientID" to "x", "RedirectURI" to "a.b:/c")) }
        assertThrowsSync { OIDCAppConfiguration.fromObject(jsonObjectOf("MetadataURL" to "https://op.example.test/.well-known/openid-configuration", "RedirectURI" to "a.b:/c")) }
    }

    @Test fun testCAEPEnabledFalseLeavesSSFScopesOutOfTheAuthorizationRequest() {
        fun configuration(caepEnabled: Boolean?, scopes: List<String>) = OIDCAppConfiguration.fromObject(jsonObjectOf(
            "MetadataURL" to "https://op.example.test/.well-known/openid-configuration",
            "ClientID" to "native-demo",
            "Scopes" to scopes,
            "RedirectURI" to "net.example.app:/callback",
            "CAEPEnabled" to caepEnabled,
        ))
        val scopes = listOf("openid", "profile", "ssf.read", "ssf.manage")
        val off = configuration(false, scopes)
        val requested = off.clientOptions().scope ?: ""
        assertEquals("openid profile", off.clientOptions().scope)
        assertFalse(requested.contains("ssf.read"))
        assertFalse(requested.contains("ssf.manage"))
        assertTrue(requested.contains("openid"))

        val defaults = configuration(null, scopes)
        assertTrue(defaults.caepEnabled)
        assertEquals("openid profile ssf.read ssf.manage", defaults.clientOptions().scope)
        assertTrue(defaults.clientOptions().scope?.contains("ssf.read") == true)

        assertNull(configuration(false, listOf("ssf.read", "ssf.manage")).clientOptions().scope)
    }

    // MARK: The authorization response

    @Test fun testStateIsSingleUse() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val request = client.createAuthorizationRequest()
        val callback = op.authorize(request.url)
        client.completeAuthorization(callback)
        assertThrowsCode("state_reused") { client.completeAuthorization(callback) }
    }

    @Test fun testUnknownMissingAndExpiredState() = runBlocking {
        val op = StubOP()
        assertThrowsCode("state_mismatch") {
            val client = makeClient(op)
            client.completeAuthorization(URI("net.example.app:/callback?code=x&state=nope&iss=$ISSUER"))
        }
        val client = makeClient(op)
        assertThrowsCode("state_missing") { client.completeAuthorization(URI("net.example.app:/callback?code=x")) }

        val clock = AtomicReference(Instant.now())
        val late = makeClient(op) { it.copy(now = { clock.get() }) }
        val request = late.createAuthorizationRequest()
        val callback = op.authorize(request.url)
        clock.set(clock.get().plusSeconds(601))
        assertThrowsCode("transaction_expired") { late.completeAuthorization(callback) }
    }

    @Test fun testFrontChannelTokensAndRepeatedParametersAreRefused() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val request = client.createAuthorizationRequest()
        val callback = op.authorize(request.url)
        assertThrowsCode("front_channel_token") { client.completeAuthorization(URI("$callback#access_token=x")) }
        assertThrowsCode("duplicate_parameter") { client.completeAuthorization(URI("$callback&code=again")) }
    }

    @Test fun testRFC9207IssuerIsRequiredAndChecked() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val request = client.createAuthorizationRequest()
        val callback = op.authorize(request.url)
        val wrong = FormParameters()
        for ((name, value) in OIDCClient.responseParameters(callback)) wrong.append(name, if (name == "iss") "https://evil.example" else value)
        assertThrowsCode("issuer_mismatch") { client.completeAuthorization(wrong) }

        val request2 = client.createAuthorizationRequest()
        val missing = FormParameters()
        for ((name, value) in OIDCClient.responseParameters(op.authorize(request2.url))) if (name != "iss") missing.append(name, value)
        assertThrowsCode("issuer_missing") { client.completeAuthorization(missing) }
    }

    @Test fun testOAuthErrorCarriesContext() = runBlocking {
        val op = StubOP()
        op.authorizeError = "login_required"
        val client = makeClient(op)
        try {
            client.authorize(StubBrowser(op), AuthorizationRequestOptions(prompt = "none", context = jsonObjectOf("intent" to "resume")))
            fail("expected an error")
        } catch (e: OIDCError) {
            assertEquals(OIDCError.Kind.OAUTH, e.kind)
            assertEquals("login_required", e.oauthError)
            assertEquals(JsonPrimitive("resume"), e.context["intent"])
            assertTrue(needsInteraction(e))
        }
    }

    @Test fun testExtraParametersCannotReplaceReservedOnes() = runBlocking {
        val client = makeClient(StubOP())
        assertThrowsCode("invalid_argument") { client.createAuthorizationRequest(AuthorizationRequestOptions(extraParameters = mapOf("state" to "x"))) }
    }

    @Test fun testWithoutPARTheRequestIsInTheURL() = runBlocking {
        val op = StubOP()
        val client = makeClient(op) { it.copy(par = PARMode.NEVER) }
        val request = client.createAuthorizationRequest(AuthorizationRequestOptions(loginHint = "alice"))
        val p = OIDCClient.responseParameters(request.url)
        assertEquals("alice", p.get("login_hint"))
        assertEquals(CLIENT_ID, p.get("client_id"))
        assertNull(p.get("request_uri"))
        client.completeAuthorization(op.authorize(request.url))
        Unit
    }

    // MARK: ID token

    @Test fun testIDTokenChecks() = runBlocking {
        val cases: List<Pair<String, (MutableMap<String, JsonElement>) -> Unit>> = listOf(
            "nonce_mismatch" to { c -> c["nonce"] = jsonOf("other") },
            "invalid_id_token" to { c -> c["aud"] = jsonOf("someone-else") },
            "invalid_id_token" to { c -> c["iss"] = jsonOf("https://evil.example") },
            "invalid_id_token" to { c -> c["exp"] = jsonOf(nowEpoch() - 3600) },
            "invalid_id_token" to { c -> c["iat"] = jsonOf(nowEpoch() - 3600) },
            "invalid_id_token" to { c -> c["aud"] = jsonOf(listOf(CLIENT_ID, "other")) },
            "invalid_id_token" to { c -> c["azp"] = jsonOf("other") },
            "invalid_id_token" to { c -> c["at_hash"] = jsonOf("AAAA") },
        )
        for ((code, mutate) in cases) {
            val op = StubOP()
            op.mutateIDToken = mutate
            val client = makeClient(op)
            assertThrowsCode(code) { signIn(client, op) }
        }
    }

    @Test fun testIDTokenSignedByAnotherKeyIsRefused() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val bad = SoftwareECSigner.generate("ES256")
        val token = signJWS(jsonObjectOf("kid" to "ec-1"), jsonObjectOf("iss" to ISSUER, "sub" to "x", "aud" to CLIENT_ID,
            "iat" to nowEpoch(), "exp" to nowEpoch() + 60), bad)
        assertThrowsCode("invalid_id_token") { client.validateIDToken(token) }
    }

    @Test fun testRSAIDTokens() = runBlocking {
        for (alg in listOf("RS256", "PS256")) {
            val op = StubOP()
            op.useRSA(alg)
            val client = makeClient(op)
            val ts = signIn(client, op)
            assertEquals(alg, "user-1", ts.claims?.string("sub"))
        }
    }

    @Test fun testUnexpectedAlgAndTypAreRefused() = runBlocking {
        val op = StubOP()
        val client = makeClient(op) { it.copy(idTokenSignedResponseAlg = "RS256") }
        assertThrowsCode("invalid_id_token") { signIn(client, op) }
        val ec = makeClient(op)
        val now = nowEpoch()
        val at = signJWS(jsonObjectOf("kid" to "ec-1", "typ" to "at+jwt"), jsonObjectOf("iss" to ISSUER, "sub" to "x", "aud" to CLIENT_ID,
            "iat" to now, "exp" to now + 60), op.signer)
        assertThrowsCode("invalid_id_token") { ec.validateIDToken(at) }
    }

    @Test fun testACRIsEnforcedAndExpectedSubChecked() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        assertThrowsCode("acr_mismatch") { signIn(client, op, AuthorizationRequestOptions(acrValues = "urn:mfa")) }
        assertThrowsCode("account_mismatch") { signIn(client, op, AuthorizationRequestOptions(expectedSub = "user-2")) }
        assertEquals("the other person's tokens are revoked", 2, op.revoked.size)
    }

    // MARK: DPoP and tokens

    @Test fun testDPoPDowngradeIsRefused() = runBlocking {
        val op = StubOP()
        op.forceTokenType = "Bearer"
        val client = makeClient(op)
        assertThrowsCode("dpop_downgrade") { signIn(client, op) }
    }

    @Test fun testDPoPNonceIsRetried() = runBlocking {
        val op = StubOP()
        op.requireDPoPNonce = true
        val client = makeClient(op)
        val ts = signIn(client, op)
        assertEquals("DPoP", ts.tokenType)
    }

    @Test fun testBearerWithoutDPoP() = runBlocking {
        val op = StubOP()
        val client = makeClient(op, dpop = false)
        val ts = signIn(client, op)
        assertEquals("Bearer", ts.tokenType)
        assertEquals("Bearer ${ts.accessToken}", client.resourceHeaders(ts, url = URI("https://api.example.test/x"))["authorization"])
    }

    @Test fun testRefreshRotatesAndChecksTheIDToken() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val first = signIn(client, op)
        val second = client.refresh(first)
        assertNotEquals(first.refreshToken, second.refreshToken)
        assertEquals("user-1", second.claims?.string("sub"))
        op.mutateIDToken = { it["sub"] = jsonOf("someone-else") }
        assertThrowsCode("invalid_id_token") { client.refresh(second) }
        assertThrowsCode("invalid_grant") { client.refresh(first) }
    }

    @Test fun testRefreshKeepsANonRotatedRefreshToken() = runBlocking {
        val op = StubOP()
        op.rotateRefreshTokens = false
        op.refreshIDToken = false
        val client = makeClient(op)
        val first = signIn(client, op)
        val second = client.refresh(first)
        assertEquals(first.refreshToken, second.refreshToken)
        assertEquals(first.idToken, second.idToken)
        assertEquals(first.claims, second.claims)
    }

    @Test fun testUserInfoChecksSub() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val ts = signIn(client, op)
        val info = client.userinfo(ts)
        assertEquals("alice@example.test", info.string("email"))
        op.userinfoSub = "other"
        assertThrowsCode("sub_mismatch") { client.userinfo(ts) }
    }

    @Test fun testLogoutStateIsCheckedOnce() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val ts = signIn(client, op)
        val request = client.createEndSessionRequest(idTokenHint = ts.idToken, context = jsonObjectOf("key" to "k"))
        assertNotNull(request)
        val p = OIDCClient.responseParameters(request!!.url)
        assertEquals(POST_LOGOUT.toString(), p.get("post_logout_redirect_uri"))
        val callback = URI("$POST_LOGOUT?state=${p.get("state")}")
        val context = client.completeEndSession(callback)
        assertEquals(JsonPrimitive("k"), context["key"])
        assertThrowsCode("state_mismatch") { client.completeEndSession(callback) }
        val v1 = client.endSession(StubBrowser(op), client.createEndSessionRequest())
        assertTrue(v1)
    }

    @Test fun testDynamicRegistrationIsPublic() = runBlocking {
        val op = StubOP()
        val (client, registration) = OIDCClient.register(
            op.metadata, jsonObjectOf("redirect_uris" to listOf(REDIRECT.toString()), "id_token_signed_response_alg" to "ES256"),
            options = OIDCClientOptions(clientID = "", dpop = DPoPOptions(), transport = op))
        assertEquals(CLIENT_ID, client.clientID)
        assertEquals("none", registration.string("token_endpoint_auth_method"))
        assertEquals(JsonPrimitive(true), registration["dpop_bound_access_tokens"])
        assertEquals(REDIRECT, client.options.redirectURI)
    }

    // MARK: Primitives

    @Test fun testPKCEAndThumbprint() {
        // RFC 7636 Appendix B.
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        // RFC 7638 §3.1.
        val jwk = jsonObjectOf("kty" to "RSA", "e" to "AQAB", "n" to "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jwkThumbprint(jwk))
        assertEquals("https://api.example.test/a/b", htuOf(URI("HTTPS://Api.Example.test:443/a/b?x=1#f")))
    }

    @Test fun testFormParametersRoundTrip() {
        val f = FormParameters()
        f.append("a", "x y&z=é")
        f.append("r", "1")
        f.append("r", "2")
        val parsed = FormParameters.parse(f.encoded)
        assertEquals("x y&z=é", parsed.get("a"))
        assertEquals(listOf("1", "2"), parsed.getAll("r"))
        f.set("r", "3")
        assertEquals(listOf("3"), f.getAll("r"))
    }
}

/** XCTAssertThrowsError: [body] must throw. */
fun assertThrowsSync(body: () -> Unit) {
    try {
        body()
    } catch (e: Exception) {
        return
    }
    fail("expected an error")
}
