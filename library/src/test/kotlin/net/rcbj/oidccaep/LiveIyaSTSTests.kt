// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext

/**
 * The library against a real iya-sts: the port of the Swift library's `LiveIyaSTSTests`, with a second factor.
 *
 * Skipped unless `IYA_STS_LIVE_CONFIG` names an `oidc_configuration.json`; `scripts/live_iya_sts.py` sets it up (a
 * fresh iya-sts, the client registration, a new test user) and runs this test alone.
 *
 * It uses the library end to end: `OIDCAppConfiguration`, `OIDCClient` (PAR, PKCE, DPoP), `AccountManager`,
 * `LoopbackWebAuthenticator` and `SSFReceiver`. Only the browser is replaced, by [IyaSTSBrowser], an HTTP walk of
 * iya-sts's sign-in screens through the JSON API they call (`/authn-api`).
 *
 * The test user is new and a second factor is required of it (the operator's `require-mfa`), so:
 *  1. the first sign-in ENROLS an authenticator app at the sign-in screen (`setup/totp`, `setup/confirm`), the
 *     secret kept and every code computed with `oathtool --totp -b <secret>`, the pattern every MFA test uses;
 *  2. a second sign-in (`reauthenticate`, prompt=login) goes through the TOTP step: a wrong code first, which must
 *     be refused, then the right one;
 *  3. the library's CAEP receiver polls the account's stream, the operator emits credential-change and then
 *     session-revoked with `POST /admin-api/caep/emit`, and the account must be signed in after the first and
 *     ended after the second.
 *
 * Trust is `TrustedCertificates` naming the self-signed root of iya-sts's chain, with `TrustSystemRoots` false;
 * `InsecureSkipTLSVerification` is never set. The result is written as JSON to `IYA_STS_LIVE_RESULT` when set.
 */
class LiveIyaSTSTests {
    @Test
    fun testSignInWithSecondFactorAndTwoCAEPSignals(): Unit = runBlocking {
        val env = System.getenv()
        val configPath = env["IYA_STS_LIVE_CONFIG"]
        assumeTrue("IYA_STS_LIVE_CONFIG is not set; scripts/live_iya_sts.py runs this test against a fresh iya-sts", !configPath.isNullOrEmpty())
        val username = env["IYA_STS_LIVE_USERNAME"] ?: "live-mfa-user"
        val password = env["CAEP_DEMO_USER_PASSWORD"] ?: error("CAEP_DEMO_USER_PASSWORD is required")
        val adminSecret = env["STS_ADMIN_API_CLIENT_SECRET"] ?: env["ADMIN_API_CLIENT_SECRET"]
        assertFalse("STS_ADMIN_API_CLIENT_SECRET is required to emit the signals", adminSecret.isNullOrEmpty())

        val config = OIDCAppConfiguration.load(File(configPath!!))
        assertFalse("the live test trusts iya-sts through TrustedCertificates only", config.insecureSkipTLSVerification)
        assertNotNull("the configuration must name iya-sts's root in TrustedCertificates", config.tlsTrust)
        val trust = config.tlsTrust!!
        assertFalse(trust.includeSystemRoots)
        val origin = originOf(config.metadataURL)!!

        // The library, with its own transport trusting TrustedCertificates only.
        val transport = config.makeTransport()
        val client = config.makeClient(MemoryKeyStore(), transport)
        val accounts = AccountManager(client, AccountManagerOptions(store = MemoryTokenStore())).restore()

        // The operator: a second factor is required of the new test user before it ever signs in.
        val browser = IyaSTSBrowser(origin, trust, username, password)
        val operatorAPI = AdminAPI(browser, origin, adminSecret!!)
        operatorAPI.requireSecondFactor(username)

        // 1. The first sign-in enrols an authenticator app.
        val authenticator = LoopbackWebAuthenticator(120.0) { url -> browser.open(url) }
        val signIn = accounts.signIn(authenticator)
        browser.failure?.let { throw AssertionError("the browser walk failed: $it") }
        assertTrue("the first sign-in enrolled an authenticator app", browser.enrolled)
        assertNotNull("the enrolment's secret was kept", browser.totpSecret)
        val key = signIn.account.key
        assertEquals(Account.Status.SIGNED_IN, signIn.account.status)
        assertTrue("the first sign-in's ID token says otp: ${signIn.tokenSet.claims?.get("amr")}", amrOf(signIn.tokenSet).contains("otp"))
        val tokens = accounts.getTokenSet()
        assertTrue("the access token is DPoP-bound", tokens.isDPoPBound)
        tokens.scope?.let { scope ->
            val granted = scope.split(" ").toSet()
            assertTrue("granted scopes: ${granted.sorted()}", "ssf.read" in granted && "ssf.manage" in granted)
        }

        // 2. A second sign-in goes through the TOTP step: a wrong code is refused, the right one accepted.
        browser.reset()
        val again = accounts.reauthenticate(key, authenticator)
        browser.failure?.let { throw AssertionError("the second browser walk failed: $it") }
        assertFalse("the second sign-in did not enrol again", browser.enrolled)
        assertTrue("the second sign-in asked for a one-time code", browser.totpSteps >= 1)
        assertTrue("a wrong one-time code was refused", browser.wrongCodeRefused)
        assertEquals("the same account signed in again", key, again.account.key)
        assertEquals("reauth", again.intent)
        assertTrue("the second sign-in's ID token says otp", amrOf(again.tokenSet).contains("otp"))

        // 3. The library's CAEP receiver, polling this account's stream every second with its DPoP-bound token.
        val received = mutableListOf<SecurityEvent>()
        var endedBySubject: Boolean? = null
        val receiver = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer = config.ssfTransmitterIssuer ?: client.issuer,
            authorization = SSFAuthorization.oidc(client) { accounts.getTokenSet() },
            eventsRequested = listOf(CAEP.CREDENTIAL_CHANGE, CAEP.SESSION_REVOKED),
            description = "android-oidc-caep-native-app live test",
            pollInterval = 1.0,
            transport = transport,
            onEventReceived = null,
        ))
        receiver
            .onCredentialChange { event -> synchronized(received) { received.add(event) } }
            .onSessionRevoked { event ->
                // The account the signal names (its iss/sub, or its session) is ended. When the subject names
                // nothing this app holds, this app's one account is.
                val named = accounts.accountsForSubject(event.subject ?: emptyJsonObject).map { it.key }
                endedBySubject = named.isNotEmpty()
                for (one in named.ifEmpty { listOf(key) }) {
                    accounts.end(one, event.reasonUser?.get("en") ?: "The session was revoked by the identity provider.")
                }
                synchronized(received) { received.add(event) }
            }
        receiver.start(catchUp = true)
        if (receiver.metadata?.get("add_subject_endpoint") != null) {
            receiver.addSubject(Subject.issSub(signIn.account.iss, signIn.account.sub))
        }

        val sessionID = operatorAPI.sessionID(username)
        operatorAPI.emit(sessionID, "credential-change")
        assertTrue(waitFor("credential-change") { synchronized(received) { received.any { it.type == CAEP.CREDENTIAL_CHANGE } } })
        val statusAfterFirst = accounts.get(key)?.status
        assertEquals("credential-change (an update) keeps the session", Account.Status.SIGNED_IN, statusAfterFirst)

        operatorAPI.emit(sessionID, "session-revoked")
        assertTrue(waitFor("session-revoked") { synchronized(received) { received.any { it.type == CAEP.SESSION_REVOKED } } })
        val statusAfterSecond = accounts.get(key)?.status
        assertEquals("session-revoked ends the account", Account.Status.ENDED, statusAfterSecond)
        receiver.stop()
        accounts.close()

        val events = synchronized(received) { received.map { jsonObjectOf("type" to it.type, "jti" to it.jti) } }
        val result = jsonObjectOf(
            "ok" to (statusAfterFirst == Account.Status.SIGNED_IN && statusAfterSecond == Account.Status.ENDED && events.size == 2),
            "subject" to signIn.account.sub,
            "issuer" to client.issuer,
            "tokenType" to tokens.tokenType,
            "secondFactorEnrolled" to browser.totpSecret.isNullOrEmpty().not(),
            "amrFirst" to JsonArray(amrOf(signIn.tokenSet).map { jsonOf(it) }),
            "amrSecond" to JsonArray(amrOf(again.tokenSet).map { jsonOf(it) }),
            "wrongCodeRefused" to browser.wrongCodeRefused,
            "signedInAfterCredentialChange" to (statusAfterFirst == Account.Status.SIGNED_IN),
            "signedInAfterSessionRevoked" to (statusAfterSecond == Account.Status.SIGNED_IN),
            "accountStatus" to (statusAfterSecond?.value ?: "missing"),
            "sessionRevokedMatchedSubject" to (endedBySubject ?: false),
            "events" to JsonArray(events),
        )
        env["IYA_STS_LIVE_RESULT"]?.takeIf { it.isNotEmpty() }?.let { File(it).writeText(result.jsonString()) }
        println("LIVE-RESULT " + result.jsonString())
    }

    private fun amrOf(tokenSet: TokenSet): List<String> = tokenSet.claims?.get("amr").stringArrayValue ?: emptyList()

    /** Waits up to 30 seconds for [condition]. */
    private suspend fun waitFor(what: String, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            delay(500)
        }
        throw AssertionError("timed out waiting for $what")
    }
}

/**
 * The browser the live test substitutes: an HTTP client with a cookie jar, walking iya-sts's static sign-in screens
 * through the JSON API they call (`/authn-api`), and finally requesting the redirect it is sent to, which is the
 * library's loopback listener. It trusts the same root the library does (a browser would have it in its own store).
 */
class IyaSTSBrowser(val origin: String, trust: TLSTrust, val username: String, private var password: String) {
    class Response(val status: Int, val headers: Map<String, String>, val body: String) {
        fun header(name: String): String? = headers[name.lowercase()]
        val json: JsonObject get() = try { parseJson(body) as? JsonObject ?: emptyJsonObject } catch (e: Exception) { emptyJsonObject }
    }

    private val cookies = mutableMapOf<String, Cookie>()
    private val http: OkHttpClient = run {
        val manager = trust.trustManager()
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(manager), SecureRandom()) }
        OkHttpClient.Builder()
            .sslSocketFactory(context.socketFactory, manager)
            .followRedirects(false).followSslRedirects(false)
            .callTimeout(30, TimeUnit.SECONDS)
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                    synchronized(this@IyaSTSBrowser.cookies) { for (c in cookies) this@IyaSTSBrowser.cookies[c.name] = c }
                }
                override fun loadForRequest(url: HttpUrl): List<Cookie> =
                    synchronized(this@IyaSTSBrowser.cookies) { this@IyaSTSBrowser.cookies.values.filter { it.matches(url) } }
            })
            .build()
    }

    @Volatile var failure: String? = null
    /** The authenticator app's secret, once one was enrolled. */
    @Volatile var totpSecret: String? = null
    /** This walk enrolled an authenticator app. */
    @Volatile var enrolled: Boolean = false
    /** How many times this walk answered the one-time code step. */
    @Volatile var totpSteps: Int = 0
    /** This walk sent a wrong code first and the service refused it. */
    @Volatile var wrongCodeRefused: Boolean = false
    private var lastTotpStep = -1L

    /** Clears what one walk observed (the secret and the cookies are kept). */
    fun reset() {
        failure = null
        enrolled = false
        totpSteps = 0
        wrongCodeRefused = false
    }

    /**
     * [LoopbackWebAuthenticator]'s `openBrowser`: the listener is already bound, but waits for the browser only once
     * this returns, so the walk runs on its own thread and ends by requesting the loopback redirect.
     */
    fun open(url: URI) {
        Thread {
            try { walk(url) } catch (e: Throwable) { failure = e.message ?: e.toString() }
        }.apply { isDaemon = true }.start()
    }

    private fun walk(start: URI) {
        var url = start
        repeat(24) {
            url = step(url) ?: return
        }
        throw IllegalStateException("the sign-in did not finish; last URL $url")
    }

    /** One page. Returns the next URL, or null once the loopback redirect was delivered. */
    private fun step(url: URI): URI? {
        val res = request("GET", url, mapOf("accept" to "text/html,application/json"))
        if (res.status in 300..399) res.header("location")?.let { return url.resolve(it) }
        if (!url.toString().startsWith(origin)) {
            // Not iya-sts: the loopback redirect, answered by the library's listener.
            check(res.status == 200) { "the redirect to $url answered ${res.status}" }
            return null
        }
        val path = url.path
        val query = FormParameters.parse(url.rawQuery ?: "")
        return when {
            path.startsWith("/authn/login") -> {
                val id = query.get("authn") ?: ""
                val csrf = view("/authn-api/pending/$id")
                act(url, "/authn-api/pending/$id/password", jsonObjectOf("username" to username, "password" to password), csrf)
            }
            path.startsWith("/authn/mfa-setup") -> enrolTotp(url, query.get("mfa") ?: "")
            path.startsWith("/authn/totp") -> oneTimeCode(url, query.get("mfa") ?: "")
            path.startsWith("/authn/password-change") -> changePassword(url, query.get("change") ?: "")
            path.startsWith("/oauth2/consent") -> {
                val id = query.get("consent") ?: ""
                val csrf = view("/authn-api/consent/$id")
                act(url, "/authn-api/consent/$id", jsonObjectOf("action" to "allow"), csrf)
            }
            path.startsWith("/authn/post-login") -> skip(url, query.get("mfa") ?: "")
            else -> throw IllegalStateException("the sign-in stopped at ${res.status} $url: ${res.body.take(300)}")
        }
    }

    /** The required enrolment: an authenticator app, its secret kept, its first code from oathtool. */
    private fun enrolTotp(page: URI, id: String): URI? {
        val setup = mfaView(id, "setup")
        check(setup.offered) { "the enrolment screen offers no authenticator app: ${setup.raw.take(300)}" }
        val chosen = request("POST", URI("$origin/authn-api/mfa/$id/setup/totp"), postHeaders(setup.csrf), "{}")
        check(chosen.status == 200 && chosen.json["ok"].boolValue == true) { "setup/totp answered ${chosen.status}: ${chosen.body.take(300)}" }
        val shown = mfaView(id, "setup")
        val secret = shown.secret ?: throw IllegalStateException("the enrolment screen showed no secret: ${shown.raw.take(300)}")
        totpSecret = secret
        enrolled = true
        return act(page, "/authn-api/mfa/$id/setup/confirm", jsonObjectOf("code" to freshCode(secret)), shown.csrf)
    }

    /** The one-time code step: a wrong code first (it must be refused), then the right one. */
    private fun oneTimeCode(page: URI, id: String): URI? {
        val secret = totpSecret ?: throw IllegalStateException("a one-time code is asked for, and no authenticator was enrolled in this test")
        totpSteps += 1
        var csrf = mfaView(id, null).csrf
        if (!wrongCodeRefused) {
            val right = currentCode(secret)
            val wrong = ((right.toInt() + 500_000) % 1_000_000).toString().padStart(6, '0')
            val refused = request("POST", URI("$origin/authn-api/mfa/$id/totp"), postHeaders(csrf), jsonObjectOf("code" to wrong).jsonString())
            val location = refused.json.string("location") ?: ""
            wrongCodeRefused = refused.json["ok"].boolValue != true || location.startsWith("/authn/totp")
            check(wrongCodeRefused) { "a wrong one-time code was accepted: ${refused.body.take(300)}" }
            csrf = mfaView(id, null).csrf
        }
        return act(page, "/authn-api/mfa/$id/totp", jsonObjectOf("code" to freshCode(secret)), csrf)
    }

    /** A password the service set must be changed before the sign-in continues. */
    private fun changePassword(page: URI, id: String): URI? {
        val csrf = view("/authn-api/password-change/$id")
        val next = "Live-" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(18).also { SecureRandom().nextBytes(it) })
        val answer = act(page, "/authn-api/password-change/$id", jsonObjectOf("password" to next, "passwordConfirm" to next), csrf)
        password = next
        return answer
    }

    /** An optional post-login step is skipped; a required one stops the walk. */
    private fun skip(page: URI, id: String): URI? {
        val csrf = mfaView(id, "post-login").csrf
        return act(page, "/authn-api/mfa/$id/post-login/skip", emptyJsonObject, csrf)
    }

    private class MfaView(val csrf: String, val offered: Boolean, val secret: String?, val raw: String)

    private fun mfaView(id: String, page: String?): MfaView {
        val res = request("GET", URI("$origin/authn-api/mfa/$id" + (page?.let { "?page=$it" } ?: "")), mapOf("accept" to "application/json"))
        val csrf = res.json.string("csrf") ?: throw IllegalStateException("the MFA view answered ${res.status}: ${res.body.take(300)}")
        val setup = res.json["view"]["setup"]
        return MfaView(csrf, setup["offered"]["totp"].boolValue == true, setup["totp"]["secret"].stringValue?.replace(" ", ""), res.body)
    }

    /** A screen's view from its API, for the CSRF token its form sends. */
    private fun view(apiPath: String): String {
        val res = request("GET", URI(origin + apiPath), mapOf("accept" to "application/json"))
        return res.json.string("csrf")?.takeIf { it.isNotEmpty() }
            ?: throw IllegalStateException("$apiPath answered ${res.status} without a csrf token: ${res.body.take(300)}")
    }

    private fun postHeaders(csrf: String) = mapOf("accept" to "application/json", "content-type" to "application/json", "origin" to origin, "x-csrf-token" to csrf)

    private fun act(page: URI, apiPath: String, body: JsonObject, csrf: String): URI? {
        val res = request("POST", URI(origin + apiPath), postHeaders(csrf), body.jsonString())
        if (res.status in 300..399) res.header("location")?.let { return page.resolve(it) }
        val location = res.json.string("location")
            ?: throw IllegalStateException("$apiPath answered ${res.status} without a location: ${res.body.take(300)}")
        return URI("$origin/").resolve(location)
    }

    /**
     * The current code, by `oathtool --totp -b <secret>`, never one already sent: the service refuses a replayed
     * time step (RFC 6238 section 5.2), so a second code inside the same 30 seconds waits for the next step.
     */
    private fun freshCode(secret: String): String {
        var step = System.currentTimeMillis() / 30_000
        if (step <= lastTotpStep) {
            Thread.sleep((lastTotpStep + 1) * 30_000 - System.currentTimeMillis() + 1_000)
            step = System.currentTimeMillis() / 30_000
        } else if (30_000 - System.currentTimeMillis() % 30_000 < 3_000) {
            // Too near the end of the step for the code to arrive inside it.
            Thread.sleep(30_000 - System.currentTimeMillis() % 30_000 + 1_000)
            step = System.currentTimeMillis() / 30_000
        }
        lastTotpStep = step
        return currentCode(secret)
    }

    private fun currentCode(secret: String): String {
        val process = ProcessBuilder("oathtool", "--totp", "-b", secret).redirectErrorStream(true).start()
        val out = process.inputStream.bufferedReader().readText().trim()
        check(process.waitFor() == 0 && out.matches(Regex("\\d{6}"))) { "oathtool failed: $out" }
        return out
    }

    /** One request: the cookie jar, the anchors, no redirects followed. */
    fun request(method: String, url: URI, headers: Map<String, String> = emptyMap(), body: String? = null): Response {
        val requestBody = body?.toRequestBody((headers["content-type"] ?: "application/octet-stream").toMediaType())
        val builder = Request.Builder().url(url.toString()).method(method, requestBody)
        for ((k, v) in headers) builder.header(k, v)
        http.newCall(builder.build()).execute().use { r ->
            return Response(r.code, r.headers.toMultimap().mapKeys { it.key.lowercase() }.mapValues { it.value.last() }, r.body.string())
        }
    }
}

/** The operator's side: iya-sts's management API, with the seeded `sts-api-client`. */
class AdminAPI(private val browser: IyaSTSBrowser, private val origin: String, private val secret: String) {
    private fun token(): String {
        val form = FormParameters(listOf("grant_type" to "client_credentials", "scope" to "admin:read admin:write", "resource" to "$origin/admin-api"))
        val basic = Base64.getEncoder().encodeToString("sts-api-client:$secret".encodeToByteArray())
        val res = browser.request("POST", URI("$origin/oauth2/token"), mapOf(
            "content-type" to "application/x-www-form-urlencoded", "accept" to "application/json", "authorization" to "Basic $basic"), form.encoded)
        return res.json.string("access_token") ?: throw IllegalStateException("the admin token request answered ${res.status}")
    }

    private fun call(method: String, path: String, body: JsonObject? = null): IyaSTSBrowser.Response {
        val headers = mutableMapOf("accept" to "application/json", "authorization" to "Bearer ${token()}")
        if (body != null) headers["content-type"] = "application/json"
        return browser.request(method, URI(origin + path), headers, body?.jsonString())
    }

    /** `POST /admin-api/users/require-mfa`: a second factor is required of [username] at the sign-in screen. */
    fun requireSecondFactor(username: String) {
        val res = call("POST", "/admin-api/users/require-mfa", jsonObjectOf("username" to username))
        check(res.status == 200 && res.json["ok"].boolValue == true) { "require-mfa answered ${res.status}: ${res.body.take(300)}" }
    }

    /** The sign-on session iya-sts's CAEP page lists for [username]. */
    suspend fun sessionID(username: String): String {
        val deadline = System.currentTimeMillis() + 20_000
        var last = ""
        while (System.currentTimeMillis() < deadline) {
            val res = call("GET", "/admin-api/caep")
            last = res.body.take(300)
            for (row in res.json["sessions"].arrayValue ?: emptyList()) {
                val o = row.objectValue ?: continue
                if (o.string("username") == username && o.string("state") != "revoked") o.string("sessionId")?.let { return it }
            }
            delay(1_000)
        }
        throw IllegalStateException("no CAEP session for $username: $last")
    }

    fun emit(sessionID: String, type: String) {
        val res = call("POST", "/admin-api/caep/emit", jsonObjectOf("session_id" to sessionID, "type" to type, "initiating_entity" to "admin"))
        val message = res.json.string("message") ?: ""
        check(res.status == 200 && res.json["ok"].boolValue != false && !message.contains("Nothing was sent")) {
            "emitting $type answered ${res.status}: ${res.body.take(300)}"
        }
        println("emitted $type: $message")
    }
}
