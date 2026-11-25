// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Ported from the Swift library's Tests/OIDCCAEPClientTests/TLSTrustTests.swift, plus one test of the Android
// library's own trust manager against a real TLS server.

package net.rcbj.oidccaep

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.net.URI
import java.nio.file.Files
import java.util.Base64

class TLSTrustTests {
    companion object {
        /** A throwaway self-signed certificate (CN=test root), DER. */
        val der: ByteArray = Base64.getDecoder().decode("MIIBfzCCASWgAwIBAgIUfXyPZp9cB8mXjlHPkMJIr0JjBrUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJdGVzdCByb290MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0IHJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7mXkF0z0Oe0rP3m8m8n0gk6Kp3o3XK6a7m3h1qkq4w8cBf1qYz0vKX3y9zYqQyB0bQ2F1q0s3K7c7R0Kj3wKoo1MwUTAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAAAAAAAAAwHwYDVR0jBBgwFoAUAAAAAAAAAAAAAAAAAAAAAAAAAAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+0CIA==")

        val pem: String get() = "-----BEGIN CERTIFICATE-----\n${Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)}\n-----END CERTIFICATE-----\n"
    }

    @Test fun testPEMChainsAndDER() {
        val chain = TLSTrust.fromPemOrDer(listOf((pem + "junk between\n" + pem).encodeToByteArray(), der))
        assertEquals("every certificate of a chain is kept, and DER is accepted", 3, chain.certificates.size)
        assertArrayEquals(der, chain.certificates[0])
        assertTrue(chain.includeSystemRoots)
        assertThrowsSync { TLSTrust.fromPemOrDer(listOf("not a certificate".encodeToByteArray())) }
        assertThrowsSync { TLSTrust.fromPemOrDer(listOf("-----BEGIN CERTIFICATE-----\nAAAA".encodeToByteArray())) }
    }

    @Test fun testConfigurationReadsTrustedCertificates() {
        val dir = Files.createTempDirectory("tls-trust").toFile()
        try {
            File(dir, "root.pem").writeText(pem)
            val base = jsonObjectOf("MetadataURL" to "https://op.example.test/.well-known/openid-configuration", "ClientID" to "c",
                "RedirectURI" to "net.example.app:/cb")
            fun write(o: kotlinx.serialization.json.JsonObject): File = File(dir, "oidc_configuration.json").apply { writeText(o.jsonString()) }
            val d = base.with("TrustedCertificates", listOf("root.pem", pem)).with("TrustSystemRoots", false)
            val c = OIDCAppConfiguration.load(write(d))
            assertEquals("a relative path, and inline PEM", 2, c.tlsTrust?.certificates?.size)
            assertEquals(false, c.tlsTrust?.includeSystemRoots)
            assertFalse(c.insecureSkipTLSVerification)
            assertNull(OIDCAppConfiguration.fromObject(base).tlsTrust)
            val missing = d.with("TrustedCertificates", listOf("missing.pem"))
            assertThrowsSync { OIDCAppConfiguration.load(write(missing)) }
            assertTrue(OIDCAppConfiguration.fromObject(base.with("InsecureSkipTLSVerification", true)).insecureSkipTLSVerification)
        } finally {
            dir.deleteRecursively()
        }
    }

    /** Not in the Swift suite: the trust manager the Android library builds, against a real TLS server. */
    @Test fun testTrustManagerAcceptsOnlyTheGivenRoot() = runBlocking {
        val root = HeldCertificate.Builder().certificateAuthority(0).commonName("test root").build()
        val leaf = HeldCertificate.Builder().signedBy(root).addSubjectAlternativeName("localhost").build()
        val server = MockWebServer()
        server.useHttps(HandshakeCertificates.Builder().heldCertificate(leaf, root.certificate).build().sslSocketFactory())
        server.start()
        try {
            val url = URI(server.url("/x").toString().replace("127.0.0.1", "localhost"))
            server.enqueue(MockResponse.Builder().body("ok").build())
            val trusted = OkHttpTransport(trust = TLSTrust.fromPemOrDer(listOf(root.certificatePem().encodeToByteArray()), includeSystemRoots = false))
            assertEquals("ok", trusted.send(HttpRequest(url), 5.0).text)
            try {
                OkHttpTransport().send(HttpRequest(url), 5.0)
                fail("a private root is not trusted by default")
            } catch (e: Exception) {
                // expected: certificate verification fails
            }
            val otherRoot = HeldCertificate.Builder().certificateAuthority(0).commonName("other root").build()
            try {
                OkHttpTransport(trust = TLSTrust.fromPemOrDer(listOf(otherRoot.certificatePem().encodeToByteArray()), includeSystemRoots = false))
                    .send(HttpRequest(url), 5.0)
                fail("another root does not vouch for this server")
            } catch (e: Exception) {
                // expected
            }
        } finally {
            server.close()
        }
    }
}

class LoopbackWebAuthenticatorTests {
    private suspend fun get(url: String): HttpResponse = OkHttpTransport().send(HttpRequest(URI(url)), 5.0)

    @Test fun testReturnsTheRedirectTheBrowserMakes() = runBlocking {
        val port = (41_000..48_000).random()
        val callback = URI("http://127.0.0.1:$port/callback")
        val other = CompletableDeferred<Int>()
        // The "browser": once the page is opened, it is sent to an unrelated path, then to the redirect URI.
        val auth = LoopbackWebAuthenticator(10.0) { _ ->
            CoroutineScope(Dispatchers.IO).launch {
                other.complete(get("http://127.0.0.1:$port/favicon.ico").status)
                get("http://127.0.0.1:$port/callback?code=abc&state=xyz&iss=https%3A%2F%2Fop")
            }
        }
        val result = auth.authenticate(URI("https://op.example.test/authorize"), callback)
        assertEquals(404, other.await())
        val p = OIDCClient.responseParameters(result)
        assertEquals("abc", p.get("code"))
        assertEquals("xyz", p.get("state"))
        assertEquals("https://op", p.get("iss"))
        assertEquals("/callback", result.path)
    }

    @Test fun testANewSignInTakesOverThePortFromOneThatNeverCameBack() = runBlocking {
        val port = (41_000..48_000).random()
        val callback = URI("http://127.0.0.1:$port/callback")
        // The first sign-in's browser never comes back (the provider showed an error page).
        val stuck = LoopbackWebAuthenticator(60.0) { _ -> }
        val first = async(Dispatchers.IO) { runCatching { stuck.authenticate(URI("https://op.example.test/authorize"), callback) } }
        delay(300)
        // The second one binds the same port and completes.
        val retry = LoopbackWebAuthenticator(10.0) { _ ->
            CoroutineScope(Dispatchers.IO).launch { get("http://127.0.0.1:$port/callback?code=again") }
        }
        val result = retry.authenticate(URI("https://op.example.test/authorize"), callback)
        assertEquals("again", OIDCClient.responseParameters(result).get("code"))
        val e = first.await().exceptionOrNull()
        if (e !is OIDCError) fail("the abandoned sign-in should end as cancelled, got $e")
        assertTrue(e!!.message, (e as OIDCError).isUserCancellation)
    }

    @Test fun testRefusesANonLoopbackRedirect() = runBlocking {
        val auth = LoopbackWebAuthenticator { _ -> }
        assertThrowsCode("invalid_argument") { auth.authenticate(URI("https://op.example.test/authorize"), URI("net.example.app:/cb")) }
    }
}
