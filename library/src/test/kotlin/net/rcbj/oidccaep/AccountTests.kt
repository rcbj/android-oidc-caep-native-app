// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Ported from the Swift library's Tests/OIDCCAEPClientTests/AccountTests.swift.

package net.rcbj.oidccaep

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Collections

class TokenManagerTests {
    @Test fun testRefreshesAreMergedAndExpiredTokensRefreshed() = runBlocking {
        val op = StubOP()
        op.tokenDelay = 50
        val client = makeClient(op)
        val ts = client.authorize(StubBrowser(op)).tokenSet
        val tokens = TokenManager(client, MemoryTokenStore(), autoRefresh = false)
        tokens.set("k", ts)
        val a = async { tokens.refresh("k") }
        val b = async { tokens.refresh("k") }
        val x = a.await()
        val y = b.await()
        assertEquals(x.accessToken, y.accessToken)
        assertEquals(1, op.refreshRequests)

        val expired = x.copy(expiresAt = nowEpoch() - 1)
        tokens.set("k", expired)
        val fresh = tokens.getTokenSet("k")
        assertNotEquals(x.accessToken, fresh.accessToken)
    }

    @Test fun testInvalidGrantDropsTheTokens() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val ts = client.authorize(StubBrowser(op)).tokenSet.copy(refreshToken = "unknown")
        val tokens = TokenManager(client, MemoryTokenStore(), autoRefresh = false)
        tokens.set("k", ts)
        assertThrowsCode("invalid_grant") { tokens.refresh("k") }
        assertNull(tokens.get("k"))
    }

    @Test fun testDeleteRevokes() = runBlocking {
        val op = StubOP()
        val client = makeClient(op)
        val ts = client.authorize(StubBrowser(op)).tokenSet
        val tokens = TokenManager(client, MemoryTokenStore())
        tokens.set("k", ts)
        tokens.delete("k", revoke = true)
        assertEquals(setOf(ts.accessToken, ts.refreshToken!!), op.revoked.toSet())
    }

    @Test fun testBackgroundRefreshFires() = runBlocking {
        val op = StubOP()
        op.expiresIn = 2
        val client = makeClient(op)
        val ts = client.authorize(StubBrowser(op)).tokenSet
        val tokens = TokenManager(client, MemoryTokenStore(), refreshSkew = 60.0, minRefreshDelay = 0.1)
        val refreshed = CompletableDeferred<Unit>()
        val sub = tokens.events.subscribe { if (it is TokenManager.Event.Refreshed) refreshed.complete(Unit) }
        tokens.set("k", ts)
        withTimeout(5000) { refreshed.await() }
        sub.cancel()
        tokens.close()
    }

    @Test fun testTokenSetRoundTripsThroughJSON() {
        val ts = TokenSet("a", "DPoP", "r", "i", "openid", 10, 5, jsonObjectOf("sub" to "s"), jsonObjectOf("x" to 1))
        val decoded = TokenSet.fromJson(parseJsonObject(ts.json.jsonBytes()))
        assertEquals(ts, decoded)
        assertEquals(2.5, ts.effectiveSkew(60.0), 0.0)
    }
}

class AccountManagerTests {
    private suspend fun makeAccounts(op: StubOP, store: TokenStore = MemoryTokenStore(),
                                     hooks: (AccountManagerOptions) -> AccountManagerOptions = { it }): AccountManager {
        val client = makeClient(op)
        return AccountManager(client, hooks(AccountManagerOptions(store = store))).restore()
    }

    @Test fun testSignInAddsAndActivates() = runBlocking {
        val op = StubOP()
        val accounts = makeAccounts(op)
        val result = accounts.signIn(StubBrowser(op))
        assertTrue(result.added)
        assertEquals("sign-in", result.intent)
        val active = accounts.active()
        assertEquals(accountKey(ISSUER, "user-1"), active?.key)
        assertEquals(Account.Status.SIGNED_IN, active?.status)
        assertEquals("alice@example.test", active?.email)
        val ts = accounts.getTokenSet()
        assertEquals("user-1", ts.claims?.string("sub"))
    }

    @Test fun testOnlyTheActiveAccountsTokensAreReachableAndSwitchingWorks() = runBlocking {
        val op = StubOP()
        val activated = Collections.synchronizedList(mutableListOf<String>())
        val accounts = makeAccounts(op) { o ->
            o.copy(onActivate = { account, access ->
                access.getTokenSet()
                activated.add(account.sub)
            })
        }
        val alice = accounts.signIn(StubBrowser(op)).account
        op.sub = "user-2"
        val bob = accounts.addAccount(StubBrowser(op)).account
        assertEquals(bob.key, accounts.activeKey())
        assertEquals("login", op.lastAuthorizeParams.get("prompt"))
        accounts.activate(alice.key)
        val ts = accounts.getTokenSet()
        assertEquals("user-1", ts.claims?.string("sub"))
        assertEquals(listOf("user-1", "user-2", "user-1"), activated.toList())
        assertEquals(listOf("user-1", "user-2"), accounts.list().map { it.sub })
    }

    @Test fun testResumeNamesTheAccountAndRefusesAnybodyElse() = runBlocking {
        val op = StubOP()
        val accounts = makeAccounts(op)
        val alice = accounts.signIn(StubBrowser(op)).account
        op.sub = "user-2"
        try {
            accounts.resume(alice.key, StubBrowser(op))
            fail("expected account_mismatch")
        } catch (e: OIDCError) {
            assertEquals("account_mismatch", e.code)
        }
        val p = op.lastAuthorizeParams
        assertEquals("none", p.get("prompt"))
        assertEquals("alice", p.get("login_hint"))
        assertNotNull(p.get("id_token_hint"))

        op.authorizeError = "login_required"
        try {
            accounts.resume(alice.key, StubBrowser(op))
            fail("expected login_required")
        } catch (e: OIDCError) {
            assertTrue(needsInteraction(e))
            assertEquals(alice.key, e.account?.key)
        }
    }

    @Test fun testSignOutRevokesAndHandsOverToAnotherAccount() = runBlocking {
        val op = StubOP()
        val left = Collections.synchronizedList(mutableListOf<String>())
        val accounts = makeAccounts(op) { o -> o.copy(onLeave = { a, _ -> left.add(a.sub) }) }
        val alice = accounts.signIn(StubBrowser(op)).account
        op.sub = "user-2"
        val bob = accounts.addAccount(StubBrowser(op)).account
        val logout = accounts.signOut(bob.key)
        assertNotNull(OIDCClient.responseParameters(logout!!.url).get("id_token_hint"))
        assertEquals(alice.key, accounts.activeKey())
        assertEquals(Account.Status.SIGNED_OUT, accounts.get(bob.key)?.status)
        assertEquals(listOf("user-2"), left.toList())
        assertEquals(2, op.revoked.size)
        accounts.signOut(authenticator = StubBrowser(op))
        assertNull(accounts.activeKey())
        accounts.forget(bob.key)
        assertEquals(1, accounts.list().size)
    }

    @Test fun testEndAndSubjectMatching() = runBlocking {
        val op = StubOP()
        val accounts = makeAccounts(op)
        val alice = accounts.signIn(StubBrowser(op)).account
        val found = accounts.accountsForSubject(Subject.complex(mapOf("user" to Subject.issSub(ISSUER, "user-1"), "session" to Subject.opaque("sid-1"))))
        assertEquals(listOf(alice.key), found.map { it.key })
        val other = accounts.accountsForSubject(Subject.complex(mapOf("user" to Subject.issSub(ISSUER, "user-1"), "session" to Subject.opaque("sid-9"))))
        assertTrue(other.isEmpty())
        accounts.end(alice.key, reason = "revoked")
        val a = accounts.get(alice.key)
        assertEquals(Account.Status.ENDED, a?.status)
        assertEquals("revoked", a?.endedReason)
        assertThrowsCode("not_active") { accounts.getTokenSet() }
    }

    @Test fun testRestoresAccountsFromThePersistentStore() = runBlocking {
        val op = StubOP()
        val store = MemoryTokenStore()
        val first = makeAccounts(op, store)
        val alice = first.signIn(StubBrowser(op)).account
        first.close()
        val second = makeAccounts(op, store)
        assertEquals(alice.key, second.activeKey())
        assertEquals(listOf(alice.key), second.list().map { it.key })
    }

    @Test fun testTheCallersContextIsKept() = runBlocking {
        val op = StubOP()
        val accounts = makeAccounts(op)
        val request = accounts.signIn(AuthorizationRequestOptions(context = jsonObjectOf("screen" to "settings")))
        val result = accounts.client.completeAuthorization(op.authorize(request.url))
        assertEquals("settings", result.context["screen"].stringValue)
        assertEquals("sign-in", result.context["intent"].stringValue)
    }

    @Test fun testTooManyAccounts() = runBlocking {
        val op = StubOP()
        val accounts = makeAccounts(op) { it.copy(maxAccounts = 1) }
        accounts.signIn(StubBrowser(op))
        op.sub = "user-2"
        assertThrowsCode("too_many_accounts") { accounts.addAccount(StubBrowser(op)) }
    }

    @Test fun testSubjectMatchingRules() {
        val id = SubjectIdentity(ISSUER, "s", "sid", "A@x.test", emailVerified = true, phoneNumber = "+1", phoneNumberVerified = false)
        assertTrue(subjectMatches(Subject.issSub(ISSUER, "s"), id))
        assertFalse(subjectMatches(Subject.issSub("https://other", "s"), id))
        assertTrue(subjectMatches(Subject.email("a@X.test"), id))
        assertFalse("an unverified phone number names nobody", subjectMatches(Subject.phone("+1"), id))
        assertTrue(subjectMatches(Subject.opaque("s"), id))
        assertTrue(subjectMatches(Subject.aliases(listOf(Subject.opaque("no"), Subject.account("acct:A@x.test"))), id))
        assertFalse(subjectMatches(Subject.complex(mapOf("device" to Subject.opaque("d"))), id))
    }
}
