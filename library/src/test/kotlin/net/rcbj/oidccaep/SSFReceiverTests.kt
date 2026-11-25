// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Ported from the Swift library's Tests/OIDCCAEPClientTests/SSFReceiverTests.swift.

package net.rcbj.oidccaep

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

class SSFReceiverTests {
    /** A signed-in client and a receiver authorized by its (DPoP-bound) token. */
    private suspend fun setUp(op: StubOP, configure: (SSFReceiverConfiguration) -> SSFReceiverConfiguration = { it }): Pair<SSFReceiver, TokenSet> {
        val client = makeClient(op)
        val ts = client.authorize(StubBrowser(op)).tokenSet
        val c = SSFReceiverConfiguration(transmitterIssuer = ISSUER, authorization = SSFAuthorization.oidc(client) { ts }, pollInterval = 3600.0,
            transport = op, onEventReceived = null)
        return SSFReceiver(configure(c)) to ts
    }

    @Test fun testOneHandlerPerEventAndAcknowledgement() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op)
        val seen = Collections.synchronizedList(mutableListOf<String>())
        receiver
            .onSessionRevoked { e -> seen.add("revoked:${e.reasonUser?.get("en") ?: ""}") }
            .onCredentialChange { e -> seen.add("credential:${e.payload.string("change_type") ?: ""}") }
            .onAnyEvent { e -> seen.add("any:${e.name}") }
        val j1 = op.queueSET(CAEP.SESSION_REVOKED, jsonObjectOf("reason_user" to mapOf("en" to "bye")), Subject.issSub(ISSUER, "user-1"))
        val j2 = op.queueSET(CAEP.CREDENTIAL_CHANGE, jsonObjectOf("change_type" to "revoke"))
        receiver.start(catchUp = true)
        assertEquals(setOf("revoked:bye", "any:session-revoked", "credential:revoke", "any:credential-change"), seen.toSet())
        receiver.stop()
        assertEquals(setOf(j1, j2), op.acks.toSet())
        assertEquals(0, op.queuedCount)
    }

    @Test fun testAThrowingHandlerLeavesTheSETForRedelivery() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op) { it.copy(maxDeliveryAttempts = 2) }
        val calls = AtomicInteger(0)
        val errors = Collections.synchronizedList(mutableListOf<String>())
        receiver
            .onSessionRevoked { calls.incrementAndGet(); throw StubError("not now") }
            .onError { e, ctx -> errors.add("${ctx.phase.value}:${e.code ?: ""}") }
        val jti = op.queueSET(CAEP.SESSION_REVOKED)
        receiver.start(catchUp = false)
        receiver.poll()
        assertEquals(1, calls.get())
        assertTrue(jti !in op.acks)
        receiver.poll() // redelivered; the second failure gives up and acknowledges
        receiver.poll()
        assertEquals(2, calls.get())
        assertTrue(jti in op.acks)
        assertTrue(errors.contains("handler:handler_failed"))
        receiver.stop()
    }

    @Test fun testInvalidSETsAreReportedAndReplaysDropped() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op)
        val seen = AtomicInteger(0)
        receiver.onSessionRevoked { seen.incrementAndGet() }
        receiver.onError { _, _ -> }
        receiver.start()
        val other = SoftwareECSigner.generate("ES256")
        op.queueSET("", jti = "forged", token = op.makeSET(CAEP.SESSION_REVOKED, jti = "forged", signer = other))
        op.queueSET("", jti = "aud", token = op.makeSET(CAEP.SESSION_REVOKED, aud = "someone-else", jti = "aud"))
        op.queueSET("", jti = "typ", token = op.makeSET(CAEP.SESSION_REVOKED, jti = "typ", typ = "JWT"))
        op.queueSET("", jti = "two", token = op.makeSET(CAEP.SESSION_REVOKED, jti = "two", extraEvents = jsonObjectOf(CAEP.CREDENTIAL_CHANGE to emptyJsonObject)))
        receiver.poll()
        receiver.poll()
        receiver.stop() // sends the setErrs still owed
        val errs = op.setErrs
        assertEquals("invalid_key", errs["forged"]["err"].stringValue)
        assertEquals("invalid_audience", errs["aud"]["err"].stringValue)
        assertEquals("invalid_request", errs["typ"]["err"].stringValue)
        assertEquals("invalid_request", errs["two"]["err"].stringValue)
        assertEquals(0, seen.get())

        val good = op.makeSET(CAEP.SESSION_REVOKED, jti = "once")
        val first = receiver.receiveSet(good)
        val replay = receiver.receiveSet(good)
        assertEquals(1, first.size)
        assertTrue(replay.isEmpty())
        assertEquals(1, seen.get())
    }

    @Test fun testVerificationAndSubjects() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op)
        receiver.start()
        receiver.addSubject(Subject.issSub(ISSUER, "user-1"))
        assertEquals("user-1", op.subjectsAdded.firstOrNull()?.string("sub"))
        val event = receiver.requestVerification(timeoutSeconds = 5.0)
        assertEquals(SSF.VERIFICATION, event.type)
        receiver.stop(deleteStream = true)
        assertEquals(1, op.streamDeletes)
    }

    @Test fun testAHandlerCanStopItsOwnReceiver() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op)
        val jti = op.queueSET(CAEP.SESSION_REVOKED)
        // As an app does when a signal ends the account: the handler stops (and forgets) the receiver.
        receiver.onSessionRevoked { receiver.stop() }
        val started = async { runCatching { receiver.start(catchUp = true) } }
        val finished = withTimeoutOrNull(5000) { started.await(); true } ?: false
        assertTrue("stop() inside a handler must not wait for the poll running that handler", finished)
        assertTrue("the handled SET is still acknowledged", jti in op.acks)
        receiver.stop()
    }

    @Test fun testAtTheStreamLimitTheReceiverReusesThePersonsStream() = runBlocking {
        val op = StubOP()
        op.maxStreams = 2
        // Two streams already: one created by another app, then one created by this receiver (same description).
        val (other, _) = setUp(op) { it.copy(description = "another app") }
        other.discover()
        other.createStream()
        val (first, _) = setUp(op)
        first.discover()
        first.createStream()
        val mine = first.stream?.string("stream_id")
        // This receiver lost its stream id and starts again: the create is refused with 403, and its stream reused.
        val (again, _) = setUp(op) { it.copy(eventsRequested = listOf(CAEP.SESSION_REVOKED)) }
        val stream = again.start()
        assertEquals("the stream whose description is this receiver's is preferred", mine, stream.string("stream_id"))
        assertEquals("no stream was created", 2, op.streamCount)
        assertEquals("the reused stream is re-pointed at this receiver", listOf(CAEP.SESSION_REVOKED),
            op.stream(mine ?: "")?.get("events_requested").stringArrayValue)
        again.stop()
    }

    @Test fun testAtTheLimitWithoutAMatchTheFirstStreamIsReused() = runBlocking {
        val op = StubOP()
        op.maxStreams = 1
        val (other, _) = setUp(op) { it.copy(description = "another app") }
        other.discover()
        other.createStream()
        val theirs = other.stream?.string("stream_id")
        val (receiver, _) = setUp(op)
        val stream = receiver.start()
        assertEquals(theirs, stream.string("stream_id"))
        receiver.stop()
    }

    @Test fun testAtTheLimitWithNothingToReuseTheRefusalIsRethrown() = runBlocking {
        val op = StubOP()
        op.maxStreams = 0
        val (receiver, _) = setUp(op)
        try {
            receiver.start()
            fail("expected the 403")
        } catch (e: OIDCError) {
            assertEquals(403, e.status)
            assertEquals("access_denied", e.code)
        }
    }

    @Test fun testPollEndpointMustBeAtTheTransmitter() = runBlocking {
        val op = StubOP()
        val (receiver, _) = setUp(op)
        receiver.start()
        // start() schedules an immediate poll; let it finish, or the poll below would join it (polls never overlap)
        // and run against the stream it started with. The Swift test relies on actor ordering for this.
        receiver.poll()
        receiver.stream = jsonObjectOf("stream_id" to "s", "aud" to CLIENT_ID, "delivery" to mapOf("endpoint_url" to "https://evil.example/poll"))
        assertThrowsCode("untrusted_endpoint") { receiver.poll() }
        receiver.stop()
    }
}
