// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.time.Instant

/** What every security event handler receives. */
public data class SecurityEvent internal constructor(
    /** Event type URI. */
    public val type: String,
    /** The event-specific object from the SET's `events` claim. */
    public val payload: JsonObject,
    /** Every validated SET claim. */
    public val set: JsonObject,
    /** The SET as received (compact JWS). */
    public val raw: String,
) {
    /** Short name, e.g. `session-revoked`. */
    public val name: String get() = eventName(type)
    /** RFC 9493 subject identifier (`sub_id`, or the legacy `subject` inside the event). */
    public val subject: JsonObject? get() = set["sub_id"].objectValue ?: payload["subject"].objectValue
    /** CAEP `event_timestamp` (seconds), falling back to the SET's `toe`, then `iat`. */
    public val eventTimestamp: Double? get() = payload["event_timestamp"].doubleValue ?: set["toe"].doubleValue ?: set["iat"].doubleValue
    /** `admin`, `user`, `policy` or `system`. */
    public val initiatingEntity: String? get() = payload.string("initiating_entity")
    public val reasonAdmin: Map<String, String>? get() = strings(payload["reason_admin"])
    public val reasonUser: Map<String, String>? get() = strings(payload["reason_user"])
    public val jti: String get() = set.string("jti") ?: ""
    public val iss: String get() = set.string("iss") ?: ""
    public val aud: JsonElement? get() = set["aud"]
    public val iat: Double get() = set["iat"].doubleValue ?: 0.0
    public val txn: String? get() = set.string("txn")

    private fun strings(v: JsonElement?): Map<String, String>? =
        v.objectValue?.mapNotNull { (k, e) -> e.stringValue?.let { k to it } }?.toMap()
}

/** A handler for one kind of event. Throwing leaves the SET for the transmitter to send again. */
public typealias SecurityEventHandler = suspend (SecurityEvent) -> Unit

/** Where an error reported to [SSFReceiver.onError] came from. */
public data class SSFErrorContext(
    public val phase: Phase,
    /** The SET concerned, when there is one. */
    public val jti: String? = null,
    /** The event whose handler threw. */
    public val event: SecurityEvent? = null,
    /** The SET was left for the transmitter to send again. */
    public val willRetry: Boolean = false,
) {
    public enum class Phase(public val value: String) {
        /** Polling, or validating a polled SET. */
        POLL("poll"),
        /** A handler threw. */
        HANDLER("handler"),
        /** `onEventReceived` threw. */
        HOOK("hook"),
        /** Sending the last acknowledgements, or deleting the stream, failed. */
        STOP("stop"),
    }
}

public typealias SSFErrorHandler = (OIDCError, SSFErrorContext) -> Unit

/** One request to the transmitter, for [SSFAuthorization.Headers]. */
public data class SSFRequestInfo(public val method: String, public val url: URI, /** A DPoP nonce the transmitter asked for. */ public val nonce: String?)

/** How the receiver authorizes its calls to the transmitter (stream management and polling). */
public sealed class SSFAuthorization {
    /** A bearer token, fetched for each request. */
    public class Bearer(public val token: suspend () -> String) : SSFAuthorization()
    /** The `authorization` (and `dpop`) headers for one request. */
    public class Headers(public val make: suspend (SSFRequestInfo) -> Map<String, String>) : SSFAuthorization()

    public companion object {
        /** The signed-in person's access token, with a DPoP proof when it is bound: the usual choice. */
        public fun oidc(client: OIDCClient, tokenSet: suspend () -> TokenSet): SSFAuthorization =
            Headers { request -> client.resourceHeaders(tokenSet(), request.method, request.url, request.nonce) }
    }
}

/**
 * The default `onEventReceived` hook: one log line per accepted event, naming the event and its `jti` only. The
 * payload and subject can carry personal data, so they are left out.
 */
public val logEventReceived: SecurityEventHandler = { event -> OIDCLog.log(OIDCLog.Level.INFO, "CAEP event received: ${event.name} (jti ${event.jti})") }

public data class SSFReceiverConfiguration(
    /** The SSF transmitter's issuer; its metadata is read from `/.well-known/ssf-configuration`. Delivery is RFC 8936 POLL. */
    public val transmitterIssuer: String,
    public val authorization: SSFAuthorization? = null,
    /** Expected SET `aud`. Default: the `aud` in the stream configuration. */
    public val audience: List<String>? = null,
    /** Default: every CAEP event type. */
    public val eventsRequested: List<String> = CAEP.all,
    /** Use an existing stream instead of creating one. */
    public val streamID: String? = null,
    public val description: String = "android-oidc-caep-native-app receiver",
    /** Seconds between polls. */
    public val pollInterval: Double = 5.0,
    /** Max SETs per poll. */
    public val maxEvents: Int = 25,
    public val clockTolerance: Double = 60.0,
    /**
     * Refuse SETs whose `iat` is older than this (seconds). Default 0: no limit. A polled SET waits at the transmitter
     * until it is read, so an age limit would throw away the signals a stopped receiver catches up on. A replay is
     * caught by its `jti` whatever its age.
     */
    public val maxSetAge: Double = 0.0,
    /** How many times a SET whose handlers throw is left for the transmitter to send again before it is acknowledged anyway. */
    public val maxDeliveryAttempts: Int = 5,
    /** Allow non-TLS SSF URLs other than loopback. */
    public val allowInsecureRequests: Boolean = false,
    /** Origins besides the transmitter's issuer and configuration_endpoint that the stream's poll `endpoint_url` may be at. */
    public val trustedPollOrigins: List<String> = emptyList(),
    /** Require the `typ: secevent+jwt` header (SSF §4.1.9). */
    public val requireTyp: Boolean = true,
    /** Replay-protection window size. */
    public val jtiCacheSize: Int = 10_000,
    public val httpTimeout: Double = 10.0,
    public val transport: HttpTransport = OkHttpTransport(),
    /**
     * Your logic for every accepted event: called once per event, before the typed handlers, and awaited. Default
     * [logEventReceived]. Null turns it off. A throw goes to `onError` with phase HOOK, and the typed handlers still run.
     */
    public val onEventReceived: SecurityEventHandler? = logEventReceived,
    public val now: () -> Instant = { Instant.now() },
)

/** SSF transmitter metadata members that are URLs, all of which must use TLS. */
private val ssfURLMembers = listOf("jwks_uri", "configuration_endpoint", "status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint")

/**
 * An OpenID Shared Signals Framework 1.0 receiver with one handler per CAEP event, polling its stream (RFC 8936).
 *
 * ```kotlin
 * val receiver = SSFReceiver(SSFReceiverConfiguration(
 *     transmitterIssuer = client.issuer,
 *     authorization = SSFAuthorization.oidc(client) { accounts.getTokenSet() }))
 * receiver
 *     .onSessionRevoked { event -> /* sign the user out */ }
 *     .onCredentialChange { event -> /* event.payload["change_type"] */ }
 * receiver.start()
 * ```
 *
 * Any other event type (e.g. RISC) can be handled with [onEvent].
 */
public class SSFReceiver(public val configuration: SSFReceiverConfiguration) {
    public data class PollResult(public val received: Int, public val moreAvailable: Boolean)

    private val dispatcher = actorDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val http = HttpClient(configuration.transport, configuration.httpTimeout)

    // Handlers: registration is synchronous, so handlers can be chained.
    private val byType = HashMap<String, MutableList<SecurityEventHandler>>()
    private val anyHandlers = mutableListOf<SecurityEventHandler>()
    private val unhandledHandlers = mutableListOf<SecurityEventHandler>()
    private val errorHandlers = mutableListOf<SSFErrorHandler>()
    private val handlerLock = Any()

    /** Transmitter metadata, once discovered. */
    public var metadata: JsonObject? = null
        private set
    /** The current stream configuration. Set it to point the receiver at a known stream id without fetching it (to delete it). */
    @Volatile public var stream: JsonObject? = null

    private var jwks: RemoteJWKSet? = null
    private val seenJtis = LinkedHashSet<String>()
    private val pendingVerifications = HashMap<String, CompletableDeferred<SecurityEvent>>()
    private var loopJob: Job? = null
    private var polling = false
    private var pollInFlight: CompletableDeferred<PollResult>? = null
    private var pollAgain = false
    private val inFlight = HashSet<String>()
    private val pendingAcks = mutableListOf<String>()
    private val pendingErrs = LinkedHashMap<String, JsonElement>()
    private val attempts = LinkedHashMap<String, Int>()
    /** Handlers are running (a poll is dispatching SETs). */
    private var dispatchDepth = 0
    /** stop() was called from inside a handler: the poll finishing now sends the last acknowledgements. */
    private var flushWhenPollEnds = false

    private val now: Instant get() = configuration.now()

    private suspend fun <T> serial(body: suspend () -> T): T = withContext(dispatcher) { body() }

    // MARK: Handler registration: one per CAEP event, plus generic hooks

    /** CAEP session-revoked: the session(s) for the subject were revoked; end local sessions. */
    public fun onSessionRevoked(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.SESSION_REVOKED, h)
    /** CAEP token-claims-change: claims in previously issued tokens changed (`payload["claims"]`). */
    public fun onTokenClaimsChange(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.TOKEN_CLAIMS_CHANGE, h)
    /** CAEP credential-change (`credential_type`, `change_type`). */
    public fun onCredentialChange(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.CREDENTIAL_CHANGE, h)
    /** CAEP assurance-level-change (`current_level`, `previous_level`, `change_direction`). */
    public fun onAssuranceLevelChange(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.ASSURANCE_LEVEL_CHANGE, h)
    /** CAEP device-compliance-change (`current_status`: `compliant` or `not-compliant`). */
    public fun onDeviceComplianceChange(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.DEVICE_COMPLIANCE_CHANGE, h)
    /** CAEP session-established (`acr`, `amr`, `fp_ua`, `ext_id`). */
    public fun onSessionEstablished(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.SESSION_ESTABLISHED, h)
    /** CAEP session-presented (`fp_ua`, `ext_id`). */
    public fun onSessionPresented(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.SESSION_PRESENTED, h)
    /** CAEP risk-level-change (`principal`, `current_level`, `previous_level`, `risk_reason`). */
    public fun onRiskLevelChange(h: SecurityEventHandler): SSFReceiver = onEvent(CAEP.RISK_LEVEL_CHANGE, h)
    /** SSF verification event (`state`). */
    public fun onVerification(h: SecurityEventHandler): SSFReceiver = onEvent(SSF.VERIFICATION, h)
    /** SSF stream-updated event (`status`, `reason`). */
    public fun onStreamUpdated(h: SecurityEventHandler): SSFReceiver = onEvent(SSF.STREAM_UPDATED, h)

    /** A handler for any event type URI (CAEP, RISC, or your own). */
    public fun onEvent(eventType: String, handler: SecurityEventHandler): SSFReceiver {
        synchronized(handlerLock) { byType.getOrPut(eventType) { mutableListOf() }.add(handler) }
        return this
    }

    /** Called for every accepted event, after its type's handlers. */
    public fun onAnyEvent(handler: SecurityEventHandler): SSFReceiver {
        synchronized(handlerLock) { anyHandlers.add(handler) }
        return this
    }

    /** Called for events no type-specific handler is registered for. */
    public fun onUnhandledEvent(handler: SecurityEventHandler): SSFReceiver {
        synchronized(handlerLock) { unhandledHandlers.add(handler) }
        return this
    }

    /** Called when a SET is rejected, a handler throws, or polling fails. Without one, errors are logged ([OIDCLog]). */
    public fun onError(handler: SSFErrorHandler): SSFReceiver {
        synchronized(handlerLock) { errorHandlers.add(handler) }
        return this
    }

    /** Removes every handler registered for [eventType]. */
    public fun removeHandlers(eventType: String): SSFReceiver {
        synchronized(handlerLock) { byType.remove(eventType) }
        return this
    }

    // MARK: Lifecycle

    /** Loads the transmitter's metadata from its well-known SSF configuration endpoint. */
    public suspend fun discover(): JsonObject = serial {
        val c = configuration
        // TLS for every SSF URL (RFC 9700 §2.6), loopback excepted: they receive the person's access token, and the
        // JWKS is what every SET is trusted by.
        if (!c.allowInsecureRequests && !isSecureURL(c.transmitterIssuer)) {
            throw OIDCError.ssf("transmitterIssuer must use https: ${c.transmitterIssuer}", code = "insecure_endpoint")
        }
        val m = discoverSSFTransmitter(c.transmitterIssuer, c.transport, c.httpTimeout)
        if (!c.allowInsecureRequests) {
            for (key in ssfURLMembers) {
                val value = m.string(key) ?: continue
                if (!isSecureURL(value)) throw OIDCError.ssf("SSF metadata $key must use https: $value", code = "insecure_endpoint")
            }
        }
        val jwksURL = parseURI(m.string("jwks_uri")) ?: throw OIDCError.ssf("SSF metadata jwks_uri is not a URL")
        m["delivery_methods_supported"].stringArrayValue?.let {
            if (Delivery.POLL !in it) throw OIDCError.ssf("Transmitter does not support poll delivery (${Delivery.POLL})")
        }
        metadata = m
        jwks = RemoteJWKSet(jwksURL, http, now = c.now)
        m
    }

    /**
     * Discovers the transmitter, creates (or reuses) a stream, and starts polling.
     *
     * When the create is refused because the person already has streams (HTTP 409, or HTTP 403 when they hold as many
     * as the transmitter allows), one of their streams is reused and re-pointed at this receiver's delivery settings
     * and events: the one whose `description` is this receiver's, else the first.
     *
     * With [catchUp], the SETs already queued on the stream are polled and dispatched before this returns, so that a
     * session revoked while the receiver was stopped is acted on before the session is used.
     */
    public suspend fun start(catchUp: Boolean = false): JsonObject = serial {
        if (metadata == null) discover()
        val id = configuration.streamID
        if (id != null) {
            stream = getStream(id)
        } else if (metadata?.get("configuration_endpoint") != null) {
            try {
                stream = createStream()
            } catch (e: OIDCError) {
                if (e.status != 409 && e.status != 403) throw e
                val existing = listStreams().filter { it.string("stream_id") != null }
                val reuse = existing.firstOrNull { it.string("description") == configuration.description } ?: existing.firstOrNull() ?: throw e
                stream = reuse
                stream = updateStream(jsonObjectOf("delivery" to deliveryRequest, "events_requested" to configuration.eventsRequested))
            }
        } else {
            throw OIDCError.ssf("Transmitter has no configuration_endpoint and no streamID was supplied")
        }
        var more = catchUp
        // A handler may end the account and delete the stream while catching up: then there is nothing to poll.
        while (more && stream != null) more = poll().moreAvailable
        if (stream == null) return@serial emptyJsonObject
        polling = true
        pollNowInternal()
        stream ?: emptyJsonObject
    }

    /** Stops polling, sends the acknowledgements still owed, and optionally deletes the stream at the transmitter. */
    public suspend fun stop(deleteStream: Boolean = false): Unit = serial {
        polling = false
        loopJob?.cancel()
        loopJob = null
        // A poll still running may finish handling SETs; their acknowledgements go in the flush below. Called from
        // inside a handler (which runs within a poll), waiting for that poll would never end: the poll sends the last
        // acknowledgements when it finishes instead.
        val running = pollInFlight
        if (dispatchDepth > 0 && running != null) {
            flushWhenPollEnds = true
            return@serial
        }
        if (running != null) runCatching { running.await() }
        flushAcks()
        if (deleteStream && stream?.string("stream_id") != null) {
            try { deleteStream() } catch (e: Exception) { emitError(OIDCError.wrap(e), SSFErrorContext(SSFErrorContext.Phase.STOP)) }
        }
    }

    // MARK: Stream management API (SSF 1.0 §8.1)

    /** Creates a stream with this receiver's delivery settings and requested events. */
    public suspend fun createStream(extra: JsonObject = emptyJsonObject): JsonObject = serial {
        val body = jsonObjectOf("delivery" to deliveryRequest, "events_requested" to configuration.eventsRequested,
            "description" to configuration.description) + extra
        stream = mgmt("POST", endpoint("configuration_endpoint"), body).objectValue
        stream ?: emptyJsonObject
    }

    /** Every stream the transmitter has for this receiver. */
    public suspend fun listStreams(): List<JsonObject> = serial {
        val result = mgmt("GET", endpoint("configuration_endpoint"))
        result.arrayValue?.mapNotNull { it.objectValue } ?: result.objectValue?.let { listOf(it) } ?: emptyList()
    }

    public suspend fun getStream(streamID: String? = null): JsonObject = serial {
        val id = streamID ?: stream?.string("stream_id") ?: throw OIDCError.ssf("No stream; call start() or createStream() first")
        stream = mgmt("GET", endpoint("configuration_endpoint").appendingQuery(FormParameters(listOf("stream_id" to id)))).objectValue
        stream ?: emptyJsonObject
    }

    /** PATCH the stream configuration. */
    public suspend fun updateStream(changes: JsonObject): JsonObject = serial {
        stream = mgmt("PATCH", endpoint("configuration_endpoint"), changes.with("stream_id", streamID())).objectValue
        stream ?: emptyJsonObject
    }

    /** PUT (replace) the stream configuration. */
    public suspend fun replaceStream(configuration: JsonObject): JsonObject = serial {
        stream = mgmt("PUT", endpoint("configuration_endpoint"), configuration.with("stream_id", streamID())).objectValue
        stream ?: emptyJsonObject
    }

    public suspend fun deleteStream(): Unit = serial {
        mgmt("DELETE", endpoint("configuration_endpoint").appendingQuery(FormParameters(listOf("stream_id" to streamID()))))
        stream = null
    }

    /** The stream's status: `{ stream_id, status: enabled|paused|disabled, reason? }`. */
    public suspend fun getStatus(): JsonObject = serial {
        mgmt("GET", endpoint("status_endpoint").appendingQuery(FormParameters(listOf("stream_id" to streamID())))).objectValue ?: emptyJsonObject
    }

    /** Sets the stream's status (`enabled`, `paused` or `disabled`). */
    public suspend fun updateStatus(status: String, reason: String? = null): JsonObject = serial {
        mgmt("POST", endpoint("status_endpoint"), jsonObjectOf("stream_id" to streamID(), "status" to status, "reason" to reason)).objectValue ?: emptyJsonObject
    }

    /** Asks the transmitter to include events about a subject in this stream (e.g. `Subject.issSub(iss, sub)`). */
    public suspend fun addSubject(subject: JsonObject, verified: Boolean? = null): Unit = serial {
        mgmt("POST", endpoint("add_subject_endpoint"), jsonObjectOf("stream_id" to streamID(), "subject" to subject, "verified" to verified))
    }

    public suspend fun removeSubject(subject: JsonObject): Unit = serial {
        mgmt("POST", endpoint("remove_subject_endpoint"), jsonObjectOf("stream_id" to streamID(), "subject" to subject))
    }

    /** Requests a verification event (SSF §8.1.4) and returns it once received. */
    public suspend fun requestVerification(timeoutSeconds: Double = 15.0, state: String = randomToken(16)): SecurityEvent {
        val waiter = CompletableDeferred<SecurityEvent>()
        serial {
            pendingVerifications[state] = waiter
            try {
                mgmt("POST", endpoint("verification_endpoint"), jsonObjectOf("stream_id" to streamID(), "state" to state))
            } catch (e: Exception) {
                pendingVerifications.remove(state)
                throw e
            }
            pollNowInternal()
        }
        try {
            return withTimeout((timeoutSeconds * 1000).toLong()) { waiter.await() }
        } catch (e: TimeoutCancellationException) {
            throw OIDCError.ssf("Verification event not received within ${(timeoutSeconds * 1000).toInt()}ms", code = "verification_timeout")
        } finally {
            serial { pendingVerifications.remove(state) }
        }
    }

    // MARK: Delivery

    /** Validates a SET and runs its handlers. Use this for SETs received through your own transport. Returns the dispatched events (empty for a replayed `jti`). */
    public suspend fun receiveSet(token: String): List<SecurityEvent> = serial {
        val events = validateSet(token)
        dispatchAll(events)
        events
    }

    /** Validates a SET (RFC 8417 / SSF 1.0 §4) without dispatching it. A replayed `jti` returns an empty list. */
    public suspend fun validateSet(token: String): List<SecurityEvent> = serial {
        if (jwks == null) discover()
        val keys = jwks
        val m = metadata
        if (keys == null || m == null) throw OIDCError.ssf("Receiver not initialised; call discover() or start()")
        val c = configuration
        if (token.split(".").size != 3) throw OIDCError.set("Body is not a compact-serialised JWS", code = "invalid_request")
        val header = try { CompactJWS(token).header } catch (e: Exception) { throw OIDCError.set("Malformed JWS header", code = "invalid_request", cause = e) }
        val alg = header.string("alg") ?: ""
        if (alg !in asymmetricJWSAlgorithms) {
            throw OIDCError.set("SET is signed with \"$alg\", which this receiver cannot verify (supported: ${asymmetricJWSAlgorithms.joinToString(", ")})", code = "invalid_key")
        }
        if (c.requireTyp) {
            val typ = (header.string("typ")?.lowercase() ?: "").removePrefix("application/")
            if (typ != "secevent+jwt") throw OIDCError.set("Unexpected typ \"${header.string("typ") ?: ""}\"; expected secevent+jwt", code = "invalid_request")
        }
        // Fail closed: SSF 1.0 requires the transmitter to supply the stream's `aud`, so a missing one is not a reason
        // to accept SETs addressed to anybody.
        val audience = c.audience ?: stream?.get("aud")?.let { it.stringValue?.let { s -> listOf(s) } ?: it.stringArrayValue }
        if (audience.isNullOrEmpty()) {
            throw OIDCError.set("No expected SET audience: the stream configuration has no \"aud\" and no audience option was set", code = "invalid_audience")
        }
        val claims = try {
            verifyJWT(token, keys, JWTVerifyOptions(
                algorithms = asymmetricJWSAlgorithms, issuer = m.string("issuer"), audience = audience, clockTolerance = c.clockTolerance,
                maxTokenAge = if (c.maxSetAge > 0) c.maxSetAge else null, requiredClaims = listOf("iss", "jti", "iat", "events"), now = now)).second
        } catch (e: JOSEError) {
            throw mapJOSEError(e)
        }
        val iat = claims["iat"].doubleValue
        if (iat == null || iat > now.seconds + c.clockTolerance) throw OIDCError.set("SET iat is missing or in the future", code = "invalid_request")
        val events = claims["events"].objectValue ?: throw OIDCError.set("SET \"events\" claim must be an object", code = "invalid_request")
        // SSF 1.0 §4.1.8: the events claim contains exactly one event.
        if (events.size != 1) throw OIDCError.set("SET \"events\" claim must contain exactly one event, not ${events.size}", code = "invalid_request")
        val (type, payload) = events.entries.first()
        // A stream event (verification, stream-updated) is about a stream, named by an opaque sub_id. One that names
        // another stream, or something else, is not about this one.
        val subId = claims["sub_id"]
        if ((type == SSF.VERIFICATION || type == SSF.STREAM_UPDATED) && subId != null) {
            val ours = stream?.string("stream_id") ?: c.streamID
            if (subId["format"].stringValue != "opaque" || (ours != null && subId["id"].stringValue != ours)) {
                throw OIDCError.set("${eventName(type)} event is not about this stream", code = "invalid_request")
            }
        }
        val jti = claims.string("jti") ?: throw OIDCError.set("SET jti must be a string", code = "invalid_request")
        if (jti in seenJtis) return@serial emptyList()
        rememberJti(jti)
        listOf(SecurityEvent(type, payload.objectValue ?: emptyJsonObject, claims, token))
    }

    /** Polls now (when polling). During a poll, another follows right after it. */
    public suspend fun pollNow(): Unit = serial { pollNowInternal() }

    private fun pollNowInternal() {
        if (!polling) return
        if (pollInFlight != null) {
            pollAgain = true
            return
        }
        scheduleLoop(0.0)
    }

    /** Performs one RFC 8936 poll request, acknowledging the SETs already handled. Polls never overlap: a call during a poll shares it. */
    public suspend fun poll(): PollResult {
        val (deferred, owner) = serial {
            pollInFlight?.let { it to false } ?: CompletableDeferred<PollResult>().also { pollInFlight = it }.let { it to true }
        }
        if (!owner) return deferred.await()
        // The slot is cleared before anyone awaiting it resumes, so a call made right after a poll finishes starts a new poll.
        val result = runCatching { serial { pollOnce() } }
        serial { pollInFlight = null }
        result.fold({ deferred.complete(it) }, { deferred.completeExceptionally(it) })
        return result.getOrThrow()
    }

    private suspend fun pollOnce(): PollResult {
        val endpoint = pollEndpoint()
        val ack = pendingAcks.toList()
        pendingAcks.clear()
        val setErrs = LinkedHashMap(pendingErrs)
        pendingErrs.clear()
        var body = jsonObjectOf("maxEvents" to configuration.maxEvents, "returnImmediately" to true, "ack" to ack)
        if (setErrs.isNotEmpty()) body = body.with("setErrs", JsonObject(setErrs))
        val result = try {
            mgmt("POST", endpoint, body)
        } catch (e: Exception) {
            // Put the acknowledgements back so they're sent with the next poll.
            pendingAcks.addAll(0, ack)
            for ((k, v) in setErrs) pendingErrs.putIfAbsent(k, v)
            throw e
        }
        // The `sets` object has no order; SETs are handled oldest first.
        val sets = (result["sets"].objectValue ?: emptyJsonObject).mapNotNull { (jti, token) -> token.stringValue?.let { jti to it } }
            .sortedWith(compareBy<Pair<String, String>>({ decodeUnverifiedJWTPayload(it.second)?.get("iat").doubleValue ?: 0.0 }, { it.first }))
        for ((jti, token) in sets) {
            if (!polling && flushWhenPollEnds) break
            receivePolled(jti, token)
        }
        if (flushWhenPollEnds) {
            flushWhenPollEnds = false
            flushAcks()
        }
        return PollResult(sets.size, result["moreAvailable"].boolValue == true)
    }

    /**
     * One polled SET. RFC 8936 §2.4: an acknowledged SET, and one reported in `setErrs`, are never sent again. So a SET
     * is acknowledged only once its handlers ran without throwing, and reported only when it is definitely invalid.
     * One whose handlers threw is left for the transmitter to send again, up to `maxDeliveryAttempts` times; one that
     * could not be checked for a reason that may pass is left until it can.
     */
    private suspend fun receivePolled(jti: String, token: String) {
        // Being handled right now: neither acknowledged nor reported, so the transmitter keeps it until done.
        if (jti in inFlight) return
        inFlight.add(jti)
        try {
            val events = try {
                validateSet(token)
            } catch (error: Exception) {
                val e = OIDCError.wrap(error)
                if (e.retryable) {
                    emitError(e, SSFErrorContext(SSFErrorContext.Phase.POLL, jti = jti, willRetry = true))
                    return
                }
                attempts.remove(jti)
                pendingErrs[jti] = jsonObjectOf("err" to (if (e.kind == OIDCError.Kind.SET_VALIDATION) e.code ?: "invalid_request" else "invalid_request"),
                    "description" to e.message)
                emitError(e, SSFErrorContext(SSFErrorContext.Phase.POLL, jti = jti))
                return
            }
            val handled = dispatchAll(events)
            if (!handled && attempt(jti) < configuration.maxDeliveryAttempts) {
                // Let the redelivery through the replay check: it is the same SET, not handled yet.
                for (evt in events) seenJtis.remove(evt.jti)
                return
            }
            if (!handled) {
                emitError(OIDCError.ssf("Gave up on SET $jti after ${configuration.maxDeliveryAttempts} attempts; its handlers kept throwing", code = "handler_failed"),
                    SSFErrorContext(SSFErrorContext.Phase.HANDLER, jti = jti))
            }
            attempts.remove(jti)
            if (jti !in pendingAcks) pendingAcks.add(jti)
        } finally {
            inFlight.remove(jti)
        }
    }

    private fun attempt(jti: String): Int {
        val n = (attempts[jti] ?: 0) + 1
        attempts[jti] = n
        if (attempts.size > configuration.jtiCacheSize) attempts.keys.firstOrNull { it != jti }?.let { attempts.remove(it) }
        return n
    }

    /**
     * The poll endpoint, which receives the person's access token on every request. It comes from the stream
     * configuration, not the transmitter's metadata, so it must use TLS and share an origin with the transmitter's own
     * endpoints: a stream re-pointed elsewhere must not be handed the token.
     */
    private fun pollEndpoint(): URI {
        val s = stream?.get("delivery")?.get("endpoint_url").stringValue
        val endpoint = parseURI(s) ?: throw OIDCError.ssf("Stream has no poll endpoint_url")
        if (!configuration.allowInsecureRequests && !isSecureURL(s)) throw OIDCError.ssf("Poll endpoint_url must use https: $s", code = "insecure_endpoint")
        val trusted = (listOfNotNull(metadata?.string("issuer"), metadata?.string("configuration_endpoint")) + configuration.trustedPollOrigins).mapNotNull { originOf(it) }
        val origin = originOf(endpoint)
        if (origin == null || origin !in trusted) {
            throw OIDCError.ssf("Poll endpoint_url $s is not at the transmitter's origin (${trusted.joinToString(", ")}); not sending the access token there",
                code = "untrusted_endpoint")
        }
        return endpoint
    }

    /** Sends the acknowledgements and errors still owed, so a stopped receiver is not sent them again. */
    private suspend fun flushAcks() {
        if ((pendingAcks.isEmpty() && pendingErrs.isEmpty()) || stream?.get("delivery")?.get("endpoint_url") == null || metadata == null) return
        val ack = pendingAcks.toList()
        pendingAcks.clear()
        val setErrs = LinkedHashMap(pendingErrs)
        pendingErrs.clear()
        try {
            var body = jsonObjectOf("maxEvents" to 0, "returnImmediately" to true, "ack" to ack)
            if (setErrs.isNotEmpty()) body = body.with("setErrs", JsonObject(setErrs))
            mgmt("POST", pollEndpoint(), body)
        } catch (e: Exception) {
            pendingAcks.addAll(0, ack)
            for ((k, v) in setErrs) pendingErrs.putIfAbsent(k, v)
            emitError(OIDCError.wrap(e), SSFErrorContext(SSFErrorContext.Phase.STOP))
        }
    }

    // MARK: Internals

    private val deliveryRequest: JsonObject get() = jsonObjectOf("method" to Delivery.POLL)

    private fun scheduleLoop(delaySeconds: Double) {
        loopJob?.cancel()
        loopJob = scope.launch {
            if (delaySeconds > 0) delay((delaySeconds * 1000).toLong())
            pollLoop()
        }
    }

    private suspend fun pollLoop() {
        if (!polling) return
        loopJob = null
        pollAgain = false
        var delaySeconds = configuration.pollInterval
        try {
            if (poll().moreAvailable) delaySeconds = 0.0
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            emitError(OIDCError.wrap(e), SSFErrorContext(SSFErrorContext.Phase.POLL))
        }
        if (pollAgain) delaySeconds = 0.0
        if (polling && loopJob == null) scheduleLoop(delaySeconds)
    }

    /** False when a handler threw. */
    private suspend fun dispatchAll(events: List<SecurityEvent>): Boolean {
        dispatchDepth += 1
        try {
            var ok = true
            for (evt in events) ok = dispatch(evt) && ok
            return ok
        } finally {
            dispatchDepth -= 1
        }
    }

    private suspend fun dispatch(evt: SecurityEvent): Boolean {
        if (evt.type == SSF.VERIFICATION) evt.payload.string("state")?.let { pendingVerifications.remove(it)?.complete(evt) }
        // validateSet() refused a stream event that names another stream; one with no sub_id is the stream's.
        if (evt.type == SSF.STREAM_UPDATED) {
            val s = stream
            val status = evt.payload["status"]
            if (s != null && status != null) stream = s.with("status", status)
        }
        configuration.onEventReceived?.let { hook ->
            try { hook(evt) } catch (e: Exception) { emitError(OIDCError.wrap(e), SSFErrorContext(SSFErrorContext.Phase.HOOK, event = evt)) }
        }
        val (specific, unhandled, any) = synchronized(handlerLock) { Triple(byType[evt.type]?.toList() ?: emptyList(), unhandledHandlers.toList(), anyHandlers.toList()) }
        var ok = true
        for (h in (specific.ifEmpty { unhandled }) + any) {
            try { h(evt) } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) {
                ok = false
                emitError(OIDCError.wrap(e), SSFErrorContext(SSFErrorContext.Phase.HANDLER, event = evt))
            }
        }
        return ok
    }

    private fun emitError(error: OIDCError, context: SSFErrorContext) {
        val registered = synchronized(handlerLock) { errorHandlers.toList() }
        // Never silent: a security event that could not be handled must leave a trace.
        if (registered.isEmpty()) {
            OIDCLog.log(OIDCLog.Level.ERROR, "${context.phase.value}: ${error.message}")
            return
        }
        for (h in registered) h(error, context)
    }

    private fun rememberJti(jti: String) {
        seenJtis.add(jti)
        while (seenJtis.size > configuration.jtiCacheSize) seenJtis.remove(seenJtis.first())
    }

    private fun endpoint(name: String): URI {
        val m = metadata ?: throw OIDCError.ssf("Receiver not initialised; call discover() or start()")
        return parseURI(m.string(name)) ?: throw OIDCError.ssf("Transmitter does not advertise $name")
    }

    private fun streamID(): String =
        stream?.string("stream_id") ?: configuration.streamID ?: throw OIDCError.ssf("No stream; call start() or createStream() first")

    private suspend fun mgmt(method: String, url: URI, body: JsonObject? = null): JsonElement? {
        val data = body?.jsonBytes()
        suspend fun send(nonce: String?): HttpResponse {
            val headers = mutableMapOf("accept" to "application/json")
            when (val auth = configuration.authorization) {
                is SSFAuthorization.Headers -> for ((k, v) in auth.make(SSFRequestInfo(method, url, nonce))) headers[k.lowercase()] = v
                is SSFAuthorization.Bearer -> headers["authorization"] = "Bearer ${auth.token()}"
                null -> {}
            }
            if (data != null) headers["content-type"] = "application/json"
            return http.send(HttpRequest(url, method, headers, data))
        }
        var res = send(null)
        // A resource server may demand a DPoP nonce (RFC 9449 §9): retry once with it.
        if (configuration.authorization is SSFAuthorization.Headers && wantsDPoPNonce(res)) res = send(res.header("dpop-nonce"))
        try {
            return readJSON(res, OIDCError.Kind.SSF)
        } catch (e: OIDCError) {
            throw if (e.kind == OIDCError.Kind.OAUTH) e.withKind(OIDCError.Kind.SSF) else e
        }
    }

    /** A JOSE failure as a SET error: a bad token (reported to the transmitter), or a check that may pass later. */
    private fun mapJOSEError(e: JOSEError): OIDCError = when (e) {
        is JOSEError.NoMatchingKey -> OIDCError.set(e.toString(), code = "invalid_key").also { it.retryable = true }
        is JOSEError.JwksUnavailable -> OIDCError.set(e.toString(), code = "invalid_request").also { it.retryable = true }
        is JOSEError.Expired -> if (e.claim == "iat") OIDCError.set("SET is too old: $e", code = "invalid_request") else OIDCError.set(e.toString())
        is JOSEError.ClaimFailed -> when (e.claim) {
            "iat" -> OIDCError.set("SET iat is not acceptable: $e", code = "invalid_request")
            "iss" -> OIDCError.set(e.toString(), code = "invalid_issuer")
            "aud" -> OIDCError.set(e.toString(), code = "invalid_audience")
            else -> OIDCError.set(e.toString())
        }
        is JOSEError.SignatureFailed, is JOSEError.AlgNotAllowed -> OIDCError.set(e.toString(), code = "invalid_key")
        else -> OIDCError.set(e.toString())
    }
}

