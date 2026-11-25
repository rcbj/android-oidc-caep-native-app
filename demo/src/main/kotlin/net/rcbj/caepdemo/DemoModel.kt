// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.caepdemo

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import net.rcbj.oidccaep.Account
import net.rcbj.oidccaep.AccountAccess
import net.rcbj.oidccaep.AccountManager
import net.rcbj.oidccaep.AccountManagerOptions
import net.rcbj.oidccaep.AndroidKeystoreKeyStore
import net.rcbj.oidccaep.AuthorizationRequestOptions
import net.rcbj.oidccaep.CAEP
import net.rcbj.oidccaep.EventSubscription
import net.rcbj.oidccaep.HttpTransport
import net.rcbj.oidccaep.KeystoreTokenStore
import net.rcbj.oidccaep.OIDCAppConfiguration
import net.rcbj.oidccaep.OIDCClient
import net.rcbj.oidccaep.OIDCError
import net.rcbj.oidccaep.SSFAuthorization
import net.rcbj.oidccaep.SSFErrorContext
import net.rcbj.oidccaep.SSFReceiver
import net.rcbj.oidccaep.SSFReceiverConfiguration
import net.rcbj.oidccaep.SecurityEvent
import net.rcbj.oidccaep.SignInResult
import net.rcbj.oidccaep.Subject
import net.rcbj.oidccaep.TokenSet
import net.rcbj.oidccaep.WebAuthenticator
import net.rcbj.oidccaep.addAccount
import net.rcbj.oidccaep.decodeUnverifiedJWTPayload
import net.rcbj.oidccaep.jsonObjectOf
import net.rcbj.oidccaep.jsonString
import net.rcbj.oidccaep.needsInteraction
import net.rcbj.oidccaep.objectValue
import net.rcbj.oidccaep.parseJson
import net.rcbj.oidccaep.preferredDPoPKeyStore
import net.rcbj.oidccaep.reauthenticate
import net.rcbj.oidccaep.resume
import net.rcbj.oidccaep.signIn
import net.rcbj.oidccaep.signOut
import net.rcbj.oidccaep.signOutAll
import net.rcbj.oidccaep.string
import net.rcbj.oidccaep.stringArrayValue
import net.rcbj.oidccaep.stringValue
import net.rcbj.oidccaep.subjectMatches
import java.io.File
import java.time.Instant
import java.util.UUID

data class LogEntry(
    val id: String = UUID.randomUUID().toString(),
    val at: Instant = Instant.now(),
    val account: String,
    val name: String,
    val type: String? = null,
    val jti: String? = null,
    val subject: String? = null,
    val payload: String? = null,
    val action: String,
) {
    fun toJson(): JsonObject = jsonObjectOf("id" to id, "at" to at.toEpochMilli(), "account" to account, "name" to name, "type" to type, "jti" to jti,
        "subject" to subject, "payload" to payload, "action" to action)

    companion object {
        fun fromJson(o: JsonObject): LogEntry? = try {
            LogEntry(o.string("id")!!, Instant.ofEpochMilli(o["at"]!!.toString().toLong()), o.string("account")!!, o.string("name")!!,
                o.string("type"), o.string("jti"), o.string("subject"), o.string("payload"), o.string("action")!!)
        } catch (e: Exception) {
            null
        }
    }
}

data class Notice(val level: Level, val text: String, val id: String = UUID.randomUUID().toString()) {
    enum class Level { INFO, WARN, DANGER }
}

data class AccountState(
    val refreshCount: Int = 0,
    val lastRefresh: Instant? = null,
    val stepUp: String? = null,
    val notices: List<Notice> = emptyList(),
)

enum class StreamStatus { DISABLED, WAITING_FOR_USER, CONNECTING, CONNECTED, UNAVAILABLE, NO_STREAM, ERROR }

data class StreamState(
    val status: StreamStatus = StreamStatus.WAITING_FOR_USER,
    val transmitter: String? = null,
    val note: String? = null,
    val error: String? = null,
    val streamStatus: String? = null,
    val streamID: String? = null,
    val audience: String? = null,
    val write: Boolean = false,
)

/**
 * The demo's state: the library objects, and what the screens show. The same design as the Swift demo's DemoModel:
 * one AccountManager, one active account, and ONE CAEP stream, the active account's, polled with its (DPoP-bound)
 * access token. A dormant account's stream keeps queueing events, and activating the account catches up on them
 * before its tokens are used.
 */
class DemoModel(application: Application) : AndroidViewModel(application) {
    private val app: Application get() = getApplication()
    private val prefs = application.getSharedPreferences("caep-demo", Context.MODE_PRIVATE)

    // Configuration and library objects.
    var config: OIDCAppConfiguration? by mutableStateOf(null); private set
    var client: OIDCClient? by mutableStateOf(null); private set
    private var accounts: AccountManager? = null
    private var subscription: EventSubscription? = null
    private var transport: HttpTransport? = null
    private lateinit var authenticator: WebAuthenticator

    // What the screens show.
    var accountList: List<Account> by mutableStateOf(emptyList()); private set
    var active: Account? by mutableStateOf(null); private set
    var currentTokens: TokenSet? by mutableStateOf(null); private set
    var signInTokens: Pair<String, TokenSet>? by mutableStateOf(null); private set
    var perAccount: Map<String, AccountState> by mutableStateOf(emptyMap()); private set
    val notices = mutableStateListOf<Notice>()
    var error: String? by mutableStateOf(null)
    var attention: Pair<String, String>? by mutableStateOf(null)
    var busy: String? by mutableStateOf(null); private set
    var userinfoOutput: String? by mutableStateOf(null)
    var dpopStoreDescription: String by mutableStateOf("memory"); private set
    var tokenStoreDescription: String by mutableStateOf("memory"); private set
    var configSource: String by mutableStateOf(""); private set

    // CAEP: the one stream this app polls, the active account's.
    var caepKey: String? by mutableStateOf(null); private set
    private var receiver: SSFReceiver? = null
    var stream: StreamState by mutableStateOf(StreamState()); private set
    val log = mutableStateListOf<LogEntry>()
    var selectedEvents: Set<String> by mutableStateOf(prefs.getStringSet(EVENTS_KEY, null)?.toSet() ?: CAEP.all.toSet())

    val signedIn: Account? get() = active?.takeIf { it.status == Account.Status.SIGNED_IN }
    fun state(key: String): AccountState = perAccount[key] ?: AccountState()

    private fun updateState(key: String, change: (AccountState) -> AccountState) {
        perAccount = perAccount + (key to change(state(key)))
    }

    init {
        loadLog()
        viewModelScope.launch { start() }
    }

    // MARK: - Configuration → client

    private suspend fun start() {
        try {
            val (cfg, source) = withContext(Dispatchers.IO) { loadConfiguration() }
            config = cfg
            configSource = source
            authenticator = cfg.makeAuthenticator(app)
            stream = StreamState(if (cfg.caepEnabled) StreamStatus.WAITING_FOR_USER else StreamStatus.DISABLED)
            // The DPoP key: generated in the Android Keystore (StrongBox or the TEE), never extractable. The tokens:
            // encrypted at rest with a Keystore key, so a relaunch keeps every account signed in.
            val keyStore: AndroidKeystoreKeyStore = preferredDPoPKeyStore(app, "net.rcbj.caepdemo.dpop")
            val tokenStore = KeystoreTokenStore(app, "net.rcbj.caepdemo.tokens", "net.rcbj.caepdemo.tokens-key")
            val t = cfg.makeTransport()
            transport = t
            val c = cfg.makeClient(keyStore, t)
            client = c
            dpopStoreDescription = keyStore.securityLevel()?.let { "Android Keystore, ${it.description}, non-extractable" } ?: "Android Keystore"
            tokenStoreDescription = "encrypted with an AES-256-GCM key in ${tokenStore.securityLevel().description}"

            // The hooks tie the app's one CAEP stream to its active account.
            val options = AccountManagerOptions(
                store = tokenStore,
                storeKey = "accounts:${c.issuer}:${c.clientID}",
                onActivate = { account, access ->
                    rememberProfile(account, access)
                    startCaep(account, access)
                },
                onDeactivate = { account -> stopCaep(account.key) },
                onLeave = { account, access -> deleteStream(account, access) },
            )
            val manager = AccountManager(c, options)
            accounts = manager
            subscription = manager.events.subscribe { event -> viewModelScope.launch { handle(event) } }
            manager.restore()
            reload()
        } catch (e: Exception) {
            error = "Could not load the OIDC configuration or reach the identity provider: ${describe(e)}"
        }
    }

    /**
     * The configuration, from the first of: a file pushed to the app's external files folder
     * (/sdcard/Android/data/net.rcbj.caepdemo/files/oidc_configuration.json), to point the demo at another provider
     * without rebuilding; else the app's assets.
     */
    private fun loadConfiguration(): Pair<OIDCAppConfiguration, String> {
        val user = app.getExternalFilesDir(null)?.let { File(it, OIDCAppConfiguration.DEFAULT_ASSET_NAME) }
        if (user != null && user.exists()) return OIDCAppConfiguration.load(user) to user.path
        return OIDCAppConfiguration.load(app) to "assets/${OIDCAppConfiguration.DEFAULT_ASSET_NAME}"
    }

    private suspend fun reload() {
        val m = accounts ?: return
        accountList = m.list()
        val a = m.active()
        active = a
        currentTokens = if (a != null && a.status == Account.Status.SIGNED_IN) runCatching { m.tokens.get(a.key) }.getOrNull() else null
    }

    private suspend fun handle(event: AccountManager.Event) {
        when (event) {
            is AccountManager.Event.Refreshed -> updateState(event.account.key) { it.copy(refreshCount = it.refreshCount + 1, lastRefresh = Instant.now()) }
            is AccountManager.Event.SignedOut -> clearLog(event.account.key)
            is AccountManager.Event.Forgotten -> clearLog(event.account.key)
            is AccountManager.Event.Activated -> {
                if (event.account?.key != signInTokens?.first) signInTokens = null
                attention = null
            }
            is AccountManager.Event.ActivationError -> error = "Could not make ${label(event.account)} active: ${describe(event.error)}"
            is AccountManager.Event.Change -> {
                // The active account may have been ended by a signal.
                val key = caepKey
                if (key != null) {
                    val status = accounts?.get(key)?.status
                    if (status != null && status != Account.Status.SIGNED_IN) stopCaep(key)
                }
            }
            else -> {}
        }
        reload()
    }

    // MARK: - Sign-in, switching, sign-out

    private val acr: AuthorizationRequestOptions get() = AuthorizationRequestOptions(acrValues = config?.acrValues)

    /** login: do not continue whoever is already signed in at the IdP. consent: offline_access is ignored unless asked for (OIDC Core §11). */
    fun signIn() = go("sign-in") { m -> m.signIn(authenticator, acr.copy(prompt = "login consent")) }
    fun addAccount() = go("sign-in") { m -> m.addAccount(authenticator, acr) }
    fun resume(key: String) = go("silent sign-in") { m -> m.resume(key, authenticator, acr) }
    fun reauthenticate(key: String) = go("sign-in") { m -> m.reauthenticate(key, authenticator, acr) }

    private fun go(what: String, run: suspend (AccountManager) -> SignInResult) {
        val m = accounts ?: return
        viewModelScope.launch {
            error = null
            try {
                val result = run(m)
                val account = result.account
                perAccount = perAccount - account.key
                if (m.activeKey() == account.key) signInTokens = account.key to result.tokenSet
                notices.add(0, Notice(Notice.Level.INFO,
                    if (result.added) "${label(account)} added. Your other accounts stay signed in, dormant until you switch to them."
                    else "Signed in as ${label(account)}."))
            } catch (e: OIDCError) {
                when {
                    e.isUserCancellation -> {} // The person closed the browser tab.
                    needsInteraction(e) && e.account != null ->
                        attention = e.account!!.key to "The identity provider could not sign ${label(e.account)} in without asking (${e.code ?: ""}): their session there has ended."
                    e.oauthError == "account_selection_required" -> error = "Several accounts are signed in at the identity provider and the request did not say which; choose one."
                    e.code == "account_mismatch" -> error = "You signed in as somebody else at the identity provider, not the account this app asked for. Nothing was changed."
                    else -> error = "The $what failed: ${describe(e)}"
                }
            } catch (e: Exception) {
                error = "The $what failed: ${describe(e)}"
            }
            reload()
        }
    }

    /** Makes another cached account the active account. Its stream catches up first. */
    fun activate(key: String) {
        val m = accounts ?: return
        viewModelScope.launch {
            val name = label(accountList.firstOrNull { it.key == key })
            busy = "Switching to $name: checking the signals queued for this account…"
            try { m.activate(key) } catch (e: Exception) { error = "Could not switch to $name: ${describe(e)}" }
            busy = null
            reload()
        }
    }

    /** Signs one account out of this app and at the IdP (its session only); the others stay signed in. */
    fun signOut(key: String? = null) {
        val m = accounts ?: return
        viewModelScope.launch {
            try { m.signOut(key, authenticator) } catch (e: OIDCError) {
                if (!e.isUserCancellation) error = "Sign-out failed: ${describe(e)}"
            } catch (e: Exception) { error = "Sign-out failed: ${describe(e)}" }
            reload()
        }
    }

    fun signOutAll() {
        val m = accounts ?: return
        viewModelScope.launch {
            try { m.signOutAll(authenticator) } catch (e: OIDCError) {
                if (!e.isUserCancellation) error = "Sign-out failed: ${describe(e)}"
            } catch (e: Exception) { error = "Sign-out failed: ${describe(e)}" }
            reload()
        }
    }

    fun forget(key: String) {
        val m = accounts ?: return
        viewModelScope.launch {
            try { m.forget(key) } catch (e: Exception) { error = "Could not forget the account: ${describe(e)}" }
            reload()
        }
    }

    // MARK: - Token cache actions

    fun callUserInfo() {
        val m = accounts ?: return
        val c = client ?: return
        val me = signedIn ?: return
        viewModelScope.launch {
            userinfoOutput = try {
                c.userinfo(m.getTokenSet(), me.sub).jsonString(pretty = true)
            } catch (e: Exception) {
                "UserInfo failed: ${describe(e)}"
            }
            reload()
        }
    }

    fun forceRefresh() {
        val m = accounts ?: return
        viewModelScope.launch {
            try { m.refresh() } catch (e: Exception) { error = "Refresh failed: ${describe(e)}" }
            reload()
        }
    }

    // MARK: - CAEP: the app polls ONE stream, the active account's, authorised by its (DPoP-bound) access token.
    // A stream belongs to the principal that created it. With only ssf.read this client lists, gets and polls the
    // account's stream; ssf.manage is what creates, changes and deletes one.

    private val transmitterIssuer: String get() = config?.ssfTransmitterIssuer ?: client?.issuer ?: ""

    private var streamIDs: Map<String, String>
        get() = (try { parseJson(prefs.getString(STREAMS_KEY, "{}")!!) } catch (e: Exception) { null }).objectValue
            ?.mapNotNull { (k, v) -> v.stringValue?.let { k to it } }?.toMap() ?: emptyMap()
        set(value) { prefs.edit().putString(STREAMS_KEY, jsonObjectOf(*value.map { it.key to it.value }.toTypedArray()).jsonString()).apply() }

    /** The scopes the transmitter enforces: those in the access token, which may be narrower than requested. */
    private fun scopes(ts: TokenSet): List<String> {
        val fromToken = decodeUnverifiedJWTPayload(ts.accessToken)?.string("scope") ?: ""
        return (fromToken.ifEmpty { ts.scope ?: "" }).split(" ").filter { it.isNotEmpty() }
    }

    /** Reads the display name and username. Profile claims are at UserInfo, not always in the ID token. */
    private suspend fun rememberProfile(account: Account, access: AccountAccess) {
        val c = client ?: return
        val ts = runCatching { access.getTokenSet() }.getOrNull() ?: return
        val info = runCatching { c.userinfo(ts, account.sub) }.getOrNull() ?: JsonObject(emptyMap())
        val full = listOfNotNull(info.string("given_name"), info.string("family_name")).joinToString(" ")
        val name = listOf(full, info.string("name") ?: "", account.name ?: "").firstOrNull { it.isNotEmpty() } ?: ""
        val accessClaims = decodeUnverifiedJWTPayload(ts.accessToken) ?: JsonObject(emptyMap())
        val username = listOfNotNull(info.string("preferred_username"), accessClaims.string("username"), account.preferredUsername).firstOrNull { it.isNotEmpty() } ?: ""
        if (name.isEmpty() && username.isEmpty()) return
        prefs.edit().putString(LABELS_KEY + account.key, "$name\n$username").apply()
    }

    /** onActivate: read the account's stream and act on what it queued while dormant. */
    private suspend fun startCaep(account: Account, access: AccountAccess) {
        if (config?.caepEnabled != true) return
        val key = account.key
        caepKey = key
        receiver = null
        stream = StreamState(StreamStatus.CONNECTING, transmitterIssuer)
        try {
            val scopes = scopes(access.getTokenSet())
            if ("ssf.read" !in scopes && "ssf.manage" !in scopes) {
                note(key, StreamStatus.UNAVAILABLE, "This sign-in was not issued ssf.read, so the app is not reading a stream.")
                return
            }
            val write = "ssf.manage" in scopes
            val held = streamIDs[key]
            var r: SSFReceiver? = if (held != null) {
                val attempt = makeReceiver(account, access, held)
                try {
                    attempt.start(catchUp = true)
                    attempt
                } catch (e: Exception) {
                    attempt.stop()
                    // The remembered stream is gone. Without ssf.manage, do not create a replacement.
                    if (write) startNew(account, access) else adoptListed(account, access)
                }
            } else {
                if (write) startNew(account, access) else adoptListed(account, access)
            }
            if (r == null) {
                note(key, StreamStatus.NO_STREAM, "No stream for this account. This client reads with ssf.read and does not create one.")
                return
            }
            // A signal received while catching up ended the account, or another account was activated meanwhile.
            val status = accounts?.get(key)?.status
            if (caepKey != key || status != Account.Status.SIGNED_IN) {
                r.stop()
                return
            }
            receiver = r
            r.stream?.string("stream_id")?.let { streamIDs = streamIDs + (key to it) }
            if (write) {
                try { syncEvents(r) } catch (e: Exception) {
                    record(LogEntry(account = key, name = "subscription", action = "Could not update the stream's event types: ${describe(e)}"))
                }
                if (r.metadata?.get("add_subject_endpoint") != null) {
                    try { r.addSubject(Subject.issSub(account.iss, account.sub)) } catch (e: Exception) {
                        record(LogEntry(account = key, name = "subject", action = "Could not add the subject: ${describe(e)}"))
                    }
                }
            }
            refreshStreamState(r, write)
            if (write) viewModelScope.launch { runCatching { r.requestVerification(30.0) } }
        } catch (e: Exception) {
            // Shown on the stream card; the account is still activated so the person is not locked out by an unreachable transmitter.
            if (caepKey == key) stream = StreamState(StreamStatus.ERROR, transmitterIssuer, error = "Could not catch up: ${describe(e)}")
        }
    }

    private suspend fun startNew(account: Account, access: AccountAccess): SSFReceiver {
        val r = makeReceiver(account, access, null)
        r.start(catchUp = true)
        return r
    }

    /** Lists this account's streams and polls the first one. Does not create a stream. */
    private suspend fun adoptListed(account: Account, access: AccountAccess): SSFReceiver? {
        val probe = makeReceiver(account, access, null)
        probe.discover()
        val id = probe.listStreams().firstNotNullOfOrNull { it.string("stream_id") } ?: return null
        val r = makeReceiver(account, access, id)
        r.start(catchUp = true)
        return r
    }

    private fun refreshStreamState(r: SSFReceiver, write: Boolean) {
        val s = r.stream ?: JsonObject(emptyMap())
        val aud = s["aud"]?.let { it.stringValue ?: (it.stringArrayValue ?: emptyList()).joinToString(", ") }
        stream = StreamState(StreamStatus.CONNECTED, transmitterIssuer, streamStatus = s.string("status") ?: "enabled", streamID = s.string("stream_id"),
            audience = aud, write = write)
    }

    private fun note(key: String, status: StreamStatus, text: String) {
        if (caepKey == key) stream = StreamState(status, transmitterIssuer, note = text)
    }

    /** onDeactivate: stop polling; the stream stays at the transmitter and keeps queueing events. */
    private suspend fun stopCaep(key: String) {
        if (caepKey != key) return
        val r = receiver
        caepKey = null
        receiver = null
        stream = StreamState(if (config?.caepEnabled == true) StreamStatus.WAITING_FOR_USER else StreamStatus.DISABLED)
        r?.stop()
    }

    /** onLeave: the account is signed out or ended. Delete its stream only when the token can write. */
    private suspend fun deleteStream(account: Account, access: AccountAccess) {
        stopCaep(account.key)
        val id = streamIDs[account.key] ?: return
        if (config?.caepEnabled != true) return
        val ts = runCatching { access.getTokenSet() }.getOrNull() ?: return
        if ("ssf.manage" !in scopes(ts)) return
        streamIDs = streamIDs - account.key
        val r = makeReceiver(account, access, id)
        try {
            r.discover()
            r.stream = jsonObjectOf("stream_id" to id)
            r.deleteStream()
        } catch (e: Exception) {
            // Left at the transmitter, which removes a poll stream nobody polls (iya-sts: after a day by default).
        }
    }

    private fun makeReceiver(account: Account, access: AccountAccess, streamID: String?): SSFReceiver {
        val c = client!!
        val r = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer = transmitterIssuer,
            // Every management and poll call carries THIS account's access token, with a DPoP proof when bound.
            authorization = SSFAuthorization.oidc(c) { access.getTokenSet() },
            eventsRequested = CAEP.all.filter { it in selectedEvents },
            streamID = streamID,
            description = "android-oidc-caep-native-app demo (${label(account)})",
            pollInterval = 5.0,
            transport = transport ?: c.options.transport,
        ))
        installHandlers(r, account.key, access)
        return r
    }

    /** Asks the transmitter for the selected event types when the stream asks for others. Needs ssf.manage. */
    private suspend fun syncEvents(r: SSFReceiver) {
        val want = CAEP.all.filter { it in selectedEvents }
        val have = r.stream?.get("events_requested").stringArrayValue ?: emptyList()
        if (want.toSet() == have.toSet()) return
        r.updateStream(jsonObjectOf("events_requested" to want))
    }

    // MARK: - CAEP buttons

    fun toggleEvent(type: String, on: Boolean) {
        selectedEvents = if (on) selectedEvents + type else selectedEvents - type
    }

    fun updateSubscription() {
        prefs.edit().putStringSet(EVENTS_KEY, selectedEvents).apply()
        val r = receiver ?: return
        viewModelScope.launch {
            try {
                syncEvents(r)
                refreshStreamState(r, stream.write)
            } catch (e: Exception) {
                stream = stream.copy(error = "Could not update the subscription: ${describe(e)}")
            }
        }
    }

    fun requestVerification() {
        val r = receiver ?: return
        viewModelScope.launch {
            try {
                r.requestVerification(30.0)
                stream = stream.copy(error = null)
            } catch (e: Exception) {
                stream = stream.copy(error = "Verification failed: ${describe(e)}")
            }
        }
    }

    fun reconnect() {
        val m = accounts ?: return
        val key = caepKey ?: signedIn?.key ?: return
        viewModelScope.launch {
            stopCaep(key)
            // Re-running the activation reconnects the stream (and catches up).
            try { m.activate(key) } catch (e: Exception) { error = "Could not reconnect: ${describe(e)}" }
            reload()
        }
    }

    // MARK: - Event policies: only events about this account (or its stream) are acted on.

    private fun installHandlers(r: SSFReceiver, key: String, access: AccountAccess) {
        r.onSessionRevoked { evt ->
            handle(key, evt) {
                end(key, evt.reasonUser?.get("en") ?: "The session was revoked by the identity provider.")
                "Session ended; its cached tokens discarded. Other accounts are unaffected."
            }
        }.onTokenClaimsChange { evt ->
            handle(key, evt) {
                access.getTokenSet(forceRefresh = true)
                val claims = evt.payload["claims"].objectValue?.keys?.sorted()?.joinToString(", ") ?: ""
                "Refreshed tokens for new claims (${claims.ifEmpty { "unspecified" }})."
            }
        }.onCredentialChange { evt ->
            handle(key, evt) {
                val type = evt.payload.string("credential_type") ?: "credential"
                val change = evt.payload.string("change_type")
                if (change == "revoke" || change == "delete") {
                    end(key, "The $type was ${change}d; sign in again.")
                    "Credential ${change}d: session ended."
                } else {
                    updateState(key) { it.copy(notices = listOf(Notice(Notice.Level.INFO, "The $type was ${change?.let { c -> "${c}d" } ?: "changed"} at the identity provider.")) + it.notices) }
                    "User notified; session kept."
                }
            }
        }.onAssuranceLevelChange { evt ->
            handle(key, evt) {
                val current = evt.payload.string("current_level") ?: "?"
                val previous = evt.payload.string("previous_level") ?: "?"
                val down = evt.payload.string("change_direction") == "decrease"
                updateState(key) { it.copy(stepUp = if (down) "Assurance dropped from $previous to $current." else null) }
                if (down) "Step-up authentication required." else "Step-up requirement cleared."
            }
        }.onDeviceComplianceChange { evt ->
            handle(key, evt) {
                if (evt.payload.string("current_status") != "not-compliant") return@handle "Device compliant: no action."
                end(key, "The device is no longer compliant with security policy.")
                "Device not compliant: session ended."
            }
        }.onRiskLevelChange { evt ->
            handle(key, evt) {
                val level = evt.payload.string("current_level") ?: "?"
                val why = evt.payload.string("risk_reason") ?: "no reason given"
                if (level == "HIGH") {
                    end(key, "High risk detected ($why).")
                    return@handle "Risk HIGH: session ended."
                }
                updateState(key) { it.copy(stepUp = if (level == "MEDIUM") "Risk raised to MEDIUM ($why)." else null) }
                "Risk $level: ${if (level == "MEDIUM") "step-up required" else "step-up cleared"}."
            }
        }.onSessionEstablished { evt ->
            handle(key, evt) { "Informational: new session at the IdP (acr=${evt.payload.string("acr") ?: "n/a"})." }
        }.onSessionPresented { evt ->
            handle(key, evt) { "Informational: session presented to another service." }
        }.onVerification { evt ->
            handle(key, evt) { "Stream verified (state=${evt.payload.string("state") ?: "none"})." }
        }.onStreamUpdated { evt ->
            handle(key, evt) {
                if (caepKey == key) stream = stream.copy(streamStatus = evt.payload.string("status"))
                "Transmitter set the stream to \"${evt.payload.string("status") ?: "?"}\"."
            }
        }.onUnhandledEvent { evt ->
            handle(key, evt) { "No handler for ${evt.type}." }
        }.onError { err, ctx ->
            if (ctx.phase != SSFErrorContext.Phase.POLL) return@onError
            viewModelScope.launch {
                if (caepKey == key) stream = stream.copy(error = "Last poll failed at ${java.time.LocalTime.now().withNano(0)}: ${describe(err)}")
            }
        }
    }

    /** Runs one event's policy when the event is about this account (or its stream), and logs what was done. */
    private suspend fun handle(key: String, evt: SecurityEvent, policy: suspend () -> String) = withContext(Dispatchers.Main) {
        // Poll delivery is at-least-once.
        if (log.any { it.jti == evt.jti && it.account == key }) return@withContext
        val identity = accounts?.identity(key)
        val mine = subjectMatches(evt.subject, identity)
        val streamID = if (caepKey == key) stream.streamID ?: streamIDs[key] else null
        val aboutStream = evt.subject == null || (evt.subject?.string("format") == "opaque" && evt.subject?.string("id") == streamID)
        var action = try {
            if (mine || aboutStream) policy() else "Not about this account (or another of its sessions); ignored."
        } catch (e: Exception) {
            "Handler failed: ${describe(e)}"
        }
        if (accounts?.activeKey() != key) action += " (caught up on activation)"
        record(LogEntry(account = key, name = evt.name, type = evt.type, jti = evt.jti, subject = evt.subject?.jsonString(pretty = true),
            payload = evt.payload.jsonString(pretty = true), action = action))
        reload()
    }

    private suspend fun end(key: String, reason: String) {
        accounts?.end(key, reason)
    }

    // MARK: - Event log

    /** The active account's entries, newest first. */
    val activeLog: List<LogEntry> get() = log.filter { it.account == active?.key }

    private fun record(entry: LogEntry) {
        log.add(0, entry)
        while (log.size > 300) log.removeAt(log.size - 1)
        saveLog()
    }

    fun clearLog(key: String? = null) {
        val k = key ?: active?.key
        log.removeAll { it.account == k }
        saveLog()
    }

    private fun saveLog() = prefs.edit().putString(LOG_KEY, JsonArray(log.map { it.toJson() }).jsonString()).apply()

    private fun loadLog() {
        val saved = prefs.getString(LOG_KEY, null) ?: return
        (try { parseJson(saved) } catch (e: Exception) { null } as? JsonArray)?.mapNotNull { it.objectValue?.let(LogEntry::fromJson) }?.let { log.addAll(it) }
    }

    // MARK: - Labels

    /** `Display name (username)`, from UserInfo when it was read; the ID token's subject is not a name. */
    fun label(a: Account?): String {
        if (a == null) return "—"
        val saved = prefs.getString(LABELS_KEY + a.key, null)?.split("\n") ?: emptyList()
        val display = (saved.getOrNull(0)?.ifEmpty { null } ?: a.name ?: "").trim()
        val username = (saved.getOrNull(1)?.ifEmpty { null } ?: a.preferredUsername ?: "").trim()
        if (display.isNotEmpty() && username.isNotEmpty() && display != username) return "$display ($username)"
        return listOf(display, username, a.email ?: "", a.sub).firstOrNull { it.isNotEmpty() } ?: "—"
    }

    fun describe(error: Throwable): String {
        val e = error as? OIDCError ?: return error.message ?: error.toString()
        var text = e.message
        e.status?.let { if (!text.contains(it.toString())) text += " (HTTP $it)" }
        (e.response as? JsonObject)?.jsonString()?.let { if (!text.contains(it)) text += " $it" }
        return text.take(600)
    }

    override fun onCleared() {
        subscription?.cancel()
        super.onCleared()
    }

    private companion object {
        const val STREAMS_KEY = "stream-ids"
        const val EVENTS_KEY = "caep-events"
        const val LABELS_KEY = "label:"
        const val LOG_KEY = "event-log"
    }
}
