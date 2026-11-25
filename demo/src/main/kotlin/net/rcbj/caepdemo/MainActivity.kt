// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.caepdemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import net.rcbj.oidccaep.Account
import net.rcbj.oidccaep.Base64URL
import net.rcbj.oidccaep.CAEP
import net.rcbj.oidccaep.TokenSet
import net.rcbj.oidccaep.decodeUnverifiedJWTPayload
import net.rcbj.oidccaep.doubleValue
import net.rcbj.oidccaep.eventName
import net.rcbj.oidccaep.jsonString
import net.rcbj.oidccaep.parseJson
import net.rcbj.oidccaep.stringValue
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class MainActivity : ComponentActivity() {
    private val model: DemoModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            MaterialTheme(colorScheme = if (android.os.Build.VERSION.SDK_INT >= 31) dynamicLightColorScheme(context) else lightColorScheme()) {
                DemoApp(model)
            }
        }
    }
}

private val green = Color(0xFF2E7D32)
private val orange = Color(0xFFEF6C00)
private val red = Color(0xFFC62828)
private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
private val dateTimeFormat = DateTimeFormatter.ofPattern("d MMM yyyy HH:mm:ss").withZone(ZoneId.systemDefault())

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DemoApp(model: DemoModel) {
    var tab by rememberSaveable { mutableStateOf(0) }
    Scaffold(topBar = {
        TopAppBar(
            title = {
                Column {
                    Text("◆ CAEP Demo", fontWeight = FontWeight.SemiBold)
                    Text("net.rcbj.oidccaep · native public client", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            actions = { AccountMenu(model) },
        )
    }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Identity") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("CAEP events") })
            }
            Column(Modifier.verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Banners(model)
                if (tab == 0) IdentityTab(model) else CaepTab(model)
                Spacer(Modifier.padding(24.dp))
            }
        }
    }
    model.attention?.let { (key, text) ->
        AlertDialog(onDismissRequest = { model.attention = null },
            title = { Text("Sign in again?") }, text = { Text(text) },
            confirmButton = { TextButton(onClick = { model.attention = null; model.reauthenticate(key) }) { Text("Sign in again") } },
            dismissButton = { TextButton(onClick = { model.attention = null }) { Text("Not now") } })
    }
}

@Composable
private fun AccountMenu(model: DemoModel) {
    var open by remember { mutableStateOf(false) }
    val current = model.active
    if (model.client == null) return
    if (model.accountList.isEmpty()) {
        Button(onClick = { model.signIn() }, Modifier.padding(end = 8.dp)) { Text("Sign in") }
        return
    }
    Box {
        TextButton(onClick = { open = true }) { Text(if (current != null) model.label(current) else "Accounts") }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            val choices = model.accountList.filter { it.key != current?.key }
            Text("Switch account", Modifier.padding(horizontal = 16.dp, vertical = 6.dp), style = MaterialTheme.typography.labelMedium)
            if (choices.isEmpty()) Text("No other account yet.", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall)
            for (a in choices) {
                DropdownMenuItem(text = { Text("${model.label(a)}  ·  ${statusText(a.status)}") }, onClick = {
                    open = false
                    when (a.status) {
                        Account.Status.SIGNED_IN -> model.activate(a.key)
                        Account.Status.TOKENS_MISSING -> model.resume(a.key)
                        else -> model.reauthenticate(a.key)
                    }
                })
            }
            HorizontalDivider()
            DropdownMenuItem(text = { Text("Sign in with another account") }, onClick = { open = false; model.addAccount() })
            if (current?.status == Account.Status.SIGNED_IN) {
                DropdownMenuItem(text = { Text("Sign out ${model.label(current)}") }, onClick = { open = false; model.signOut() })
            }
            if (current != null && current.status != Account.Status.SIGNED_IN) {
                DropdownMenuItem(text = { Text("Forget ${model.label(current)}") }, onClick = { open = false; model.forget(current.key) })
            }
            DropdownMenuItem(text = { Text("Sign out of all accounts") }, onClick = { open = false; model.signOutAll() })
        }
    }
}

private fun statusText(s: Account.Status) = when (s) {
    Account.Status.SIGNED_IN -> "signed in"
    Account.Status.TOKENS_MISSING -> "tokens expired"
    Account.Status.SIGNED_OUT -> "signed out"
    Account.Status.ENDED -> "session ended"
}

@Composable
private fun Banners(model: DemoModel) {
    model.error?.let { Banner(it, red) { model.error = null } }
    model.busy?.let { Banner(it, MaterialTheme.colorScheme.primary, null) }
    model.notices.take(3).forEach { n -> Banner(n.text, if (n.level == Notice.Level.DANGER) red else green) { model.notices.remove(n) } }
    model.signedIn?.let { me ->
        model.state(me.key).notices.take(3).forEach { n -> Banner(n.text, MaterialTheme.colorScheme.primary, null) }
    }
}

@Composable
private fun Banner(text: String, color: Color, onDismiss: (() -> Unit)?) {
    Surface(color = color.copy(alpha = 0.10f), shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f), color = color, style = MaterialTheme.typography.bodyMedium)
            if (onDismiss != null) TextButton(onClick = onDismiss) { Text("Dismiss") }
        }
    }
}

@Composable
private fun DemoCard(title: String, trailing: (@Composable () -> Unit)? = null, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                trailing?.invoke()
            }
            content()
        }
    }
}

@Composable
private fun Pill(text: String, color: Color) {
    Surface(color = color.copy(alpha = 0.15f), shape = RoundedCornerShape(50)) {
        Text(text, Modifier.padding(horizontal = 10.dp, vertical = 3.dp), color = color, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun KeyValues(rows: List<Pair<String, String>>) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        for ((k, v) in rows) {
            Row {
                Text(k, Modifier.width(130.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                SelectionContainer { Text(v, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
            }
        }
    }
}

@Composable
private fun Mono(text: String) {
    SelectionContainer {
        Text(text, Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(6.dp)).horizontalScroll(rememberScrollState()).padding(8.dp),
            fontFamily = FontFamily.Monospace, fontSize = 11.sp)
    }
}

// MARK: - Identity tab

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun IdentityTab(model: DemoModel) {
    val cur = model.active
    DemoCard("OpenID Connect") {
        Text(heroTitle(model, cur), style = MaterialTheme.typography.headlineSmall)
        Text(heroText(model, cur), color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (model.client != null) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when (cur?.status) {
                    Account.Status.TOKENS_MISSING -> Button(onClick = { model.resume(cur.key) }) { Text("Continue as ${model.label(cur)}") }
                    Account.Status.ENDED, Account.Status.SIGNED_OUT -> Button(onClick = { model.reauthenticate(cur.key) }) { Text("Sign in again as ${model.label(cur)}") }
                    null -> Button(onClick = { model.signIn() }) { Text("Sign in") }
                    else -> {}
                }
                if (cur != null) OutlinedButton(onClick = { model.addAccount() }) { Text("Sign in with another account") }
            }
        }
    }
    SessionCard(model)
    TokenCacheCard(model)
    TokensCard(model)
    SecurityCard(model)
    if (model.configSource.isNotEmpty()) {
        Text("Configuration: ${model.configSource}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun heroTitle(model: DemoModel, cur: Account?): String = when {
    model.client == null -> if (model.error == null) "Connecting…" else "Not connected"
    cur == null -> "Not signed in"
    else -> when (cur.status) {
        Account.Status.SIGNED_IN -> "Signed in as ${model.label(cur)}"
        Account.Status.TOKENS_MISSING -> "${model.label(cur)}'s tokens have expired"
        Account.Status.ENDED -> "${model.label(cur)}'s session was ended"
        Account.Status.SIGNED_OUT -> "${model.label(cur)} is signed out"
    }
}

private fun heroText(model: DemoModel, cur: Account?): String {
    if (model.client == null) return if (model.error == null) "Loading the OIDC configuration." else "The identity provider could not be reached."
    if (cur == null) {
        if (model.accountList.any { it.status == Account.Status.SIGNED_IN }) return "These accounts are signed in. Pick one from the menu at the top. No password is needed."
        if (model.accountList.isNotEmpty()) return "None of the accounts is signed in. Sign in again as one of them from the menu, or sign in with another account."
        return "Sign in through your identity provider, in your browser. This app keeps the session and the tokens. CAEP events are on the other tab."
    }
    return when (cur.status) {
        Account.Status.SIGNED_IN -> "The session, token cache, and tokens for this account are below."
        Account.Status.TOKENS_MISSING -> "The tokens cached for this account have expired and cannot be refreshed. New ones can be fetched without a password while its session at the identity provider lasts."
        Account.Status.ENDED, Account.Status.SIGNED_OUT -> {
            val reason = if (cur.status == Account.Status.ENDED) cur.endedReason?.let { "$it " } ?: "" else ""
            "${reason}Sign in again as ${model.label(cur)}, switch to another account, or sign in with another account."
        }
    }
}

@Composable
private fun SessionCard(model: DemoModel) {
    val me = model.signedIn
    val stepUp = me?.let { model.state(it.key).stepUp }
    DemoCard(me?.let { "Session · ${model.label(it)}" } ?: "Session", trailing = {
        Pill(if (me == null) "Signed out" else if (stepUp != null) "Step-up required" else "Active",
            if (me == null) Color.Gray else if (stepUp != null) orange else green)
    }) {
        if (me == null) {
            Text("No one is signed in.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@DemoCard
        }
        stepUp?.let { Text(it, color = orange) }
        val claims = model.currentTokens?.claims ?: me.claims
        val shown = listOf("sub", "name", "email", "preferred_username", "acr", "amr", "sid", "iss", "auth_time")
        KeyValues(shown.mapNotNull { k ->
            val v = claims[k] ?: return@mapNotNull null
            if (k == "auth_time") v.doubleValue?.let { return@mapNotNull k to dateTimeFormat.format(Instant.ofEpochSecond(it.toLong())) }
            k to (v.stringValue ?: v.jsonString())
        })
    }
}

@Composable
private fun TokenCacheCard(model: DemoModel) {
    val me = model.signedIn
    val s = me?.let { model.state(it.key) }
    var now by remember { mutableLongStateOf(Instant.now().epochSecond) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = Instant.now().epochSecond
        }
    }
    DemoCard("Token cache", trailing = { if (s != null) Text("${s.refreshCount} refreshes", style = MaterialTheme.typography.bodySmall) }) {
        val ts = model.currentTokens
        val fraction = fraction(ts, now)
        LinearProgressIndicator(progress = { fraction.toFloat() }, modifier = Modifier.fillMaxWidth(), color = if (fraction < 0.2) orange else MaterialTheme.colorScheme.primary)
        Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
            Stat(ts?.expiresAt?.let { duration(maxOf(0, it - now)) } ?: "—", "access token\nexpires in")
            Stat(autoRefresh(ts, now), "auto-refresh\nin")
            Stat(s?.lastRefresh?.let { timeFormat.format(it) } ?: "—", "last\nrefresh")
        }
        Text("Cache: ${model.tokenStoreDescription}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { model.callUserInfo() }, enabled = me != null) { Text("Call UserInfo") }
            OutlinedButton(onClick = { model.forceRefresh() }, enabled = me != null) { Text("Force refresh") }
        }
        model.userinfoOutput?.let { Mono(it) }
    }
}

private fun fraction(ts: TokenSet?, now: Long): Double {
    val exp = ts?.expiresAt ?: return 0.0
    val iat = ts.issuedAt ?: return 0.0
    if (exp <= iat) return 0.0
    return ((exp - now).toDouble() / (exp - iat)).coerceIn(0.0, 1.0)
}

private fun autoRefresh(ts: TokenSet?, now: Long): String {
    val exp = ts?.expiresAt ?: return "—"
    if (ts.refreshToken == null) return "—"
    return duration(maxOf(0, (exp - ts.effectiveSkew(60.0) - now).toLong()))
}

private fun duration(seconds: Long) = if (seconds >= 60) "${seconds / 60}m ${seconds % 60}s" else "${seconds}s"

@Composable
private fun Stat(value: String, caption: String) {
    Column {
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Text(caption, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun TokensCard(model: DemoModel) {
    var which by rememberSaveable { mutableStateOf(0) }
    var decoded by rememberSaveable { mutableStateOf(true) }
    DemoCard("Tokens") {
        SingleChoiceSegmentedButtonRow {
            listOf("At sign-in", "Current").forEachIndexed { i, label ->
                SegmentedButton(selected = which == i, onClick = { which = i }, shape = SegmentedButtonDefaults.itemShape(i, 2)) { Text(label) }
            }
        }
        val ts = if (which == 1) model.currentTokens else model.signInTokens?.takeIf { it.first == model.signedIn?.key }?.second
        if (ts == null) {
            Text(if (which == 0) "Shown right after a sign-in in this session." else "No one is signed in.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@DemoCard
        }
        KeyValues(listOfNotNull("token_type" to ts.tokenType, ts.scope?.let { "scope" to it }, ts.expiresAt?.let { "expires_at" to dateTimeFormat.format(Instant.ofEpochSecond(it)) },
            "refresh_token" to if (ts.refreshToken != null) "present (${ts.refreshToken!!.length} chars)" else "none"))
        SingleChoiceSegmentedButtonRow {
            listOf("Decoded JWT", "Encoded").forEachIndexed { i, label ->
                SegmentedButton(selected = decoded == (i == 0), onClick = { decoded = i == 0 }, shape = SegmentedButtonDefaults.itemShape(i, 2)) { Text(label) }
            }
        }
        for ((name, token) in listOf("ID token" to ts.idToken, "Access token" to ts.accessToken)) {
            token ?: continue
            Text(name, style = MaterialTheme.typography.labelLarge)
            if (!decoded || token.count { it == '.' } != 2) {
                Mono(token)
            } else {
                val header = token.substringBefore('.').let { Base64URL.decode(it) }?.let { runCatching { parseJson(it).jsonString(pretty = true) }.getOrNull() } ?: "—"
                Text("Header", style = MaterialTheme.typography.labelSmall)
                Mono(header)
                Text("Payload", style = MaterialTheme.typography.labelSmall)
                Mono(decodeUnverifiedJWTPayload(token)?.jsonString(pretty = true) ?: "—")
            }
        }
        Text("Decoded for display. The library validated the ID token's signature and claims when it was issued.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SecurityCard(model: DemoModel) {
    DemoCard("Protections in effect") {
        val client = model.client
        if (client == null) {
            Text("The identity provider has not been reached yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@DemoCard
        }
        val f = client.securityFeatures
        val items = listOf(
            "Public client" to "no client secret; token_endpoint_auth_method none",
            "System browser" to "sign-in in a Custom Tab (RFC 8252); the app never sees the password",
            "Redirect URI" to "private-use scheme ${model.config?.redirectURI?.scheme ?: ""}",
            "PKCE" to f.pkce,
            "state" to f.state,
            "nonce" to "random, checked against the ID token",
            "Issuer identification" to f.issuerIdentification,
            "Pushed Authorization Requests" to if (f.par) "on: the request never passes through the browser URL" else "off",
            "DPoP" to (f.dpop?.let { "on (${it.alg}, ${model.dpopStoreDescription}, jkt ${it.jkt.take(12)}…)" } ?: "off: bearer tokens"),
            "ID token" to f.idToken,
            "TLS" to if (f.tlsEnforced) "required for the IdP (loopback excepted)" else "not enforced",
            "Token cache" to "${model.tokenStoreDescription}, refreshed before expiry",
            "One active account" to "only its tokens are reachable, refreshed and used to poll; the others stay dormant until activated, and their queued signals are acted on first",
            "Several accounts" to "a sign-in naming an account refuses anybody else; sign-out names the account's ID token so only its IdP session ends",
            "Resource indicators" to if (f.resourceIndicators.isEmpty()) "none" else f.resourceIndicators.joinToString(", "),
        )
        for ((k, v) in items) {
            Row {
                Text("✓ ", color = green)
                Column {
                    Text(k, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                    Text(v, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

// MARK: - CAEP tab

@Composable
private fun CaepTab(model: DemoModel) {
    val st = model.stream
    val me = model.signedIn
    DemoCard("Shared Signals stream", trailing = {
        Pill(when (st.status) {
            StreamStatus.DISABLED -> "CAEP off"
            StreamStatus.WAITING_FOR_USER -> "Waiting for sign-in"
            StreamStatus.CONNECTING -> "Connecting…"
            StreamStatus.CONNECTED -> "Polling"
            StreamStatus.UNAVAILABLE -> "Not authorized"
            StreamStatus.NO_STREAM -> "No stream"
            StreamStatus.ERROR -> "Error"
        }, when (st.status) {
            StreamStatus.CONNECTED -> green
            StreamStatus.ERROR -> red
            StreamStatus.CONNECTING -> orange
            else -> Color.Gray
        })
    }) {
        KeyValues(listOfNotNull(st.transmitter?.let { "transmitter" to it }, st.streamID?.let { "stream_id" to it }, st.streamStatus?.let { "status" to it },
            st.audience?.let { "aud" to it }, "delivery" to "poll (RFC 8936), every 5 s", "access" to if (st.write) "ssf.manage (read and write)" else "ssf.read"))
        st.note?.let { Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        st.error?.let { Text(it, color = red, style = MaterialTheme.typography.bodySmall) }
        Text("Event types this stream asks for", style = MaterialTheme.typography.labelLarge)
        for (type in CAEP.all) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = type in model.selectedEvents, onCheckedChange = { model.toggleEvent(type, it) })
                Text(eventName(type), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { model.updateSubscription() }, enabled = st.write) { Text("Update") }
            OutlinedButton(onClick = { model.requestVerification() }, enabled = st.status == StreamStatus.CONNECTED && st.write) { Text("Verify") }
            OutlinedButton(onClick = { model.reconnect() }, enabled = me != null) { Text("Reconnect") }
        }
    }
    DemoCard("Events · ${model.label(model.active)}", trailing = { TextButton(onClick = { model.clearLog() }) { Text("Clear") } }) {
        val entries = model.activeLog
        if (entries.isEmpty()) {
            Text("No CAEP events yet. Sign in, then trigger an event at your identity provider (for example, revoke your session).",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        for (e in entries) EventRow(e)
    }
}

@Composable
private fun EventRow(e: LogEntry) {
    var open by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider()
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(vertical = 6.dp)) {
                Text(e.name, fontWeight = FontWeight.SemiBold)
                Text(e.action, style = MaterialTheme.typography.bodySmall)
                Text("${timeFormat.format(e.at)}${e.jti?.let { " · jti $it" } ?: ""}", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (e.payload != null) TextButton(onClick = { open = !open }) { Text(if (open) "Hide" else "Details") }
        }
        if (open) {
            e.subject?.let { Text("Subject", style = MaterialTheme.typography.labelSmall); Mono(it) }
            e.payload?.let { Text("Payload", style = MaterialTheme.typography.labelSmall); Mono(it) }
        }
    }
}

