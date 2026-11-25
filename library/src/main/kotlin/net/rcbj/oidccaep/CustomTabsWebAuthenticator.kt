// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.util.UUID

/**
 * [WebAuthenticator] with a Custom Tab: the provider's pages open in the person's browser (sharing its sign-in
 * session, as RFC 8252 asks), and the sign-in ends when the browser is redirected to the app's redirect URI.
 *
 * The redirect URI is a private-use scheme (`com.example.app:/callback`, RFC 8252 §7.1). The app declares the scheme
 * in its `build.gradle.kts` (the library's manifest registers [RedirectUriReceiverActivity] for it):
 *
 * ```kotlin
 * android { defaultConfig { manifestPlaceholders["oidcRedirectScheme"] = "com.example.app" } }
 * ```
 *
 * The flow is AppAuth's: [AuthorizationManagementActivity] opens the Custom Tab in the app's task; the redirect
 * arrives at [RedirectUriReceiverActivity], which hands it back with `CLEAR_TOP`, closing the tab; a return to the
 * app without a redirect (the person closed the tab) is a cancellation.
 *
 * @param prefersEphemeralWebBrowserSession ask the browser not to share cookies with this sign-in (Custom Tabs
 *   ephemeral browsing, where the browser supports it). Off by default: sharing the browser's session is what lets
 *   several accounts, single sign-on and `prompt=none` work.
 */
public class CustomTabsWebAuthenticator(
    context: Context,
    public val prefersEphemeralWebBrowserSession: Boolean = false,
) : WebAuthenticator {
    private val appContext = context.applicationContext
    private val launcher: Context = context

    override suspend fun authenticate(url: URI, callback: URI): URI {
        val scheme = callback.scheme?.lowercase() ?: throw OIDCError.usage("The redirect URI has no scheme: $callback")
        if (scheme == "http" || scheme == "https") {
            throw OIDCError.usage("A Custom Tab returns to the app through a private-use scheme such as com.example.app:/callback; for a loopback redirect use LoopbackWebAuthenticator")
        }
        val id = UUID.randomUUID().toString()
        val pending = PendingAuthorization(callback, CompletableDeferred())
        PendingAuthorizations.put(id, pending)
        try {
            withContext(Dispatchers.Main) {
                val intent = Intent(appContext, AuthorizationManagementActivity::class.java)
                    .putExtra(AuthorizationManagementActivity.EXTRA_ID, id)
                    .putExtra(AuthorizationManagementActivity.EXTRA_URL, url.toString())
                    .putExtra(AuthorizationManagementActivity.EXTRA_EPHEMERAL, prefersEphemeralWebBrowserSession)
                if (launcher !is Activity) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                launcher.startActivity(intent)
            }
            return pending.result.await()
        } finally {
            PendingAuthorizations.remove(id)
        }
    }
}

internal class PendingAuthorization(val callback: URI, val result: CompletableDeferred<URI>)

/** The sign-ins waiting for their redirect, in this process. */
internal object PendingAuthorizations {
    private val pending = HashMap<String, PendingAuthorization>()
    fun put(id: String, p: PendingAuthorization) = synchronized(pending) { pending[id] = p }
    fun get(id: String): PendingAuthorization? = synchronized(pending) { pending[id] }
    fun remove(id: String) = synchronized(pending) { pending.remove(id) }
    /** The sign-in a redirect belongs to: the one whose callback it matches (scheme and path), latest first. */
    fun matching(uri: Uri): Pair<String, PendingAuthorization>? = synchronized(pending) {
        pending.entries.lastOrNull { (_, p) ->
            p.callback.scheme.equals(uri.scheme, ignoreCase = true) && (p.callback.rawPath ?: p.callback.rawSchemeSpecificPart.substringBefore('?')) ==
                (uri.encodedPath ?: uri.encodedSchemeSpecificPart.substringBefore('?'))
        }?.toPair()
    }
}

/**
 * Opens the Custom Tab, and receives its result. Not for apps to start: [CustomTabsWebAuthenticator] does.
 */
public class AuthorizationManagementActivity : Activity() {
    private var started = false
    private var id: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        id = (savedInstanceState ?: intent.extras)?.getString(EXTRA_ID)
        started = savedInstanceState?.getBoolean(STATE_STARTED) ?: false
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(EXTRA_ID, id)
        outState.putBoolean(STATE_STARTED, started)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        val id = id
        val pending = id?.let { PendingAuthorizations.get(it) }
        if (pending == null || pending.result.isCompleted) {
            // The process was restarted while the browser was open, or the request was cancelled: nobody is waiting.
            finish()
            return
        }
        if (!started) {
            started = true
            val url = intent.getStringExtra(EXTRA_URL) ?: return fail(pending, "No authorization URL")
            val tab = CustomTabsIntent.Builder().setShowTitle(true)
                .apply { if (intent.getBooleanExtra(EXTRA_EPHEMERAL, false)) setEphemeralBrowsingEnabled(true) }
                .build()
            try {
                tab.launchUrl(this, Uri.parse(url))
            } catch (e: ActivityNotFoundException) {
                fail(pending, "No browser is installed to sign in with")
            }
            return
        }
        val data = intent.data
        if (data != null) {
            pending.result.complete(URI(data.toString()))
        } else {
            pending.result.completeExceptionally(OIDCError(OIDCError.Kind.GENERAL, "The sign-in window was closed", code = OIDCError.USER_CANCELLED_CODE))
        }
        finish()
    }

    private fun fail(pending: PendingAuthorization, message: String) {
        pending.result.completeExceptionally(OIDCError(OIDCError.Kind.GENERAL, "The browser sign-in failed: $message", code = "web_authentication_failed"))
        finish()
    }

    internal companion object {
        const val EXTRA_ID = "net.rcbj.oidccaep.ID"
        const val EXTRA_URL = "net.rcbj.oidccaep.URL"
        const val EXTRA_EPHEMERAL = "net.rcbj.oidccaep.EPHEMERAL"
        const val STATE_STARTED = "net.rcbj.oidccaep.STARTED"
    }
}

/**
 * Receives the redirect to the app's private-use scheme and hands it to the waiting sign-in, closing the Custom Tab.
 * Registered by the library's manifest for `${oidcRedirectScheme}`.
 */
public class RedirectUriReceiverActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent.data
        val match = data?.let { PendingAuthorizations.matching(it) }
        if (data != null && match != null) {
            startActivity(Intent(this, AuthorizationManagementActivity::class.java)
                .setData(data)
                .putExtra(AuthorizationManagementActivity.EXTRA_ID, match.first)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        } else {
            // A stray redirect (nothing is waiting for it): bring the app forward and drop it.
            packageManager.getLaunchIntentForPackage(packageName)?.let { startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        }
        finish()
    }
}
