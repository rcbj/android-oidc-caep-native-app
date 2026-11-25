// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import java.net.URI

/**
 * Shows the provider's pages in the system browser and returns the redirect URL it ends at.
 *
 * RFC 8252 §8.12: a native app signs people in through an external user agent (the system browser), never an
 * embedded web view, so the app never sees the password and the person's browser session is shared. On Android,
 * [CustomTabsWebAuthenticator] does this with a Custom Tab.
 */
public fun interface WebAuthenticator {
    /** Opens [url] and returns the URL the browser is redirected to on [callback]. */
    public suspend fun authenticate(url: URI, callback: URI): URI
}

/** Signs a person in through the system browser: creates the request, shows it, and completes the sign-in from the redirect. */
public suspend fun OIDCClient.authorize(authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): AuthorizationResult {
    val request = createAuthorizationRequest(opts)
    val redirect = opts.redirectURI ?: options.redirectURI ?: throw OIDCError.usage("redirectURI is required")
    return completeAuthorization(authenticator.authenticate(request.url, redirect))
}

/**
 * RP-Initiated Logout through the system browser, checking the `state` it returns with. Returns false, without
 * opening the browser, when there is nothing to complete: the provider has no end_session_endpoint, or the request
 * has no post-logout redirect URI.
 */
public suspend fun OIDCClient.endSession(authenticator: WebAuthenticator, request: EndSessionRequest?): Boolean {
    if (request == null) return false
    val redirect = OIDCClient.responseParameters(request.url).get("post_logout_redirect_uri")?.let(::parseURI) ?: return false
    completeEndSession(authenticator.authenticate(request.url, redirect))
    return true
}

private suspend fun AccountManager.run(authenticator: WebAuthenticator, opts: AuthorizationRequestOptions, request: AuthorizationRequest): SignInResult {
    val redirect = opts.redirectURI ?: client.options.redirectURI ?: throw OIDCError.usage("redirectURI is required")
    return handleCallback(authenticator.authenticate(request.url, redirect))
}

/** [AccountManager.signIn] through the system browser, then [AccountManager.handleCallback]. */
public suspend fun AccountManager.signIn(authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): SignInResult =
    run(authenticator, opts, signIn(opts))

/** [AccountManager.chooseAccount] through the system browser. */
public suspend fun AccountManager.chooseAccount(authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): SignInResult =
    run(authenticator, opts, chooseAccount(opts))

/** [AccountManager.addAccount] through the system browser. */
public suspend fun AccountManager.addAccount(authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): SignInResult =
    run(authenticator, opts, addAccount(opts))

/** [AccountManager.resume] through the system browser. */
public suspend fun AccountManager.resume(key: String, authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): SignInResult =
    run(authenticator, opts, resume(key, opts))

/** [AccountManager.reauthenticate] through the system browser. */
public suspend fun AccountManager.reauthenticate(key: String, authenticator: WebAuthenticator, opts: AuthorizationRequestOptions = AuthorizationRequestOptions()): SignInResult =
    run(authenticator, opts, reauthenticate(key, opts))

/** [AccountManager.signOut], then the provider's logout in the system browser. The account is signed out of the app even if the browser step is cancelled. */
public suspend fun AccountManager.signOut(key: String? = null, authenticator: WebAuthenticator, revoke: Boolean = true) {
    client.endSession(authenticator, signOut(key, revoke, endSession = true))
}

/** [AccountManager.signOutAll], then the provider's logout in the system browser. */
public suspend fun AccountManager.signOutAll(authenticator: WebAuthenticator, revoke: Boolean = true) {
    client.endSession(authenticator, signOutAll(revoke, endSession = true))
}
