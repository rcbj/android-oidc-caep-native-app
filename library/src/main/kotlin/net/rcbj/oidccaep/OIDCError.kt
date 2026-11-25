// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.serialization.json.JsonElement

/**
 * Every error this library throws.
 *
 * [kind] says which family it belongs to, and [code] is a stable, machine-readable reason
 * (`state_mismatch`, `invalid_id_token`, `dpop_downgrade`, an OAuth `error` …). Match on those, not on the message.
 */
public class OIDCError(
    public var kind: Kind = Kind.GENERAL,
    message: String,
    public val code: String? = null,
    /** The HTTP status, when the error came from an HTTP response. */
    public val status: Int? = null,
    /** The response body (or a description of it), when there was one. */
    public val response: JsonElement? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {
    public enum class Kind {
        /** A failure of the library or the network (`network_error`, `no_tokens`, `not_active` …). */
        GENERAL,
        /** The authorization server answered with an OAuth 2.0 error. [code] is the `error` value. */
        OAUTH,
        /** A response from the provider failed validation (bad ID token, state mismatch, metadata mismatch …). */
        VALIDATION,
        /** A Security Event Token could not be accepted. [code] is an RFC 8935 §2.3 error code. */
        SET_VALIDATION,
        /** A Shared Signals Framework management API call failed. */
        SSF,
    }

    override val message: String get() = super.message ?: ""

    /** OAuth `error_description`. */
    public var oauthErrorDescription: String? = null
    /** OAuth `error_uri`. */
    public var errorURI: String? = null
    /** The `context` the authorization or logout request was created with. */
    public var context: JsonElement? = null
    /** The account a `resume` or `reauth` request was about ([AccountManager]). */
    public var account: Account? = null
    /** The SET may pass on a later attempt (a JWKS that could not be fetched, a key it does not hold yet). */
    public var retryable: Boolean = false

    /** The OAuth `error` value, for an error of kind [Kind.OAUTH]. */
    public val oauthError: String? get() = if (kind == Kind.OAUTH) code else null

    /** The person closed the sign-in (or logout) window. */
    public val isUserCancellation: Boolean get() = code == USER_CANCELLED_CODE

    override fun toString(): String = message

    public companion object {
        /** The person closed the sign-in (or logout) window. */
        public const val USER_CANCELLED_CODE: String = "user_cancelled"

        internal fun validation(message: String, code: String? = null, response: JsonElement? = null) =
            OIDCError(Kind.VALIDATION, message, code = code, response = response)

        internal fun ssf(message: String, code: String? = null, status: Int? = null) =
            OIDCError(Kind.SSF, message, code = code, status = status)

        internal fun set(message: String, code: String = "invalid_request", cause: Throwable? = null) =
            OIDCError(Kind.SET_VALIDATION, message, code = code, cause = cause)

        internal fun oauth(error: String, description: String? = null, uri: String? = null, status: Int? = null, response: JsonElement? = null) =
            OIDCError(Kind.OAUTH, description?.let { "$error: $it" } ?: error, code = error, status = status, response = response).also {
                it.oauthErrorDescription = description
                it.errorURI = uri
            }

        /** A programming error: an option or argument this library cannot use. */
        internal fun usage(message: String) = OIDCError(Kind.GENERAL, message, code = "invalid_argument")

        /** Any error as an [OIDCError] (kept as is when it already is one). */
        public fun wrap(error: Throwable): OIDCError =
            error as? OIDCError ?: OIDCError(Kind.GENERAL, error.message ?: error.toString(), cause = error)
    }
}

/** Copies an error with another kind (an OAuth error from an SSF call is reported as an SSF error). */
internal fun OIDCError.withKind(kind: Kind): OIDCError {
    val copy = OIDCError(kind, message, code, status, response, cause)
    copy.oauthErrorDescription = oauthErrorDescription
    copy.errorURI = errorURI
    copy.context = context
    copy.account = account
    copy.retryable = retryable
    return copy
}

private typealias Kind = OIDCError.Kind

/**
 * Errors the OP answers a `prompt=none` request with when it would have to show the person a screen
 * (OpenID Connect Core §3.1.2.6).
 */
public val interactionRequiredErrors: Set<String> = setOf("login_required", "interaction_required", "account_selection_required", "consent_required")

/** True when [error] is an OAuth error that a request showing the sign-in screen (no `prompt=none`) would get past. */
public fun needsInteraction(error: Throwable): Boolean {
    val e = error as? OIDCError ?: return false
    return e.kind == OIDCError.Kind.OAUTH && e.code in interactionRequiredErrors
}
