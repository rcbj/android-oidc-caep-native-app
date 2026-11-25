// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject

private const val CAEP_BASE = "https://schemas.openid.net/secevent/caep/event-type/"
private const val SSF_BASE = "https://schemas.openid.net/secevent/ssf/event-type/"
private const val RISC_BASE = "https://schemas.openid.net/secevent/risc/event-type/"

/** OpenID CAEP 1.0 event types. */
public object CAEP {
    public const val SESSION_REVOKED: String = CAEP_BASE + "session-revoked"
    public const val TOKEN_CLAIMS_CHANGE: String = CAEP_BASE + "token-claims-change"
    public const val CREDENTIAL_CHANGE: String = CAEP_BASE + "credential-change"
    public const val ASSURANCE_LEVEL_CHANGE: String = CAEP_BASE + "assurance-level-change"
    public const val DEVICE_COMPLIANCE_CHANGE: String = CAEP_BASE + "device-compliance-change"
    public const val SESSION_ESTABLISHED: String = CAEP_BASE + "session-established"
    public const val SESSION_PRESENTED: String = CAEP_BASE + "session-presented"
    public const val RISK_LEVEL_CHANGE: String = CAEP_BASE + "risk-level-change"

    /** Every CAEP 1.0 event type. */
    public val all: List<String> = listOf(SESSION_REVOKED, TOKEN_CLAIMS_CHANGE, CREDENTIAL_CHANGE, ASSURANCE_LEVEL_CHANGE, DEVICE_COMPLIANCE_CHANGE,
        SESSION_ESTABLISHED, SESSION_PRESENTED, RISK_LEVEL_CHANGE)
}

/** OpenID Shared Signals Framework 1.0 stream-control event types. */
public object SSF {
    public const val VERIFICATION: String = SSF_BASE + "verification"
    public const val STREAM_UPDATED: String = SSF_BASE + "stream-updated"
}

/** OpenID RISC 1.0 event types (receivable through [SSFReceiver.onEvent]). */
public object RISC {
    public const val ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: String = RISC_BASE + "account-credential-change-required"
    public const val ACCOUNT_PURGED: String = RISC_BASE + "account-purged"
    public const val ACCOUNT_DISABLED: String = RISC_BASE + "account-disabled"
    public const val ACCOUNT_ENABLED: String = RISC_BASE + "account-enabled"
    public const val IDENTIFIER_CHANGED: String = RISC_BASE + "identifier-changed"
    public const val IDENTIFIER_RECYCLED: String = RISC_BASE + "identifier-recycled"
    public const val CREDENTIAL_COMPROMISE: String = RISC_BASE + "credential-compromise"
    public const val OPT_IN: String = RISC_BASE + "opt-in"
    public const val OPT_OUT_INITIATED: String = RISC_BASE + "opt-out-initiated"
    public const val OPT_OUT_CANCELLED: String = RISC_BASE + "opt-out-cancelled"
    public const val OPT_OUT_EFFECTIVE: String = RISC_BASE + "opt-out-effective"
    public const val RECOVERY_ACTIVATED: String = RISC_BASE + "recovery-activated"
    public const val RECOVERY_INFORMATION_CHANGED: String = RISC_BASE + "recovery-information-changed"
}

/** SSF delivery methods. */
public object Delivery {
    public const val PUSH: String = "urn:ietf:rfc:8935"
    public const val POLL: String = "urn:ietf:rfc:8936"
}

/** The short name (`session-revoked`) of an event type URI. */
public fun eventName(uri: String): String = uri.substringAfterLast('/')

/** Builders for RFC 9493 Subject Identifiers, as carried in a SET's `sub_id` claim and sent to [SSFReceiver.addSubject]. */
public object Subject {
    public fun issSub(iss: String, sub: String): JsonObject = jsonObjectOf("format" to "iss_sub", "iss" to iss, "sub" to sub)
    public fun email(email: String): JsonObject = jsonObjectOf("format" to "email", "email" to email)
    public fun phone(phoneNumber: String): JsonObject = jsonObjectOf("format" to "phone_number", "phone_number" to phoneNumber)
    public fun opaque(id: String): JsonObject = jsonObjectOf("format" to "opaque", "id" to id)
    public fun account(uri: String): JsonObject = jsonObjectOf("format" to "account", "uri" to uri)
    public fun uri(uri: String): JsonObject = jsonObjectOf("format" to "uri", "uri" to uri)
    public fun did(url: String): JsonObject = jsonObjectOf("format" to "did", "url" to url)
    public fun aliases(identifiers: List<JsonObject>): JsonObject = jsonObjectOf("format" to "aliases", "identifiers" to JsonArray(identifiers))
    /** An SSF complex subject, e.g. `Subject.complex(mapOf("user" to Subject.issSub(iss, sub), "session" to Subject.opaque(sid)))`. */
    public fun complex(members: Map<String, JsonObject>): JsonObject = JsonObject(members + mapOf("format" to jsonOf("complex")))
}

/** What a security event's subject is compared with: one identity, from validated ID token claims. */
public data class SubjectIdentity(
    public val iss: String? = null,
    public val sub: String? = null,
    /** The OP session id. */
    public val sid: String? = null,
    public val email: String? = null,
    public val emailVerified: Boolean = false,
    public val phoneNumber: String? = null,
    public val phoneNumberVerified: Boolean = false,
    /** Opaque ids for the other complex-subject members: `device`, `application`, `tenant`, `org_unit`, `group`. */
    public val other: Map<String, String> = emptyMap(),
)

private val complexMembers = listOf("user", "session", "device", "application", "tenant", "org_unit", "group")

/**
 * Whether a subject identifier refers to a known identity.
 *
 * - An email or phone number identifies somebody only when the OP said it was verified: OIDC Core §5.7 makes neither
 *   a stable or unique identifier, and an unverified one may be anybody's.
 * - A top-level opaque id is compared with `sub`. A session is named inside a complex subject.
 * - In a complex subject every member must match, and the members this identity can't be checked against count as a
 *   non-match: an event about one session matches only an identity holding that `sid`.
 */
public fun subjectMatches(subId: JsonObject?, identity: SubjectIdentity?): Boolean {
    if (subId == null || identity == null) return false
    return when (subId.string("format")) {
        "iss_sub" -> {
            val sub = subId.string("sub") ?: return false
            val mine = identity.sub
            if (mine.isNullOrEmpty() || sub != mine) return false
            identity.iss.isNullOrEmpty() || subId.string("iss") == identity.iss
        }
        "email" -> {
            val mine = identity.email
            val theirs = subId.string("email")
            identity.emailVerified && mine != null && theirs != null && theirs.lowercase() == mine.lowercase()
        }
        "phone_number" -> identity.phoneNumberVerified && subId.string("phone_number")?.let { it == identity.phoneNumber } == true
        "opaque" -> opaqueIs(subId, identity.sub)
        "account" -> identity.emailVerified && identity.email != null && subId.string("uri") == "acct:${identity.email}"
        "aliases" -> (subId["identifiers"].arrayValue ?: emptyList()).any { subjectMatches(it.objectValue, identity) }
        "complex" -> {
            val members = complexMembers.filter { subId[it] != null && subId[it] != JsonNull }
            members.isNotEmpty() && members.all { member ->
                val value = subId[member].objectValue
                when (member) {
                    "user" -> subjectMatches(value, identity)
                    "session" -> opaqueIs(value, identity.sid)
                    else -> opaqueIs(value, identity.other[member])
                }
            }
        }
        else -> false
    }
}

/** An opaque identifier naming exactly [id]: both must be non-empty strings. */
private fun opaqueIs(value: JsonObject?, id: String?): Boolean {
    if (value == null || value.string("format") != "opaque") return false
    val v = value.string("id")
    return !v.isNullOrEmpty() && !id.isNullOrEmpty() && v == id
}
