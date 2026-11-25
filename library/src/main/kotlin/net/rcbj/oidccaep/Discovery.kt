// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.time.Instant

/**
 * An OpenID Provider metadata document (OpenID Connect Discovery 1.0 §3), with typed accessors for the members this
 * library reads. [raw] holds every member.
 */
public class ProviderMetadata(public val raw: JsonObject) {
    public operator fun get(key: String): JsonElement? = raw[key]

    public val issuer: String get() = raw.string("issuer") ?: ""
    public val authorizationEndpoint: String? get() = raw.string("authorization_endpoint")
    public val tokenEndpoint: String? get() = raw.string("token_endpoint")
    public val jwksURI: String? get() = raw.string("jwks_uri")
    public val userinfoEndpoint: String? get() = raw.string("userinfo_endpoint")
    public val endSessionEndpoint: String? get() = raw.string("end_session_endpoint")
    public val revocationEndpoint: String? get() = raw.string("revocation_endpoint")
    public val pushedAuthorizationRequestEndpoint: String? get() = raw.string("pushed_authorization_request_endpoint")
    public val registrationEndpoint: String? get() = raw.string("registration_endpoint")
    public val requirePushedAuthorizationRequests: Boolean get() = raw["require_pushed_authorization_requests"].boolValue == true
    public val authorizationResponseIssParameterSupported: Boolean get() = raw["authorization_response_iss_parameter_supported"].boolValue == true
    public val scopesSupported: List<String>? get() = raw["scopes_supported"].stringArrayValue
    public val idTokenSigningAlgValuesSupported: List<String> get() = raw["id_token_signing_alg_values_supported"].stringArrayValue ?: emptyList()
    public val codeChallengeMethodsSupported: List<String>? get() = raw["code_challenge_methods_supported"].stringArrayValue
    public val tokenEndpointAuthMethodsSupported: List<String>? get() = raw["token_endpoint_auth_methods_supported"].stringArrayValue
    public val dpopSigningAlgValuesSupported: List<String>? get() = raw["dpop_signing_alg_values_supported"].stringArrayValue

    override fun equals(other: Any?): Boolean = other is ProviderMetadata && other.raw == raw
    override fun hashCode(): Int = raw.hashCode()
}

/** The OpenID Connect Discovery 1.0 §4 URL: the well-known suffix appended to the issuer. */
public fun oidcDiscoveryURL(issuer: String): String = issuer.trimEnd('/') + "/.well-known/openid-configuration"

/**
 * RFC 8414 §3-style well-known URLs: the suffix inserted between host and path, then (when different) appended
 * OIDC-style, in preference order.
 */
public fun wellKnownURLs(issuer: String, suffix: String): List<String> {
    val url = parseURI(issuer) ?: return emptyList()
    val origin = originOf(url) ?: return emptyList()
    val path = (url.rawPath ?: "").trimEnd('/')
    val inserted = "$origin/.well-known/$suffix$path"
    val appended = "$origin$path/.well-known/$suffix"
    return if (inserted == appended) listOf(inserted) else listOf(inserted, appended)
}

private object MetadataCache {
    private val entries = HashMap<String, Pair<JsonObject, Instant>>()
    fun get(key: String, now: Instant): JsonObject? = synchronized(entries) { entries[key]?.takeIf { it.second.isAfter(now) }?.first }
    fun set(key: String, metadata: JsonObject, expiresAt: Instant) = synchronized(entries) { entries[key] = metadata to expiresAt }
    fun clear() = synchronized(entries) { entries.clear() }
}

/** Clears the in-process metadata cache (mostly useful in tests). */
public fun clearDiscoveryCache(): Unit = MetadataCache.clear()

/** Fetches metadata from the first URL that answers 2xx and checks that its `issuer` matches exactly. */
internal suspend fun fetchMetadata(urls: List<String>, expectedIssuer: String, http: HttpClient, cacheTTL: Double, now: Instant): JsonObject {
    val cacheKey = urls.joinToString("|")
    MetadataCache.get(cacheKey, now)?.let { return it }
    for ((i, string) in urls.withIndex()) {
        val url = parseURI(string) ?: throw OIDCError.validation("Invalid metadata URL $string")
        val res = http.get(url)
        if (res.status == 404 && i < urls.size - 1) continue
        val metadata = readJSON(res) as? JsonObject ?: throw OIDCError.validation("Metadata at $string is not a JSON object")
        // Discovery §4.3 / RFC 8414 §3.3: issuer MUST be identical to the one used to build the URL.
        if (metadata.string("issuer") != expectedIssuer) {
            throw OIDCError.validation("Issuer mismatch in $string: expected \"$expectedIssuer\", got \"${metadata.string("issuer") ?: ""}\"", code = "issuer_mismatch")
        }
        MetadataCache.set(cacheKey, metadata, now.plusSeconds(cacheTTL))
        return metadata
    }
    throw OIDCError.validation("No metadata found for $expectedIssuer")
}

private val requiredOPMetadata = listOf("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported",
    "subject_types_supported", "id_token_signing_alg_values_supported")

/**
 * Validates an OpenID Provider metadata document (OIDC Discovery 1.0 §3) for use by a code-flow RP. When
 * [expectedIssuer] is given, `issuer` must match it exactly (§4.3).
 */
public fun validateOpenIDProviderMetadata(metadata: JsonObject, expectedIssuer: String? = null): ProviderMetadata {
    val missing = requiredOPMetadata.filter { metadata[it] == null }
    if (missing.isNotEmpty()) throw OIDCError.validation("OpenID Provider metadata is missing required fields: ${missing.joinToString(", ")}")
    if (expectedIssuer != null && metadata.string("issuer") != expectedIssuer) {
        throw OIDCError.validation("Issuer mismatch: expected \"$expectedIssuer\", got \"${metadata.string("issuer") ?: ""}\"", code = "issuer_mismatch")
    }
    for (key in listOf("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint", "revocation_endpoint")) {
        val value = metadata[key] ?: continue
        val url = parseURI(value.stringValue)
        if (url?.scheme == null || url.host == null) throw OIDCError.validation("OpenID Provider metadata $key is not a valid URL")
        if (key == "issuer" && (url.rawQuery != null || url.rawFragment != null)) throw OIDCError.validation("issuer must not contain a query or fragment")
    }
    if (metadata["response_types_supported"].stringArrayValue?.contains("code") != true) {
        throw OIDCError.validation("OpenID Provider does not support response_type=code")
    }
    if (metadata["id_token_signing_alg_values_supported"].arrayValue == null) {
        throw OIDCError.validation("id_token_signing_alg_values_supported must be an array")
    }
    return ProviderMetadata(metadata)
}

/** Retrieves and validates OpenID Provider metadata from `<issuer>/.well-known/openid-configuration`. */
public suspend fun discoverOpenIDProvider(issuer: String, transport: HttpTransport = OkHttpTransport(), timeout: Double = 10.0,
                                          cacheTTL: Double = 3600.0): ProviderMetadata {
    val http = HttpClient(transport, timeout)
    val metadata = fetchMetadata(listOf(oidcDiscoveryURL(issuer)), issuer, http, cacheTTL, Instant.now())
    return validateOpenIDProviderMetadata(metadata, issuer)
}

/**
 * Retrieves and validates OpenID Provider metadata from its metadata URL
 * (`https://idp.example.com/.well-known/openid-configuration`), the form an app's configuration holds.
 *
 * The document's `issuer` must be the one the URL was built from (Discovery §4.3), in either the OpenID form or the
 * RFC 8414 form.
 */
public suspend fun discoverOpenIDProvider(metadataURL: URI, transport: HttpTransport = OkHttpTransport(), timeout: Double = 10.0,
                                          cacheTTL: Double = 3600.0): ProviderMetadata {
    val http = HttpClient(transport, timeout)
    val now = Instant.now()
    val key = metadataURL.toString()
    val metadata = MetadataCache.get(key, now) ?: (readJSON(http.get(metadataURL)) as? JsonObject
        ?: throw OIDCError.validation("Metadata at $key is not a JSON object"))
    val issuer = metadata.string("issuer") ?: throw OIDCError.validation("OpenID Provider metadata is missing required fields: issuer")
    val forms = listOf(oidcDiscoveryURL(issuer)) + wellKnownURLs(issuer, "openid-configuration")
    if (key !in forms) {
        throw OIDCError.validation("The metadata at $key names the issuer \"$issuer\", whose metadata is not at that URL", code = "issuer_mismatch")
    }
    val validated = validateOpenIDProviderMetadata(metadata, issuer)
    MetadataCache.set(key, metadata, now.plusSeconds(cacheTTL))
    return validated
}

/** Retrieves SSF 1.0 transmitter metadata from `/.well-known/ssf-configuration` (path insertion first, then appended). */
public suspend fun discoverSSFTransmitter(issuer: String, transport: HttpTransport = OkHttpTransport(), timeout: Double = 10.0,
                                          cacheTTL: Double = 3600.0): JsonObject {
    val http = HttpClient(transport, timeout)
    val metadata = fetchMetadata(wellKnownURLs(issuer, "ssf-configuration"), issuer, http, cacheTTL, Instant.now())
    if (metadata.string("jwks_uri") == null) throw OIDCError.validation("SSF transmitter metadata has no jwks_uri")
    return metadata
}
