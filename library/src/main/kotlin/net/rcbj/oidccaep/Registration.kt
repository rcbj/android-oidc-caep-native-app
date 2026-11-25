// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.serialization.json.JsonObject
import java.net.URI

/** Client metadata values the server must honour exactly as requested; if it registers something else the registration is rejected. */
private val mustMatch = listOf("id_token_signed_response_alg", "token_endpoint_auth_method")

/** OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 / RFC 7592, for a public client. */
public object ClientRegistration {
    /** Registers a client. [clientMetadata] needs `redirect_uris`. Returns the Client Information Response. */
    public suspend fun register(metadata: ProviderMetadata, clientMetadata: JsonObject, initialAccessToken: String? = null,
                                allowInsecureRequests: Boolean = false, transport: HttpTransport = OkHttpTransport(),
                                timeout: Double = 10.0): JsonObject {
        val endpoint = metadata.registrationEndpoint
            ?: throw OIDCError(OIDCError.Kind.GENERAL, "OpenID Provider does not advertise a registration_endpoint", code = "registration_not_supported")
        // The request may carry an initial access token, and the answer is this client's identity.
        if (!allowInsecureRequests && !isSecureURL(endpoint)) {
            throw OIDCError.validation("registration_endpoint must use https: $endpoint", code = "insecure_endpoint")
        }
        val uris = clientMetadata["redirect_uris"].stringArrayValue
        if (uris.isNullOrEmpty()) throw OIDCError.usage("clientMetadata.redirect_uris is required")
        clientMetadata.string("id_token_signed_response_alg")?.let { alg ->
            if (alg !in supportedIDTokenAlgorithms) throw OIDCError.validation("Refusing to register id_token_signed_response_alg $alg: this library cannot verify it")
            val offered = metadata.idTokenSigningAlgValuesSupported
            if (offered.isNotEmpty() && alg !in offered) throw OIDCError.validation("OpenID Provider does not support id_token_signed_response_alg $alg")
        }
        val headers = mutableMapOf("content-type" to "application/json", "accept" to "application/json")
        if (initialAccessToken != null) headers["authorization"] = "Bearer $initialAccessToken"
        val url = parseURI(endpoint) ?: throw OIDCError.validation("registration_endpoint is not a URL")
        val res = HttpClient(transport, timeout).send(HttpRequest(url, "POST", headers, clientMetadata.jsonBytes()))
        val registration = readJSONObject(res)
        if (registration.string("client_id") == null) {
            throw OIDCError.validation("Registration response is missing client_id", response = registration)
        }
        for (key in mustMatch) {
            val wanted = clientMetadata[key] ?: continue
            val got = registration[key] ?: continue
            if (wanted != got) {
                throw OIDCError.validation("The OP registered $key=${got.stringValue ?: got.jsonString()} instead of the requested ${wanted.stringValue ?: wanted.jsonString()}",
                    code = "registration_mismatch", response = registration)
            }
        }
        return registration
    }

    /** Reads the current registration (OIDC DCR §4 / RFC 7592 §2.1). */
    public suspend fun read(registration: JsonObject, allowInsecureRequests: Boolean = false, transport: HttpTransport = OkHttpTransport(),
                            timeout: Double = 10.0): JsonObject {
        val (uri, token) = managementCredentials(registration, allowInsecureRequests)
        return readJSONObject(HttpClient(transport, timeout).get(uri, mapOf("authorization" to "Bearer $token", "accept" to "application/json")))
    }

    /** Deletes a registration (RFC 7592 §2.3). */
    public suspend fun delete(registration: JsonObject, allowInsecureRequests: Boolean = false, transport: HttpTransport = OkHttpTransport(),
                              timeout: Double = 10.0) {
        val (uri, token) = managementCredentials(registration, allowInsecureRequests)
        val res = HttpClient(transport, timeout).send(HttpRequest(uri, "DELETE", mapOf("authorization" to "Bearer $token")))
        if (!res.isOK) readJSON(res)
    }

    // The registration access token goes to registration_client_uri, so that must use TLS (RFC 7592 §5).
    private fun managementCredentials(registration: JsonObject, allowInsecureRequests: Boolean): Pair<URI, String> {
        val uri = registration.string("registration_client_uri")
        val token = registration.string("registration_access_token")
        val url = parseURI(uri)
        if (uri == null || token == null || url == null) {
            throw OIDCError(OIDCError.Kind.GENERAL, "Registration has no registration_client_uri / registration_access_token", code = "registration_not_manageable")
        }
        if (!allowInsecureRequests && !isSecureURL(uri)) throw OIDCError.validation("registration_client_uri must use https: $uri", code = "insecure_endpoint")
        return url to token
    }
}
