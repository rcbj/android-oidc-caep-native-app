// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import android.content.Context
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.net.URI

/**
 * An app's OpenID Connect settings, read from a JSON file: on Android, **`oidc_configuration.json`** in the app's
 * assets. The keys are those of the Swift library's `OIDCConfiguration.plist`, so one set of settings reads the same
 * on both:
 *
 * ```json
 * {
 *   "MetadataURL": "https://idp.example.com/.well-known/openid-configuration",
 *   "ClientID": "my-native-app",
 *   "Scopes": ["openid", "profile", "email"],
 *   "RedirectURI": "com.example.myapp:/oauth2/callback"
 * }
 * ```
 *
 * | Key | Type | Required | Meaning |
 * |---|---|---|---|
 * | `MetadataURL` | string | yes | The provider's metadata (discovery) URL |
 * | `ClientID` | string | yes | The public client's `client_id` |
 * | `Scopes` | array or space-separated string | no | Default `openid profile email` (+ `offline_access` when offered) |
 * | `RedirectURI` | string | yes | Private-use scheme (`com.example.app:/callback`) or loopback |
 * | `PostLogoutRedirectURI` | string | no | Where the provider returns after logout |
 * | `Resource` | array or string | no | RFC 8707 resource indicators |
 * | `DPoP` | bool | no | Bind tokens to a key (default `true`) |
 * | `PAR` | string | no | `auto` (default), `always` or `never` |
 * | `IDTokenSignedResponseAlg` | string | no | Default: RS256 when offered, else the first the provider offers that this library verifies |
 * | `ACRValues` | string | no | Requested `acr_values` |
 * | `PrefersEphemeralWebBrowserSession` | bool | no | No shared browser cookies at sign-in (default `false`) |
 * | `SSFTransmitterIssuer` | string | no | CAEP transmitter, if not the provider's issuer |
 * | `CAEPEnabled` | bool | no | Turns off CAEP and RISC when false: the receiver is not started, and `ssf.read` and `ssf.manage` are left out of the authorization request (default `true`) |
 * | `TrustedCertificates` | array | no | PEM or DER files (or inline PEM) to trust for TLS: trust anchors or whole chains. Relative paths are asset names on Android |
 * | `TrustSystemRoots` | bool | no | Whether the system's roots still count beside `TrustedCertificates` (default `true`) |
 * | `InsecureSkipTLSVerification` | bool | no | Accept any TLS certificate from the provider. **Local test providers only** (default `false`) |
 */
public data class OIDCAppConfiguration(
    public val metadataURL: URI,
    public val clientID: String,
    public val scopes: List<String> = emptyList(),
    public val redirectURI: URI,
    public val postLogoutRedirectURI: URI? = null,
    public val resource: List<String> = emptyList(),
    public val dpop: Boolean = true,
    public val par: PARMode = PARMode.AUTO,
    public val idTokenSignedResponseAlg: String? = null,
    public val acrValues: String? = null,
    public val prefersEphemeralWebBrowserSession: Boolean = false,
    public val ssfTransmitterIssuer: String? = null,
    public val caepEnabled: Boolean = true,
    /** Accept any TLS certificate from the provider and the transmitter. Local test providers only. */
    public val insecureSkipTLSVerification: Boolean = false,
    /** Extra certificates to trust for TLS (`TrustedCertificates`, `TrustSystemRoots`). */
    public val tlsTrust: TLSTrust? = null,
) {
    /** The configured scope string (`openid profile email`), or null when `Scopes` is empty. */
    public val scope: String? get() = if (scopes.isEmpty()) null else scopes.joinToString(" ")

    /** The HTTP transport this configuration calls for. Pass the same transport to an [SSFReceiverConfiguration]. */
    public fun makeTransport(): HttpTransport = when {
        insecureSkipTLSVerification -> OkHttpTransport(insecureSkipTLSVerification = true)
        tlsTrust != null -> OkHttpTransport(trust = tlsTrust)
        else -> OkHttpTransport()
    }

    /**
     * Client options from this configuration. Pass the DPoP key store to use (e.g. [AndroidKeystoreKeyStore]); it is
     * ignored when `DPoP` is false. When `caepEnabled` is false, `ssf.read` and `ssf.manage` are left out of `scope`.
     */
    public fun clientOptions(dpopKeyStore: DPoPKeyStore = MemoryKeyStore(), transport: HttpTransport? = null): OIDCClientOptions =
        OIDCClientOptions(clientID = clientID, redirectURI = redirectURI, postLogoutRedirectURI = postLogoutRedirectURI, scope = authorizationScope,
            resource = resource, idTokenSignedResponseAlg = idTokenSignedResponseAlg ?: "RS256", par = par,
            dpop = if (dpop) DPoPOptions(dpopKeyStore) else null, transport = transport ?: makeTransport())

    /** Scopes for the authorization request. `CAEPEnabled` false leaves `ssf.read` and `ssf.manage` out. */
    private val authorizationScope: String?
        get() {
            if (caepEnabled) return scope
            val kept = scopes.filter { it != "ssf.read" && it != "ssf.manage" }
            return if (kept.isEmpty()) null else kept.joinToString(" ")
        }

    /**
     * Discovers the provider and creates a client. The DPoP key is kept where [dpopKeyStore] says (on Android, pass
     * [preferredDPoPKeyStore]: the Keystore, so that tokens cached across launches stay usable), and in memory otherwise.
     *
     * `ACRValues` and `SSFTransmitterIssuer` are the app's to apply (to its requests and its [SSFReceiver]).
     */
    public suspend fun makeClient(dpopKeyStore: DPoPKeyStore? = null, transport: HttpTransport? = null): OIDCClient {
        val t = transport ?: makeTransport()
        var options = clientOptions(dpopKeyStore ?: MemoryKeyStore(), t)
        if (idTokenSignedResponseAlg == null) {
            // Pick an algorithm the provider uses: RS256 when offered, else the first this library verifies.
            val algs = discoverOpenIDProvider(metadataURL, t).idTokenSigningAlgValuesSupported
            options = options.copy(idTokenSignedResponseAlg = if ("RS256" in algs) "RS256" else algs.firstOrNull { it in supportedIDTokenAlgorithms } ?: "RS256")
        }
        return OIDCClient.discover(metadataURL, options)
    }

    /** A [CustomTabsWebAuthenticator] with this configuration's `PrefersEphemeralWebBrowserSession`. */
    public fun makeAuthenticator(context: Context): CustomTabsWebAuthenticator =
        CustomTabsWebAuthenticator(context, prefersEphemeralWebBrowserSession)

    public companion object {
        /** The asset [load] reads. */
        public const val DEFAULT_ASSET_NAME: String = "oidc_configuration.json"

        /** Reads [asset] from the app's assets. Relative `TrustedCertificates` are asset names too. */
        public fun load(context: Context, asset: String = DEFAULT_ASSET_NAME): OIDCAppConfiguration {
            val assets = context.assets
            val text = try { assets.open(asset).use { it.readBytes().decodeToString() } } catch (e: Exception) {
                throw OIDCError.usage("No $asset in the app's assets")
            }
            val base = asset.substringBeforeLast('/', "")
            return fromJson(text, asset) { path ->
                if (path.startsWith("/")) File(path).readBytes()
                else assets.open(if (base.isEmpty()) path else "$base/$path").use { it.readBytes() }
            }
        }

        /** Reads a JSON file. Relative `TrustedCertificates` paths are resolved against its folder. */
        public fun load(file: File): OIDCAppConfiguration = fromJson(file.readText(), file.name) { path ->
            (if (path.startsWith("/")) File(path) else File(file.parentFile, path)).readBytes()
        }

        /**
         * Parses the JSON text of a configuration.
         * @param readFile reads a `TrustedCertificates` file.
         */
        public fun fromJson(text: String, source: String = "the configuration", readFile: (String) -> ByteArray = { File(it).readBytes() }): OIDCAppConfiguration {
            val d = (try { parseJson(text) } catch (e: Exception) { null }) as? JsonObject ?: throw OIDCError.usage("$source is not a JSON object")
            return fromObject(d, readFile)
        }

        /** From an object with the keys in the table above. */
        public fun fromObject(d: JsonObject, readFile: (String) -> ByteArray = { File(it).readBytes() }): OIDCAppConfiguration {
            fun string(key: String) = d[key].stringValue?.trim()?.ifEmpty { null }
            fun bool(key: String, default: Boolean) = d[key].boolValue ?: default
            fun list(key: String): List<String> =
                d[key].arrayValue?.mapNotNull { it.stringValue?.trim()?.ifEmpty { null } } ?: string(key)?.split(Regex("\\s+")) ?: emptyList()
            fun url(key: String, required: Boolean): URI? {
                val s = string(key) ?: if (required) throw OIDCError.usage("The OIDC configuration has no $key") else return null
                val u = parseURI(s)
                if (u?.scheme == null) throw OIDCError.usage("The OIDC configuration's $key is not a URL: $s")
                return u
            }
            val metadataURL = url("MetadataURL", true)!!
            val redirectURI = url("RedirectURI", true)!!
            if (!(metadataURL.path ?: "").contains("/.well-known/")) {
                throw OIDCError.usage("MetadataURL must be the provider's metadata URL (…/.well-known/openid-configuration), not $metadataURL")
            }
            val clientID = string("ClientID") ?: throw OIDCError.usage("The OIDC configuration has no ClientID")
            val par = string("PAR")?.let { value -> PARMode.entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: throw OIDCError.usage("PAR must be auto, always or never, not $value") }

            val trusted = (d["TrustedCertificates"].arrayValue?.mapNotNull { it.stringValue } ?: string("TrustedCertificates")?.let { listOf(it) } ?: emptyList())
                .map { it.trim() }.filter { it.isNotEmpty() }
            val tlsTrust = if (trusted.isEmpty()) null else TLSTrust.fromPemOrDer(trusted.map { entry ->
                if (entry.contains("-----BEGIN CERTIFICATE-----")) entry.encodeToByteArray()
                else try { readFile(entry) } catch (e: Exception) { throw OIDCError.usage("Could not read the trusted certificate file $entry: ${e.message}") }
            }, bool("TrustSystemRoots", true))

            return OIDCAppConfiguration(metadataURL, clientID, list("Scopes"), redirectURI, url("PostLogoutRedirectURI", false), list("Resource"),
                bool("DPoP", true), par ?: PARMode.AUTO, string("IDTokenSignedResponseAlg"), string("ACRValues"),
                bool("PrefersEphemeralWebBrowserSession", false), string("SSFTransmitterIssuer"), bool("CAEPEnabled", true),
                bool("InsecureSkipTLSVerification", false), tlsTrust)
        }
    }
}
