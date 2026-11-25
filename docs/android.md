---
title: Android and macOS
---

# Android and macOS

This library is the Android counterpart of [swift-oidc-caep-native-app](https://rcbj.github.io/swift-oidc-caep-native-app/), the Swift library for macOS. Both do the same protocol work with the same checks, the same error codes and the same test suite (ported test for test). They differ in what each platform provides, and in the conventions of each language:

- how the browser returns to the app;
- where tokens and the DPoP key are kept;
- where the configuration lives, and how TLS trust is configured;
- how the API is spelled in Kotlin;
- what the demo app is built with.

This page lists every difference. A difference not listed here is a bug in one of the two libraries.

## At a glance

| | macOS (Swift) | Android (Kotlin) |
|---|---|---|
| **Sign-in window** | `SystemWebAuthenticator`: `ASWebAuthenticationSession` | `CustomTabsWebAuthenticator`: a Custom Tab in the default browser |
| **Redirect URI** | Private-use scheme, caught by `ASWebAuthenticationSession`; no app registration | Private-use scheme, registered through `manifestPlaceholders["oidcRedirectScheme"]` and received by the library's `RedirectUriReceiverActivity` |
| **`https` redirect** | With an associated domain, macOS 14.4 and later | Not supported by `CustomTabsWebAuthenticator` |
| **Loopback redirect** | `LoopbackWebAuthenticator` (`xdg-open` on Linux, `open` on macOS) | `LoopbackWebAuthenticator`, with an `openBrowser` you supply |
| **Token cache** | `KeychainTokenStore`, the default (`defaultTokenStore()`) | `KeystoreTokenStore(context)`: AES-256-GCM under an Android Keystore key, values in `SharedPreferences`. The default is `MemoryTokenStore`; the app passes the Keystore store |
| **DPoP key** | `SecureEnclaveKeyStore` (ES256, non-extractable), else `KeychainKeyStore` (a software key in the Keychain) | `AndroidKeystoreKeyStore` (ES256, non-extractable), in StrongBox when present, else the TEE. No software key persisted to disk: the Keystore is always there |
| **Key store chosen by `makeClient()`** | `preferredDPoPKeyStore()` when none is given | `MemoryKeyStore` when none is given; pass `preferredDPoPKeyStore(context)` |
| **Where the key lives** | `securityFeatures.dpop.extractable` | the same, and `AndroidKeystoreKeyStore.securityLevel()` (`STRONGBOX`, `TRUSTED_ENVIRONMENT`, `SOFTWARE`) |
| **Configuration** | `OIDCConfiguration.plist` in the bundle, or an `OIDCConfiguration` key in `Info.plist` | `oidc_configuration.json` in the assets, with the same keys; no second location |
| **HTTP** | `URLSession`; on Linux, `curl` for extra CAs | OkHttp |
| **Extra trusted CAs** (`TrustedCertificates`) | Anchors in the URLSession trust evaluation | A JSSE `X509TrustManager` over the anchors (and the system roots, when allowed) |
| **Relative `TrustedCertificates` paths** | Relative to the plist's folder; `~` allowed | Asset names beside the configuration file (or files beside a configuration loaded from a file) |
| **Concurrency** | Swift actors, `async`/`await` | Kotlin coroutines; each manager keeps its state on a single-threaded dispatcher of its own, which gives actor semantics, reentrancy included |
| **Events** | `EventHub.stream()` → `AsyncStream` | `EventHub.flow()` → `Flow` |
| **Logging** | standard output and error | Logcat, tag `OIDCCAEPClient` |
| **Errors specific to storage** | `keychain_error`, `secure_enclave_unavailable` | `store_error`, `keystore_unavailable` |
| **Signature verification** | CryptoKit / swift-crypto | The platform's JCA (Conscrypt); Ed25519 where the platform provides it |
| **Demo user interface** | SwiftUI (GTK 4 on Linux) | Jetpack Compose |
| **Demo's TLS default** | Certificates verified (Linux: off) | Certificates verified against iya-sts's root only, written by `scripts/setup-emulator.sh` |
| **Minimum OS** | macOS 13 (demo: 14) | Android 9, API 28 |
| **Distribution** | Swift Package Manager, from version tags | An AAR built from a version tag (no Maven publication yet) |

Everything else is the same design on both platforms:

- discovery and metadata validation;
- PKCE, `state` and `nonce`;
- PAR and DPoP proofs;
- RFC 9207 issuer checks;
- ID token validation;
- refresh and revocation;
- several accounts with one active account;
- the SSF receiver and every CAEP handler;
- the demo's event policies.

## Signing in

**macOS.** `ASWebAuthenticationSession` opens the provider's page in a sheet tied to the app's window. It uses the default browser's cookies, so single sign-on and several accounts work. The session ends when the browser is sent to the private-use scheme, which macOS hands back to the session; no app registration is needed. Closing the sheet throws an error whose `isUserCancellation` is true.

**Android.** There is no equivalent of `ASWebAuthenticationSession` that catches the redirect for you, so the library does what AppAuth does:

1. `CustomTabsWebAuthenticator` starts the library's `AuthorizationManagementActivity` (not exported, `singleTask`, translucent), which opens the authorization URL in a Custom Tab in the app's task.
2. The provider redirects to `com.example.myapp:/callback`. Android delivers it to `RedirectUriReceiverActivity`, which the library's manifest registers for the scheme the app names in `manifestPlaceholders["oidcRedirectScheme"]`.
3. The receiver hands the URL back to the management activity with `FLAG_ACTIVITY_CLEAR_TOP`, which closes the tab, and the waiting `authenticate()` call returns it. The redirect is matched to the waiting sign-in by scheme and path.
4. A return to the management activity with no redirect (the person closed the tab or pressed back) is a cancellation: `isUserCancellation` is true.

On Android:

- **The scheme is declared.** Any app may declare an intent filter for the same scheme, so the scheme must be one you control in reverse-domain form; PKCE keeps a code another app captures useless to it.
- **Ephemeral browsing** (`PrefersEphemeralWebBrowserSession`) asks the Custom Tab for ephemeral mode, which only some browsers honour.
- **Process death.** If Android kills the app while the tab is open, the sign-in in progress is lost (it is held in memory, as on macOS) and the management activity finishes without an answer.
- **A script's click is not a gesture.** Chrome asks "Continue to <app>?" before handing a redirect to an app when the step that caused it was not a user gesture. A person tapping through never sees it.

## Where tokens and keys are kept

The rule is the same on both platforms: **tokens in the platform's secure storage, and a DPoP key that cannot be read out.** What differs is who chooses.

- **macOS** has the Keychain, reachable without anything from the app, so `defaultTokenStore()` and `preferredDPoPKeyStore()` are the defaults.
- **Android**'s Keystore stores need a `Context`, which the library cannot reach on its own, so the defaults are the memory stores and **the app passes** `KeystoreTokenStore(context)` and `preferredDPoPKeyStore(context)`. The guide's examples always do.

`KeystoreTokenStore` keeps the ciphertext in the app's private `SharedPreferences` (`<package>.oidc-tokens`) and the AES key in the Keystore (`<package>.oidc-tokens-key`). Exclude the file from backups: the key is never backed up, so restored ciphertext cannot be decrypted. `AndroidKeystoreKeyStore` keeps the P-256 key under `<package>.oidc-dpop`. Both report where their key lives with `securityLevel()`.

There is no counterpart of `KeychainKeyStore` (a software DPoP key persisted in the Keychain): on Android the Keystore is always available, so a hardware-backed key is always possible. `MemoryKeyStore` still creates ES256, ES384 and ES512 software keys for tests.

## TLS trust

Both platforms verify the provider's and the transmitter's certificates by default, and take the same three configuration keys:

| Key | Type | Default | |
|---|---|---|---|
| `TrustedCertificates` | array of strings | — | PEM or DER, or inline PEM text. Each may hold a trust anchor (a root) or a whole chain; every certificate counts as an anchor. On Android a relative path is an asset name beside the configuration (or a file beside a configuration loaded from a file). |
| `TrustSystemRoots` | bool | `true` | Whether the system's trusted roots still count beside `TrustedCertificates`. With `false`, only the listed certificates are trusted. |
| `InsecureSkipTLSVerification` | bool | `false` | Accept **any** certificate. For a local test provider only. The library logs a warning when it is on. |

The host name is always checked, except with `InsecureSkipTLSVerification`.

- **macOS:** the certificates are added as anchors to the URLSession server-trust evaluation.
- **Android:** `OkHttpTransport` builds an `X509TrustManager` over a key store of the anchors, and asks the system's trust manager too when `TrustSystemRoots` is true. A chain that contains one of the given certificates (a leaf given as an anchor) is accepted as well.

In code, the same settings are `TLSTrust` and `OkHttpTransport(trust = …)` or `OkHttpTransport(insecureSkipTLSVerification = true)`. `OIDCAppConfiguration.makeTransport()` returns the transport the file asks for. Pass that one transport to the client and to every `SSFReceiverConfiguration`.

The browser has its own trust store, so it must trust the same CA for the sign-in pages. On a phone, install the CA in the system settings; on the emulator, `scripts/setup-emulator.sh` gives Chrome `--ignore-certificate-errors-spki-list` for iya-sts's CA keys only ([Running the demo](demo.md#set-up-the-emulator)).

## How the API is spelled

The Kotlin API keeps the Swift names wherever Kotlin allows. These are the systematic differences:

| Swift | Kotlin |
|---|---|
| `URL` | `java.net.URI` |
| `Date`, `TimeInterval` | `java.time.Instant`, `Double` seconds |
| `JSONValue`, `JSONObject` | kotlinx.serialization `JsonElement`, `JsonObject`, with the accessors `stringValue`, `objectValue` … and `JsonObject.string(key)` |
| `async throws` | `suspend`, throwing `OIDCError` |
| enum cases (`.signedIn`, `.auto`, `.setValidation`) | upper-case constants (`Account.Status.SIGNED_IN`, `PARMode.AUTO`, `OIDCError.Kind.SET_VALIDATION`) |
| event cases (`.ended(account, reason:)`) | sealed classes (`AccountManager.Event.Ended(account, reason)`) |
| `CAEP.sessionRevoked`, `SSF.verification`, `Delivery.poll` | `CAEP.SESSION_REVOKED`, `SSF.VERIFICATION`, `Delivery.POLL` |
| `OIDCClient.discover(issuer:options:)` | `OIDCClient.discoverIssuer(issuer, options)` |
| `client.authorize(using:)`, `accounts.signIn(using:)` | extension functions taking the authenticator: `client.authorize(authenticator)`, `accounts.signIn(authenticator)` |
| `accounts.active`, `accounts.activeKey` (actor properties) | `accounts.active()`, `accounts.activeKey()` (suspend functions) |
| `SSFAuthorization.oidc(client) { … }`, `.bearer`, `.headers` | `SSFAuthorization.oidc(client) { … }`, `SSFAuthorization.Bearer { … }`, `SSFAuthorization.Headers { … }` |
| `requestVerification(timeout:)` | `requestVerification(timeoutSeconds)` |
| `OIDCAppConfiguration.load(bundle:resource:)`, `load(contentsOf:)` | `OIDCAppConfiguration.load(context, asset)`, `load(file)`, `fromJson(text)` |
| `URLSessionTransport`, `HTTPTransport` | `OkHttpTransport`, `HttpTransport` |
| `OIDCLog.handler: (Level, String)` | `OIDCLog.handler: (OIDCLog.Level, String) -> Unit` |

## The demo

The demo has one model (`DemoModel.kt`, the Swift demo's `DemoModel`) and one Compose activity. It shows the same layout as the Swift demo:

- a top bar with the account menu;
- banners;
- the **Identity** tab: sign-in, session, token cache, tokens, protections in effect;
- the **CAEP events** tab: stream, event-type picker, verification, reconnect, event log.

Differences in the Android front end:

| | macOS (SwiftUI) | Android (Compose) |
|---|---|---|
| Tabs | A tab view | A Material tab row |
| Cards | Group boxes | Material cards |
| Token and payload details | Collapsible sections | Encoded and decoded views; event details behind **Details** |
| Event-type picker | A grid of checkboxes | A column of checkboxes |
| Configuration override | `OIDC_CONFIG`, `~/.config/caep-demo/` (Linux) | A file pushed to `/sdcard/Android/data/net.rcbj.caepdemo/files/oidc_configuration.json` |
| Where it runs | macOS 14, or a Linux desktop as an AppImage | Android 9 or later; the Android emulator on a laptop, with `scripts/setup-emulator.sh` |
