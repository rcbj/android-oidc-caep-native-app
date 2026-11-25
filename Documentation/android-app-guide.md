# Building a native Android app with android-oidc-caep-native-app

This guide shows how to add OpenID Connect sign-in and CAEP to a native Android app with the library in this repository (package `net.rcbj.oidccaep`). By the end, your app signs people in through the system browser, keeps their tokens encrypted at rest and fresh, calls your APIs with sender-constrained tokens, and reacts within seconds when the identity provider reports a change about a signed-in user through CAEP.

The app is a **public client**: it has no client secret, because anything shipped in an APK can be read out of it. Sign-in happens in the person's browser through a **Custom Tab**, as RFC 8252 (OAuth 2.0 for Native Apps) requires. The app never sees the password, and never shows the provider's pages in a `WebView`.

The [API reference](reference.md) lists every option, method and event. This guide is the walkthrough. It explains which pieces to use, in what order, and why. The demo in this repository ([`demo/`](../demo)) is a working Jetpack Compose app built this way.

**Who this is for.** Android apps written in Kotlin, with Jetpack Compose or Views. The library needs Android 9 (API 28) or later, and is built against Android 17 (API 37.1). Everything that can suspend is a `suspend` function: call it from a coroutine (`viewModelScope`, `lifecycleScope`).

## Contents

1. [How the pieces fit together](#1-how-the-pieces-fit-together)
2. [Add the library](#2-add-the-library)
3. [Register the app at the identity provider](#3-register-the-app-at-the-identity-provider)
4. [Create oidc_configuration.json](#4-create-oidc_configurationjson)
5. [Create the client](#5-create-the-client)
6. [Where tokens and keys are kept](#6-where-tokens-and-keys-are-kept)
7. [Sign in](#7-sign-in)
8. [Call your APIs](#8-call-your-apis)
9. [Receive CAEP events](#9-receive-caep-events)
10. [Sign out](#10-sign-out)
11. [Errors](#11-errors)
12. [Manifest, backups and shrinking](#12-manifest-backups-and-shrinking)
13. [Security checklist](#13-security-checklist)
14. [Troubleshooting](#14-troubleshooting)

## 1. How the pieces fit together

| Piece | What it does |
|---|---|
| `OIDCAppConfiguration` | Reads the app's settings from `oidc_configuration.json` in the assets and creates the client. |
| `OIDCClient` | Sign-in (Authorization Code + PKCE, PAR, DPoP), ID token validation, refresh, UserInfo, sign-out. |
| `CustomTabsWebAuthenticator` | Shows the provider's pages in a Custom Tab, and returns the redirect to the app's private-use scheme. |
| `TokenManager` | Caches one person's tokens and refreshes them before they expire. |
| `AccountManager` | Several people signed in to one app, with one active account. Use it instead of `TokenManager` when you need that; it also suits a single account. |
| `SSFReceiver` | Subscribes to the identity provider's Shared Signals stream, polls it, validates each event and hands it to your handlers. |
| Stores | Where tokens and the DPoP key are kept: the Android Keystore (`AndroidKeystoreKeyStore`, `KeystoreTokenStore`), or memory. |

```
 Your Android app                                         Identity provider
 ────────────────                                         ─────────────────
 CustomTabsWebAuthenticator ── Custom Tab: sign-in ─────▶ authorization endpoint
        ▲                                                       │
        └──── redirect to com.example.myapp:/callback ◀─────────┘
 OIDCClient ──── PAR, token, UserInfo (DPoP proofs) ────▶ OpenID Connect endpoints
 AccountManager / TokenManager (Keystore-encrypted cache, refresh)
 SSFReceiver ──── create / read stream, poll ───────────▶ SSF transmitter
      ▲                                                       │
      └──────────── signed security events (SETs) ◀───────────┘
 your handlers: end the session, refresh tokens, ask for step-up, ...
 your APIs ◀──── fetchResource(): access token + DPoP proof
```

The identity provider is usually both the OpenID provider and the SSF transmitter. The receiver authenticates to the transmitter with the **signed-in person's own access token**, so it can only see that person's stream. An app has no public endpoint for the transmitter to push to, so delivery is always **poll** (RFC 8936).

## 2. Add the library

There is no published Maven artifact yet. Build the AAR from a checkout and add it with its four runtime dependencies:

```sh
git clone https://github.com/rcbj/android-oidc-caep-native-app.git
cd android-oidc-caep-native-app
./gradlew :library:assembleRelease          # library/build/outputs/aar/library-release.aar
```

Copy `library-release.aar` into your app module's `libs/` folder, then in the app's `build.gradle.kts`:

```kotlin
android {
    defaultConfig {
        // The redirect URI's private-use scheme (step 3). The library's manifest registers its redirect
        // activity for it; without this line the manifest merge fails.
        manifestPlaceholders["oidcRedirectScheme"] = "com.example.myapp"
    }
}

dependencies {
    implementation(files("libs/library-release.aar"))
    // An AAR file carries no dependency information, so the library's own dependencies are listed here.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    implementation("androidx.browser:browser:1.10.0")
}
```

The versions are the ones in the library's `gradle/libs.versions.toml` for the release you built. Versions are semantic-version tags on `main`; build from a tag for a reproducible app. While the version is 0.x, a new minor version may change the API.

The library needs JDK 17 to build and runs on API 28 and later. It brings the `INTERNET` permission and the `<queries>` entries Custom Tabs need on Android 11 and later through its manifest.

## 3. Register the app at the identity provider

Register your app as a **public client**:

| Setting | Value |
|---|---|
| Client type | public, `token_endpoint_auth_method: none` |
| Grant types | `authorization_code`, `refresh_token` |
| Response type | `code` |
| Redirect URI | a private-use scheme, e.g. `com.example.myapp:/callback` |
| Post-logout redirect URI | e.g. `com.example.myapp:/logged-out` |
| Allowed scopes | `openid profile email`, `offline_access` for refresh tokens, and the CAEP scopes below |

**The redirect URI.** RFC 8252 §7.1 gives a native app a **private-use URI scheme** named after a domain you control, in reverse order: `example.com` becomes `com.example`, and a scheme such as `com.example.myapp`. The redirect URI is that scheme, a colon, and **one** slash: `com.example.myapp:/callback`. The library refuses a scheme without a period, since a single word such as `myapp` could belong to any app. The scheme goes into the app's `manifestPlaceholders["oidcRedirectScheme"]` (step 2), which registers the library's `RedirectUriReceiverActivity` for it. The post-logout redirect URI uses the same scheme.

Other redirect URIs:

- **`https`** (Android App Links) is accepted by `OIDCClient`, but `CustomTabsWebAuthenticator` refuses it: it receives private-use schemes only.
- **Loopback** (`http://127.0.0.1:port/…`, RFC 8252 §7.3) works with `LoopbackWebAuthenticator`, which listens on the port while the browser is open. The library's live test uses it. On Android, prefer the private-use scheme: another app on the device could listen on the port first.

**No CORS.** A native app's requests are not subject to CORS, so the provider needs no web origin for it.

**TLS.** Every provider endpoint must be `https`. Loopback `http` (`localhost`, `127.0.0.1`) is allowed for development. The app must trust the provider's certificate, and so must the browser that shows the sign-in pages. For a provider with a private CA, name its root in `TrustedCertificates` (step 4) rather than turning verification off.

**CAEP scopes.** These are the CAEP Interoperability Profile's names:

| Scope | Lets the receiver |
|---|---|
| `ssf.read` | read its stream and its status, and poll for events |
| `ssf.manage` | everything `ssf.read` does, plus create, change or delete a stream, add or remove subjects, change the stream's status and request a verification event |

An app that only consumes a stream someone else created needs `ssf.read`. An app that creates its own stream, chooses its event types or adds the user as the stream's subject needs `ssf.manage`.

`CAEPEnabled` defaults to true, so a configuration that lists these scopes still receives events. Set it to false to turn off CAEP and RISC at an identity provider that does not implement Shared Signals: the receiver is not started, and `ssf.read` and `ssf.manage` are left out of the authorization request even when `Scopes` lists them.

### iya-sts

With iya-sts, both scopes are gated by role. A person is issued `ssf.read` only while two things are true: they are in the group `ssf-read`, and your application is an **application member** of the native role `SSF_READ`. `ssf.manage` works the same way through the group `ssf-manage` and the role `SSF_MANAGE`, which does not authorize `ssf.read`, so ask for both. Every realm has these roles and groups by default. Applications have to be added to the roles; nothing adds them for you.

[`scripts/register-iya-sts-client.mjs`](../scripts/register-iya-sts-client.mjs) does all of this for the demo, from the demo's `oidc_configuration.json`:

- registers the public client with the file's redirect and post-logout redirect URIs;
- adds it to `SSF_READ` and `SSF_MANAGE`;
- creates a test user in `ssf-read` and `ssf-manage`.

Pass `--config` to run it on your own app's file, or read it as an example of the management API calls involved. [Running the demo](../docs/demo.md) shows how to run it.

## 4. Create oidc_configuration.json

The app's OpenID Connect settings live in a JSON file in the app's assets: **`src/main/assets/oidc_configuration.json`**. Its keys are the Swift library's `OIDCConfiguration.plist` keys, so one set of settings reads the same on both platforms.

```json
{
  "MetadataURL": "https://idp.example.com/.well-known/openid-configuration",
  "ClientID": "my-native-app",
  "Scopes": ["openid", "profile", "email", "offline_access", "ssf.read", "ssf.manage"],
  "RedirectURI": "com.example.myapp:/callback",
  "PostLogoutRedirectURI": "com.example.myapp:/logged-out"
}
```

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `MetadataURL` | string | yes | — | The provider's metadata URL. It must contain `/.well-known/`, e.g. `…/.well-known/openid-configuration`. |
| `ClientID` | string | yes | — | The public client's `client_id`. |
| `Scopes` | array of strings, or a space-separated string | no | `openid profile email`, plus `offline_access` when the provider offers it | The scopes requested at sign-in. |
| `RedirectURI` | string | yes | — | A private-use scheme (`com.example.myapp:/callback`), or loopback with `LoopbackWebAuthenticator`. |
| `PostLogoutRedirectURI` | string | no | — | Where the provider returns after logout. Needed to sign out in the browser (step 10). |
| `Resource` | array or string | no | — | RFC 8707 resource indicators: the APIs the tokens are for. |
| `DPoP` | bool | no | `true` | Bind tokens to a key (RFC 9449). |
| `PAR` | string | no | `auto` | Pushed authorization requests: `auto`, `always` or `never`. |
| `IDTokenSignedResponseAlg` | string | no | `RS256` when the provider offers it, else the first algorithm it offers that the library verifies | The one ID token `alg` accepted. |
| `ACRValues` | string | no | — | `acr_values` for your sign-in requests. |
| `PrefersEphemeralWebBrowserSession` | bool | no | `false` | Ask the Custom Tab for ephemeral browsing (no shared cookies), where the browser supports it. |
| `SSFTransmitterIssuer` | string | no | the provider's issuer | The CAEP transmitter, when it is not the provider. |
| `CAEPEnabled` | bool | no | `true` | Receive CAEP and RISC events. `false` turns both off: the receiver is not started, and `ssf.read` and `ssf.manage` are left out of the authorization request, so the app can sign in at an identity provider that does not implement Shared Signals. |
| `TrustedCertificates` | array | no | — | PEM or DER files (or inline PEM) to trust for TLS: a private CA's root, or a whole chain. A relative path is an asset name (beside the configuration file); an absolute path is a file. See [Android and macOS](https://rcbj.github.io/android-oidc-caep-native-app/android.html#tls-trust). |
| `TrustSystemRoots` | bool | no | `true` | Whether the system's roots still count beside `TrustedCertificates`. |
| `InsecureSkipTLSVerification` | bool | no | `false` | Accept any TLS certificate. **Local test providers only.** |

`makeClient()` applies the first nine keys. When `CAEPEnabled` is false it also leaves `ssf.read` and `ssf.manage` out of the scopes on the authorization request. If nothing else was listed, the client's default applies: `openid profile email`, plus `offline_access` when the provider offers it, and that default does not add the SSF scopes. Sign-in does not fetch SSF transmitter metadata; only a started receiver does, and `false` means the receiver is not started. `ACRValues`, `PrefersEphemeralWebBrowserSession`, `SSFTransmitterIssuer` and `CAEPEnabled` are read into `OIDCAppConfiguration` for your code, and the examples below show where: `acrValues` in the sign-in options, `prefersEphemeralWebBrowserSession` through `makeAuthenticator(context)`, and `ssfTransmitterIssuer` and `caepEnabled` when starting the receiver. `TrustedCertificates`, `TrustSystemRoots` and `InsecureSkipTLSVerification` are applied by `makeTransport()`, which `makeClient()` calls when it is given no transport.

**Loading it.** `OIDCAppConfiguration.load(context)` reads `oidc_configuration.json` from the assets; `load(context, asset = "other.json")` reads another asset. `OIDCAppConfiguration.load(file)` reads a file anywhere, which is how the demo lets a configuration pushed to the device replace the built-in one. `OIDCAppConfiguration.fromJson(text)` parses text, and the data class's constructor (`OIDCAppConfiguration(metadataURL = URI(…), clientID = …, redirectURI = URI(…))`) builds it in code. Every loader throws an `OIDCError` with code `invalid_argument` naming the key at fault.

## 5. Create the client

```kotlin
import net.rcbj.oidccaep.*

val configuration = OIDCAppConfiguration.load(context)
val client = configuration.makeClient(dpopKeyStore = preferredDPoPKeyStore(context))
```

`makeClient()` fetches the provider's metadata from `MetadataURL` and creates an `OIDCClient`. Before it returns, it checks the provider:

- the metadata's `issuer` must be the one `MetadataURL` was built from (Discovery §4.3);
- every endpoint must use `https`;
- the provider must offer PKCE `S256` and accept public clients (`none`);
- it must sign ID tokens with an algorithm the library verifies;
- PAR is used when the provider offers it (`PAR` `auto`).

It also loads the DPoP key from the key store, or creates one there. **Pass `preferredDPoPKeyStore(context)`**: it returns an `AndroidKeystoreKeyStore`, which generates a P-256 key in the Android Keystore (StrongBox when the device has it, else the TEE) under the alias `<package>.oidc-dpop`. Without a key store, `makeClient()` uses a `MemoryKeyStore`: a new key every launch, which makes tokens cached across launches useless, because a DPoP-bound refresh token works only with the key it was bound to. Step 6 explains the stores.

Without a configuration file, create the client from options:

```kotlin
val client = OIDCClient.discover(
    metadataURL = URI("https://idp.example.com/.well-known/openid-configuration"),
    options = OIDCClientOptions(
        clientID = "my-native-app",
        redirectURI = URI("com.example.myapp:/callback"),
        postLogoutRedirectURI = URI("com.example.myapp:/logged-out"),
        dpop = DPoPOptions(keyStore = preferredDPoPKeyStore(context)),
    ),
)
```

`client.securityFeatures` summarizes the protections in effect (PKCE, PAR, DPoP algorithm and key thumbprint, whether the key is extractable). `AndroidKeystoreKeyStore.securityLevel()` says where the key lives (`STRONGBOX`, `TRUSTED_ENVIRONMENT`, `SOFTWARE`). The demo shows both as **Protections in effect**.

Create the client and the account manager once, in a `ViewModel` or your application object, not per screen: the account manager runs the background refresh, and the CAEP receiver polls from it.

## 6. Where tokens and keys are kept

| What | Default | Recommended on Android |
|---|---|---|
| Tokens, and `AccountManager`'s account list | `MemoryTokenStore` | `KeystoreTokenStore(context)`: encrypted at rest, kept across launches |
| The DPoP key | `MemoryKeyStore` (when `makeClient` is given none) | `preferredDPoPKeyStore(context)`: an `AndroidKeystoreKeyStore`, never extractable |
| A sign-in in progress (state, nonce, PKCE verifier) | `MemoryTransactionStore` | memory; the redirect comes back to the process that started the sign-in |

Both Android stores need a `Context`, so the library cannot choose them for you: pass them. Memory is the safe default for code that has none (the JVM unit tests).

**Tokens.** `KeystoreTokenStore` encrypts every value with AES-256-GCM under a key held in the Android Keystore (alias `<package>.oidc-tokens-key`; the key never leaves it), with the item's name as associated data, and keeps the ciphertext in the app's private `SharedPreferences` file `<package>.oidc-tokens`. A relaunch keeps every signed-in account. A value that cannot be decrypted (the key was deleted, the file restored from elsewhere) is ignored with a warning, and the account shows as `TOKENS_MISSING`.

**The DPoP key.** `AndroidKeystoreKeyStore` generates an ES256 key with purpose SIGN. The private key can be used to sign but never read out, not by the app and not by malware running as the app, so stolen access or refresh tokens are useless on any other device. It asks for StrongBox (a separate secure element) first, when the device has `FEATURE_STRONGBOX_KEYSTORE`, and falls back to the TEE. An emulator has neither, and reports `SOFTWARE`.

**Names.** The defaults are derived from the app's package name, so two apps never share items. To choose them yourself:

```kotlin
val keyStore = preferredDPoPKeyStore(context, alias = "com.example.myapp.dpop")
val client = configuration.makeClient(dpopKeyStore = keyStore)
val accounts = AccountManager(client, AccountManagerOptions(
    store = KeystoreTokenStore(context, fileName = "com.example.myapp.tokens", keyAlias = "com.example.myapp.tokens-key"),
))
```

**Other choices:**

- **Memory only:** `AccountManagerOptions(store = MemoryTokenStore())`. Nothing persists; after a relaunch, `resume` gets new tokens without a screen while the provider's session lasts.
- **Your own store:** implement `TokenStore` (`get`, `set`, `delete`, `isPersistent`) or `DPoPKeyStore` (`load`, `create`, `delete`, `supportedAlgorithms`, `isExtractable`).

`AccountManager` logs a warning when tokens go to persistent storage with DPoP off: anything that can read the store could use them anywhere.

## 7. Sign in

```kotlin
val authenticator = configuration.makeAuthenticator(activity)   // a CustomTabsWebAuthenticator
val accounts = AccountManager(client, AccountManagerOptions(store = KeystoreTokenStore(context)))
accounts.restore()             // the accounts from the last launch, and the active one

viewModelScope.launch {
    try {
        val result = accounts.signIn(authenticator, AuthorizationRequestOptions(acrValues = configuration.acrValues))
        println("Signed in as ${result.account.name ?: result.account.sub}")
    } catch (e: OIDCError) {
        if (!e.isUserCancellation) showError(e)     // the person closed the Custom Tab: never mind
    }
}
```

`signIn(authenticator)` builds the authorization request (PKCE, `state`, `nonce`, PAR, `dpop_jkt`), opens it in a Custom Tab, waits for the redirect, and completes the sign-in: the `state` is checked, the code is redeemed with the PKCE verifier and a DPoP proof, and the ID token is validated. The account is cached and becomes the active account.

**How the redirect comes back.** `CustomTabsWebAuthenticator` starts the library's `AuthorizationManagementActivity`, which opens the Custom Tab in the app's task. When the provider redirects to `com.example.myapp:/callback`, Android delivers it to `RedirectUriReceiverActivity` (registered for your scheme by the manifest placeholder), which hands it back with `FLAG_ACTIVITY_CLEAR_TOP`, closing the tab. A return to the app with no redirect (the person closed the tab, or pressed back) is a cancellation: `OIDCError.isUserCancellation` is true. Give `makeAuthenticator()` an `Activity` when you have one; with an application context the tab starts in a new task.

Leave `PrefersEphemeralWebBrowserSession` off unless you have a reason: sharing the browser's session is what makes single sign-on, `prompt=none` and several accounts work. Ephemeral browsing is honoured only by browsers that implement it.

**Choosing the request.** Each is an extension function that takes the authenticator:

| Call | Request | Use |
|---|---|---|
| `signIn(authenticator)` | the provider decides | Its account picker when several people are signed in there. |
| `chooseAccount(authenticator)` | `prompt=select_account` | Always the provider's picker. |
| `addAccount(authenticator)` | `prompt=login` | A fresh sign-in, added as another account. |
| `resume(key, authenticator)` | `prompt=none`, naming the account | New tokens without a screen while its session at the provider lasts. |
| `reauthenticate(key, authenticator)` | `prompt=login`, naming the account | Sign that person in again, e.g. step-up with `acrValues` or `maxAge`. |

`resume` and `reauthenticate` send `login_hint` and the cached `id_token_hint`. If the provider signs in somebody else, the sign-in is refused with `account_mismatch` and the tokens it got are revoked.

**After a relaunch.** `restore()` loads the account list from the store and reactivates the account that was active, refreshing its tokens if they are due. An account whose cached tokens can't be used has status `TOKENS_MISSING`; get new ones without a screen, and fall back to a visible sign-in:

```kotlin
val account = accounts.active()
if (account != null && account.status == Account.Status.TOKENS_MISSING) {
    try {
        accounts.resume(account.key, authenticator)
    } catch (e: OIDCError) {
        if (needsInteraction(e)) accounts.reauthenticate(account.key, authenticator) else throw e
    }
}
```

**The provider's time limit.** The whole sign-in, from opening the tab to the redirect, must finish within the transaction's lifetime (`transactionTTL`, 10 minutes) and, with PAR, within the provider's `request_uri` lifetime. iya-sts's default is 60 seconds (`oauth2.parRequestUriLifetimeS`), which is short for a person who also changes a password or answers a second factor; raise it on the provider when sign-ins time out with `invalid_request_uri`.

### Several accounts in one app

Some providers keep several people signed in in one browser and let each request say which one it is for. iya-sts does this with `authn.multipleAccounts`, on by default. `AccountManager` is the app's side of that:

- **One token cache.** Every signed-in account's tokens are cached until that account is signed out or its session ends, so any of them can become active without a password.
- **One active account.** Only its tokens can be reached: `getTokenSet()` takes no account. Only its tokens are refreshed in the background. The others are **dormant**: stored, not used, not refreshed.

```kotlin
accounts.list()                       // every account, in the order added
accounts.activate(otherKey)           // the previous account goes dormant
val tokenSet = accounts.getTokenSet() // the ACTIVE account's, refreshed when due
```

**Activating** a dormant account refreshes its tokens first if they are due, then runs `onActivate` (step 9), and only then makes it active. If either fails, the previously active account is reactivated and the error is thrown.

**Statuses:** `SIGNED_IN`, `TOKENS_MISSING`, `SIGNED_OUT` and `ENDED` (ended by the provider, a security event or a refused refresh; `endedReason` says why). Signed-out accounts stay listed for `rememberSignedOutDays` (default 30). Past `maxAccounts` (default 10), the account that left longest ago is forgotten; when all of them are signed in, a new sign-in is refused (`too_many_accounts`).

**Following changes.** `accounts.events` delivers `Added`, `Updated`, `Activated`, `Refreshed`, `SignedOut`, `Ended`, `Forgotten`, `ActivationError` and `Change`, as callbacks (`subscribe { }`) or as a `Flow` (`flow()`):

```kotlin
viewModelScope.launch {
    accounts.events.flow().collect { event ->
        when (event) {
            is AccountManager.Event.Ended -> show("${event.account.name ?: event.account.sub}: ${event.reason ?: "session ended"}")
            AccountManager.Event.Change -> reload()
            else -> {}
        }
    }
}
```

`subscribe { }` calls back on whatever thread emitted the event; hop to the main thread before touching views (Compose state may be written from any thread).

### One person only

Without an account list, use `OIDCClient` and `TokenManager` directly:

```kotlin
val tokens = TokenManager(client, store = KeystoreTokenStore(context))   // auto-refreshing
val result = client.authorize(authenticator)
tokens.set("user", result.tokenSet)
val tokenSet = tokens.getTokenSet("user")     // refreshed first when (nearly) expired
```

## 8. Call your APIs

`fetchResource` sends a request with the access token. A DPoP-bound token gets a fresh proof for that method and URL. When the resource server asks for a DPoP nonce, it retries once with it.

```kotlin
val tokenSet = accounts.getTokenSet()
val response = client.fetchResource(tokenSet, URI("https://api.example.com/me"))
if (response.isOK) {
    val me = parseJson(response.text)
}
```

It takes `method`, `headers` and `body` too. To send the request with your own OkHttp or Retrofit client, ask for the headers instead:

```kotlin
val url = URI("https://api.example.com/orders")
val request = Request.Builder().url(url.toString()).post(body)
for ((name, value) in client.resourceHeaders(tokenSet, method = "POST", url = url)) {
    request.header(name, value)    // authorization, and dpop when bound
}
```

Make the headers again for every request: a DPoP proof is for one request only. `resourceHeaders` doesn't retry on a nonce challenge; `fetchResource` does. In an OkHttp `Interceptor`, call `accounts.getTokenSet()` with `runBlocking` only off the main thread, since it may refresh.

**UserInfo.** `client.userinfo(tokenSet)` returns the claims, after checking that their `sub` is the ID token's.

**A 401 from your API** usually means the access token expired or was revoked. Call `accounts.refresh()` and retry once. If the refresh fails with `invalid_grant`, the account's tokens are dropped and it is ended; ask the person to sign in again.

## 9. Receive CAEP events

### Wire a receiver to the active account

Each account has its own stream at the transmitter: iya-sts gives a stream created with a person's token to that person, and sends it only events about them. So the receiver follows the active account. `AccountManager`'s three hooks are where it starts and stops.

`CAEPEnabled` defaults to true. Set it to false to turn off CAEP and RISC at an identity provider that does not implement Shared Signals. Do not start the receiver (the example below already checks `configuration.caepEnabled`), and `makeClient()` leaves `ssf.read` and `ssf.manage` out of the authorization request. Sign-in itself does not read `/.well-known/ssf-configuration`.

- **`onActivate`** runs before an account becomes active, with access to its tokens. Start its receiver here with `catchUp = true`, so the events queued while it was dormant are acted on before the account is used.
- **`onDeactivate`** runs when it stops being active. Stop polling; its stream keeps queueing.
- **`onLeave`** runs when it is signed out or ended, while its tokens still work. Delete its stream.

The receiver's handlers call `accounts.end(key, reason)` to end the account an event is about. That runs `onLeave` and `onDeactivate` **while the handler is still running**. Calling `SSFReceiver.stop()` there is safe: from inside a handler it returns at once, and the poll running the handler sends the last acknowledgements when it finishes.

```kotlin
import net.rcbj.oidccaep.*

/** The active account's SSF receiver. */
class Signals(
    private val client: OIDCClient,
    private val transmitter: String,
    private val scope: CoroutineScope,
    private val stepUp: suspend (key: String, why: String) -> Unit,
) {
    lateinit var accounts: AccountManager
    private var receiver: SSFReceiver? = null
    private var key: String? = null

    /** onActivate: open the account's stream and act on what it queued while it was dormant. */
    suspend fun start(account: Account, access: AccountAccess) {
        val r = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer = transmitter,
            // Every call to the transmitter carries this person's token, with a DPoP proof when bound.
            authorization = SSFAuthorization.oidc(client) { access.getTokenSet() },
        ))
        register(r, account, access)
        receiver = r
        key = account.key
        try {
            r.start(catchUp = true)
            runCatching { r.addSubject(Subject.issSub(account.iss, account.sub)) }   // needs ssf.manage
        } catch (e: Exception) {
            println("CAEP is not running for ${account.sub}: $e")
        }
        // A handler may have ended the account during the catch-up, which stopped this receiver.
        if (receiver !== r) r.stop()
    }

    /** onDeactivate. */
    fun stop() {
        val r = receiver ?: return
        receiver = null
        key = null
        scope.launch { r.stop() }
    }

    /** onLeave: the account's tokens still work, so its stream can be deleted (needs ssf.manage). */
    suspend fun leave(account: Account) {
        val r = receiver ?: return
        if (key != account.key) return
        runCatching { r.deleteStream() }
        stop()
    }

    private fun register(r: SSFReceiver, account: Account, access: AccountAccess) {
        val key = account.key
        val identity = account.identity
        // Act only on events about this account: another of the person's sessions is not this one.
        fun mine(event: SecurityEvent) = subjectMatches(event.subject, identity)
        r.onSessionRevoked { event ->
            if (mine(event)) end(key, event.reasonUser?.get("en") ?: "The session was revoked.")
        }.onTokenClaimsChange { event ->
            if (mine(event)) access.getTokenSet(forceRefresh = true)
        }.onCredentialChange { event ->
            val change = event.payload.string("change_type")
            if (mine(event) && change in setOf("revoke", "delete")) end(key, "A credential was ${change}d. Sign in again.")
        }.onAssuranceLevelChange { event ->
            if (mine(event) && event.payload.string("change_direction") == "decrease") stepUp(key, "Assurance dropped.")
        }.onDeviceComplianceChange { event ->
            if (mine(event) && event.payload.string("current_status") == "not-compliant") end(key, "This device no longer meets policy.")
        }.onRiskLevelChange { event ->
            if (!mine(event)) return@onRiskLevelChange
            when (event.payload.string("current_level")) {
                "HIGH" -> end(key, "Unusual activity was detected.")
                "MEDIUM" -> stepUp(key, "The risk level was raised.")
            }
        }.onError { error, context ->
            println("CAEP ${context.phase.value} ${error.code ?: ""} ${error.message}")
        }
    }

    private suspend fun end(key: String, reason: String) {
        runCatching { accounts.end(key, reason) }
    }
}
```

Create it before the account manager, give the manager the hooks, then attach it and restore:

```kotlin
val signals = Signals(client, configuration.ssfTransmitterIssuer ?: client.issuer, viewModelScope) { key, why ->
    model.requireStepUp(key, why)
}
val caep = configuration.caepEnabled
val accounts = AccountManager(client, AccountManagerOptions(
    store = KeystoreTokenStore(context),
    onActivate = { account, access -> if (caep) signals.start(account, access) },
    onDeactivate = { signals.stop() },
    onLeave = { account, _ -> signals.leave(account) },
))
signals.accounts = accounts
accounts.restore()             // runs onActivate for the account that was active
```

`model.requireStepUp` stands for your UI: show a banner, and call `accounts.reauthenticate(key, authenticator, AuthorizationRequestOptions(acrValues = …))` when the person agrees.

Here a receiver that fails to start is reported and the account is activated anyway. To refuse activation instead, rethrow from `start`: an exception thrown by `onActivate` aborts the activation.

`start()` either opens an existing stream or creates one:

- **Opening an existing stream:** pass its id as `SSFReceiverConfiguration(streamID = …)`. Keep the id, for example in `SharedPreferences`, to reopen the same stream later.
- **Creating a stream:** this needs `ssf.manage`. If the transmitter refuses the create because the person already has streams (HTTP 409, or HTTP 403 `access_denied` when they hold as many as it allows; iya-sts allows `ssf.maxStreams`, 25), one of their streams is reused and re-pointed at this receiver: the one whose `description` is this receiver's, else the first. So an app that lost its stored stream id (a reinstall, cleared data) doesn't fail at the limit.

With `ssf.read` only, you can't create a stream. Find one with `listStreams()` and pass its id as `streamID`.

### Choose the event types

A new stream asks for every CAEP event type (`CAEP.all`) unless you pass `eventsRequested`. To change an existing stream's types (needs `ssf.manage`):

```kotlin
receiver.updateStream(jsonObjectOf("events_requested" to listOf(CAEP.SESSION_REVOKED, CAEP.CREDENTIAL_CHANGE, CAEP.RISK_LEVEL_CHANGE)))
val delivered = receiver.stream?.get("events_delivered")   // what the transmitter will actually send
```

The transmitter decides `events_delivered`: the types you asked for that it supports. The scopes control which operations you may perform on the stream, not which event types you may receive. The demo's **CAEP events** tab lets the person tick types and applies them with this call. `getStatus()` returns the stream's status, and `requestVerification()` asks the transmitter for a verification event and returns it once it arrives.

### Handle the events

Each handler gets a validated `SecurityEvent`: `type`, `name`, `payload`, `subject`, `eventTimestamp`, `initiatingEntity`, `reasonAdmin`, `reasonUser`, `jti` and the whole SET (`set`, `raw`). A handler that throws leaves the event for the transmitter to send again. Handlers are `suspend` functions and run on the receiver's own dispatcher, not the main thread.

Which events need action is your policy. These are reasonable defaults, and the ones the demo uses:

| Event | Reasonable reaction |
|---|---|
| session-revoked | End the account and discard its tokens: `accounts.end(key, reason)`. |
| token-claims-change | Refresh tokens so the new claims (`payload["claims"]`) take effect. |
| credential-change | Revoked or deleted: end the account. Otherwise tell the person. |
| assurance-level-change | Decrease: require step-up before sensitive actions. |
| device-compliance-change | Not compliant: end the account, or limit what the app allows. |
| risk-level-change | HIGH: end the account. MEDIUM: require step-up. |
| session-established, session-presented | Informational; record or display them. |

**Check who an event is about.** A stream can carry events about other sessions of the same person. Compare the event's subject with the account before acting: `subjectMatches(event.subject, account.identity)`, or `accounts.accountsForSubject(subId)` to find every listed account it is about. An email or phone number subject counts only when the ID token said it was verified. An event that names a session matches only the account holding that `sid`.

### Add your own logic for every event

`onEventReceived` runs once for every accepted event, before the typed handlers. By default it is `logEventReceived`, which logs the event's name and `jti` through `OIDCLog`, leaving out the payload and subject, which can carry personal data. Put logging, auditing or analytics here:

```kotlin
val configuration = SSFReceiverConfiguration(
    transmitterIssuer = transmitter,
    authorization = SSFAuthorization.oidc(client) { access.getTokenSet() },
    onEventReceived = { event ->
        logEventReceived(event)                 // keep the log line, or drop it
        audit.record(event.name, event.subject, event.eventTimestamp)
    },
)
```

Pass `onEventReceived = null` to turn it off. If it throws, `onError` gets the error with phase `HOOK`, and the typed handlers still run. `OIDCLog.handler` decides where the library's log lines go (Logcat, tag `OIDCCAEPClient`, by default); replace it to send them to Timber or nowhere.

### What the receiver checks for you

Every event (a signed SET) is refused unless all of these hold:

- **The signature** verifies against the transmitter's keys, uses an asymmetric algorithm, and has `typ: secevent+jwt`.
- **`iss`** is the transmitter.
- **`aud`** is your stream's.
- **`iat`** isn't in the future. There's no age limit by default, so events queued while nobody was polling are still acted on when the receiver catches up.
- **`events`** holds exactly one event, and a stream event (verification, stream-updated) names this stream.
- **`jti`** hasn't been seen before. A repeat is dropped.

The receiver is careful about what it tells the transmitter, because an acknowledged event, or one reported as an error, is never sent again:

- **An invalid event** goes to `onError`, is reported back to the transmitter on the next poll, and never reaches your handlers.
- **An event that couldn't be checked** for a reason that may pass (a network error fetching the keys, a key the cached set doesn't hold yet) is left for the transmitter to send again.
- **An event is acknowledged only after your handlers succeed.** If one throws, the event comes back on a later poll, up to `maxDeliveryAttempts` times (default 5). Write handlers so that running twice is harmless.
- **The poll URL** must use https and be at the transmitter's origin, because every poll carries the person's access token.

Without an `onError`, errors are logged through `OIDCLog`, so a lost event always leaves a trace.

### Stop and clean up

```kotlin
receiver.stop()                       // stop polling; the stream keeps queueing events
receiver.stop(deleteStream = true)    // with ssf.manage: also remove the stream
```

`stop()` sends the acknowledgements still owed. Called from inside a handler, it leaves that to the poll running the handler.

**When to delete the stream, and when not:**

- **Signing out or removing an account:** delete it when the token holds `ssf.manage` (`stop(deleteStream = true)`, in `onLeave` while the tokens still work); otherwise just stop polling. The demo does this.
- **The app goes to the background, is killed, or its account is made dormant:** don't delete it. The transmitter keeps queueing events for it, and `start(catchUp = true)` acts on them when the app comes back. Keep the stream id (the demo uses `SharedPreferences`) and pass it as `streamID` on the next launch. The receiver polls from a coroutine, so it stops when the process does; it is not a background service.
- **An app that never comes back** (uninstalled) leaves its stream behind. The transmitter removes it: iya-sts deletes a person's poll stream after `ssf.personStreamInactivityTimeoutS` (a day by default) with no poll ([iya-sts#1094](https://github.com/rcbj/iya-sts/issues/1094)). Within that time, a reinstalled app that lost the id reuses the stream (see above).

## 10. Sign out

```kotlin
try {
    accounts.signOut(authenticator = authenticator)        // the active account
} catch (e: OIDCError) {
    if (!e.isUserCancellation) throw e
    // Signed out of the app already; the provider's session was left as it was.
}
```

`signOut(authenticator = …)` signs the account out of the app first: `onLeave` runs, its tokens are revoked at the provider (RFC 7009) and removed from the store, and it stays listed as `SIGNED_OUT`. If it was the active account, the most recently added signed-in account becomes active. Then it opens the provider's logout page in a Custom Tab (RP-Initiated Logout), naming that account's ID token so the provider ends that session only, and checks the `state` it returns with.

- Pass a key to sign out another account: `accounts.signOut(key, authenticator)`.
- `accounts.signOutAll(authenticator)` signs every account out, with one logout request that names nobody, so the provider asks which sessions to end.
- The browser step needs `PostLogoutRedirectURI`, so that the tab closes when the provider is done. Without one (or without an `end_session_endpoint`), the extension signs out locally and opens no tab.
- To sign out of the app only and leave the provider's session: `accounts.signOut(endSession = false)`.

With `TokenManager`, do the same steps yourself:

```kotlin
val tokenSet = tokens.getTokenSet("user")
val logout = client.createEndSessionRequest(idTokenHint = tokenSet.idToken)
tokens.delete("user", revoke = true)
client.endSession(authenticator, logout)
```

## 11. Errors

Every error the library throws is an `OIDCError`. Match on `kind` and `code`, not on the message.

| `kind` | When | Examples of `code` |
|---|---|---|
| `OAUTH` | The provider answered with an OAuth error. `oauthErrorDescription` and `errorURI` hold the rest. | `login_required`, `consent_required`, `account_selection_required`, `invalid_grant`, `invalid_scope` |
| `VALIDATION` | A response, token or provider setting failed a check. | `state_missing`, `state_mismatch`, `state_reused`, `transaction_expired`, `issuer_mismatch`, `nonce_mismatch`, `invalid_id_token`, `acr_mismatch`, `account_mismatch`, `front_channel_token`, `insecure_endpoint`, `insecure_redirect_uri`, `pkce_not_supported`, `public_client_not_supported`, `dpop_downgrade` |
| `SET_VALIDATION` | A security event was refused. Reported to `onError`. | `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` |
| `SSF` | The transmitter can't be used as configured, or a stream call failed. | `insecure_endpoint`, `untrusted_endpoint`, `verification_timeout`, `handler_failed`, `http_error` |
| `GENERAL` | Everything else. | `user_cancelled`, `web_authentication_failed`, `network_error`, `http_error`, `store_error`, `keystore_unavailable`, `no_tokens`, `not_active`, `too_many_accounts`, `invalid_argument` |

Two helpers:

- **`error.isUserCancellation`** is true when the person closed the Custom Tab (`user_cancelled`). Treat it as "never mind", not as a failure.
- **`needsInteraction(error)`** is true when only a visible sign-in can fix the problem: `login_required`, `interaction_required`, `consent_required` or `account_selection_required`. When it is true, sign the person in with a screen rather than retrying silently.

An error from a `resume` or `reauthenticate` carries the account it was for in `error.account`, and the request's `context` in `error.context`. `status` and `response` hold the HTTP status and body when there was one, and `cause` the underlying exception.

## 12. Manifest, backups and shrinking

**Manifest.** The library's manifest is merged into the app's. It adds:

- the `INTERNET` permission;
- `<queries>` for `android.support.customtabs.action.CustomTabsService` and for browsable `https` links, so the app can find a browser on Android 11 and later;
- `AuthorizationManagementActivity` (not exported, `singleTask`, translucent) and `RedirectUriReceiverActivity` (exported, with an intent filter for `${oidcRedirectScheme}`).

The only thing the app supplies is `manifestPlaceholders["oidcRedirectScheme"]`. Don't declare another activity for the same scheme: Android would ask the person which app should open the redirect.

**Backups.** Turn off backup of the token store, or exclude it. The encryption key lives in this device's Keystore and is never backed up, so restored ciphertext could not be decrypted anyway, and a restored account list would point at tokens that are gone. The demo sets `android:allowBackup="false"` and `android:dataExtractionRules`:

```xml
<data-extraction-rules>
    <cloud-backup><exclude domain="sharedpref" path="." /></cloud-backup>
    <device-transfer><exclude domain="sharedpref" path="." /></device-transfer>
</data-extraction-rules>
```

Narrow the `path` to the token file (`<package>.oidc-tokens.xml`) if the app has other preferences it wants backed up.

**Shrinking (R8).** The library uses no reflection and no serialization plugin, so it needs no keep rules of its own (`consumer-rules.pro` is empty). OkHttp, kotlinx.serialization and kotlinx.coroutines ship their own rules in their artifacts.

**Process death.** A sign-in in progress is held in memory (`MemoryTransactionStore`). If Android kills the app's process while the Custom Tab is open, the redirect arrives at a new process that holds no transaction, and the sign-in is lost: the management activity finishes quietly and the person starts again. A custom `TransactionStore` that persists transactions could carry a sign-in across, but the suspended `signIn` call that was waiting for it is gone with the process.

## 13. Security checklist

- [ ] The client is public. The app holds no secret.
- [ ] The redirect URI is a private-use scheme in reverse-domain form that you control, registered exactly at the provider and set in `manifestPlaceholders["oidcRedirectScheme"]`.
- [ ] Sign-in happens in a Custom Tab (`CustomTabsWebAuthenticator`), never in a `WebView`.
- [ ] DPoP is on, and `makeClient` is given `preferredDPoPKeyStore(context)`.
- [ ] Tokens are in `KeystoreTokenStore`, and the token file is excluded from backups.
- [ ] The app asks for only the scopes it uses. `ssf.manage` is only for apps that manage their own stream.
- [ ] The receiver catches up (`start(catchUp = true)`) in `onActivate`, before a restored account is used.
- [ ] CAEP handlers check `subjectMatches()` before acting, and fail safe.
- [ ] Signing out revokes tokens, deletes or stops the stream, and clears any stored events.
- [ ] `InsecureSkipTLSVerification` is never set in a release build; a private CA is named in `TrustedCertificates`.

## 14. Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Manifest merger failed : Attribute data@scheme at AndroidManifest.xml requires a placeholder substitution but no value for &lt;oidcRedirectScheme&gt; is provided." | The app has no `manifestPlaceholders["oidcRedirectScheme"]` (step 2). |
| `invalid_argument`: "No oidc_configuration.json in the app's assets" | The file isn't in `src/main/assets/`, or another asset name was meant: `load(context, asset = …)`. |
| `invalid_argument`: "MetadataURL must be the provider's metadata URL" | `MetadataURL` is the issuer. Use the full `…/.well-known/openid-configuration` URL. |
| `issuer_mismatch` at `makeClient` | The metadata's `issuer` isn't the one its URL was built from. On an emulator, reach a provider on the host with `adb reverse tcp:<port> tcp:<port>` and `https://localhost:<port>`, not `10.0.2.2`, so the issuer matches. |
| `network_error` on discovery, token or SSF calls | The app doesn't trust the provider's certificate (add its root to `TrustedCertificates`), the provider isn't reachable from the device, or the app lacks `INTERNET` (the library's manifest adds it). |
| `insecure_endpoint` / `insecure_redirect_uri` | An endpoint isn't `https`, or the redirect URI's scheme has no period (`myapp:/callback`). Use `com.example.myapp:/callback`. Only loopback may use `http`. |
| `invalid_argument`: "A Custom Tab returns to the app through a private-use scheme" | The redirect URI is `http(s)://…`. Use a private-use scheme with `CustomTabsWebAuthenticator`, or `LoopbackWebAuthenticator` for loopback. |
| The provider shows "invalid redirect_uri" in the browser | The URI in the configuration isn't registered exactly as written at the provider. |
| The browser shows a certificate warning | The browser does not trust the provider's CA. On a device, install the CA; on the emulator, `scripts/setup-emulator.sh` tells Chrome to trust iya-sts's CA keys. |
| Chrome asks "Continue to <app>?" before returning | The redirect was not started by a user gesture (a script clicked the last button). A person tapping the button is not asked. |
| `web_authentication_failed` | No browser is installed, or the tab could not start. |
| `invalid_request_uri` / "The request_uri has expired" in the browser | The sign-in took longer than the provider's PAR lifetime. Raise it at the provider (iya-sts: `oauth2.parRequestUriLifetimeS`), or set `PAR` to `never` if the provider allows it. |
| `public_client_not_supported` / `pkce_not_supported` | The provider's metadata doesn't list `none` in `token_endpoint_auth_methods_supported`, or `S256` in `code_challenge_methods_supported`. |
| `dpop_not_supported` | The provider accepts no DPoP algorithm the key store creates. `AndroidKeystoreKeyStore` creates ES256 only; `MemoryKeyStore` creates ES256, ES384 and ES512. |
| Every account is signed out after a relaunch | `makeClient` was given no key store, so the DPoP key was in memory and the cached tokens can't be refreshed; or the token store is `MemoryTokenStore`. |
| `keystore_unavailable` | The Keystore could not create the DPoP key (rare; seen on some emulator images and devices with a broken Keystore). |
| `state_mismatch` or `transaction_expired` | The sign-in was started in a process that has since died, or took longer than 10 minutes. Start again. |
| `invalid_scope`, or a scope missing from the token | The client isn't allowed that scope, or (iya-sts) the person or application lacks the role. iya-sts logs `STS-ADMIN-0821` saying which condition failed. |
| The SSF calls answer 401 or 403 | The access token lacks `ssf.read` / `ssf.manage`, or the stream belongs to somebody else. |
| `untrusted_endpoint` | The stream's poll URL isn't at the transmitter's origin. Add its origin to `trustedPollOrigins` if it is legitimately elsewhere. |
| No events arrive | The stream doesn't ask for that type (`stream["events_delivered"]`), has no subject, or isn't polling (`onError` with phase `POLL`). |
| `account_mismatch` | A request that named an account came back signed in as somebody else. The tokens were revoked; ask the person to sign in as the named account. |

To check a setup end to end, run the demo against your provider ([Running the demo](../docs/demo.md)), and send test events from the provider's admin console or API.
