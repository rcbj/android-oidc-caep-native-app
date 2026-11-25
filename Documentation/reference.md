# android-oidc-caep-native-app reference

An OpenID Connect client library for **native Android apps**, in Kotlin, configured from the provider's metadata document. It runs as a **public client**: no client secret, and `token_endpoint_auth_method: none`. It covers:

- signing users in through the system browser (a Custom Tab);
- caching tokens encrypted at rest and refreshing them before they expire;
- subscribing to **CAEP** events through the OpenID Shared Signals Framework, with **one handler per CAEP event**.

It is the Kotlin port of the Swift library [swift-oidc-caep-native-app](https://rcbj.github.io/swift-oidc-caep-native-app/), and keeps its names where Kotlin allows; [Android and macOS](https://rcbj.github.io/android-oidc-caep-native-app/android.html) lists every difference. Everything is in the package `net.rcbj.oidccaep`. It needs Android 9 (API 28) or later. Its dependencies are kotlinx.coroutines, kotlinx.serialization-json, OkHttp and androidx.browser. The core is plain JVM code and is unit-tested on the JVM; only the Keystore stores and the Custom Tab authenticator need Android.

**New to the library?** [Building a native Android app](android-app-guide.md) walks through it step by step: registering the app, the configuration file, sign-in, storage, calling APIs, CAEP events, sign-out and the manifest. This page is the reference. The [Dokka reference](https://rcbj.github.io/android-oidc-caep-native-app/api/) documents every public declaration.

## Installing

There is no published Maven artifact yet. Build the AAR from a release tag and add it with the library's dependencies:

```sh
./gradlew :library:assembleRelease     # library/build/outputs/aar/library-release.aar
```

```kotlin
android { defaultConfig { manifestPlaceholders["oidcRedirectScheme"] = "com.example.myapp" } }

dependencies {
    implementation(files("libs/library-release.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    implementation("androidx.browser:browser:1.10.0")
}
```

`oidcRedirectScheme` is the scheme of the redirect URI; the library's manifest registers its redirect activity for it, and the manifest merge fails without it.

**Versions** are semantic-version tags on `main`. While the version is 0.x a minor version may change the API.

## Security features

These follow RFC 9700 (the OAuth 2.0 Security Best Current Practice), RFC 8252 (OAuth 2.0 for Native Apps) and OpenID Connect Core.

| Protection | What the library does |
|---|---|
| **System browser** | `CustomTabsWebAuthenticator` shows the provider's pages in a Custom Tab, in the person's default browser (RFC 8252 §8.12). The app never sees the password, and there is no `WebView`. The browser's session is shared, so single sign-on, `prompt=none` and several accounts work; `prefersEphemeralWebBrowserSession` asks for ephemeral browsing where the browser supports it. Closing the tab is `user_cancelled`. |
| **Redirect URIs** | A private-use scheme in reverse-domain form (`com.example.app:/callback`, RFC 8252 §7.1): the scheme must contain a period and the URI no fragment. `https` and loopback `http` are also accepted by the client. `CustomTabsWebAuthenticator` takes a private-use scheme only; `LoopbackWebAuthenticator` takes loopback. A redirect is matched to the sign-in waiting for it by scheme and path. |
| **Authorization Code + PKCE** | Uses only `response_type=code`, with PKCE `S256`. It refuses an OP whose metadata doesn't offer S256 (downgrade protection), or doesn't accept public clients (`none`). |
| **`state`** | A new random 256-bit value per request, kept with the transaction in memory (`MemoryTransactionStore`). On return, `state` is **required** and compared in constant time, and the transaction is **single use** (a replayed response is refused: `state_reused`). It **expires** after `transactionTTL` (default 10 minutes) and is **bound to the issuer and client** that started it. It is checked *before* an error response is reported. |
| **`nonce`** | A new random 256-bit value per request, compared in constant time with the ID token's `nonce`. |
| **Mix-up defence** | RFC 9207: the `iss` response parameter must match, and is required when the OP advertises it. Transactions are bound to their issuer. |
| **Authorization response hygiene** | Refuses tokens in the front channel (`access_token`, `id_token` and so on, including in the fragment) and repeated parameters. |
| **PAR** (RFC 9126) | The authorization request is pushed to the OP, so only `client_id` and `request_uri` pass through the browser. Used automatically when advertised (`par = PARMode.AUTO`), and required when the OP sets `require_pushed_authorization_requests`. |
| **DPoP** (RFC 9449) | Access and refresh tokens are bound to a key. `AndroidKeystoreKeyStore` generates it in the **Android Keystore**, in StrongBox when the device has it, else the TEE: the app can ask it to sign but nothing can read it out, so stolen tokens are useless on any other device. `preferredDPoPKeyStore(context)` returns one. The authorization code is bound too (`dpop_jkt`). Proofs are sent to the token endpoint, UserInfo, the SSF endpoints and your own APIs (`fetchResource`). Server nonces are handled (one retry on `use_dpop_nonce`). With DPoP on, a `Bearer` token response is refused (`requireDPoP`, default on), and a DPoP-bound grant is never refreshed into a Bearer one. |
| **ID token validation** | Covers everything in OIDC Core §3.1.3.7: signature against the JWKS with the expected `alg` only, `iss`, `aud`, `azp`, `exp`, `iat` (no older than `maxIDTokenAge`), `nonce`, `at_hash`, `max_age`/`auth_time`, and the refresh rules in §12.2. It also refuses other JWT types presented as ID tokens (`typ` `at+jwt`, `logout+jwt` and so on), unknown `crit` headers, and an `acr` outside the requested `acr_values` (`enforceACR`). Signatures are verified with the platform's JCA: RSA (PKCS#1 v1.5 and PSS), ECDSA P-256/384/521, and Ed25519 where the platform provides it. |
| **TLS** | Every OP endpoint, every SSF transmitter URL (including the JWKS and the stream's poll endpoint), the registration endpoint and `registration_client_uri` must use `https`. Loopback `http` is allowed for local development. `TLSTrust` adds a private CA's root, or a whole chain, as trust anchors, with or without the system roots; the host name is still checked. |
| **HTTP** | `OkHttpTransport` has no cookie jar and no cache, and never follows a redirect. |
| **Audience-restricted tokens** | RFC 8707 resource indicators (`resource`) on the authorization, token and refresh requests. |
| **Refresh tokens** | Rotation is handled. Concurrent refreshes of one key are merged into one request, so rotation stays safe. With DPoP, refresh tokens are sender-constrained, as RFC 9700 §2.2.2 recommends for public clients. A refreshed ID token must keep the original `iss`, `sub`, `aud` and `azp` (OIDC Core §12.2). A deletion waits for a refresh in flight, so revoked tokens are never written back. |
| **Logout** | RP-Initiated Logout with its own single-use, expiring `state`, checked on return (`completeEndSession`, or `endSession(authenticator, request)` in the browser). `TokenManager.delete(key, revoke = true)` and `AccountManager.signOut` revoke the tokens (RFC 7009); `createEndSessionRequest` alone does not. |
| **Token storage** | `KeystoreTokenStore` encrypts each value with AES-256-GCM under a key in the Android Keystore, with the item name as associated data, in the app's private `SharedPreferences`. The default store is `MemoryTokenStore`; an app passes the Keystore store, which needs a `Context`. A token set's `claims` come only from a validated ID token; a stored record without them is never filled in by decoding the ID token. `AccountManager` logs a warning when tokens go to persistent storage without DPoP. |
| **UserInfo** | The response `sub` must equal the ID token's: `expectedSub`, or by default the token set's ID token `sub` (OIDC Core §5.3.2). A signed UserInfo response is verified with an asymmetric algorithm (`userinfoSignedResponseAlg` pins one). |

**Not included:**

- Confidential-client authentication: client secrets, `private_key_jwt`, mTLS. This library is a public client only.
- JAR/JARM (signed request objects and responses).
- Back- and front-channel logout, which need a server endpoint.
- CAEP push delivery, which an app without a public endpoint can't receive.
- `https` redirects (Android App Links) in `CustomTabsWebAuthenticator`.
- A `WebView` sign-in, on purpose.
- A sign-in that survives the death of the app's process: transactions are in memory, so the redirect must come back to the process that started the sign-in.
- A Maven publication (for now).

## Signing in

```kotlin
import net.rcbj.oidccaep.*

val configuration = OIDCAppConfiguration.load(context)                 // assets/oidc_configuration.json
val client = configuration.makeClient(dpopKeyStore = preferredDPoPKeyStore(context))
val tokens = TokenManager(client, store = KeystoreTokenStore(context))  // encrypted at rest, auto-refreshing
val authenticator = configuration.makeAuthenticator(activity)          // a Custom Tab

// 1. Sign in through the system browser: request (PKCE, PAR), browser, callback, validation.
val result = client.authorize(authenticator)
tokens.set("user", result.tokenSet)

// 2. Call APIs. The token is fresh, and carries a DPoP proof when bound.
val response = client.fetchResource(tokens.getTokenSet("user"), URI("https://api.example.com/me"))

// 3. Sign out: revoke, then the provider's logout in the browser, with its state checked.
val tokenSet = tokens.getTokenSet("user")
val logout = client.createEndSessionRequest(idTokenHint = tokenSet.idToken)
tokens.delete("user", revoke = true)
client.endSession(authenticator, logout)
```

Every call is a `suspend` function. Without a browser step, the same flow is `createAuthorizationRequest(opts)`, which returns the URL to open, and `completeAuthorization(callbackURL)`, which returns `AuthorizationResult(tokenSet, context)`. Logout is `createEndSessionRequest(…)` and `completeEndSession(callbackURL)`.

### oidc_configuration.json

`OIDCAppConfiguration.load(context, asset = "oidc_configuration.json")` reads it from the app's assets. `load(file)`, `fromJson(text, source, readFile)` and `fromObject(jsonObject, readFile)` read it from elsewhere. The keys are the Swift library's `OIDCConfiguration.plist` keys.

| Key | Type | Default | Applied by |
|---|---|---|---|
| `MetadataURL` | string, required, contains `/.well-known/` | — | `makeClient` |
| `ClientID` | string, required | — | `makeClient` |
| `Scopes` | array, or space-separated string | the client's: `openid profile email` (+ `offline_access`) | `makeClient` |
| `RedirectURI` | string, required | — | `makeClient` |
| `PostLogoutRedirectURI` | string | — | `makeClient` |
| `Resource` | array or string | — | `makeClient` |
| `DPoP` | bool | `true` | `makeClient` |
| `PAR` | `auto`, `always`, `never` | `auto` | `makeClient` |
| `IDTokenSignedResponseAlg` | string | `RS256` if offered, else the first offered that the library verifies | `makeClient` |
| `ACRValues` | string | — | your code: `AuthorizationRequestOptions(acrValues = …)` |
| `PrefersEphemeralWebBrowserSession` | bool | `false` | `makeAuthenticator(context)` |
| `SSFTransmitterIssuer` | string | — (the provider's issuer) | your code: `SSFReceiverConfiguration(transmitterIssuer = …)` |
| `CAEPEnabled` | bool | `true` | `makeClient` drops `ssf.read` and `ssf.manage` when false; your code does not start the receiver |
| `TrustedCertificates` | array | — | `makeTransport()`: extra trust anchors or chains (`TLSTrust`). A relative path is an asset name beside the configuration |
| `TrustSystemRoots` | bool | `true` | `makeTransport()` |
| `InsecureSkipTLSVerification` | bool | `false` | `makeTransport()`: certificate verification off. Local test providers only |

`makeClient(dpopKeyStore, transport)` discovers the provider and creates the client; `clientOptions(dpopKeyStore, transport)` returns the `OIDCClientOptions` without discovering. With no `dpopKeyStore`, `makeClient` uses a `MemoryKeyStore`: pass `preferredDPoPKeyStore(context)` so that tokens cached across launches stay usable. `makeAuthenticator(context)` returns a `CustomTabsWebAuthenticator` with `PrefersEphemeralWebBrowserSession` applied. `makeTransport()` returns the `OkHttpTransport` the TLS keys ask for; pass the same transport to every `SSFReceiverConfiguration`.

`CAEPEnabled` defaults to true. `false` turns off CAEP and RISC: the receiver is not started, and `clientOptions()` (and therefore `makeClient()`) leaves `ssf.read` and `ssf.manage` out of the authorization request, so the app can sign in at an identity provider that does not implement Shared Signals. If no scopes remain, `scope` is null and the client uses its default (`openid profile email`, plus `offline_access` only when the provider offers it), which does not add the SSF scopes. When the flag is true or omitted, the scopes in the file are sent unchanged. Sign-in does not fetch SSF transmitter metadata; the receiver does, and only after it is started.

### Dynamic Client Registration

```kotlin
val (client, registration) = OIDCClient.register(
    metadata = metadataJson,
    clientMetadata = jsonObjectOf(
        "redirect_uris" to listOf("com.example.myapp:/callback"),
        "id_token_signed_response_alg" to "ES256",
    ),
    initialAccessToken = initialAccessToken,
    options = OIDCClientOptions(clientID = "", dpop = DPoPOptions(keyStore = preferredDPoPKeyStore(context))),
)
```

The registration always requests `token_endpoint_auth_method: none` (and `dpop_bound_access_tokens` with DPoP on). It fails if the OP issues a client secret, or registers a different ID token `alg` than requested (`registration_mismatch`). `ClientRegistration.read(registration)` and `ClientRegistration.delete(registration)` implement RFC 7592.

## Several accounts in one app

Some OPs keep several people signed in in one browser and let each request say which one it is for. iya-sts does this with `authn.multipleAccounts`, which is on by default. `AccountManager` is the app's side of that, and it follows two rules:

- **One token cache.** Every signed-in account's tokens are cached until that account is signed out or its session ends. With `KeystoreTokenStore`, a relaunch doesn't lose any account, and any cached account can be made active without a password.
- **One active account.** Only the active account's tokens can be reached: `getTokenSet()` takes no account. Only its tokens are refreshed in the background. The other accounts are **dormant**: their tokens stay stored, but they aren't refreshed or used. The active account is remembered in the store across launches.

```kotlin
val accounts = AccountManager(client, AccountManagerOptions(
    store = KeystoreTokenStore(context),
    // Runs before an account becomes active, with that account's tokens: catch up on its signals.
    onActivate = { account, access -> /* e.g. receiver.start(catchUp = true) */ },
    onDeactivate = { account -> /* stop polling its stream */ },
    onLeave = { account, access -> /* signed out or ended: delete its stream */ },
))
accounts.restore()                                 // reactivates the account active at the last launch

accounts.signIn(authenticator)                     // the OP decides (its picker if several are signed in)
accounts.chooseAccount(authenticator)              // prompt=select_account: always the OP's picker
accounts.addAccount(authenticator)                 // prompt=login: a fresh sign-in, added as an account

accounts.activate(otherKey)                        // the previous account goes dormant
val tokenSet = accounts.getTokenSet()              // the ACTIVE account's, refreshed when due

accounts.signOut(key, authenticator)               // revokes; id_token_hint ends that sid only
```

The forms taking an authenticator are extension functions; each has a member form without it that returns the `AuthorizationRequest` (or `EndSessionRequest`) for your own browser step, completed with `handleCallback(callbackURL)`.

- **Activating** a dormant account refreshes its tokens first if they are due, then runs `onActivate`, and only then makes the account active. If a signal handled during `onActivate` ends the account, it becomes active with status `ENDED` and its tokens are never handed out. If the refresh or the hook fails, the previously active account is reactivated and the error thrown.
- **A request that names an account only accepts that account.** `resume(key, authenticator)` asks without a screen (`prompt=none`); `reauthenticate(key, authenticator)` uses `prompt=login`. Both send `login_hint` and the cached `id_token_hint`. If the OP signs in somebody else, the callback refuses with `account_mismatch` and revokes the tokens it got. `AuthorizationRequestOptions(expectedSub = …)` gives the same check to any request.
- **`prompt=none` failures say which account they were for.** With several accounts signed in and nothing naming one, the OP answers `account_selection_required` (OpenID Connect Core §3.1.2.6). `needsInteraction(error)` covers it, along with `login_required`, `interaction_required` and `consent_required`. For `resume` and `reauth`, `error.account` is set.
- **Signing out one account leaves the others signed in.** Its logout request names its ID token, so the OP ends that session only. If it was the active account, the most recently added signed-in account becomes active. `signOutAll(authenticator)` sends one logout request that names nobody, so the OP asks which accounts to end. The authenticator form signs the account out of the app even when the browser step is cancelled.
- **Security events reach the account they are about.** `accountsForSubject(subId)` matches by `iss`/`sub`, a **verified** `email` or phone number (`email_verified` / `phone_number_verified` in the ID token), and `sid`. An SSF complex subject that names a session matches only the account holding that session; an account whose ID token has no `sid` doesn't match it. `end(key, reason)` drops the account's cached tokens; it stays listed as `ENDED`.
- **Statuses:** `SIGNED_IN`, `TOKENS_MISSING` (the cached tokens expired and can't be refreshed; `resume` gets new ones while the OP session lasts), `SIGNED_OUT` and `ENDED`. Past `maxAccounts` (default 10), the account that left longest ago is forgotten. If every account is signed in, a new sign-in is refused (`too_many_accounts`).
- **Stream lifecycle.** A create refused with 409, or with 403 at the transmitter's limit (iya-sts `ssf.maxStreams`, 25), reuses one of the person's streams: the one whose `description` is this receiver's, else the first. Delete the stream on sign-out when the token holds `ssf.manage`; don't delete it when the app goes to the background or is killed, and keep its id for the next launch. iya-sts removes a poll stream nobody polls after `ssf.personStreamInactivityTimeoutS` (a day by default).
- **Streams are per person.** iya-sts gives a stream created with a person's token to that person, and sends it only events about them. So each account keeps its own stream. The app polls only its active account's stream. A dormant account's stream keeps queueing at the transmitter, and `start(catchUp = true)` in `onActivate` acts on what it queued before the account is used.
- **Hooks and `stop()`.** A handler that calls `end(key, reason)` runs `onLeave` and `onDeactivate` before it returns, and `SSFReceiver.stop()` waits for the poll that is running the handler. Don't call `stop()` directly in those hooks; launch it in a coroutine. The [guide](android-app-guide.md#wire-a-receiver-to-the-active-account) shows the pattern.
- **Concurrency.** `AccountManager`, `TokenManager` and `SSFReceiver` each keep their state on a single-threaded dispatcher of their own, like a Swift actor: call them from any coroutine, and a hook that calls back into its manager does not deadlock.

Pair the Keystore cache with DPoP. A DPoP-bound refresh token is useless without its key, and a Keystore key can't be copied. Cached tokens last until the account is signed out, its session ends, or its refresh is refused; closing the app doesn't clear them.

## CAEP: one handler per event

```kotlin
val receiver = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer = client.issuer,                          // reads /.well-known/ssf-configuration
    // The signed-in user's token authorizes the stream, with a DPoP proof when bound:
    authorization = SSFAuthorization.oidc(client) { accounts.getTokenSet() },
))

receiver
    .onSessionRevoked { event -> /* sign the user out */ }
    .onTokenClaimsChange { event -> /* event.payload["claims"]: refresh tokens */ }
    .onCredentialChange { event -> /* event.payload.string("credential_type"), ("change_type") */ }
    .onAssuranceLevelChange { event -> /* ("current_level"), ("change_direction") */ }
    .onDeviceComplianceChange { event -> /* ("current_status") */ }
    .onSessionEstablished { event -> /* ("acr"), ["amr"], ("fp_ua") */ }
    .onSessionPresented { event -> /* ("fp_ua"), ("ext_id") */ }
    .onRiskLevelChange { event -> /* ("current_level"), ("risk_reason") */ }
    .onError { error, context -> println("${context.phase} $error") }

receiver.start()                                    // discover, create (or reuse) the stream, start polling
// receiver.start(catchUp = true) first acts on the SETs already queued (e.g. while the account was dormant)
receiver.addSubject(Subject.issSub(account.iss, account.sub))   // events about this user only
```

Delivery is **poll** (RFC 8936). To authorize with a static bearer token instead, pass `authorization = SSFAuthorization.Bearer { token }`; `SSFAuthorization.Headers { request -> … }` builds the headers for each request yourself.

| CAEP event | Method | Constant | Notable `payload` fields |
|---|---|---|---|
| session-revoked | `onSessionRevoked` | `CAEP.SESSION_REVOKED` | — |
| token-claims-change | `onTokenClaimsChange` | `CAEP.TOKEN_CLAIMS_CHANGE` | `claims` |
| credential-change | `onCredentialChange` | `CAEP.CREDENTIAL_CHANGE` | `credential_type`, `change_type`, `friendly_name` |
| assurance-level-change | `onAssuranceLevelChange` | `CAEP.ASSURANCE_LEVEL_CHANGE` | `namespace`, `current_level`, `previous_level`, `change_direction` |
| device-compliance-change | `onDeviceComplianceChange` | `CAEP.DEVICE_COMPLIANCE_CHANGE` | `previous_status`, `current_status` |
| session-established | `onSessionEstablished` | `CAEP.SESSION_ESTABLISHED` | `fp_ua`, `acr`, `amr`, `ext_id` |
| session-presented | `onSessionPresented` | `CAEP.SESSION_PRESENTED` | `fp_ua`, `ext_id` |
| risk-level-change | `onRiskLevelChange` | `CAEP.RISK_LEVEL_CHANGE` | `principal`, `current_level`, `previous_level`, `risk_reason` |
| SSF verification | `onVerification` | `SSF.VERIFICATION` | `state` |
| SSF stream-updated | `onStreamUpdated` | `SSF.STREAM_UPDATED` | `status`, `reason` |

`payload` is a kotlinx.serialization `JsonObject`: read a string field with `event.payload.string("change_type")`, or any field with `event.payload["claims"]` and the accessors `stringValue`, `boolValue`, `doubleValue`, `longValue`, `objectValue`, `arrayValue` and `stringArrayValue`.

**Your own logic for every event.** `onEventReceived` in the configuration is called once for each accepted event, before the typed handlers, and is awaited. By default it is `logEventReceived`, which logs `CAEP event received: <name> (jti …)` through `OIDCLog`. It leaves the payload and subject out, because they can carry personal data. Replace it with your own suspend lambda, call `logEventReceived(event)` from yours to keep the line, or pass `null` to turn it off. If it throws, `onError` gets the error with phase `HOOK`, and the typed handlers still run.

```kotlin
val receiver = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer = client.issuer,
    authorization = SSFAuthorization.oidc(client) { accounts.getTokenSet() },
    onEventReceived = { event ->
        logEventReceived(event)
        audit.record(event.name, event.subject, event.payload)   // your logic
    },
))
```

The receiver also has these generic hooks. Each returns the receiver, so they chain:

- `onEvent(eventType, handler)` handles any event type URI, for example the RISC events in `RISC`.
- `onAnyEvent(handler)` runs for every event, after its type's handlers.
- `onUnhandledEvent(handler)` runs for events that have no specific handler.
- `onError(handler)` runs on errors, with an `SSFErrorContext` (`phase` `POLL`, `HANDLER`, `HOOK` or `STOP`; `jti`, `event`, `willRetry`). It is a plain (non-suspend) function.
- `removeHandlers(eventType)` removes every handler of a type.

Every handler is a `suspend (SecurityEvent) -> Unit` and receives a `SecurityEvent`: `type`, `name`, `payload`, `subject`, `eventTimestamp`, `initiatingEntity`, `reasonAdmin`, `reasonUser`, `jti`, `iss`, `aud`, `iat`, `txn`, `set` and `raw`. Use `subjectMatches(event.subject, account.identity)` to tell whether an event is about your user; `SubjectIdentity(iss = …, sub = …, sid = …, email = …, emailVerified = …)` builds an identity by hand. An email or phone number counts only when verified, and a session-scoped subject matches only the identity holding that `sid`.

**SET validation.** Every SET must meet all of the following, or it is rejected:

- It is a compact JWS with `typ` `secevent+jwt` (`requireTyp`), signed with an asymmetric algorithm.
- Its signature verifies against the transmitter's JWKS.
- `iss` matches the transmitter.
- `aud` matches the stream's `aud` (or the `audience` option). If neither exists, the check fails closed.
- `jti`, `iat` and `events` are present, and `events` holds exactly one event (SSF 1.0).
- `iat` is not in the future. There is no age limit by default: a polled SET waits at the transmitter until it is read, so catching up after a stop must not throw old signals away. Set `maxSetAge` to impose one.
- A verification or stream-updated event names this stream (an opaque `sub_id`), if it names anything.

In addition, a replayed `jti` is dropped (`jtiCacheSize` remembers the last 10,000).

**Acknowledgement (RFC 8936).** An acknowledged SET, and one reported back as an error, is never sent again, so the receiver is careful with both:

- A SET is acknowledged only after its handlers ran without throwing. If one throws, the SET is left for the transmitter to send again, up to `maxDeliveryAttempts` times (default 5). After that it is acknowledged and `onError` gets `handler_failed`. Make handlers idempotent.
- Only a definitely invalid SET is reported as an error (bad signature, issuer, audience, `typ`, claims). One that couldn't be checked for a reason that may pass is left for redelivery for as long as that lasts, and never reported: a network error fetching the JWKS, or a key the cached JWKS doesn't hold yet.
- Polls never overlap: `poll()` during a poll shares it, and `pollNow()` during a poll asks for another right after it. A SET whose handlers are still running is never acknowledged by another poll.
- `stop()` sends the acknowledgements still owed. It waits for a poll in progress first.
- The poll endpoint must use TLS and share an origin with the transmitter (`trustedPollOrigins` adds others), because every poll carries the person's access token.
- Errors go to `onError`; without one, they are logged through `OIDCLog`, so a lost signal always leaves a trace.

SETs that arrive some other way can be handed to `receiveSet(token)`, which validates and dispatches them, or `validateSet(token)`, which only validates.

## API summary

All of it is in `net.rcbj.oidccaep`. Durations are `Double` seconds, times are `java.time.Instant`, URLs are `java.net.URI`, JSON is kotlinx.serialization's `JsonElement`.

**`OIDCAppConfiguration`** (a data class): `load(context, asset)`, `load(file)`, `fromJson(text, source, readFile)`, `fromObject(jsonObject, readFile)`, `makeClient(dpopKeyStore, transport)`, `clientOptions(dpopKeyStore, transport)`, `makeTransport()`, `makeAuthenticator(context)`, `scope`, `DEFAULT_ASSET_NAME`.

**`OIDCClient`**:

- `OIDCClient.discover(metadataURL, options)`, `OIDCClient.discoverIssuer(issuer, options)`, `OIDCClient.fromMetadata(jsonObject, options)`, `OIDCClient.register(metadata, clientMetadata, initialAccessToken, options)` → `Pair<OIDCClient, JsonObject>`
- `authorize(authenticator, opts)` → `AuthorizationResult` (an extension); or `createAuthorizationRequest(opts)` → `AuthorizationRequest(url, state)` and `completeAuthorization(callbackURL)` → `AuthorizationResult(tokenSet, context)`; `completeAuthorization(parameters: FormParameters)`
- `refresh(previous, scope)`, `refresh(refreshToken, previousClaims, scope)`
- `resourceHeaders(tokenSet, method, url, nonce)`, `resourceHeaders(accessToken, tokenType, method, url, nonce)`, `fetchResource(tokenSet, url, method, headers, body)` → `HttpResponse`
- `userinfo(tokenSet, expectedSub)`, `revoke(token, hint)`
- `createEndSessionRequest(idTokenHint, postLogoutRedirectURI, logoutHint, context)`, `completeEndSession(callbackURL)` → context, `endSession(authenticator, request)` (an extension)
- `validateIDToken(idToken, nonce, maxAge, acrValues, accessToken, previousClaims)`
- `metadata` (`ProviderMetadata`), `options`, `issuer`, `clientID`, `scope`, `usesPAR`, `dpopKey`, `tokenEvents`, `securityFeatures` (`SecurityFeatures`, with `dpop: DPoPFeature(alg, jkt, extractable)?`)

**`AuthorizationRequestOptions`** (a data class): `scope`, `redirectURI`, `prompt`, `maxAge`, `loginHint`, `idTokenHint`, `acrValues`, `expectedSub`, `context`, `extraParameters` (which may not replace the parameters the client sets).

These are the `OIDCClientOptions` (a data class; `copy()` changes one):

| Option | Default |
|---|---|
| `clientID` | required |
| `redirectURI`, `postLogoutRedirectURI` | `null` |
| `scope` | `openid profile email` + `offline_access` if supported |
| `resource` | `emptyList()` |
| `idTokenSignedResponseAlg` | `"RS256"` |
| `par` | `PARMode.AUTO` |
| `dpop` | `null` (off); `DPoPOptions(keyStore, alg, key)`, whose `keyStore` defaults to `MemoryKeyStore()` |
| `requireDPoP` | `null`: true when `dpop` is set |
| `userinfoSignedResponseAlg` | `null`: any asymmetric algorithm |
| `transactionStore` | `MemoryTransactionStore()` |
| `transactionTTL` | 600 s |
| `maxIDTokenAge` | 600 s (0: no limit) |
| `enforceACR` | `true` |
| `requireAuthTime` | `false` |
| `allowInsecureRequests` | `false` |
| `clockTolerance` | 30 s |
| `httpTimeout` | 10 s |
| `discoveryCacheTTL` | 3600 s |
| `transport` | `OkHttpTransport()` |
| `now` | `{ Instant.now() }` |

**`CustomTabsWebAuthenticator(context, prefersEphemeralWebBrowserSession = false)`**, a `WebAuthenticator`: `authenticate(url, callback)`. Takes a private-use scheme redirect only; give it an `Activity` so the tab opens in the app's task.

**`LoopbackWebAuthenticator(timeoutSeconds = 300.0, openBrowser: suspend (URI) -> Unit)`**, a `WebAuthenticator` for a loopback redirect URI with a port: it listens on the port, calls `openBrowser`, and returns the redirect the browser makes. On Android, `openBrowser` usually launches a Custom Tab or an `ACTION_VIEW` intent.

**`WebAuthenticator`** is a `fun interface` with `suspend fun authenticate(url: URI, callback: URI): URI`; implement it for another browser step.

**`TokenManager(client, store, refreshSkew, autoRefresh, minRefreshDelay, retryDelay)`**:

| Option | Default |
|---|---|
| `store` | `MemoryTokenStore()` |
| `refreshSkew` | 60 s (capped at half the token's lifetime) |
| `autoRefresh` | `true` |
| `minRefreshDelay` | 1 s |
| `retryDelay` | 5 s |

- `set(key, tokenSet, schedule)`, `get(key)`, `getTokenSet(key, forceRefresh)`, `getAccessToken(key, forceRefresh)`, `refresh(key)`, `schedule(key)`, `unschedule(key)`, `delete(key, revoke)`, `close()`
- `events`: `TokenManager.Event.Refreshed(key, tokenSet)`, `RefreshError(key, error)`, `Expired(key)`, `Removed(key)`

**`AccountManager(client, options)`**:

- `restore()`, `list()`, `get(key)`, `active()`, `activeKey()`, `identity(key)`, `accountsForSubject(subId)` (all `suspend`)
- `signIn(opts)`, `chooseAccount(opts)`, `addAccount(opts)`, `resume(key, opts)`, `reauthenticate(key, opts)`, each also as an extension taking the authenticator; `handleCallback(callbackURL)` → `SignInResult(account, tokenSet, intent, added)`
- `activate(key)`, `getTokenSet(forceRefresh)` and `refresh()` (the active account's only), `signOut(key, revoke, endSession, postLogoutRedirectURI)`, `signOut(key, authenticator, revoke)`, `signOutAll(revoke, endSession, postLogoutRedirectURI)`, `signOutAll(authenticator, revoke)`, `end(key, reason)`, `forget(key)`, `close()`
- `client`, `tokens` (its `TokenManager`), `events`: `AccountManager.Event.Added`, `Updated`, `Activated(account, previous)`, `Refreshed`, `SignedOut`, `Ended(account, reason)`, `Forgotten`, `ActivationError(account, error)`, `Change`
- Also: `needsInteraction(error)`, `interactionRequiredErrors`, `accountKey(iss, sub)`

| `AccountManagerOptions` | Default |
|---|---|
| `store` | `MemoryTokenStore()` |
| `storeKey` | `"accounts"` (the active account is kept under `active:accounts`) |
| `refreshSkew` | 60 s |
| `maxAccounts` | 10 |
| `rememberSignedOutDays` | 30 |
| `loginHint` | `preferred_username`, else `email` |
| `onActivate`, `onDeactivate`, `onLeave` | `null` |

**`Account`** (a data class): `key`, `status` (`Account.Status`, with `value` `signed-in` …), `endedReason`, `addedAt`, `lastUsedAt`, `changedAt`, `claims` (profile claims only, no tokens), `iss`, `sub`, `sid`, `name`, `email`, `preferredUsername`, `identity`. **`AccountAccess`**: `getTokenSet(forceRefresh)`.

**`TokenSet`** (a data class): `accessToken`, `tokenType`, `refreshToken`, `idToken`, `scope`, `expiresAt`, `issuedAt` (epoch seconds), `claims`, `additional`, `isDPoPBound`, `expiresIn(now)`, `effectiveSkew(skew)`, `isExpired(skew, now)`, `json`, `TokenSet.fromJson(jsonObject)`.

**`EventHub<E>`**, the type of every `events`: `subscribe(listener)` → `EventSubscription` (`cancel()`), and `flow()` → `Flow<E>`.

**`SSFReceiver(configuration)`**:

- Handlers: `onSessionRevoked`, `onTokenClaimsChange`, `onCredentialChange`, `onAssuranceLevelChange`, `onDeviceComplianceChange`, `onSessionEstablished`, `onSessionPresented`, `onRiskLevelChange`, `onVerification`, `onStreamUpdated`, `onEvent(eventType, handler)`, `onAnyEvent`, `onUnhandledEvent`, `onError`, `removeHandlers(eventType)`
- Lifecycle: `discover()`, `start(catchUp)`, `stop(deleteStream)`, `poll()` → `PollResult(received, moreAvailable)`, `pollNow()`
- Streams (SSF 1.0 §8.1): `createStream(extra)`, `listStreams()`, `getStream(streamID)`, `updateStream(changes)`, `replaceStream(configuration)`, `deleteStream()`, `getStatus()`, `updateStatus(status, reason)`, `addSubject(subject, verified)`, `removeSubject(subject)`, `requestVerification(timeoutSeconds, state)`
- Delivery: `receiveSet(token)`, `validateSet(token)`
- `metadata`, `stream` (settable, to point the receiver at a known stream id without fetching it), `configuration`

| `SSFReceiverConfiguration` | Default |
|---|---|
| `transmitterIssuer` | required |
| `authorization` | `null`; `SSFAuthorization.oidc(client) { tokenSet }`, `SSFAuthorization.Bearer { token }` or `SSFAuthorization.Headers { request -> … }` |
| `audience` | the stream's `aud` |
| `eventsRequested` | `CAEP.all` |
| `streamID` | `null`: create or reuse a stream |
| `description` | `"android-oidc-caep-native-app receiver"` |
| `pollInterval` | 5 s |
| `maxEvents` | 25 |
| `clockTolerance` | 60 s |
| `maxSetAge` | 0 (no limit) |
| `maxDeliveryAttempts` | 5 |
| `allowInsecureRequests` | `false` |
| `trustedPollOrigins` | `emptyList()` |
| `requireTyp` | `true` |
| `jtiCacheSize` | 10000 |
| `httpTimeout` | 10 s |
| `transport` | `OkHttpTransport()` |
| `onEventReceived` | `logEventReceived` |
| `now` | `{ Instant.now() }` |

**Subjects and constants:** `Subject.issSub`, `.email`, `.phone`, `.opaque`, `.account`, `.uri`, `.did`, `.aliases`, `.complex`; `SubjectIdentity`, `subjectMatches(subId, identity)`; `CAEP.*` and `CAEP.all`, `SSF.*`, `RISC.*`, `Delivery.PUSH` / `Delivery.POLL`, `eventName(uri)`.

**Stores:**

| Store | Kind | Notes |
|---|---|---|
| `KeystoreTokenStore(context, fileName, keyAlias)` | tokens | AES-256-GCM under an Android Keystore key (`<package>.oidc-tokens-key`), values in `SharedPreferences` (`<package>.oidc-tokens`). `securityLevel()`. |
| `MemoryTokenStore()` | tokens | The default. Nothing persists. |
| `AndroidKeystoreKeyStore(alias, preferStrongBox, context)` | DPoP key | ES256, non-extractable, StrongBox first. `securityLevel()` → `KeySecurityLevel` (`STRONGBOX`, `TRUSTED_ENVIRONMENT`, `SOFTWARE`, `UNKNOWN`). |
| `preferredDPoPKeyStore(context, alias)` | DPoP key | An `AndroidKeystoreKeyStore` named `<package>.oidc-dpop`. |
| `MemoryKeyStore()` | DPoP key | ES256/384/512 software key; a new key every launch. The default. |
| `MemoryTransactionStore()` | sign-ins in progress | The default. |

Your own stores implement `TokenStore`, `DPoPKeyStore` or `TransactionStore`; your own networking implements `HttpTransport` (`suspend fun send(request: HttpRequest, timeoutSeconds: Double): HttpResponse`). `OkHttpTransport(trust, insecureSkipTLSVerification)` is the default; `TLSTrust(certificates, includeSystemRoots)` and `TLSTrust.fromPemOrDer(entries, includeSystemRoots)` describe extra anchors.

**JOSE and helpers:** `DPoPKey`, `DPoPKeyStore`, `dpopAlgorithms`, `htuOf(url)`, `JWSSigner`, `SoftwareECSigner`, `signJWS`, `decodeProtectedHeader`, `decodeUnverifiedJWTPayload` (for display only), `jwkThumbprint`, `asymmetricJWSAlgorithms`, `supportedIDTokenAlgorithms`, `generateCodeVerifier()`, `codeChallengeS256(verifier)`, `randomToken(bytes)`, `Base64URL`, `FormParameters`; discovery: `discoverOpenIDProvider(metadataURL | issuer, …)`, `validateOpenIDProviderMetadata`, `discoverSSFTransmitter`, `oidcDiscoveryURL`, `wellKnownURLs`, `clearDiscoveryCache()`; JSON: `parseJson`, `jsonOf`, `jsonObjectOf`, `JsonObject.string(key)`, `JsonElement.jsonString(pretty)`, `emptyJsonObject`.

**Errors:** `OIDCError` with `kind` (`GENERAL`, `OAUTH`, `VALIDATION`, `SET_VALIDATION`, `SSF`), `code`, `message`, `status`, `response`, `cause`, `oauthError`, `oauthErrorDescription`, `errorURI`, `context`, `account`, `retryable`, `isUserCancellation`; `OIDCError.USER_CANCELLED_CODE`, `OIDCError.wrap(throwable)`. The [guide](android-app-guide.md#11-errors) lists the codes.

**Logging:** `OIDCLog.handler: (OIDCLog.Level, String) -> Unit` receives the library's few log lines (`INFO`, `WARNING`, `ERROR`): a received CAEP event, a warning about token storage, an SSF error nobody handles. The default writes them to Logcat under the tag `OIDCCAEPClient`, and to standard output and error on a plain JVM.

## Tests

```sh
./gradlew :library:testDebugUnitTest       # on the JVM
docker build --target test .               # the same, in a container
python3 scripts/live_iya_sts.py            # live, against a fresh iya-sts
```

The unit tests run against a strict in-memory OpenID Provider and SSF transmitter, injected as the library's `HttpTransport`; they are the Swift library's XCTest suite, ported test for test. The live test signs in to a real iya-sts with a second factor and handles two CAEP signals; [Development](https://rcbj.github.io/android-oidc-caep-native-app/development.html) describes both.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC.
