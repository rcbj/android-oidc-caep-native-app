# android-oidc-caep-native-app

An OpenID Connect client library for native Android apps, in Kotlin, and a CAEP receiver. Package `net.rcbj.oidccaep`. The client is public: Authorization Code with PKCE in the system browser (a Custom Tab), PAR, and DPoP. It is a port of [swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) and keeps its behaviour, its error codes and its test suite; a difference between the two is a bug in one of them unless this file names it.

minSdk 28, compileSdk 37.1 (Compose BOM 2026.11 requires 37.1), AGP 9.5 with its built-in Kotlin, Gradle 9.9 (wrapper), JDK 17. The license is the MIT License in `LICENSE`; the Business Source License used by iya-sts does not apply here.

## Layout

| Path | What it is |
|---|---|
| `library/src/main/kotlin/net/rcbj/oidccaep` | The library, one package. Pure JVM code (`OIDCClient`, `JWS`, `DPoP`, `Discovery`, `TokenSet`, `TokenManager`, `AccountManager`, `SSFReceiver`, `CAEP`, `Http`, `TLSTrust`, `AppConfiguration`, `LoopbackWebAuthenticator`) beside the Android-only files (`AndroidKeystore.kt`, `CustomTabsWebAuthenticator.kt`). |
| `library/src/main/AndroidManifest.xml` | `AuthorizationManagementActivity` and `RedirectUriReceiverActivity`, the latter registered for `${oidcRedirectScheme}`, which the app sets. |
| `library/src/test` | JUnit 4 on the JVM. `StubOP.kt` is the in-memory provider and SSF transmitter. One file per Swift test file; test names follow the Swift ones. |
| `demo` | The Compose demo (`net.rcbj.caepdemo`): `DemoModel.kt` is the Swift demo's `DemoModel`, `MainActivity.kt` its views. |
| `scripts/register-iya-sts-client.mjs` | Registers the demo's public client on iya-sts from `demo/src/main/assets/oidc_configuration.json`, grants the SSF roles, creates the test user. Needs `ADMIN_API_CLIENT_SECRET`. |
| `scripts/setup-emulator.sh` | Run after each emulator start: `adb reverse` for iya-sts's port, iya-sts's root CA into the demo's assets (gitignored), Chrome's `--ignore-certificate-errors-spki-list` for that CA's keys only. |
| `Dockerfile` | `docker build --target test .` runs the unit suite in a container. |

## How the Swift design maps

- **Actors** are classes whose state is touched only on a single-threaded dispatcher (`actorDispatcher()`, `Dispatchers.Default.limitedParallelism(1)`) through `serial { }`. That keeps Swift's actor semantics, reentrancy at suspension points included: a hook (`onActivate`) that calls back into its `AccountManager` does not deadlock. Do not replace this with a `Mutex` held across suspensions.
- **JSON** is kotlinx.serialization's `JsonElement` with the accessors in `Json.kt` (`stringValue`, `objectValue` …), no `@Serializable` classes and no serialization plugin.
- **HTTP** is OkHttp: `HttpURLConnection` cannot send `PATCH`, which the SSF stream API needs. Redirects are never followed.
- **Crypto** is the platform's JCA: ECDSA signatures are converted between DER and JWS `r || s` (`derToRaw`, `rawToDer`); RSASSA-PSS falls back to Conscrypt's `SHA256withRSA/PSS` name; Ed25519 verifies where the platform has it.
- **Secure Enclave / Keychain** become `AndroidKeystoreKeyStore` (P-256, StrongBox when present, never extractable) and `KeystoreTokenStore` (AES-256-GCM under a Keystore key, the item name as associated data, values in SharedPreferences). There is no software-key store persisted to disk: the Keystore is always available on Android.
- **ASWebAuthenticationSession** becomes `CustomTabsWebAuthenticator`, AppAuth's arrangement: the management activity opens the tab, the redirect activity hands the result back with `CLEAR_TOP`, and a return without a redirect is `user_cancelled`.
- **`OIDCConfiguration.plist`** becomes `oidc_configuration.json` in the assets, with the same keys; relative `TrustedCertificates` are asset names.

## Tests

```sh
./gradlew :library:testDebugUnitTest
docker build --target test .
```

`unitTests.isReturnDefaultValues` is on, and `OIDCLog` falls back to standard output when `android.util.Log` is a stub, so the JVM tests need no Robolectric.

## The emulator and iya-sts

- The demo's provider is iya-sts at `https://localhost:8081`, reached through `adb reverse`, so the issuer in the metadata is the URL the app uses.
- `oauth2.parRequestUriLifetimeS` (default 60 s) bounds the WHOLE sign-in, password, second factor and consent included; a person working through iya-sts's screens needs more. The 8081 instance runs with 600.
- A browser step driven by a script (Chrome DevTools, `adb forward tcp:9333 localabstract:chrome_devtools_remote`) is not a user gesture: Chrome then asks "Continue to <app>?" before handing a redirect to the app. Submit the last step (consent's Allow) with a real tap (`adb shell input tap`) and the hand-off goes straight through.
- A test user with a second factor has its TOTP secret enrolled at sign-in (iya-sts's `/authn-api/mfa/{id}/setup/totp` and `setup/confirm`) and its codes computed with `oathtool --totp -b <secret>`.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main` and fast-forward `develop` to that same commit so both branches name one hash.
