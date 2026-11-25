# android-oidc-caep-native-app

An OpenID Connect client library for native Android apps, in Kotlin, and a CAEP receiver. Package `net.rcbj.oidccaep`. The client is public: Authorization Code with PKCE in the system browser (a Custom Tab), PAR, and DPoP. It is a port of [swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) and keeps its behaviour, its error codes and its test suite; a difference between the two is a bug in one of them unless this file names it.

Documentation: <https://rcbj.github.io/android-oidc-caep-native-app/>. `Documentation/android-app-guide.md` (the integration guide) and `Documentation/reference.md` (the API reference) are written once and copied into the site by `.github/workflows/pages.yml`, which also publishes the Dokka reference at `/api/`.

minSdk 28, compileSdk 37.1 (Compose BOM 2026.11 requires 37.1), AGP 9.5 with its built-in Kotlin, Gradle 9.9 (wrapper), JDK 17. The license is the MIT License in `LICENSE`; the Business Source License used by iya-sts does not apply here.

## Layout

| Path | What it is |
|---|---|
| `library/src/main/kotlin/net/rcbj/oidccaep` | The library, one package. Pure JVM code (`OIDCClient`, `JWS`, `DPoP`, `Discovery`, `TokenSet`, `TokenManager`, `AccountManager`, `SSFReceiver`, `CAEP`, `Http`, `TLSTrust`, `AppConfiguration`, `LoopbackWebAuthenticator`) beside the Android-only files (`AndroidKeystore.kt`, `CustomTabsWebAuthenticator.kt`). |
| `library/src/main/AndroidManifest.xml` | `AuthorizationManagementActivity` and `RedirectUriReceiverActivity`, the latter registered for `${oidcRedirectScheme}`, which the app sets. |
| `library/src/test` | JUnit 4 on the JVM. `StubOP.kt` is the in-memory provider and SSF transmitter. One file per Swift test file; test names follow the Swift ones. |
| `demo` | The Compose demo (`net.rcbj.caepdemo`): `DemoModel.kt` is the Swift demo's `DemoModel`, `MainActivity.kt` its views. |
| `scripts/register-iya-sts-client.mjs` | Registers the demo's public client on iya-sts from `demo/src/main/assets/oidc_configuration.json`, grants the SSF roles, creates the test user. Needs `ADMIN_API_CLIENT_SECRET`. |
| `scripts/live_iya_sts.py` | The live test's driver: a fresh iya-sts, the registration of a new MFA test user, and `LiveIyaSTSTests` with the Gradle wrapper. |
| `scripts/setup-emulator.sh` | Run after each emulator start: `adb reverse` for iya-sts's port, iya-sts's root CA into the demo's assets (gitignored), Chrome's `--ignore-certificate-errors-spki-list` for that CA's keys only. |
| `Dockerfile` | `docker build --target test .` runs the unit suite in a container. |
| `Documentation` | `android-app-guide.md` (the Swift `native-app-guide.md`'s counterpart) and `reference.md`. Every API name in them is the Kotlin source's; change them with the API. |
| `docs` | The GitHub Pages site (Jekyll, minima with a sidebar): `index.md`, `demo.md`, `development.md`, `android.md` (every difference from the Swift library). |
| `library/Module.md` | The Dokka reference's landing page. `./gradlew :library:dokkaGeneratePublicationHtml` writes `library/build/dokka/html`. |
| `.github/workflows/pages.yml` | Builds the site and Dokka on pushes to `main` that touch the docs or `library/src/main`, and deploys to Pages. Pages must first be set to build from GitHub Actions (the workflow's header). |

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

### Live test against iya-sts

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts:local LIVE_STS_PORT=18507 LIVE_DEMO_PORT=18607 python3 scripts/live_iya_sts.py
```

`LiveIyaSTSTests.kt` is skipped unless `IYA_STS_LIVE_CONFIG` is set; `scripts/live_iya_sts.py` (host `python3`, standard library only) sets it up, as the Swift library's driver does: a fresh iya-sts (memory mode, clustering off, no workers, `oauth2.parRequestUriLifetimeS` 300), an `oidc_configuration.json` from the demo's with a loopback redirect and the iya-sts root as the only trust anchor, the client and a NEW test user registered with `register-iya-sts-client.mjs` in a Node container, then `./gradlew :library:testDebugUnitTest --tests '*LiveIyaSTSTests*' --rerun` on the host. The result comes back through `IYA_STS_LIVE_RESULT`.

The test is the Swift `LiveIyaSTSTests` plus the MFA pattern every iya-sts MFA test uses: it requires a second factor of the new user (`POST /admin-api/users/require-mfa`), the first sign-in ENROLS an authenticator app (`/authn-api/mfa/{id}/setup/totp`, then `setup/confirm` with a code from `oathtool --totp -b <secret>`), and a second sign-in (`reauthenticate`) answers `/authn/totp` with a wrong code (refused) and then the right one. A code is never sent twice in one 30-second step (RFC 6238 section 5.2). `IyaSTSBrowser` walks the screens over `/authn-api` with OkHttp and a cookie jar, trusting the same root; `LoopbackWebAuthenticator`'s `openBrowser` starts the walk on its own thread, because the listener accepts only after `openBrowser` returns. Ports: 18507 and 18607 (the Swift run uses 18506 and 18606); 3000, 8081 and 18481 to 18495 are refused. `.github/workflows/nightly.yml` runs it daily at 06:41 UTC against iya-sts built from `main`.

`unitTests.isReturnDefaultValues` is on, and `OIDCLog` falls back to standard output when `android.util.Log` is a stub, so the JVM tests need no Robolectric.

## The emulator and iya-sts

- The demo's provider is iya-sts at `https://localhost:8081`, reached through `adb reverse`, so the issuer in the metadata is the URL the app uses.
- `oauth2.parRequestUriLifetimeS` (default 60 s) bounds the WHOLE sign-in, password, second factor and consent included; a person working through iya-sts's screens needs more. The 8081 instance runs with 600.
- A browser step driven by a script (Chrome DevTools, `adb forward tcp:9333 localabstract:chrome_devtools_remote`) is not a user gesture: Chrome then asks "Continue to <app>?" before handing a redirect to the app. Submit the last step (consent's Allow) with a real tap (`adb shell input tap`) and the hand-off goes straight through.
- A test user with a second factor has its TOTP secret enrolled at sign-in (iya-sts's `/authn-api/mfa/{id}/setup/totp` and `setup/confirm`) and its codes computed with `oathtool --totp -b <secret>`.

## Releases

A release is `com.iyasec:oidc-caep-android` on Maven Central, a semantic-version tag `vM.N.P` on `main`, and a GitHub Release. `.github/workflows/publish.yml` makes all three after the Tests workflow succeeds on `main` for a commit that came from a merged pull request; a direct push does not release. `.github/scripts/release_decision.py` (the same script as the other client libraries) picks the version: `VERSION` (M.N, read as M.N.0) when it is ahead of what is published, else one patch higher when the library's shipped files (`library/` less its tests, `VERSION`, `gradle/libs.versions.toml`) changed since the last release's tag, else no release. The version reaches Gradle as `-PreleaseVersion` and is never committed. A version already on Maven Central stays; the next release is a new version.

Publishing is the `com.vanniktech.maven.publish` plugin (`library/build.gradle.kts`): the AAR, a sources jar, a javadoc jar built from Dokka's HTML, and the POM, signed and uploaded to the Central Portal, then released automatically (`publishAndReleaseToMavenCentral`). The four repository secrets are `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token for this repository) and `GPG_PRIVATE_KEY` (ASCII-armored) and `GPG_PASSPHRASE`. Without a signing key nothing is signed, so `./gradlew :library:publishToMavenLocal` works anywhere for a local check. The namespace `com.iyasec` is the one the Java libraries publish under.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main` and fast-forward `develop` to that same commit so both branches name one hash.
