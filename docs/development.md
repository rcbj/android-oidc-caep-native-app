---
title: Development
---

# Development

## Tests

From the repository root, on a machine with JDK 17 and the Android SDK:

```sh
./gradlew :library:testDebugUnitTest
```

Or anywhere with Docker, with nothing else installed:

```sh
docker build --target test .
```

The `test` stage of the [`Dockerfile`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/Dockerfile) installs JDK 17, the Android command-line tools (pinned by SHA-256), platform `android-37.1` and build-tools 36, and runs the same Gradle task.

The 57 JUnit tests in `library/src/test` are the Swift library's XCTest suite, ported test for test and named after the Swift tests. They run on the JVM against a strict in-memory OpenID Provider and SSF transmitter (`StubOP.kt`), injected as the library's `HttpTransport`. The stub enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces). The suite covers:

- discovery from a metadata URL, the JSON configuration, and the setup checks (S256, public clients, TLS, redirect URIs);
- state, the front channel, RFC 9207, OAuth errors and reserved parameters;
- ID token validation (EC and RSA keys, `alg`, `typ`, `acr`, `expectedSub`), refresh (OIDC Core §12.2) and UserInfo;
- DPoP (downgrades, nonces), PAR, logout state and dynamic registration;
- the token cache: merged refreshes, background refresh, `invalid_grant`, revocation on delete;
- several accounts: sign-in, switching, `resume`, sign-out, `end`, subject matching, restoring from a persistent store, `too_many_accounts`;
- the SSF receiver: one handler per event, acknowledgement, redelivery after a throwing handler, invalid and replayed SETs, verification, subjects, and the poll endpoint's origin;
- TLS trust against a real TLS server (a private root accepted, refused without it, another root refused), and the loopback authenticator.

The Android-only parts (`AndroidKeystoreKeyStore`, `KeystoreTokenStore`, `CustomTabsWebAuthenticator`) need a device and are exercised by the demo. The JVM tests need no Robolectric: `unitTests.isReturnDefaultValues` is on, and `OIDCLog` falls back to standard output where `android.util.Log` is a stub.

The demo is built separately:

```sh
./gradlew :demo:assembleDebug
```

### Live test against iya-sts

```sh
python3 scripts/live_iya_sts.py                                  # builds iya-sts from its main branch
IYA_STS_IMAGE=iya-sts:local python3 scripts/live_iya_sts.py      # or starts an image already built
```

[`scripts/live_iya_sts.py`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/scripts/live_iya_sts.py) is the port of the Swift library's driver. It needs Docker, the host's `python3` (standard library only), the Gradle toolchain above, and `oathtool` (`apt install oathtool`). It:

1. starts a fresh iya-sts in a container on port 18507 (memory mode, clustering off, no workers, and `oauth2.parRequestUriLifetimeS` 300, since a one-time code may wait out a 30-second step);
2. writes an `oidc_configuration.json` from the demo's, with a loopback redirect on 18607 and iya-sts's root CA as the only trust anchor (fetched once from `GET /tls/server-certificate`; TLS verification is never turned off);
3. registers the client and a **new test user** (`live-mfa-<random>`) with `register-iya-sts-client.mjs` in a Node container;
4. runs `LiveIyaSTSTests` alone with the Gradle wrapper, and prints its result as JSON.

`LiveIyaSTSTests` (skipped unless `IYA_STS_LIVE_CONFIG` is set) uses the library end to end: `OIDCAppConfiguration`, `OIDCClient` (PAR, PKCE, DPoP), `AccountManager`, `LoopbackWebAuthenticator` and `SSFReceiver`. Only the browser is replaced, by an HTTP walk of iya-sts's sign-in screens through the JSON API they call (`/authn-api`). It follows the pattern every iya-sts test that needs a second factor follows:

- the operator requires a second factor of the new user (`POST /admin-api/users/require-mfa`);
- **the first sign-in enrols an authenticator app** at the sign-in screen (`/authn-api/mfa/{id}/setup/totp`, then `setup/confirm`), keeps the secret, and answers with a code from `oathtool --totp -b <secret>`;
- **a second sign-in** (`reauthenticate`, `prompt=login`) goes through the one-time code step: a wrong code first, which must be refused, then the right one. A code is never sent twice in one 30-second step (RFC 6238 section 5.2);
- then the library's CAEP receiver polls the account's stream, the operator emits **credential-change** (the account must stay signed in) and **session-revoked** (the account must end) with `POST /admin-api/caep/emit`.

`IYA_STS_URL` uses an iya-sts that is already running; `LIVE_STS_PORT` and `LIVE_DEMO_PORT` choose the ports (3000, 8081 and 18481 to 18495 are refused; the Swift live run uses 18506 and 18606). The driver removes only the container it started.

## API reference (Dokka)

The site's [Dokka reference](https://rcbj.github.io/android-oidc-caep-native-app/api/) is generated from the source's KDoc comments and `library/Module.md`. To build it locally:

```sh
./gradlew :library:dokkaGeneratePublicationHtml
xdg-open library/build/dokka/html/index.html
```

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| [`tests.yml`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/.github/workflows/tests.yml) | every push to `main` and `develop`, and pull requests | the unit suite, and a debug build of the demo |
| [`nightly.yml`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/.github/workflows/nightly.yml) | every day at 06:41 UTC, and on demand | the unit suite, then the live test against iya-sts built from its `main` branch |
| [`pages.yml`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/.github/workflows/pages.yml) | pushes to `main` that change the docs or the library's source, and on demand | builds this site, generates the Dokka reference, and deploys both to GitHub Pages |

Before the first Pages run, Pages must be set to build from GitHub Actions; the workflow's header says how.

## Branches

- **`develop`** is where work comes together. Create every feature or fix branch from it, and merge back into it.
- **`main`** is what is released. It receives `develop` through a pull request merged with a merge commit, and then `develop` is fast-forwarded to that commit, so both branches name one hash. Its pushes publish this site.

```sh
git switch develop && git pull
git switch -c feature/<issue>          # or fix/<issue>
# commit, push, and open a pull request into develop
```

The default branch is `main`, so a closing keyword on a pull request into `develop` does not close its issue: close the issue in a comment that names the `develop` commit. A release is a semantic-version tag on `main` (`0.1.0`, `0.1.1`, …).

## Setting up a Linux laptop

Tested on Pop!_OS 22.04 with KVM. Download the Android command-line tools from [developer.android.com/studio](https://developer.android.com/studio#command-tools), check the SHA-256 published there, and unpack them as `~/Android/Sdk/cmdline-tools/latest`. Then:

```sh
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin
yes | sdkmanager --licenses
sdkmanager "platform-tools" "emulator" "platforms;android-37.1" "build-tools;36.0.0" \
           "system-images;android-37.0;google_apis;x86_64"
avdmanager create avd -n pixel_api37 -k "system-images;android-37.0;google_apis;x86_64" -d pixel_8
echo "sdk.dir=$ANDROID_HOME" > local.properties
```

The emulator needs hardware virtualization: `/dev/kvm` readable and writable by your user. The `google_apis` image (not `google_apis_playstore`) is debuggable, which `scripts/setup-emulator.sh` relies on for Chrome's command line. Android Studio is not needed; it can open the project as it is.

## Layout of the repository

```
settings.gradle.kts                the two modules: :library and :demo
gradle/libs.versions.toml          every version (AGP, Kotlin, coroutines, OkHttp, Compose, Dokka …)
library/
  build.gradle.kts                 the Android library (minSdk 28, compileSdk 37.1), explicit API mode, Dokka
  Module.md                        the Dokka reference's landing page
  src/main/AndroidManifest.xml     INTERNET, Custom Tabs <queries>, the two activities
  src/main/kotlin/net/rcbj/oidccaep/
    OIDCError.kt Json.kt Util.kt   errors, JSON accessors, EventHub, OIDCLog, URL and actor helpers
    Http.kt TLSTrust.kt            HttpTransport, OkHttpTransport, FormParameters, TLSTrust
    JWS.kt DPoP.kt                 JWS signing and verification, JWKS, DPoP keys and proofs
    Discovery.kt Registration.kt   provider and SSF metadata, dynamic client registration
    OIDCClient.kt                  the client
    AppConfiguration.kt            oidc_configuration.json
    WebAuthentication.kt           WebAuthenticator and the extensions that run the browser step
    TokenSet.kt TokenManager.kt AccountManager.kt   tokens, stores, the cache, several accounts
    CAEP.kt SSFReceiver.kt         constants, subjects, the SSF receiver
    AndroidKeystore.kt             Android only: AndroidKeystoreKeyStore, KeystoreTokenStore
    CustomTabsWebAuthenticator.kt  Android only: the Custom Tab and its two activities
    LoopbackWebAuthenticator.kt    a loopback redirect listener
  src/test/kotlin/net/rcbj/oidccaep/   the JUnit suite, StubOP, and LiveIyaSTSTests
demo/                              the Compose demo (net.rcbj.caepdemo)
  src/main/assets/oidc_configuration.json
Documentation/
  android-app-guide.md             the integration guide
  reference.md                     the API reference
docs/                              this site's frame and pages (Jekyll)
scripts/register-iya-sts-client.mjs   registers the demo's client (and a test user) on iya-sts
scripts/setup-emulator.sh          prepares the emulator after each start
scripts/live_iya_sts.py            the live test's driver
Dockerfile                         the container test stage
.github/workflows/                 tests.yml, nightly.yml, pages.yml
```

The guide and the reference are written once, in `Documentation/`, and read the same in the repository and on this site: the Pages workflow copies them in and rewrites the few links that point outside the site.
