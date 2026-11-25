# android-oidc-caep-native-app

An OpenID Connect client library for **native Android apps**, written in Kotlin, and a demo app built on it. It is the Android counterpart of [swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) (macOS): the same use case, protections and API shape. The client runs in the app as a **public client** (Authorization Code + PKCE in the system browser, PAR, DPoP) and receives **CAEP** security events through the Shared Signals Framework.

| Path | |
|---|---|
| [`library`](library) | The library, package `net.rcbj.oidccaep`. Android library module, minSdk 28. |
| [`demo`](demo) | The demo app (`net.rcbj.caepdemo`, Jetpack Compose), which uses the library as any app would. |
| [`scripts`](scripts) | `register-iya-sts-client.mjs` (registers the demo on iya-sts) and `setup-emulator.sh` (gets the emulator ready). |

## What it does

- **Sign-in in the system browser** (RFC 8252): a Custom Tab, with the redirect to a private-use scheme (`com.example.app:/callback`) received by the library's own activity. A loopback redirect (`LoopbackWebAuthenticator`) is also supported.
- **Authorization Code + PKCE S256**, state and nonce (random, single use, constant-time compared), RFC 9207 issuer identification, **PAR** (RFC 9126), **DPoP** (RFC 9449) with the key generated in the **Android Keystore** (StrongBox when the device has one, else the TEE; never extractable), RFC 8707 resource indicators, full ID token validation (OIDC Core 3.1.3.7, 12.2; RFC 8725).
- **Several accounts, one active**: `AccountManager` keeps each account's tokens (encrypted at rest by `KeystoreTokenStore`, AES-256-GCM under a Keystore key), refreshes the active account's before they expire, and can resume, re-authenticate, sign out (RP-Initiated Logout) and forget accounts.
- **CAEP receiver** (`SSFReceiver`): SSF 1.0 stream management and RFC 8936 poll delivery authorised by the signed-in person's DPoP-bound token, SET validation (RFC 8417), one handler per CAEP event, replay protection, acknowledgement only after the handlers succeed.
- **Private CAs without turning TLS off**: `TrustedCertificates` names the trust anchors; `InsecureSkipTLSVerification` exists for local test providers only.

## Use

```kotlin
// build.gradle.kts of the app
android { defaultConfig { manifestPlaceholders["oidcRedirectScheme"] = "com.example.myapp" } }
dependencies { implementation(project(":library")) }   // or the published artifact, once there is one
```

Put the settings in `src/main/assets/oidc_configuration.json` (the keys of the Swift library's `OIDCConfiguration.plist`):

```json
{
  "MetadataURL": "https://idp.example.com/.well-known/openid-configuration",
  "ClientID": "my-native-app",
  "Scopes": ["openid", "profile", "email", "offline_access"],
  "RedirectURI": "com.example.myapp:/oauth2/callback"
}
```

```kotlin
val config = OIDCAppConfiguration.load(context)
val client = config.makeClient(dpopKeyStore = preferredDPoPKeyStore(context))
val accounts = AccountManager(client, AccountManagerOptions(store = KeystoreTokenStore(context))).restore()
accounts.signIn(config.makeAuthenticator(activity))     // a Custom Tab
val tokens = accounts.getTokenSet()                      // refreshed when due
```

Every key of the configuration is documented on `OIDCAppConfiguration`.

## Build and test

JDK 17 and the Android SDK (platform `android-37.1`, build-tools 36). See [Development setup](#development-setup) for a Linux laptop.

```sh
./gradlew :library:testDebugUnitTest      # the unit suite, on the JVM
./gradlew :demo:assembleDebug             # the demo APK
docker build --target test .              # the unit suite in a container
```

The unit suite runs against `StubOP`, an in-memory OpenID Provider and SSF transmitter; it is a port of the Swift library's XCTest suite, test for test.

## Run the demo

The demo signs in to iya-sts on `https://localhost:8081`, which the emulator reaches through `adb reverse`.

```sh
ADMIN_API_CLIENT_SECRET=… node scripts/register-iya-sts-client.mjs   # once: the client and a test user
scripts/setup-emulator.sh                                             # after each emulator start
./gradlew :demo:installDebug
adb shell am start -n net.rcbj.caepdemo/.MainActivity
```

`setup-emulator.sh` starts the emulator if needed, forwards the port, writes iya-sts's root CA into the demo's assets (the app trusts that root only), and tells Chrome on the emulator to accept certificates under that CA's keys only. To point the demo at another provider without rebuilding, push a configuration to `/sdcard/Android/data/net.rcbj.caepdemo/files/oidc_configuration.json`.

## Development setup

On Linux (tested on Pop!_OS 22.04 with KVM): the Android command-line tools in `~/Android/Sdk`, then

```sh
sdkmanager "platform-tools" "emulator" "platforms;android-37.1" "build-tools;36.0.0" \
           "system-images;android-37.0;google_apis;x86_64"
avdmanager create avd -n pixel_api37 -k "system-images;android-37.0;google_apis;x86_64" -d pixel_8
```

and `ANDROID_HOME=$HOME/Android/Sdk` with `platform-tools`, `emulator` and `cmdline-tools/latest/bin` on `PATH`. The `google_apis` image (not `google_apis_playstore`) is debuggable, which `setup-emulator.sh` relies on.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
