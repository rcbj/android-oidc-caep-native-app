---
title: Running the demo
---

# Running the demo

The demo, **CAEP Demo** (`net.rcbj.caepdemo`), is a Jetpack Compose app built on the library. It is the Android counterpart of [the Swift library's demo](https://rcbj.github.io/swift-oidc-caep-native-app/demo.html), with the same screens and the same reactions to CAEP events.

It lives in [`demo/`](https://github.com/rcbj/android-oidc-caep-native-app/tree/main/demo), a module of its own that depends on the library module (`implementation(project(":library"))`) the way your app depends on the AAR. `DemoModel.kt` holds the accounts, the CAEP stream and the event policies; `MainActivity.kt` draws them. It runs on Android 9 (API 28) or later; this page runs it on the Android emulator, against iya-sts on the same computer.

## Set up the emulator

The emulator is a virtual Pixel phone from the Android SDK. [Development](development.md#setting-up-a-linux-laptop) shows how to install the SDK and create one (`pixel_api37`, Android 17, the `google_apis` x86_64 image). Then, after **each start of the emulator**, from the repository root:

```sh
scripts/setup-emulator.sh
```

[`scripts/setup-emulator.sh`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/scripts/setup-emulator.sh) does four things:

1. **Starts the emulator** (`AVD`, default `pixel_api37`) unless a device is already connected, and waits for it to boot.
2. **Forwards iya-sts's port** with `adb reverse tcp:8081 tcp:8081` (`STS_PORT`), so that `https://localhost:8081` on the phone is iya-sts on the computer. The issuer in iya-sts's metadata is `https://localhost:8081`, so the app uses the very URL the issuer names. (`10.0.2.2`, the emulator's usual name for the host, would fail the issuer check.)
3. **Saves iya-sts's root CA for the app.** It fetches the chain from `GET /tls/server-certificate` and writes its self-signed root to `demo/src/main/assets/sts-root.pem`, which the demo's configuration lists under `TrustedCertificates` with `TrustSystemRoots` false. TLS verification stays on, and the app trusts that root only. The file is gitignored.
4. **Lets Chrome trust the same CA, and nothing else.** It writes `--ignore-certificate-errors-spki-list=<the CA keys' SHA-256 hashes>` to `/data/local/tmp/chrome-command-line`, which Chrome reads on a debuggable build such as the emulator's `google_apis` image, and restarts Chrome. The sign-in pages then load without a certificate warning. It also passes `--disable-fre --no-first-run`, so Chrome's welcome screens don't come in the way.

Run it again after iya-sts's CA changes (a rebuilt instance), and rebuild the demo so it carries the new root.

## Register the client on iya-sts

The demo's configuration points at iya-sts on `https://localhost:8081`, client `oidc-caep-android-demo`. Register it in the default realm, from the repository root:

```sh
ADMIN_API_CLIENT_SECRET=… node scripts/register-iya-sts-client.mjs
```

[`scripts/register-iya-sts-client.mjs`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/scripts/register-iya-sts-client.mjs) needs Node.js and nothing installed. It reads the demo's `oidc_configuration.json`, gets a management API token as `sts-api-client` (the client iya-sts seeds for its management API), and:

- creates the public client (`token_endpoint_auth_method: none`) with the file's redirect URI and post-logout redirect URI, and the file's scopes. A native app needs no CORS origin;
- adds the client to `SSF_READ` and `SSF_MANAGE`, for whichever of `ssf.read` and `ssf.manage` the file asks for (iya-sts issues each only when the application is a member of the role and the person is in its group, `ssf-read` or `ssf-manage`);
- creates a test user, `caep-demo-user`, in those groups. Its password is `CAEP_DEMO_USER_PASSWORD`, or one is generated and printed once. iya-sts asks for a generated password to be changed at the first sign-in.

| Option | Use |
|---|---|
| `--config path` | Another `oidc_configuration.json`, such as your own app's. |
| `--test-user name`, `--no-test-user` | Name the test user, or skip it. |

The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. Every step can be repeated safely.

**The sign-in's time limit.** The demo pushes its sign-in request to iya-sts (PAR), and iya-sts holds a pushed request for `oauth2.parRequestUriLifetimeS` seconds, 60 by default. That covers the whole sign-in: the password, a password change, a second factor and the consent screen. A person working through those screens needs longer; on the iya-sts the demo uses, raise it (600 is RFC 9126's maximum) with `POST /admin-api/config/set` (`{"key":"oauth2.parRequestUriLifetimeS","value":600}`). A sign-in that takes too long ends at iya-sts with `invalid_request_uri`; start it again from the app.

## Start it

```sh
./gradlew :demo:installDebug
adb shell am start -n net.rcbj.caepdemo/.MainActivity
```

or open the **CAEP Demo** icon on the emulator. The app reads [`demo/src/main/assets/oidc_configuration.json`](https://github.com/rcbj/android-oidc-caep-native-app/blob/main/demo/src/main/assets/oidc_configuration.json):

| Key | Value |
|---|---|
| `MetadataURL` | `https://localhost:8081/.well-known/openid-configuration` |
| `ClientID` | `oidc-caep-android-demo` |
| `Scopes` | `openid profile email offline_access ssf.read ssf.manage` |
| `RedirectURI` | `net.rcbj.caepdemo:/callback` |
| `PostLogoutRedirectURI` | `net.rcbj.caepdemo:/logged-out` |
| `DPoP`, `PAR`, `CAEPEnabled` | `true`, `auto`, `true` |
| `TrustedCertificates`, `TrustSystemRoots` | `["sts-root.pem"]`, `false` |

To point the demo at another provider without rebuilding, push a file with the same keys to the app's external files folder; the demo reads it in place of the built-in one, and **Configuration** at the foot of the Identity tab says which it used:

```sh
adb push my_oidc_configuration.json /sdcard/Android/data/net.rcbj.caepdemo/files/oidc_configuration.json
```

A relative `TrustedCertificates` entry in such a file is a file beside it. [Building a native Android app](android-app-guide.md#4-create-oidc_configurationjson) lists every key.

**Driving the sign-in from a script.** A person taps through iya-sts's pages in the Custom Tab. A script can fill them through Chrome's DevTools (`adb forward tcp:9333 localabstract:chrome_devtools_remote`), but a button it clicks is not a user gesture, and Chrome then asks "Continue to CAEP Demo?" before handing the redirect to the app. Submit the last step (consent's **Allow**) with a real tap (`adb shell input tap x y`) and the hand-off goes straight through.

## What it does

- **Sign-in** happens in a Custom Tab (RFC 8252), never in a `WebView`. The browser's session is shared, so a second sign-in can use the provider's account picker.
- **DPoP** binds tokens to a P-256 key generated in the Android Keystore (`preferredDPoPKeyStore`): StrongBox or the TEE on a phone, software on the emulator, which has no secure hardware. The key is never extractable.
- **PAR** is used whenever the provider offers it.
- **Tokens** for every signed-in account are cached in `KeystoreTokenStore` (AES-256-GCM under a Keystore key), so they survive the app being closed. Backups are off for the app, since the key cannot be restored on another device.
- **CAEP:** the stream is created with the person's access token (with a DPoP proof) and polled from the app every 5 seconds. With `ssf.manage`, the person is added as the stream's subject, and the stream asks for the event types picked on the **CAEP events** tab. `CAEPEnabled` defaults to true. Set it to false to turn off CAEP and RISC: the receiver is not started, and those two scopes are left out of the authorization request, so the same app can sign in at an identity provider that does not implement Shared Signals.

The screen has a top bar and two tabs.

**The top bar** shows the active account. Its menu switches to another signed-in account, signs in with another account, signs out, forgets an account that is no longer signed in, and signs out of all accounts. With nobody signed in, it is a **Sign in** button.

**Identity:**

- **OpenID Connect:** who is signed in, and **Sign in** / **Sign in with another account**, or **Continue as …** / **Sign in again as …** for an account whose tokens expired or whose session ended.
- **Session:** the validated ID token's claims for the active account (`sub`, `acr`, `amr`, `sid`, `iss`, `auth_time` …), and whether a step-up is required.
- **Token cache:** a meter of the time left before the access token expires, the time to the next automatic refresh, the last refresh, where the cache is kept, and **Call UserInfo** and **Force refresh**.
- **Tokens:** the tokens issued at sign-in beside the current ones, encoded or decoded.
- **Protections in effect:** PKCE, `state`, `nonce`, issuer identification, PAR, the DPoP algorithm, key thumbprint and where the key lives (StrongBox, TEE or software), resource indicators, TLS, the ID token checks, and the token cache (`client.securityFeatures`).

**CAEP events:**

- **Shared Signals stream:** the transmitter, the `stream_id`, the stream's status, its `aud`, the delivery, and whether the token can manage the stream (`ssf.manage`) or only read it.
- **Event types:** a checkbox per CAEP event type, and **Update**, which applies them to the stream (`updateStream`).
- **Verify** asks the transmitter for a verification event; **Reconnect** restarts the receiver.
- **Events:** each event received for the active account, with the action taken; **Details** shows its subject and payload.

It reacts to events about the signed-in person:

| Event | Action |
|---|---|
| session-revoked | Ends the account and discards its tokens. |
| token-claims-change | Refreshes the tokens. |
| credential-change | Revoked or deleted: ends the account. Otherwise tells the person. |
| assurance-level-change | Decrease: asks for step-up (re-authentication). |
| device-compliance-change | Not compliant: ends the account. |
| risk-level-change | HIGH: ends the account. MEDIUM: asks for step-up. |
| session-established, session-presented | Logged only. |

To try it, sign in, open the **CAEP events** tab, and send an event from iya-sts: `POST /admin-api/caep/emit` with the person's `session_id` and a `type` such as `credential-change` (the person stays signed in) or `session-revoked` (the account ends).

## Several accounts

iya-sts can keep several people signed in to one browser (`authn.multipleAccounts`). The app has **one active account**: only its tokens are used and refreshed, and only its stream is polled. The others are dormant.

- **Switching** (the account menu) needs no password. The account's stream first catches up on the events queued while it was dormant.
- **A signed-out or ended account** in the menu starts a sign-in that names it (`login_hint`) and refuses anybody else.
- **Sign in with another account** is a fresh sign-in (`prompt=login`).
- **The event log** shows the active account's events only, and is cleared for an account when it signs out.
- **An event that ends a session** ends that account only. A `session-revoked` naming another of the person's sessions is ignored.
- **Sign out** revokes that account's tokens, ends its session at the provider in a Custom Tab, and keeps the other accounts. **Sign out of all accounts** ends them all.
- **Closing the app** keeps every account: the cache is encrypted on the device, and the active account is reactivated at the next launch.
