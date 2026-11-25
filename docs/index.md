---
title: android-oidc-caep-native-app
---

# android-oidc-caep-native-app

An OpenID Connect client library for **native Android apps**, written in Kotlin. It runs in the app as a **public client**, with no client secret. It is the Android counterpart of the Swift library [swift-oidc-caep-native-app](https://rcbj.github.io/swift-oidc-caep-native-app/) (macOS), itself the native port of the JavaScript library [oidc-caep-client](https://rcbj.github.io/oidc-caep-client/). It covers:

- **Signing in:** Authorization Code with PKCE, PAR, DPoP-bound tokens, RFC 9207 mix-up defence, and full ID token validation. The sign-in page opens in the system browser through a Custom Tab (RFC 8252), never in a `WebView`.
- **Tokens:** cached encrypted at rest (AES-256-GCM under an Android Keystore key) and refreshed before they expire.
- **DPoP keys:** generated in the Android Keystore, in StrongBox when the device has it, else the TEE, so the private key can never be read out.
- **Several accounts:** several people signed in to one app, with one active account.
- **CAEP:** subscribing to the identity provider's Shared Signals stream, with one handler per CAEP event and a hook for your own logic. `CAEPEnabled` defaults to true. Set it to false to turn off CAEP and RISC: the receiver is not started, and `ssf.read` and `ssf.manage` are left out of the authorization request, so the app can sign in at an identity provider that does not implement Shared Signals.

Everything is in the package `net.rcbj.oidccaep`. The library needs Android 9 (API 28) or later; its dependencies are kotlinx.coroutines, kotlinx.serialization-json, OkHttp and androidx.browser. The API follows the Swift library's, with Kotlin's conventions; [Android and macOS](android.md) lists every difference.

## Install

There is no published Maven artifact yet. Build the AAR from a release tag of [the repository](https://github.com/rcbj/android-oidc-caep-native-app):

```sh
./gradlew :library:assembleRelease          # library/build/outputs/aar/library-release.aar
```

Copy it into your app's `libs/` folder and, in the app module's `build.gradle.kts`:

```kotlin
android {
    defaultConfig {
        manifestPlaceholders["oidcRedirectScheme"] = "com.example.myapp"   // the redirect URI's scheme
    }
}

dependencies {
    implementation(files("libs/library-release.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    implementation("androidx.browser:browser:1.10.0")
}
```

## Where to read

- **[Building a native Android app](android-app-guide.md)**, the walkthrough:
  - registering the app at the identity provider, with a private-use redirect URI;
  - the `oidc_configuration.json` file;
  - signing in, and where tokens and keys are kept;
  - calling your APIs;
  - receiving CAEP events;
  - signing out, errors, the manifest, backups and troubleshooting.
- **[API reference](reference.md):** the security features, every option and its default, the methods and events, and the CAEP event table.
- **[API reference (Dokka)](api/)**, generated from the source for every public declaration.
- **[Running the demo](demo.md):** a complete Jetpack Compose app built this way, with several accounts, a CAEP event log and an event-type picker, and how to run it on the Android emulator against iya-sts.
- **[Android and macOS](android.md):** every difference from the Swift library.
- **[Development](development.md):** tests (unit and live), CI, branches and the layout of the repository.

## Quick look

```kotlin
import net.rcbj.oidccaep.*

// assets/oidc_configuration.json: MetadataURL, ClientID, Scopes, RedirectURI, …
val configuration = OIDCAppConfiguration.load(context)
val client = configuration.makeClient(dpopKeyStore = preferredDPoPKeyStore(context))
val accounts = AccountManager(client, AccountManagerOptions(store = KeystoreTokenStore(context))).restore()

// Sign in in a Custom Tab.
val signedIn = accounts.signIn(configuration.makeAuthenticator(activity))
val key = signedIn.account.key
val identity = signedIn.account.identity

// React to security events about the signed-in person.
val caep = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer = client.issuer,
    authorization = SSFAuthorization.oidc(client) { accounts.getTokenSet() },
    // Runs for every event, before the handlers below. The default, logEventReceived, logs the
    // event's name and jti; replace it with your own logic, or pass null to turn it off.
    onEventReceived = { event ->
        logEventReceived(event)
        audit.record(event.name, event.subject)
    },
))

// One handler per event type. Register your own to decide what each event does.
caep
    .onSessionRevoked { event ->
        if (subjectMatches(event.subject, identity)) accounts.end(key, "Your session was ended.")
    }
    .onTokenClaimsChange { accounts.refresh() }
    .onCredentialChange { event ->
        if (event.payload.string("change_type") in setOf("revoke", "delete")) accounts.end(key, "Sign in again.")
    }
    .onAssuranceLevelChange { event ->
        if (event.payload.string("change_direction") == "decrease") requireStepUp()
    }
    .onDeviceComplianceChange { event ->
        if (event.payload.string("current_status") == "not-compliant") accounts.end(key, "This device no longer meets policy.")
    }
    .onRiskLevelChange { event ->
        if (event.payload.string("current_level") == "HIGH") accounts.end(key, "Unusual activity was detected.")
    }
    .onError { error, context -> println("CAEP ${context.phase.value} ${error.code ?: ""} ${error.message}") }

caep.start(catchUp = true)
```

Every call is a `suspend` function: run it in a coroutine (`viewModelScope.launch { … }`). `audit` and `requireStepUp()` stand for your app's own code. Registering a handler for an event type adds to what runs; `removeHandlers(CAEP.SESSION_REVOKED)` removes them again. `onEvent(type, handler)` handles any other type, such as the RISC events in `RISC`. The [guide](android-app-guide.md#9-receive-caep-events) wires a receiver to the active account and suggests a reaction for each event, and the [reference](reference.md#caep-one-handler-per-event) lists every handler and its payload fields.

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.
