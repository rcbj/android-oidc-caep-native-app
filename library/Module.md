# Module android-oidc-caep-native-app

An OpenID Connect client library for native Android apps, in Kotlin, and a CAEP receiver. The client is public:
Authorization Code with PKCE in the system browser (a Custom Tab), PAR, and DPoP with a key in the Android Keystore.

The [guide](https://rcbj.github.io/android-oidc-caep-native-app/android-app-guide.html) walks through an integration,
and the [reference](https://rcbj.github.io/android-oidc-caep-native-app/reference.html) lists every option and its
default. This is the generated reference of every public declaration.

# Package net.rcbj.oidccaep

Everything is in one package: the client (`OIDCClient`, `OIDCAppConfiguration`), the token cache (`TokenManager`,
`AccountManager`), the CAEP receiver (`SSFReceiver`), the browser step (`CustomTabsWebAuthenticator`,
`LoopbackWebAuthenticator`) and the Android Keystore stores (`AndroidKeystoreKeyStore`, `KeystoreTokenStore`).
