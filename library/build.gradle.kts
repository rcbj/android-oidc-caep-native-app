// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.dokka)
    alias(libs.plugins.vanniktech.maven.publish)
}

// The version: -PreleaseVersion=M.N.P from the publish workflow (.github/scripts/release_decision.py chose it),
// otherwise VERSION (M.N, read as M.N.0). Nothing is stamped into a committed file.
val libraryVersion = providers.gradleProperty("releaseVersion").orNull
    ?: rootProject.file("VERSION").readText().trim().let { if (it.count { c -> c == '.' } == 1) "$it.0" else it }

android {
    namespace = "net.rcbj.oidccaep"
    compileSdk {
        version = release(37) { minorApiLevel = 1 }
    }
    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
        buildConfigField("String", "LIBRARY_VERSION", "\"$libraryVersion\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.json)
    api(libs.okhttp)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.browser)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
}

// The API reference (Dokka 2): `./gradlew :library:dokkaGeneratePublicationHtml` writes library/build/dokka/html,
// which .github/workflows/pages.yml publishes at /api/ on the documentation site.
dokka {
    moduleName.set("android-oidc-caep-native-app")
    dokkaSourceSets.configureEach {
        includes.from("Module.md")
        sourceLink {
            localDirectory.set(file("src/main/kotlin"))
            remoteUrl("https://github.com/rcbj/android-oidc-caep-native-app/tree/main/library/src/main/kotlin")
            remoteLineSuffix.set("#L")
        }
    }
}

// Maven Central: com.iyasec:oidc-caep-android, the AAR with its sources and a javadoc jar (Dokka's HTML), signed.
// The publish workflow supplies the Central Portal token and the signing key as ORG_GRADLE_PROJECT_mavenCentralUsername,
// ORG_GRADLE_PROJECT_mavenCentralPassword, ORG_GRADLE_PROJECT_signingInMemoryKey and
// ORG_GRADLE_PROJECT_signingInMemoryKeyPassword. Without a key nothing is signed, so publishToMavenLocal works anywhere.
mavenPublishing {
    coordinates("com.iyasec", "oidc-caep-android", libraryVersion)
    configure(
        com.vanniktech.maven.publish.AndroidSingleVariantLibrary(
            javadocJar = com.vanniktech.maven.publish.JavadocJar.Dokka("dokkaGeneratePublicationHtml"),
            sourcesJar = com.vanniktech.maven.publish.SourcesJar.Sources(),
            variant = "release",
        ),
    )
    publishToMavenCentral(automaticRelease = true)
    if (providers.gradleProperty("signingInMemoryKey").isPresent) signAllPublications()
    pom {
        name.set("oidc-caep-android")
        description.set(
            "OpenID Connect client library for native Android apps: Authorization Code + PKCE in a Custom Tab, PAR, " +
                "DPoP with Android Keystore keys, several accounts with tokens encrypted at rest, and a CAEP/SSF receiver.",
        )
        url.set("https://github.com/rcbj/android-oidc-caep-native-app")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("rcbj")
                name.set("Robert C. Broeckelmann Jr.")
                organization.set("Iya CyberSecurity Solutions, LLC")
                url.set("https://github.com/rcbj")
            }
        }
        scm {
            url.set("https://github.com/rcbj/android-oidc-caep-native-app")
            connection.set("scm:git:https://github.com/rcbj/android-oidc-caep-native-app.git")
            developerConnection.set("scm:git:ssh://git@github.com/rcbj/android-oidc-caep-native-app.git")
        }
        issueManagement {
            system.set("GitHub Issues")
            url.set("https://github.com/rcbj/android-oidc-caep-native-app/issues")
        }
    }
}
