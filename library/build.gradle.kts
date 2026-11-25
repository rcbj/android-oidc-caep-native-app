// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.dokka)
}

val libraryVersion = rootProject.file("VERSION").readText().trim().let { if (it.count { c -> c == '.' } == 1) "$it.0" else it }

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
