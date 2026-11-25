# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The library's unit tests in a container, like the other rcbj client libraries:
#   docker build --target test .
# The image holds JDK 17 and the Android SDK packages the build needs (no emulator: the tests run on the JVM).

FROM eclipse-temurin:17-jdk-noble AS sdk
ARG CMDLINE_TOOLS=commandlinetools-linux-15859902_latest.zip
ARG CMDLINE_TOOLS_SHA256=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583
ENV ANDROID_HOME=/opt/android-sdk
RUN apt-get update && apt-get install -y --no-install-recommends unzip curl ca-certificates && rm -rf /var/lib/apt/lists/* \
 && curl -fsSLo /tmp/clt.zip "https://dl.google.com/android/repository/${CMDLINE_TOOLS}" \
 && echo "${CMDLINE_TOOLS_SHA256}  /tmp/clt.zip" | sha256sum -c - \
 && mkdir -p "$ANDROID_HOME/cmdline-tools" && unzip -q /tmp/clt.zip -d /tmp/clt \
 && mv /tmp/clt/cmdline-tools "$ANDROID_HOME/cmdline-tools/latest" && rm -rf /tmp/clt /tmp/clt.zip \
 && yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null \
 && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platforms;android-37.1" "build-tools;36.0.0" > /dev/null

FROM sdk AS test
WORKDIR /src
# The wrapper and build scripts first, so the Gradle distribution and dependencies are a cached layer.
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties VERSION ./
COPY gradle gradle
COPY library/build.gradle.kts library/consumer-rules.pro library/
COPY demo/build.gradle.kts demo/
RUN ./gradlew --no-daemon -q help
COPY . .
RUN ./gradlew --no-daemon :library:testDebugUnitTest
