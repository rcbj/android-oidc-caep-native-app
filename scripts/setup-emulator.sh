#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Gets the Android emulator ready to run the demo against a local iya-sts:
#
#   1. starts the emulator (AVD $AVD, default pixel_api37) unless a device is already connected, and waits for it;
#   2. `adb reverse tcp:$STS_PORT tcp:$STS_PORT`, so that https://localhost:$STS_PORT on the phone is the
#      iya-sts on this computer: the issuer in the metadata (https://localhost:8081) is then the URL the app uses;
#   3. fetches the chain from GET /tls/server-certificate and writes its self-signed root to
#      demo/src/main/assets/sts-root.pem, which the demo's oidc_configuration.json trusts (TrustedCertificates,
#      with TrustSystemRoots false). TLS verification stays on in the app;
#   4. tells Chrome on the emulator to accept certificates chaining to that root, and only those, with
#      --ignore-certificate-errors-spki-list (read from /data/local/tmp/chrome-command-line, which Chrome honours on
#      debuggable builds such as the emulator's google_apis image). The sign-in pages then load without a warning.
#
# Run it after each emulator start (the adb reverse rule and the Chrome flags do not survive a cold boot), and after
# iya-sts's CA changes (a rebuilt instance).
#
#   scripts/setup-emulator.sh
#   STS_PORT=8081 AVD=pixel_api37 scripts/setup-emulator.sh
set -euo pipefail

STS_PORT="${STS_PORT:-8081}"
AVD="${AVD:-pixel_api37}"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
EMULATOR="$ANDROID_HOME/emulator/emulator"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ASSET="$ROOT_DIR/demo/src/main/assets/sts-root.pem"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if ! "$ADB" get-state >/dev/null 2>&1; then
  echo "Starting the emulator ($AVD)…"
  nohup "$EMULATOR" -avd "$AVD" -no-boot-anim >"$WORK/../caep-demo-emulator.log" 2>&1 &
fi
"$ADB" wait-for-device
for _ in $(seq 1 150); do
  [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 2
done
echo "Device: $("$ADB" shell getprop ro.product.model | tr -d '\r'), Android $("$ADB" shell getprop ro.build.version.release | tr -d '\r')"

"$ADB" reverse "tcp:$STS_PORT" "tcp:$STS_PORT" >/dev/null
echo "adb reverse: localhost:$STS_PORT on the device → localhost:$STS_PORT here"

# The chain iya-sts serves (leaf first); its last certificate is the self-signed root.
curl -sSk "https://localhost:$STS_PORT/tls/server-certificate" -o "$WORK/chain.pem"
awk -v dir="$WORK" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (dir "/cert" n ".pem")}' "$WORK/chain.pem"
count=$(ls "$WORK"/cert*.pem | wc -l)
[ "$count" -ge 1 ] || { echo "No certificate in https://localhost:$STS_PORT/tls/server-certificate" >&2; exit 1; }
root="$WORK/cert$count.pem"
if [ "$(openssl x509 -in "$root" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" != "$(openssl x509 -in "$root" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')" ]; then
  echo "The last certificate of the chain is not self-signed; refusing to guess the root." >&2
  exit 1
fi
mkdir -p "$(dirname "$ASSET")"
openssl x509 -in "$root" -out "$ASSET"
echo "Trust anchor for the app: $(openssl x509 -in "$ASSET" -noout -subject) → ${ASSET#"$ROOT_DIR"/}"

# Chrome: accept chains containing one of the CA keys (root and intermediates), nothing else.
spkis=""
for i in $(seq 2 "$count"); do
  h=$(openssl x509 -in "$WORK/cert$i.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
  spkis="${spkis:+$spkis,}$h"
done
echo "_ --disable-fre --no-default-browser-check --no-first-run --ignore-certificate-errors-spki-list=$spkis" >"$WORK/chrome-command-line"
"$ADB" push "$WORK/chrome-command-line" /data/local/tmp/chrome-command-line >/dev/null
"$ADB" shell chmod 644 /data/local/tmp/chrome-command-line
"$ADB" shell am force-stop com.android.chrome
echo "Chrome trusts the iya-sts CA keys only ($((count - 1)) SPKI hashes); it picks this up on its next start."
