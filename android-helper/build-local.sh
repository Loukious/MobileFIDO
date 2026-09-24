#!/usr/bin/env bash
# Reproducible release-signed development build using JDK 17 and Android SDK 35.
# Set JAVA_HOME, ANDROID_SDK_ROOT, MOBILEFIDO_KEYSTORE and optionally
# ANDROID_BUILD_TOOLS / MOBILEFIDO_KEY_ALIAS. Signing passwords are prompted
# without echo on an interactive terminal or may be supplied through the
# MOBILEFIDO_STOREPASS / MOBILEFIDO_KEYPASS environment variables.
set -euo pipefail
umask 077

cd "$(dirname "$0")"
if [[ -z "${JAVA_HOME:-}" ]]; then
    echo "JAVA_HOME must point to JDK 17" >&2
    exit 1
fi
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "${ANDROID_SDK_ROOT}" ]]; then
    echo "ANDROID_SDK_ROOT must point to an Android SDK containing platforms/android-35" >&2
    exit 1
fi
ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-${ANDROID_SDK_ROOT}/build-tools/35.0.0}"
PLATFORM_JAR="${ANDROID_SDK_ROOT}/platforms/android-35/android.jar"
if [[ ! -r "${PLATFORM_JAR}" || ! -x "${ANDROID_BUILD_TOOLS}/aapt2" ||
      ! -x "${JAVA_HOME}/bin/javac" ]]; then
    echo "Install SDK Platform 35, Build-tools 35 and JDK 17" >&2
    exit 1
fi

# An APK signing identity is an Android app-data/Keystore continuity boundary.
# The long-term MobileFIDO release key deliberately lives OUTSIDE this tree.
# Never generate a replacement signer when a checkout/build directory is
# cleaned and never uninstall the app to work around a signature mismatch.
APPROVED_CERT_SHA="c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da"
SIGNING_JKS="${MOBILEFIDO_KEYSTORE:-}"
SIGNING_ALIAS="${MOBILEFIDO_KEY_ALIAS:-mobilefido}"
if [[ -z "${SIGNING_JKS}" ]]; then
    echo "REFUSED: set MOBILEFIDO_KEYSTORE to the external long-term release JKS" >&2
    echo "Do not copy a signing keystore into this repository and NEVER uninstall the existing app." >&2
    exit 1
fi
if [[ ! -f "${SIGNING_JKS}" || -L "${SIGNING_JKS}" ]]; then
    echo "REFUSED: approved release signing keystore is absent/invalid: ${SIGNING_JKS}" >&2
    echo "Restore the original signing keystore securely. NEVER uninstall the existing app to replace its signature." >&2
    exit 1
fi
if [[ -z "${MOBILEFIDO_STOREPASS+x}" ]]; then
    if [[ -t 0 ]]; then
        read -r -s -p "MobileFIDO release keystore password: " MOBILEFIDO_STOREPASS
        printf '\n' >&2
        export MOBILEFIDO_STOREPASS
    else
        echo "REFUSED: no interactive terminal; set MOBILEFIDO_STOREPASS in the environment" >&2
        exit 1
    fi
fi
if [[ -z "${MOBILEFIDO_KEYPASS+x}" ]]; then
    # keytool commonly creates the key with the store password. A distinct key
    # password remains supported by explicitly setting MOBILEFIDO_KEYPASS.
    MOBILEFIDO_KEYPASS="${MOBILEFIDO_STOREPASS}"
    export MOBILEFIDO_KEYPASS
fi
trap 'unset MOBILEFIDO_STOREPASS MOBILEFIDO_KEYPASS' EXIT

# Hash the DER certificate itself rather than parsing localized keytool output.
# :env keeps passwords out of process arguments and build logs.
CERT_SHA="$("${JAVA_HOME}/bin/keytool" -exportcert \
    -keystore "${SIGNING_JKS}" -alias "${SIGNING_ALIAS}" \
    -storepass:env MOBILEFIDO_STOREPASS | sha256sum | cut -d ' ' -f 1)"
if [[ "${CERT_SHA}" != "${APPROVED_CERT_SHA}" ]]; then
    echo "REFUSED: signing certificate is not the pinned MobileFIDO release identity" >&2
    exit 1
fi

OUTPUT="app/build/manual"
chmod 700 -- "${OUTPUT}"
# Retain last-known-good signed APKs, but never leak a class/resource removed
# from source into the NEXT APK. The signing keystore is external to OUTPUT.
rm -rf -- "${OUTPUT}/classes" "${OUTPUT}/dex" "${OUTPUT}/resources"
mkdir -p "${OUTPUT}/classes" "${OUTPUT}/dex"
find app/src/main/java -type f -name '*.java' | LC_ALL=C sort > "${OUTPUT}/sources.txt"
"${JAVA_HOME}/bin/javac" -source 17 -target 17 -Xlint:all \
    -cp "${PLATFORM_JAR}" -d "${OUTPUT}/classes" @"${OUTPUT}/sources.txt"
RESOURCES=( )
if [[ -d app/src/main/res ]]; then
    mkdir -p "${OUTPUT}/resources"
    "${ANDROID_BUILD_TOOLS}/aapt2" compile --dir app/src/main/res \
        -o "${OUTPUT}/resources"
    while IFS= read -r -d '' resource; do
        RESOURCES+=( -R "$resource" )
    done < <(find "${OUTPUT}/resources" -type f -name '*.flat' -print0 | sort -z)
fi
"${ANDROID_BUILD_TOOLS}/aapt2" link -o "${OUTPUT}/unsigned.apk" \
    --manifest app/src/main/AndroidManifest.xml \
    -I "${PLATFORM_JAR}" --min-sdk-version 31 --target-sdk-version 35 \
    --auto-add-overlay \
    --version-code 50101 --version-name 5.1.1-dev \
    "${RESOURCES[@]}"

CLASSES=()
while IFS= read -r -d '' class_file; do
    CLASSES+=("${class_file}")
done < <(find "${OUTPUT}/classes" -type f -name '*.class' -print0)
JAVA_HOME="${JAVA_HOME}" PATH="${JAVA_HOME}/bin:${PATH}" \
    "${ANDROID_BUILD_TOOLS}/d8" --min-api 31 --lib "${PLATFORM_JAR}" \
    --output "${OUTPUT}/dex" "${CLASSES[@]}"
"${JAVA_HOME}/bin/jar" uf "${OUTPUT}/unsigned.apk" -C "${OUTPUT}/dex" classes.dex

# aapt2/jar ZIP entry timestamps and ordering otherwise change across builds.
# Canonicalize ONLY the unsigned APK's ZIP container, preserve entry bytes
# and stored/compressed status (notably uncompressed resources.arsc), then
# run Android zipalign and apksigner on the canonical bytes. This intentionally
# contains no signing key material and cannot rewrite an already signed APK.
python3 - "${OUTPUT}/unsigned.apk" <<'PY'
import os
from pathlib import Path
import sys
import tempfile
import zipfile

apk = Path(sys.argv[1])
fd, temporary = tempfile.mkstemp(prefix=".ctap3b-unsigned-", suffix=".apk", dir=apk.parent)
try:
    with os.fdopen(fd, "wb") as destination:
        with zipfile.ZipFile(apk, "r") as original, zipfile.ZipFile(
                destination, "w", allowZip64=False) as canonical:
            files = original.infolist()
            names = [entry.filename for entry in files]
            if len(names) != len(set(names)) or not names:
                raise ValueError("unsigned APK contains duplicate or no ZIP entries")
            for entry in sorted(files, key=lambda item: item.filename):
                if entry.is_dir():
                    raise ValueError("unexpected directory in unsigned APK")
                info = zipfile.ZipInfo(entry.filename, (2020, 1, 1, 0, 0, 0))
                info.compress_type = entry.compress_type
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                canonical.writestr(info, original.read(entry),
                                   compress_type=entry.compress_type, compresslevel=9)
        destination.flush()
        os.fsync(destination.fileno())
    os.replace(temporary, apk)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
"${ANDROID_BUILD_TOOLS}/zipalign" -f 4 \
    "${OUTPUT}/unsigned.apk" "${OUTPUT}/aligned.apk"

# The APK certificate is distinct from the nonexportable FIDO signing keys.
# It MUST remain the pinned release identity for future updates.
JAVA_HOME="${JAVA_HOME}" PATH="${JAVA_HOME}/bin:${PATH}" \
    "${ANDROID_BUILD_TOOLS}/apksigner" sign \
    --ks "${SIGNING_JKS}" --ks-key-alias "${SIGNING_ALIAS}" \
    --ks-pass env:MOBILEFIDO_STOREPASS --key-pass env:MOBILEFIDO_KEYPASS \
    --out "${OUTPUT}/MobileFIDO-5.1.1-release.apk.new" "${OUTPUT}/aligned.apk"
VERIFY_OUTPUT="$(JAVA_HOME="${JAVA_HOME}" PATH="${JAVA_HOME}/bin:${PATH}" \
    "${ANDROID_BUILD_TOOLS}/apksigner" verify --verbose --print-certs \
    "${OUTPUT}/MobileFIDO-5.1.1-release.apk.new")"
printf '%s\n' "${VERIFY_OUTPUT}" | grep -q '^Verifies$' || {
    echo "REFUSED: apksigner did not verify the release APK" >&2
    exit 1
}
APK_CERT_SHA="$(printf '%s\n' "${VERIFY_OUTPUT}" | sed -n \
    's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr '[:upper:]' '[:lower:]')"
[[ "${APK_CERT_SHA}" = "${APPROVED_CERT_SHA}" ]] || {
    echo "REFUSED: final APK signer is not the pinned MobileFIDO release identity" >&2
    exit 1
}
mv -f -- "${OUTPUT}/MobileFIDO-5.1.1-release.apk.new" \
    "${OUTPUT}/MobileFIDO-5.1.1-release.apk"
sha256sum "${OUTPUT}/MobileFIDO-5.1.1-release.apk"
