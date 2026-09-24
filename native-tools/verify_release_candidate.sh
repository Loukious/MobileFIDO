#!/usr/bin/env bash
# Host-only release-candidate gate. Never run adb/su, enumerate USB gadgets,
# install apps/modules, change the Android signing certificate, or fetch deps.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

# This gate creates a release-SIGNED development candidate. Using the long-term
# release signer does not imply FIDO certification or completion of external QA.
# build-local.sh requires MOBILEFIDO_KEYSTORE and obtains signing passwords
# without putting them in source or command-line arguments.

: "${JAVA_HOME:?Set JAVA_HOME to JDK 17}"
: "${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT to Android SDK 35}"
: "${ANDROID_BUILD_TOOLS:=${ANDROID_SDK_ROOT}/build-tools/35.0.0}"
: "${ANDROID_LINKER:?Set ANDROID_LINKER to NDK aarch64-linux-android35-clang}"
if [[ -z "${CARGO_BIN:-}" ]]; then
    CARGO_BIN="$(command -v cargo || true)"
    if [[ -z "${CARGO_BIN}" && -x "${HOME}/.cargo/bin/cargo" ]]; then
        CARGO_BIN="${HOME}/.cargo/bin/cargo"
    fi
fi
if [[ -z "${CARGO_BIN:-}" || ! -x "${CARGO_BIN}" ]]; then
    echo 'REFUSED: Rust Cargo is unavailable (set CARGO_BIN)' >&2
    exit 1
fi
if [[ ! -x "${ANDROID_LINKER}" ]]; then
    echo "REFUSED: Android NDK linker is unavailable: ${ANDROID_LINKER}" >&2
    exit 1
fi

echo '[1/5] Production and adversarial Python + Java host tests'
python3 -m unittest discover -s tests -p 'test_*.py' -q
echo '[2/5] Offline native CTAPHID tests'
(cd native-ctaphid && "${CARGO_BIN}" test --locked --offline --all-targets -q)
echo '[3/5] Locked, offline Android ARM64 native build'
(cd native-ctaphid &&
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_LINKER}" \
    "${CARGO_BIN}" build --release --target aarch64-linux-android --locked --offline -q)
echo '[4/5] Pinned release-signer JDK17/SDK35 APK build'
JAVA_HOME="${JAVA_HOME}" ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT}" \
ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS}" bash android-helper/build-local.sh
echo '[5/5] Deterministic release-signed APK + native KernelSU ZIP'
python3 native-tools/build_native_module.py

echo 'Host-only release-candidate checks passed (NOT FIDO certification).'
sha256sum android-helper/app/build/manual/MobileFIDO-5.1.1-release.apk \
    native-ctaphid/target/aarch64-linux-android/release/pocof7-native-ctaphid \
    native-tools/dist/MobileFIDO-Android-FIDO2-KSU-Next.zip
