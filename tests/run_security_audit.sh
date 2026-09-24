#!/usr/bin/env bash
# Automated NONDESTRUCTIVE security gate for MobileFIDO source/artifacts.
# Usage: bash tests/run_security_audit.sh [--idle-device ADB_SERIAL]
# NO credential creation/deletion, module install, app launch, root commands,
# biometric interaction or USB ConfigFS writes. Active WebAuthn tests require
# an explicitly user-driven, disposable account and are NOT automated here.
set -euo pipefail

cd "$(dirname "$0")/.."

idle_device=
if [[ "${1:-}" == --idle-device && -n "${2:-}" && $# == 2 ]]; then
  idle_device="$2"
elif (( $# )); then
  echo 'Usage: bash tests/run_security_audit.sh [--idle-device ADB_SERIAL]' >&2
  exit 2
fi

echo '== Python: archive tampering, approval invariants, APK/module identity, GUI and capability probes =='
python3 -m unittest discover -s tests -p 'test_*.py' -q

echo '== Native Rust: CTAPHID parser, channel isolation, cancellation, timeouts and stale responses =='
if ! command -v cargo >/dev/null 2>&1; then
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    echo 'Rust security tests NOT RUN: install Rust/Cargo and a host C linker.' >&2
    exit 2
  fi
fi
if [[ -z "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-}" ]] &&
   ! command -v cc >/dev/null 2>&1 &&
   [[ -x /tmp/mobilefido-test-toolchain/host-cc ]]; then
  export CC=/tmp/mobilefido-test-toolchain/host-cc
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
fi
( cd native-ctaphid && cargo test --all-targets --locked --offline )

echo '== KernelSU release packaging and integrity gate =='
python3 -m unittest tests.test_native_module -q

if [[ -n "$idle_device" ]]; then
  echo '== OPTIONAL READ-ONLY idle battery/thermal and CPU measurement =='
  bash tests/measure_android_readonly.sh "$idle_device" 6 10
fi

echo 'PASS: automated non-destructive security gate; live biometric/device-migration checks remain manual.'
