# MobileFIDO

MobileFIDO is an experimental Android FIDO2 / CTAPHID authenticator that turns
a rooted Android phone into a USB security key. The current implementation uses
a native Android ARM64 CTAPHID responder plus an Android app that keeps working
signing keys in Android Keystore StrongBox/TEE and requires a real
`BiometricPrompt.CryptoObject` authorization for every FIDO signature.

> **Development / research software.** MobileFIDO is not FIDO Alliance
> certified, has not received an independent security audit, and should not be
> your only recovery method for important accounts.

## Current release

The current development release is **5.1.1-dev**.

- Android package: `org.pocof7.ctap3b`
- KernelSU module ID: `pocof7_ctap_native`
- CTAPHID helper socket: `ctaphid-m3b-v1`
- Development AAGUID: `PocoF7-BIO-DEV01`
- Minimum Android API: 31 / Android 12
- First validated device: Poco F7 (`onyx`), Android 17, KernelSU Next

These legacy-looking compatibility identifiers are intentionally stable. They
must not be casually renamed because existing credentials and installations
depend on them.

## Highlights

- Native USB CTAPHID transport; no Kali/NetHunter/Python runtime dependency in
  the current standalone KernelSU module.
- ES256 credentials use verified StrongBox or TEE Android Keystore keys for
  normal signing. Software/unknown security levels fail closed.
- Every assertion signature requires strong biometric authorization through a
  genuine `BiometricPrompt.CryptoObject`, including Windows/WebAuthn
  `up=false` preflight assertions.
- RP-bound resident/discoverable and non-discoverable credentials.
- Password-encrypted MobileFIDO recovery archives for new recoverable passkeys.
- Legacy 4.x hardware-generated credentials remain device-bound and unchanged.
- Backup readback verification, archive freshness status, corrupt/wrong-password
  handling, and interrupted-restore cleanup.
- Dynamic-color Android UI with credential catalog and conservative read-only
  device capability reporting.
- Reproducible KernelSU packaging with pinned APK release-signer verification.

## Architecture

```text
Windows / browser WebAuthn
          |
       CTAPHID
          |
  USB HID gadget (/dev/hidgN)
          |
  native Rust responder (root / KernelSU)
          |
  root-only local Android socket
          |
  org.pocof7.ctap3b Android app
          |
  BiometricPrompt.CryptoObject
          |
  Android Keystore StrongBox / TEE
```

The native responder never contains a software FIDO private-key fallback. The
Android helper owns credential metadata, biometric authorization and hardware
key use.

## Installation

The recommended installation artifact is the KernelSU Next ZIP attached to the
GitHub release. It bundles the matching Android helper APK and native responder.

1. Keep another authentication/recovery method registered for important
   accounts.
2. Install the release ZIP from KernelSU Next Manager on a compatible rooted
   ARM64 Android device.
3. Reboot when KernelSU requests it.
4. Open MobileFIDO once, grant notification permission, and confirm the app
   reports its local service and device support correctly.
5. Test registration/authentication with a disposable WebAuthn account before
   relying on it elsewhere.

If `org.pocof7.ctap3b` is already installed, **do not uninstall it or clear its
data**. That can destroy access to app-owned Android Keystore credentials.

The current installer only auto-updates an existing helper whose certificate is
already the pinned long-term MobileFIDO release signer. It deliberately refuses
automatic migration from the historical development signer.

## Recovery model

MobileFIDO 5 recoverable credentials deliberately trade strict non-copyability
for disaster recovery. A new credential is created transiently, imported into
verified StrongBox/TEE for normal signing, and may be exported inside an
authenticated password-encrypted `.mobilefido` archive.

New archives use:

- PBKDF2-HMAC-SHA256, 600,000 iterations
- AES-256-GCM
- random salt and nonce
- minimum 16-character user-chosen password
- authenticated CXF-shaped passkey data inside the MobileFIDO envelope

The primary device has successfully completed a disposable
register → export → delete → restore → authenticate round trip. Cross-device
restore is implemented but **has not yet been physically validated on a second
phone**.

Legacy 4.x credentials were generated as nonexportable Android Keystore keys.
No archive can reconstruct those private keys after they are destroyed.

See:

- [`android-helper/MOBILEFIDO_5_0.md`](android-helper/MOBILEFIDO_5_0.md)
- [`android-helper/MOBILEFIDO_5_1_RECOVERY_QA.md`](android-helper/MOBILEFIDO_5_1_RECOVERY_QA.md)
- [`research/ONLYKEY_RECOVERY_AUDIT.md`](research/ONLYKEY_RECOVERY_AUDIT.md)

## Build from source

### Android helper

The manual release builder uses JDK 17 and Android SDK / Build-tools 35. The
release signing key is intentionally external to the repository.

```bash
export JAVA_HOME=/path/to/jdk-17
export ANDROID_SDK_ROOT=/path/to/android-sdk
export ANDROID_BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/35.0.0"
export MOBILEFIDO_KEYSTORE="$HOME/mobilefido-signing/mobilefido-release.jks"
export MOBILEFIDO_KEY_ALIAS=mobilefido

bash android-helper/build-local.sh
```

On an interactive terminal the build script prompts for the keystore password
without echo. It can also read `MOBILEFIDO_STOREPASS` and
`MOBILEFIDO_KEYPASS` from a trusted local environment, but secrets must never be
committed or printed to CI logs.

The official release signer certificate SHA-256 is:

```text
c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da
```

`build-local.sh` fails closed if a different certificate is supplied.

### Native responder

```bash
cd native-ctaphid
cargo test --locked
cargo build --release --target aarch64-linux-android --locked
```

Cross-building requires an Android NDK AArch64 linker for the target API. See
[`native-ctaphid/README.md`](native-ctaphid/README.md).

### KernelSU package

After building the native responder and a release-signed APK:

```bash
python3 native-tools/build_native_module.py
```

The packager verifies the APK with Android SDK `apksigner`, pins the approved
release certificate, records provenance/checksums, and refuses to bundle JKS or
private-key material.

## Tests

The local non-destructive audit is:

```bash
bash tests/run_security_audit.sh
```

The latest release preparation passed:

- 120 Python tests, 2 skipped
- 25 Rust unit tests
- 4 Rust integration tests
- 9 current native-module packaging tests

Physical biometric acceptance/rejection, USB replug behavior, abrupt power
loss, cross-device restore, OEM compatibility and formal FIDO conformance still
require real-device/manual testing.

## Repository layout

| Path | Purpose |
| --- | --- |
| `android-helper/` | Android Java app, recovery implementation and build tooling |
| `native-ctaphid/` | Current Rust CTAPHID/CTAP2 native responder |
| `ksu-native-module/` | Current standalone KernelSU Next runtime module source |
| `native-tools/` | Current deterministic package/release tooling |
| `tests/` | Host security, recovery, UI and packaging regression tests |
| `research/` | Recovery/security source studies and audit notes |
| `ctaphid/`, `ksu-module/`, `ksu-tools/` | Historical Python/prototype implementation retained for reference/tests |
| `README-milestone*.md` | Historical development notes; not the current install guide |

## Security notes

- Never uninstall or `pm clear` the Android helper when credentials matter.
- Never publish the release JKS, signing passwords, recovery archives or local
  credential metadata.
- MobileFIDO deliberately does not bypass the Android biometric UI or silently
  approve FIDO signatures.
- A rooted/unlocked Android device has a larger trust surface than a dedicated
  certified hardware authenticator.
- The current AAGUID/attestation identity is developmental and makes no FIDO
  certification claim.

See [`SECURITY.md`](SECURITY.md) and
[`android-helper/PRODUCTION_READINESS.md`](android-helper/PRODUCTION_READINESS.md)
for the current security/release gates.

## License

No project-wide software license has been selected yet. The source is published
for inspection and collaboration, but no additional reuse rights are granted by
this repository until a license is added. Third-party dependencies retain their
own licenses.
