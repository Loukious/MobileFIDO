# MobileFIDO — release-readiness notes

This project is a functional, **experimental** root-enabled USB security-key
implementation, not a FIDO-certified authenticator. The UI may be suitable
for everyday use once tested, but a polished interface does not imply that
the hardware, firmware, attestation, or security lifecycle are certified.

See `SIGNING_AND_RECOVERY_PLAN.md` for the staged signing-key migration,
nonportable-key recovery procedure, physical QA and separate-account policy.

## Non-negotiable compatibility and security requirements

- Preserve Android package `org.pocof7.ctap3b`, app-private data, and existing
  `AndroidKeyStore` aliases. The primary phone is now signed by the owner's
  long-term release certificate
  `c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da`.
  Keep the release JKS backed up securely outside the repository; **do not
  publish its private key or passwords**. Losing it prevents normal future
  same-signer updates.
- The old one-year development signer is no longer the intended build identity.
  The owner's custom/rooted ROM accepted that signer transition in place, which
  is unusual and must not be assumed on stock Android or another device. The
  KernelSU installer therefore refuses automatic legacy-dev-signer → release-
  signer migration and only auto-updates an already release-signed installation.
- Gradle's default debug keystore is NOT the approved installed app signer:
  do not install arbitrary IDE `assembleDebug` output over the working app.
  `build-local.sh` requires the external release JKS, pins the certificate
  SHA-256, and never auto-generates a replacement key.
- Preserve hardware-backed ES256 private keys and their per-signature
  `BIOMETRIC_STRONG` `BiometricPrompt.CryptoObject` authorization. Windows may
  need separate biometric authorizations for credential preflight and assertion.
- Keep the standalone KernelSU Next native CTAPHID responder. Android app
  UI changes must never require Kali/NetHunter or a software signing fallback.
- Never allow an imported backup file to create arbitrary credential mappings,
  downgrade key policy, reset a higher signature counter, or authorize a
  pending CTAP request. File-picker activity is not biometric consent.

## Google Drive / local archive: what is and is not recoverable

The system file picker lets a user choose a provider (including Google Drive
**if** the installed Drive provider appears in the picker) and save/open an
encrypted metadata archive with their passphrase. No direct Google login,
Drive API token, broad storage permission, or automatic background upload is
needed. Keep `android:allowBackup="false"`: generic Android app backup is not
an alternative to a deliberately scoped archive.

Legacy 4.x credentials use private keys generated nonexportably inside Android
Keystore/StrongBox and cannot be recovered onto another device. MobileFIDO 5
**recoverable** credentials are different by design: their PKCS#8 private key is
included only inside the user-password-encrypted authenticated recovery archive,
then re-imported into verified StrongBox/TEE for normal signing after restore.
The user has verified register → export → delete → restore → authenticate on the
primary device. Second-device migration remains untested and must not be claimed
as validated until exercised on another compatible device.

## Release gate (host-only and eventual physical QA)

1. Compile the exact APK with the external release keystore; verify APK v3
   signature, package, declared foreground service, no INTERNET permission,
   boot receiver, and `POST_NOTIFICATIONS` consent.
2. Exercise archive round-trips, wrong passphrase, tampered/truncated files,
   duplicate records, excessive sizes/counts, missing aliases, mismatched
   hardware public keys/policies, and an import while live credentials exist.
3. Rebuild a deterministic standalone KSU ZIP; verify binary architecture,
   release APK signature with Android SDK `apksigner`, pinned signer certificate,
   manifest/provenance, ZIP checksums, and installer-side release-signer/UID
   continuity without relying on a historical whole-APK hash allowlist.
4. With the phone **connected only when its owner permits**, verify boot after
   initial unlock without opening the Activity, first background request
   notification, direct fingerprint, double per-use fingerprint when Windows
   preflights, cancellation and notification expiry, repeated signed assertion
   and increasing counter, USB ADB preservation, same UID and credential ID.
5. Evaluate app icon, screen-reader content, font scaling, light/dark,
   notification denial and restricted battery policy, and all backup
   error/partial-restore messages on a real Android 17 device.

The owner confirmed installed 4.4.0-dev (APK + module) worked on WebAuthn.io
September 24, 2026; whether both registration and login succeeded is not yet
recorded. New HOST-ONLY 4.5.0-dev implements explicitly discoverable
credentials, RP-scoped account selection, omitted-allowList login and v3
metadata archives containing authenticated discoverability flags. Existing
4.4 registrations stay non-discoverable by default. The development
AAGUID (`PocoF7-BIO-DEV01`), production signing
distribution, third-party security review, device-loss recovery and FIDO
certification require distinct future work.

## MobileFIDO 4.6 credential-manager development status (host-only)

Source and same-signed development artifacts now include RP-grouped searchable
credential catalog, optional validated site-provided account name/displayName
and creation date for NEW registrations, friendly discoverable account picker,
explicit-confirmation + strong-biometric individual deletion, and v4
authenticated encrypted metadata backup with v1/v2/v3 import support.
The existing user-installed build remains **4.5.0-dev**. No 4.6 deletion,
account-picker, same-device metadata restore, or browser interop is physically
verified; tests and APK signing checks are host-only. Test deletion only with
an unimportant credential after a second recovery method is registered.
See `POCOKEY_4_6.md` for the detailed compatibility and deletion test plan.

## MobileFIDO 5 recoverable-passkey development status

MobileFIDO 5 source introduces Recoverable credentials for **new** registrations:
the ES256 private key exists transiently for recovery setup, is imported into
verified StrongBox/TEE for normal per-use-biometric signing, and can be placed
in a user-encrypted archive whose plaintext follows FIDO CXF 1.0 Passkey
fields. Recoverable credentials use BE/BS semantics and a permanently-zero
signature counter; existing 4.x credentials remain device-bound and unchanged.

This remains a development feature until the physical Poco F7 proves the full
register → export → delete → restore → authenticate round trip and a second
compatible phone or deliberately wiped **test** device proves device-loss
recovery. The `.mobilefido` envelope is not itself CXP and is not yet a direct
vendor-hardware-key import format. See `MOBILEFIDO_5_0.md`.

## Functionality still required before calling it a general-purpose FIDO2 key

* **Multi-RP and discoverable physical interop are still release gates**:
  4.4.0-dev implements
  matching Rust/Android DNS RP-ID validation, persistent per-credential RP
  bindings, RP-bound allow/exclude-list selection, SHA-256 of the requested RP,
  and backward-compatible localhost v1 backup import. Host-side mock tests
  do NOT replace real Chrome/Edge registration and authentication for at least
  two distinct HTTPS domains plus wrong-RP refusal and original-localhost
  credential reauthentication on the actual Poco F7. IDNA A-label and public
  suffix/origin checks remain the WebAuthn browser/client responsibility.
* Standard CTAP2/WebAuthn conformance beyond the existing minimal, local
  `FIDO_2_0`/ES256 subset: spec-driven test vectors, required
  extensions for any newly claimed version, authenticatorGetInfo option
  accuracy, client platform/browser interop, CTAPHID error/keepalive and
  cancellation, PIN/UV policies, attestation model, credential management,
  and real tests of discoverable/resident-key flows. Never advertise
  unsupported capabilities or claim certificates/certification not earned.
  The 4.5.0-dev native bridge deliberately advertises **no** `clientPin`
  option (unsupported, not merely unconfigured) and rejects an explicit
  `options.up` in makeCredential because it advertises CTAP2.0, not CTAP2.1;
  this is also covered by Rust host regressions.
* Account recovery: legacy 4.x nonexportable StrongBox/TEE keys remain
  unrecoverable. New 5.0 Recoverable credentials deliberately trade strict
  non-copyability for encrypted recovery. The password/KDF, local escrow,
  hardware import, restore transaction and rooted-device threat model need
  independent review before this should replace an independent authenticator
  for important accounts.
* External review of the rooted/USB gadget trust boundary, reproducible
  releases, fail-closed Android Keystore KeyInfo checks, OEM service/boot
  restrictions, app signing, notification/biometric prompt spoofing risks,
  and on-device tests. FIDO Alliance certification is a separate formal
  program, not a label awarded by compiling the APK or passing host tests.
