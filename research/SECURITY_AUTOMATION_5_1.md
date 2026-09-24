# MobileFIDO 5.1 development security gate and UI review

Run the host gate (requires Python, JDK17, Rust/Cargo and a C linker):

```sh
bash tests/run_security_audit.sh
```

Optional idle phone measurements, **read-only** and run only when requested:

```sh
bash tests/run_security_audit.sh --idle-device <ADB_SERIAL>
```

The optional script reads process CPU, battery level/temperature, thermal
service, system load and optional battery current. It does NOT root the app,
modify the USB gadget, generate/restore/delete keys or authorize any FIDO
request. On Windows WSL where only `adb.exe` is available, put a shell wrapper
named `adb` on PATH which forwards arguments to the installed adb.exe.

## Automated surface

- Native Rust engine tests: malformed/oversized frames, cross-CID isolation,
  worker saturation, cancellation, USB clear/re-enumeration, stale job/result
  rejection, UP/UV semantics, per-RP request checks and bounded timeouts.
- Python tests: recovery tamper/static protocol invariants, approval/event
  timeouts, FIDO import/counter flags, package/signer/UID migration guard,
  metadata/privacy constraints, module packaging, UI lifecycle, capability
  probe read-only behavior.
- Java host tests: actual `RecoveryArchiveVerifier` source rejects changed,
  truncated, appended, missing and oversized document-provider reads and
  matches SHA-256 for exact readback, including zero-byte reads.
- Android read-only idle measurement: 2026-09-24, 3 samples 5 seconds apart,
  battery 31.8–31.9°C; Android thermal status 0; native responder ~0.1% CPU,
  helper app ~0.2% CPU. This is a short idle sample, not an active battery-life
  or stress benchmark; HAL cached thermal values can be stale and are not
  interchangeable with current battery temperature.

## GUI adjustments

- `KEY STATUS` rows now use the same 14sp regular-weight typography and
  9dp vertical separation; its redundant explanatory subtitle was removed.
- The notification settings action appears only when approval notifications
  are disabled; the local listener no longer prints an implementation-specific
  Unix socket string into the main app status.
- The app header says MobileFIDO once; repetitive disclaimers, duplicate
  bottom recovery cautions and long file-picker instructions were condensed.
- Credential labels no longer falsely say recovery material is never
  exportable; MobileFIDO 5 recovery is deliberately an encrypted export.
- The new device-support section reports Android version, current strong
  biometrics, published StrongBox feature versus verified StrongBox/TEE keys,
  visible HID endpoint and the limits of app-side root detection. Its worker
  thread cannot delay active CTAP signing and it never generates a test key.
- Recovery-critical warnings and the explicit development/uncertified label
  remain. The biometric approval path and user-chosen recovery password are
  unchanged.

## Tests that cannot safely be fully automated on the owner's primary phone

An external biometric rig/human is needed to validate real fingerprint
consent for all negative and positive paths, interrupted hardware import at
physical power-loss boundaries, genuine factory-reset/new-device migration,
and full USB disconnect/reconnect/reboot tests. Tests using a disposable RP
can exercise these, but deleting accounts or wiping the only device is not an
acceptable unattended security test. Formal FIDO certification and external
security review are independent release gates, not assumed from host tests.
