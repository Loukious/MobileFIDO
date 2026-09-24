# Device compatibility probe

`DeviceCapabilities.detect(Context)` returns a read-only snapshot. Run it on a
worker thread: enumerating existing AndroidKeyStore entries can take time on
some OEM builds. It does not generate keys, execute `su`, request root, create
USB gadgets, or change authentication settings or credentials.

| Snapshot field | Meaning | Limit |
| --- | --- | --- |
| `sdk` | Android API level; the app's supported minimum is 31 (Android 12). | SDK level alone does not establish USB gadget support. |
| `strongBiometrics`, `biometricStatus` | The framework's current `BIOMETRIC_STRONG` authentication result. | Hardware temporarily unavailable yields `UNKNOWN`; no enrolled strong biometric yields `UNAVAILABLE` at the time of the check. A fingerprint sensor feature flag alone is insufficient. |
| `strongBoxFeature` | PackageManager reports the StrongBox Keystore feature. | A feature flag does not guarantee that generating/importing a specific key with the required policy will succeed. |
| `teeObserved`, `strongBoxObserved` | `KeyInfo.getSecurityLevel()` confirms the level of at least one existing MobileFIDO signing key. | `UNKNOWN` means no matching hardware-backed key was observed; it does **not** mean the hardware is absent. This does not generate test keys or inspect unrelated apps' keys. |
| `configfsGadget` | `/sys/kernel/config/usb_gadget` directory is visible. | A missing or restricted path yields `UNKNOWN` because SELinux may hide kernel support. Visibility alone does not prove that the app can configure it. |
| `hidFunction` | At least one visible gadget has an existing `hid.*` function. | `UNKNOWN` can mean no configured HID function or insufficient permissions, not lack of kernel HID support. |
| `hidDevice` | `/dev/hidg0` exists. | File presence does not prove it is readable/writable or is the correct live gadget endpoint. |
| `rootAccess` | `AVAILABLE` only if this exact app process runs as UID 0. | Normally `UNKNOWN`: checking an `su` executable or running `su -c id` cannot safely establish durable, authorized KernelSU access and could trigger a privilege prompt. |
| `kernelSu` | `/sys/kernel/ksu` is visible as a KernelSU indicator. | A hidden/absent path yields `UNKNOWN`; presence does not prove the app has root grants or that its module is installed. KernelSU forks may expose different paths. |

All capability fields use `State.AVAILABLE`, `State.UNAVAILABLE`, or
`State.UNKNOWN`. Only `strongBoxFeature` and current biometric enrollment/
capability can ordinarily be reported `UNAVAILABLE` by this conservative
snapshot. Treat any unknown result as requiring a separate user-controlled
compatibility check, especially USB permissions, HID support, actual secure
key import/generation, and KernelSU module access. This is a status display,
not an attestation of certified FIDO2 hardware or host compatibility.
