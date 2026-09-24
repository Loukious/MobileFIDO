# Standalone Android FIDO2 security key — KernelSU Next (experimental)

MobileFIDO **5.1.1-dev** supports Recoverable credentials. New ES256 keys are
created transiently, imported into verified StrongBox/TEE with the same
per-use `BIOMETRIC_STRONG` signing policy, and can be placed in an encrypted
recovery archive whose plaintext follows FIDO CXF 1.0 passkey fields. Existing
4.x AndroidKeyStore-generated credentials remain device-bound and unchanged.
See `android-helper/MOBILEFIDO_5_0.md` for the security model and test plan.
In 5.0.1 recovery exports are read back and authenticated before backup status
is recorded; a standalone read-only saved-archive checker and backup-freshness
UI were added. See `android-helper/MOBILEFIDO_5_1_RECOVERY_QA.md`.

This separate **`pocof7_ctap_native`** module runs a native Android ARM64
CTAPHID responder with its own module service. It contains **no Kali/NetHunter
chroot, Python interpreter, Python packages, or network downloads at boot**.
Private signing keys remain in the separately installed `org.pocof7.ctap3b`
Android Keystore helper. The helper requires a foreground approval and real
`BiometricPrompt.CryptoObject` for **every signature** (including the Windows
`up=false` credential preflight). No silent signing or software-key fallback.

The helper UI includes an encrypted **MobileFIDO recovery archive** saved/opened
through Android's system document picker, which may offer Google Drive. For
new 5.0 Recoverable credentials it contains password-encrypted CXF passkey key
material and can recreate the credential after loss/reset on a compatible
device. Legacy 4.x metadata-only archives remain importable but cannot recreate
their old nonexportable private keys. The saved envelope is not CXP and should
not be advertised as directly importable by unrelated physical keys.

## Preconditions

* KernelSU Next root; arm64 Android 12/API 31 or later.
* Android hardware Keystore with BIOMETRIC_STRONG, an enrolled fingerprint,
  and hardware-enforced per-use auth in StrongBox or TEE.
* USB gadget with writable ConfigFS, a bound controller, one existing ADB
  function link and an available HID gadget function. This first version is
  validated only for the Poco F7 onyx `g1/configs/b.1`, `hid.2` and Android 17.
  Other ROM/gadget layouts fail closed; no guarantee of automatic portability.
* The Android helper app is bundled. Installer first-installs only when absent.
  Existing installs are accepted for automatic update only when their APK
  signing certificate matches the pinned long-term MobileFIDO release signer.
  The installer verifies signer identity from the APK Signing Block, keeps the
  PackageManager UID stable, and never clears/uninstalls app data. Historical
  development-signed installs are deliberately refused for automatic signer
  migration because normal Android does not permit unrelated signer replacement.
* Grant notification permission once during initial setup. On subsequent
  boots, after the first normal PIN/pattern/password unlock makes private
  credential storage available, Android's `BOOT_COMPLETED` receiver starts
  the foreground listener automatically. No app opening or first foreground
  authentication is required. App updates use `MY_PACKAGE_REPLACED` to start
  the listener as well. Native CTAPHID starts as soon as that socket appears.
  Force-stop, revoked permission or restrictive OEM battery policy can block
  startup; the module never silently launches a UI or bypasses the lockscreen.

## Install/migrate from the earlier Python module

The previous `pocof7_ctap3b` module and manual Kali CTAPHID are NOT removed,
and your registered StrongBox key is NOT migrated or regenerated. On the Poco
F7 where the prior module exists, disable it in KernelSU Manager **before the
first reboot with this standalone module**, to prevent two boot services
competing for the same /dev/hidgN endpoint. The new service also refuses to
run if it sees an active old module or other CTAPHID process. Re-enabling the
old module and disabling this module is the reversible fallback.

The `service.sh` waits for Android/USB completion and either adopts an already
valid FIDO `hid.2` function read-only or attempts a **guarded ADB-only** setup:
snapshot + independent 30-second rollback watchdog, no adbd stop, and no edits
to other HID functions or VID/PID. It refuses an incompatible USB Arsenal mode
or read-only ConfigFS and never globally remounts `/config`.

**USB disconnect/reconnect:** unplugging during a fingerprint operation must
cancel that specific CTAP challenge; unplugging is NOT permission to sign it
after the device is reconnected. The supervisor stays alive when Android's USB
HAL temporarily unbinds the UDC. It stops only the module-owned responder,
waits without touching ConfigFS, and starts a new responder when the same
FIDO+ADB gadget becomes healthy again. The browser must send a **fresh** CTAP
request after the host re-enumerates the key. If Chrome does not retry its
pending WebAuthn dialog, cancel that dialog and start login again; we cannot
replay a canceled browser challenge safely.

The KernelSU Manager **Action** button opens the Android helper when the user
taps it and prints status. No automatic background biometric authorization is
possible. CLI from local root: `sh action.sh open|status|start|stop|rollback`.
Do not execute USB rollback from an ADB shell; reboot is safer if uncertain.

The CTAPHID responder discovers /dev/hidgN by the configfs `dev` attribute,
verifies the 34-byte FIDO report descriptor (ConfigFS reads may be padded to
4096 bytes), checks the Android helper app UID via SO_PEERCRED for each socket
request. The installed 4.4.0-dev sources add RP-bound canonical ASCII DNS IDs,
and the 4.5.0-dev candidate additionally supports RP-bound discoverable
credentials (uninstalled/untested on the real phone). Both retain the
existing localhost development credentials. AAGUID
remains `PocoF7-BIO-DEV01`, preserving previously registered credentials.
Root/bootloader-unlocked devices and development attestation are NOT FIDO
certified; do not rely on this version as sole access to an important account.

## Verification

Installer: `bin/pocof7-native-ctaphid --self-test` (no USB mutation).
Read-only gadget check: `bin/pocof7-native-ctaphid --check --configfs
/config/usb_gadget/g1/functions/hid.2`.
Windows native test: existing `windows/ctap3b_windows_test.py authenticate`
with the helper's foreground **service** running; the Activity itself can be
backgrounded. When a request arrives, tap the phone's approval notification.
The Activity should open directly into the system biometric prompt (no
intermediate Continue dialog). The FIRST background request should produce
its own notification even if the Activity was bound but not yet RESUMED;
no foreground priming test is necessary. Each signature still requires its own strong
fingerprint, including Windows' possible `up=false` preflight. Requests expire
after about 60 seconds, and Windows can cancel earlier. If the phone is still
in Direct Boot mode after a restart, first unlock the phone normally to make
the Keystore credential metadata available. The device-specific boot and
notification behavior must be verified on the actual ROM.
