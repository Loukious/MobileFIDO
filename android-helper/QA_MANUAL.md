# PocoKey 4.3.0-dev: owner's live-device acceptance checklist

The stable, already-installed user-test artifacts are APK SHA-256
`fd64a2dea98de33daa168e581319c1887f93a25806579d9a4b2ebcb98fd4f283`
and KernelSU ZIP SHA-256
`c2f24efd99b45e6721f202026a302ff56b6a026b61e1f4a7aab148e35131ee85`.
Do not install another APK, wipe app data, uninstall the app, or change the
installed signing key during the acceptance test.

1. After a reboot, **unlock the phone normally once** with its PIN/password.
   The foreground `PocoKey DEV` Activity should not need to be opened for the
   root-only listener to start. KernelSU module `pocof7_ctap_native` should be
   enabled, and the prior Kali-based `pocof7_ctap3b` module disabled.
2. While the phone is at its launcher, run the existing Windows localhost
   `windows/ctap3b_windows_test.py authenticate` command with an already
   registered localhost development credential. Confirm that the FIRST
   request creates a tappable notification, which opens the app directly into
   Android's biometric prompt. Fingerprint authorizes only that operation;
   the Windows `up=false` preflight and actual assertion may need TWO separate
   fingerprints. The host script verifies the returned signature and counter.
3. Open PocoKey: status card shows listener/notification readiness, existing
   credential catalog and STRONGBOX/TEE. Check dark/light mode and large
   font/screen-reader labeling. The app remains labeled DEVELOPMENT ONLY,
   localhost and NOT FIDO-certified; status text alone is not proof that USB
   native CTAP is listening.
4. Tap Export encrypted backup, enter and confirm a UNIQUE 12+ character
   passphrase, and pick a system document provider (Google Drive when it is
   installed/available, or local Downloads). The document MUST be described
   as encrypted metadata only; its private hardware key remains on the phone.
   Check cancelled picker, incorrect/mismatched/short passphrase and storage
   failure do not modify credentials. Do not share the passphrase or file.
5. Import the file on the original device. If metadata is already present,
   the status should report `Already present`, not create duplicate credentials
   or lower the signature counter. Wrong password or a corrupted file must be
   rejected without changing credentials. **Do not delete a real Keystore
   alias or uninstall the app to test recovery.** This file cannot reconstruct
   deleted hardware private keys, a reset phone or a new device.
6. Retry the Windows existing-credential authentication after the backup UI,
   confirming there is no interruption in root-only listener/USB ADB and no
   regression in notification/fingerprint flow.

Record which stage failed, the exact visible status/error without posting
private metadata, whether notification settings allow alerts, and whether
Windows produced one or two biometric prompts. Do not upload debug keystores,
secret passphrases, raw biometric data, or unredacted credential metadata.

This live test covers UX/interoperability of the development localhost
authenticator. FIDO2 certification, general website RP IDs and portable
hardware key recovery are NOT established by it.
