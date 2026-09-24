# Milestone 3A: localhost-only development FIDO2 credentials

**Not a production security key.** This adds `authenticatorMakeCredential` and
`authenticatorGetAssertion` to the existing verified CTAPHID gadget. ES256 P-256
private keys are saved **unencrypted** in a mode-0600 JSON file in the Kali
chroot. Do not register this prototype with GitHub, Google, Microsoft, or any
other important account. There is no Android Keystore, fingerprint-based UV,
FIDO certification, discoverable credential, ClientPIN, CTAP1, or attestable
hardware identity.

The only enabled relying-party ID is `localhost`. A fresh **physical Volume Up
press on the phone** is required for each operation. Reading the physical
`gpio-keys` device avoids mistaking the connected smart band's virtual volume
controls for a touch. This is user presence (UP), **not** user verification
(UV). A compromised Android OS/root user could bypass it.

## Launch

The standard `ctaphid_start.sh` without `--dev` retains Milestone 2 GetInfo-only
behavior. From a rooted Android shell, after copying the updated package into
the Kali chroot's `/root/ctaphid`:

```sh
sh /data/local/tmp/fido2/ctaphid_stop.sh
sh /data/local/tmp/fido2/ctaphid_start.sh --dev
```

This changes **only the userspace daemon**; it does not edit ConfigFS,
re-enumerate the USB gadget, or change ADB, VID/PID, or NetHunter Arsenal.
The development key store is `/root/ctap-dev-credentials.json` *inside Kali*,
or `/data/local/nhsystem/kali-arm64/root/ctap-dev-credentials.json` on Android.
No service is registered at boot.

## Local Windows WebAuthn test

Run with regular Windows Python; this uses the Windows WebAuthn API rather
than administrator-only raw HID. It is an independent RP using Yubico's
`Fido2Server` and will reject an AAGUID other than our development authenticator.

```powershell
python windows/ctap3a_windows_test.py register
python windows/ctap3a_windows_test.py authenticate
```

In the Windows Security dialog choose the external **security key** if asked;
physically press **Volume Up** on the Poco F7 after it receives a request.
During authentication Windows first sends a silent `getAssertion` request
with `options.up=false` to check whether this key recognizes the credential.
The prototype answers that probe with a valid ES256 assertion but leaves UP/UV
both clear; it then requires a **fresh phone Volume Up press** for the actual
`up=true` operation. Supporting the silent check avoids Windows showing
"this security key doesn't look familiar" despite possessing the credential.
This silent mode works only for `localhost` and an explicit matching allowList
in this development build; do not enable it for arbitrary RPs in a deployed
software-key implementation without reviewing the privacy/security model.
Registration saves only public `AttestedCredentialData` into
`windows/local-test-credential.json` (never private key material). Authentication
can be repeated following daemon restart or physical USB reconnect. The JSON
file is excluded from application code; do not commit it to a public repo.

If no user approves within the configured timeout, registration and signing
must fail. `ctaphid_start.sh` has no production or auto-approve option.

## Test suite

```sh
python3 -m tests.test_offline
python3 -m unittest tests.test_credentials tests.test_async tests.test_approval -q
```

## Recovery

To go back to Milestone 2, stop the daemon then launch without `--dev`.
The original `/root/ctaphid` tree was separately backed up on the phone before
deployment under `/root/ctaphid-m2-backup`. Do **not** use the USB gadget
rollback merely to switch development credential modes. Keep the software key
store separate from the backup, and do not copy it into reports or cloud logs.

## Still required for a security-key replacement

Port signing to an Android app using Android Keystore, bind each operation to
`BiometricPrompt.CryptoObject`, implement key metadata and credential storage
without exporting private keys, then test biometric enrollment/invalidation,
locking, reboot, rollback, cancellation, backup and recovery behavior. Preserve
the native HID endpoint and change only its userspace backend. Hardware-backed
Keystore support must be measured on this ROM rather than assumed.
