# Milestone 3B — Poco F7 Android Keystore biometric authenticator (development)

This is a separate `localhost`-only prototype. It does **not** replace the
verified Milestone 3A software-key store, and must not be registered as a
security key for important accounts. The distinctive AAGUID is
`PocoF7-BIO-DEV01`, not a certified or trustworthy hardware attestation.

## Current live-device status

The Java helper APK is built and installed as `org.pocof7.ctap3b` (Android
app UID initially observed `10271`); Android reports fingerprint, Keystore
and StrongBox features. The helper's private abstract Unix socket appears as
`@ctaphid-m3b-v1`, and the Kali root daemon has successfully connected with
**both** sides checking each other's Linux UID. Windows enumerates the
original `1209:0001` FIDO HID interface and sends a valid CTAP2
`makeCredential` request to the Android IPC backend.

**Not yet confirmed end to end:** Android's TEE/StrongBox `KeyInfo` check,
the `BiometricPrompt.CryptoObject` signature, or Windows registration and
authentication with a hardware-backed credential. The most recent live
registration request reached the helper but never completed: first attempts
rejected the StrongBox key due to an incorrect KeyInfo duration comparison,
and an additional request timed out during the on-phone authorization flow.
No Milestone 3B credential was saved by the Windows test. Do not report this
as working fingerprint FIDO2 until the Windows test prints its success lines
and the app displays a measured TEE/StrongBox security level.

### Poco F7 / Android 17 KeyInfo duration correction

The first on-device key-generation diagnostic measured `level=2/STRONGBOX`,
`authRequired=true`, `authDuration=0`, `biometricAllowed=true`, and
`hardwareEnforcedAuth=true`, with **only** `authDuration` flagged as failed.
The original validation erroneously expected `-1` exclusively. The current
`KeyGenParameterSpec.Builder.setUserAuthenticationParameters(0,
AUTH_BIOMETRIC_STRONG)` explicitly uses `0` for **every use** on Android 17,
while older `KeyInfo` documentation describes `-1` for every use. The app now
accepts only `0` or legacy `-1`, *never a positive authentication duration*,
and retains the StrongBox/TEE, hardware-enforcement and CryptoObject checks.
This specific rejection was a validation mismatch, not evidence that the
StrongBox-generated key lacked per-operation biometric restrictions. A fresh
end-to-end registration/assertion test is still required.

## Phone operation — a human must approve

Open **Poco F7 CTAP 3B DEV** and leave the Activity visible; do not switch
to another app, minimize, or lock the screen while testing. When Windows
starts a registration, the phone displays an explicit localhost consent
dialog. Tap **Continue to biometric**, then authorize the subsequent Android
system fingerprint prompt. Each request has about 25 seconds. Windows may
request **two** prompts during subsequent authentication: one preflight
(`up=false`, no UP bit) and one actual assertion (`up=true`). Both need
biometric authorization because the private key is auth-per-use.

If Windows reports **"This security key doesn't look familiar"**, check
`/root/ctaphid.log` inside Kali before assuming the credential is lost. On
2026-09-24 the live assertion failed with `Android helper unavailable`: the
phone had switched to ChatGPT, its biometric-consent Activity was no longer
foreground, and Android's ActivityManager stopped the idle HelperService;
`@ctaphid-m3b-v1` disappeared from `/proc/net/unix`. Reopening the helper
restored the socket and Python's `AndroidBackend` handshake without creating
or replacing any credential. The Windows test script now proactively checks
that the Activity is **topResumed** and the abstract socket is present before
starting WebAuthn, with an explicit remediation message if either is missing.

## From WSL — Windows test

Run from the repository root using a Windows Python installation that has the
required FIDO test dependencies:

```sh
python.exe windows/ctap3b_windows_test.py register
python.exe windows/ctap3b_windows_test.py authenticate
```

The new public RP credential (if registration succeeds) is stored at
`windows/local-test-keystore-credential.json`, **not** the Milestone 3A
`local-test-credential.json`. Do not delete the app or clear its storage after
registering: the Keystore aliases and metadata belong to the installed app.

## USB and daemon safety

No ConfigFS/UDC/VID/PID/ADB settings need changing. The M3B mode only
replaces the userspace CTAPHID daemon on `/dev/hidg2`.

```sh
# Run with /mnt/d/platform-tools/adb.exe shell (the full Windows adb path is
# D:\platform-tools\adb.exe):
sh /data/local/tmp/fido2/ctaphid_stop.sh
sh /data/local/tmp/fido2/ctaphid_start.sh --android
```

The script resolves the actual installed APK UID with Android's package
manager and passes it to Python's `SO_PEERCRED` validation. Android likewise
rejects non-root clients. No TCP listener or INTERNET permission is used.
If the Android helper app is not open/ready, the daemon fails closed instead
of silently reverting to software credentials.

To restore the original working Milestone 3A volume-key prototype:

```sh
sh /data/local/tmp/fido2/ctaphid_stop.sh
sh /data/local/tmp/fido2/ctaphid_start.sh --dev
```

Its original software credential store is preserved in the Kali chroot at
`/root/ctap-dev-credentials.json`, and its public Windows test credential is
preserved separately. The pre-Milestone-3A source tree is also backed up on
the phone at `/root/ctaphid-m2-backup` inside Kali.

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -q
python3 -m tests.test_offline
```

Unit and mock IPC tests cover malformed CBOR/JSON, RP and credential-ID
scoping, honest UP/UV flags, Windows silent preflight, per-request cancellation,
channel safety, and refusal to connect to a server with the wrong app UID.
These tests are not substitutes for measured AndroidKeyStore security-level
and physical biometric hardware tests.
