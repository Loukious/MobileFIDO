# PocoKey 4.5.0-dev — multi-RP and discoverable-credential release gate

**The owner confirmed WebAuthn.io worked on installed 4.4.0-dev on September
24, 2026.** This does not establish successful 4.5.0-dev discoverable flow:
the new source/build has NOT been installed or physically tested. Keep
installed 4.4.0-dev as the known-good rollback path. Do not uninstall
PocoKey, clear its app storage, change
its APK signer, delete any KeyStore aliases or re-enable a competing HID
gadget service. Backups cannot recover deleted nonexportable private keys.

## Check old localhost credentials before creating new ones

1. With the same-signer package update (`adb install -r` when the owner permits),
   verify `org.pocof7.ctap3b` retains the **same UID**, previously stored
   credential ID and intact hardware key. A mismatch is an immediate rollback
   blocker; no uninstall or reset. The matching KernelSU module/ARM64 binary
   must be installed together; its new IPC `rpIdPolicy` handshake deliberately
   rejects an old mixed-version native/app combination.
2. First post-reboot PIN/password unlock: verify automatic foreground helper
   listener, native USB HID responder and ADB simultaneously. Activity launch
   must not throw (including after tapping a fresh approval notification).
3. Use the existing Windows localhost credential with
   `windows/ctap3b_windows_test.py authenticate`; the independent
   `Fido2Server` must verify the ES256 assertion, RP hash, `UP=1`, `UV=1`,
   and **increasing counter**. Windows' `up=false` preflight can require a
   separate strong-biometric prompt and must never claim UP. A cancelled,
   timed-out or stale-notification request must not sign anything.

## Check real HTTPS relying parties

4. With Chrome and Edge, register **test-only** non-discoverable security-key
   credentials at two DIFFERENT HTTPS origins you control. Observe the phone
   showing the actual RP ID, not just localhost. Check the resulting hardware
   key is StrongBox/TEE with per-use strong biometric and no silent-signing
   fallback. Sites requesting resident/discoverable credentials or unsupported
   CTAP PIN/extensions can fail; the helper must not claim to support them.
5. Authenticate to each HTTPS test RP. Both should work independently.
   Verify the allow/exclude list does not select an ID from the OTHER RP;
   a wrong-RP assertion must return `NO_CREDENTIALS` without a biometric
   prompt or signature; registering another RP must not be blocked by an
   exclude list containing only the first RP's ID.
6. Browser/OS handles origin vs RP validation. This CTAP bridge accepts only
   canonical lowercase ASCII DNS A-labels and the legacy `localhost` RP,
   not URLs/ports/paths/IPs/Unicode/trailing dots. Exercise a punycode RP
   test and a malformed RP test; do not broaden validation by silently
   stripping or normalizing what the host requested.

## Backup interoperability and recovery limits

7. New `CTAP3BM3` backups must include each RP ID and authenticated
   discoverability bit, reject corrupted files
   and wrong passphrases without mutation, never overwrite another RP's
   credential mapping, and preserve the largest available sign counter.
   Re-import on original phone with intact key should be idempotent.
8. An authentic old `CTAP3BM1` archive from 4.3.x must import as **localhost
   only**; it must never silently rebind its hardware key to a new website.
   Real `CTAP3BM2` archives from 4.4.x import with exact RP ID but remain
   **non-discoverable**, including when newer discoverable keys also exist.
   Cloud/local SAF selection must be user-directed; Drive is just storage
   for encrypted metadata and cannot restore on a new or reset phone.

## New 4.5 discoverable credentials

9. On an unimportant WebAuthn test account, request `residentKey: required`.
   Verify makeCredential carries `rk=true` and ONLY that new key is marked
   discoverable in the phone catalog. Existing 4.4 WebAuthn.io/localhost
   registrations remain non-discoverable after the update.
10. Start username-less login (CTAP getAssertion with OMITTED allowList).
    It must select only a live discoverable key bound to that RP and return
    user.id after fresh fingerprint approval. With two discoverable keys under
    one RP, the phone MUST show an account picker BEFORE the biometric, return
    the selected account's user.id, and never display another RP's account.
11. Check `rk=false` registration never appears in username-less login;
    wrong RP, canceled chooser, bad fingerprint, timeout and unplug MUST sign
    nothing. Test backup v3 round-trip, actual legacy v1/v2 imports, Chrome
    and Edge. Host mocks are not sufficient to claim general passkey support.

## Genuine production release requires additional work

* Long-lived, protected production signing identity and a verified safe
  Android v3 signing-lineage migration preserving on-device hardware keys.
  The currently installed short-lived known-password dev JKS MUST NOT be
  published or treated as a production release signer.
* Independent security review of root/KernelSU/USB/AndroidKeyStore trust,
  passphrase archive and data-loss behavior; official FIDO conformance,
  certification and attestation planning are separate external requirements.
* A tested lost-phone/recovery plan consisting of registering additional
  security keys/passkeys with services before loss. No encrypted metadata file
  is a portable backup of StrongBox/TEE signing private keys.
