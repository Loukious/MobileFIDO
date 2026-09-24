# MobileFIDO 5.0.1-dev — verified recovery and migration gate

The recovery password stays **user-chosen**. New full-recovery archives require
at least 16 characters, use PBKDF2-HMAC-SHA256 (600,000 iterations) and
AES-256-GCM, and include the recoverable FIDO credential's private-key material
encrypted inside the archive. Do not upload a real archive or passphrase to a
bug report. A separate randomly generated recovery code is NOT required.

## Export and backup freshness

The export operation runs under the existing foreground strong-biometric and
CTAP-maintenance controls. After the Android Storage Access Framework provider
closes its output stream, MobileFIDO opens the chosen document again and
streams through it with a 512 KiB cap. The read-back SHA-256 and byte length
must match the exact ciphertext just produced. MobileFIDO also decrypts that
same ciphertext using the original user-chosen password, strictly parses its
CXF payload, validates key pairs, and checks that the credential ID set matches
the export snapshot. The password and plaintext key buffers are cleared on
normal/error paths. Only **after all these checks** does MobileFIDO persist:

- the latest verified export timestamp and number of credentials;
- a per-credential last-verified-export timestamp;
- a SHA-256 fingerprint of the encrypted archive (no credential key material).

If the provider cannot read the file back (including some not-yet-uploaded
cloud documents), the file is **NOT VERIFIED**, even when the write returned
success. Keep the old backup and export to a readable location; optionally use
the separate read-only verification action later. The app cannot prove a remote
cloud provider will retain the file forever or synchronize it to another device.
The SAF picker suggests a timestamped, unique `.mobilefido` filename so an
interrupted write does not overwrite the only known-good archive by default.

The recovery card shows the last locally verified archive and how many current
recoverable credentials have no locally recorded, read-back-verified archive.
Individual credentials show their verified export time, or clearly distinguish
older/reimported archives whose file was not verified by this installation.
New registrations are not silently claimed to be covered by an old export.

**Important:** The new verification timestamp does not retroactively certify
archives created by MobileFIDO 5.0.0-dev. Select **Verify an existing recovery
archive** or export a fresh archive. Read-only verification checks an existing
file, its password, the archived key pairs, and coverage of keys currently on
this phone. If the archive exactly matches the full current recoverable set,
MobileFIDO records verification and the per-credential dates. Otherwise it
reports the missing, mismatched or extra credentials and does not certify
freshness. It does not import/delete signing credentials; only verified-backup
metadata and WebAuthn BS state can change when full coverage is established.

## Interrupted and damaged files

Export write/flush failure, provider unreadability, truncation, size mismatch,
modified ciphertext, changed credential set and failed authenticated CXF
parsing must not update backup freshness or mark a new credential as backed up.
A document provider might still leave an empty/partial file after failure;
MobileFIDO warns the user not to rely on it. Do not delete or overwrite the
last verified independent archive until a newer one has been verified.

Restore rejects malformed/wrong-password/tampered archives before touching
hardware aliases. Duplicate IDs and mismatches with an already-working key
are rejected; existing live signing keys are never overwritten with different
material. Staged hardware-import aliases are now journaled *before* import.
After a crash or interrupted restore, the next CryptoKeyManager initialization
can delete only unreferenced staged aliases, preserving any alias already
referenced by a committed credential mapping. The first boot after a restore
interruption may log safe generic journal-cleanup diagnostics.

## Second Android phone migration — needs another real phone

Only one device (`onyx`, Poco F7) was attached while this change was built.
There is no honest way to claim second-device migration passed on that basis.
Never factory-reset the only phone containing important credentials to run
this test. When a second supported phone is available:

1. Ensure Android >= 12 (API 31), KernelSU Next or a deliberately implemented
   equivalent root integration, appropriate USB ConfigFS/HID support, and a
   STRONG biometric. StrongBox-first key import must pass hardware verification;
   a verified TEE-only fallback is permissible; software key storage is not.
2. Register a *disposable* recoverable credential from Phone A with a test RP,
   export and readback-verify an archive, and keep its passphrase private.
3. Install the same-signer MobileFIDO development package on Phone B, with its
   separate device-specific USB gadget integration reviewed first. Do NOT copy
   the first phone's USB controller name, vendor/product ID, app data or local
   hardware-wrapped escrow as a substitute for recovery.
4. Transfer the encrypted archive through a document provider, restore it on
   Phone B after explicit strong biometric, and verify the RP/account/credential
   ID are identical to Phone A. The browser should recognize the SAME existing
   test account without creating a new WebAuthn credential.
5. Authenticate from both devices; portable credentials use signCount=0 and
   BE=1. Verify that the biometric prompt remains per use on Phone B and that
   Phone A still works. Check that no unrelated keys were replaced/deleted.

The APK package ID `org.pocof7.ctap3b`, development AAGUID, signer and Keystore
domain strings are legacy compatibility boundaries; their Poco-specific spellings
do NOT imply every Poco or Android device has been validated.

## OnlyKey interoperability — source audit, no unverified compatibility claim

Source inspected: `trustcrypto/OnlyKey-Firmware` at
`9600daa8ffc8a0d727808fcb561911eed6dc0bfb`, and `trustcrypto/libraries`
at `20e1623faf69c560864c746cd697a83dcb238e26`.

`libraries/fido2/ctap.h::CTAP_residentKey` lacks a per-credential arbitrary
private scalar. `crypto.cpp::generate_private_key` derives each ES256 key from
the credential data and master secret; `onlykey/okcore.cpp::backup` saves that
master authenticator state plus resident records. Stock firmware `RESTORE`
loads broad device state, not a standalone PKCS#8 passkey. Its experimental
`CTAPHID_LOADKEY` controls master state, NOT one arbitrary credential's private
scalar. Normal OnlyKey user-configured ECC slots are not FIDO resident keys.

Therefore a current MobileFIDO CXF passkey cannot be repackaged as an OnlyKey
device-backup file and expected to authenticate as the same existing account.
True cross-hardware migration would require an OnlyKey-compatible credential
creation mode *before registration* and very careful whole-device backup-state
management, or a supported custom-firmware per-credential import extension.
Do not patch/overwrite a user's stock OnlyKey just to test. Obtain real hardware
and separate explicit permission before any destructive OnlyKey restore trial.

No CryptoTrust-specific source was copied into the MobileFIDO app; see
`../research/ONLYKEY_RECOVERY_AUDIT.md` for source paths and licensing details.
