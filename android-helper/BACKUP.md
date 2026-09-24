# Backup and recovery formats

> **MobileFIDO 5:** new Recoverable credentials now have a real encrypted recovery
> archive that can recreate their FIDO key after deletion, app-data loss,
> factory reset, or on another compatible MobileFIDO device. See
> `MOBILEFIDO_5_0.md` and `RecoverableBackupManager.java`. Its authenticated
> plaintext follows FIDO CXF 1.0 passkey fields; the saved `.mobilefido` file is a
> password-encrypted MobileFIDO envelope, not raw CXF/CXP.
>
> The remainder of this document describes the **legacy 4.x CTAP3BM1..4
> metadata-only format**, retained for import compatibility.

## Legacy 4.x encrypted metadata catalog

**This is not a portable backup of FIDO2 keys.** The Poco F7's StrongBox/TEE
AndroidKeyStore private keys are deliberately **nonexportable**. This feature
encrypts the app's credential catalog metadata, not hardware private keys.
Saving the file to Google Drive or another SAF document provider does **not**
make credentials recoverable on another phone, after uninstall clears this
app's Keystore entries, after a factory reset, or after deletion/invalidation
of a hardware alias.

Restore can only recover a **lost catalog mapping on the original device** if
the same Keystore alias **still exists** and its exact public P-256 point,
STRONGBOX/TEE security level and hardware-enforced per-use BIOMETRIC_STRONG
KeyInfo policy match the encrypted record. A mismatch counts as unavailable;
it cannot be replaced or generated, even using the correct password. Existing
conflicting catalog records are left untouched.

## Integration contract for the Android UI worker

    List<CryptoKeyManager.CredentialInfo> catalog = keys.listCredentials();
    // Each entry has credentialId, securityLevel, available.

    byte[] blob = BackupManager.exportEncrypted(keys, passwordChars);
    BackupManager.RestoreResult outcome =
        BackupManager.restoreEncrypted(keys, blob, passwordChars);
    // outcome.restored / outcome.alreadyPresent / outcome.unavailable

Calls are intended for the existing **off-main-thread cryptoExecutor**, NOT
the UI thread; PBKDF2 is deliberately expensive. Each method **consumes and
zeroes its supplied char[]**, including failures. Do not reuse that array.
Minimum password length is 12 characters (maximum 1024). The UI should also
clear its EditText after constructing the temporary char[]; Java immutable
String allocations made by Android text APIs cannot be reliably wiped.
Use a password confirmation for export. Do not persist any passphrase.
Keep the encrypted byte[] only as long as needed for the SAF write/read.

Use ACTION_CREATE_DOCUMENT / ACTION_OPEN_DOCUMENT and a *user-selected*
document provider for Google Drive or local storage: no Google SDK, OAuth
token, background upload, network permission or implicit cloud access.
Suggested MIME type is application/octet-stream and filename extension
.ctap3b-catalog. Clearly display **"Encrypted metadata only; not recoverable
on a different phone or after key deletion"** before export and restore.
An unavailable local credential prevents producing a misleading incomplete
backup, and an empty credential catalog is not an exportable backup either;
explain these failures without promising recovery.

Restoration does not reset the global sign counter: it persists
max(existing, backedUp) in the same atomic SharedPreferences.Editor.commit()
as any restored entries, *only if at least one hardware alias was verified*.
Nevertheless, **restoring an old catalog after local metadata was lost can
roll the effective counter backwards relative to signatures performed after
the backup**. Some relying parties may reject a credential because they
remember a later counter. Neither the catalog nor the app can reconstruct a
counter history that was lost. This is a genuine risk even on the original
device; do not claim the backup guarantees recovery.

The existing AAGUID (PocoF7-BIO-DEV01) remains unchanged, and pre-4.4
`localhost` records remain bound to localhost. Multi-RP metadata is likewise
bound to its exact validated RP ID. The app is uncertified; backup does not
alter those limitations.

## Crypto format and validation

Versioned binary CTAP3BM4 envelope, random independent 16-byte PBKDF2 salt
and 12-byte GCM nonce for every export, PBKDF2-HMAC-SHA256 (240,000 iterations),
AES-256-GCM (128-bit authentication tag), entire header authenticated as GCM
AAD. The inner CTAPCAT4 binary catalog contains credential ID, exact RP ID,
original Keystore alias, user ID, authenticated per-credential discoverability
flag (0 or 1), bounded optional account/display names and creation date,
hardware security level and **public** P-256 x/y coordinates plus a global
counter; no private key, BiometricPrompt token,
registration signing object or exportable fallback is stored. Strict parser
limits: 320 KiB envelope, 256 KiB decrypted catalog, 256 entries, 1..64 byte
user IDs, canonical ctap3b-UUID aliases, unique IDs and aliases,
constant-format bounds, no trailing data. Existing authenticated v1
CTAP3BM1/CTAPCAT1 `localhost` backups and v2 CTAP3BM2/CTAPCAT2 multi-RP
backups remain importable, but **never gain discoverability on restore**.
Version 3 CTAP3BM3/CTAPCAT3 discoverable archives also remain importable;
missing historical account labels and creation timestamps stay unknown.
Unsupported versions, corrupt
headers, wrong passwords and altered ciphertext are rejected before any
metadata changes.

Host-only offline tests: python3 -m unittest tests.test_backup_codec -v.
They exercise the production Java codec with a host-side test double plus
static AndroidKeyStore policy checks; they **do not** emulate actual StrongBox,
test hardware restoration, build an APK, access a phone or touch USB.
