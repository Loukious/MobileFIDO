# MobileFIDO 5 recoverable-passkey implementation review

Date: 2026-09-24

## What is already implemented in source

New credentials follow a recoverable design instead of the legacy 4.x
nonexportable-only design:

1. Generate a transient P-256 keypair in the app process.
2. Import the private key into AndroidKeyStore using `KeyProtection` with
   `PURPOSE_SIGN`, SHA-256, per-operation `BIOMETRIC_STRONG`, biometric
   re-enrollment invalidation and StrongBox requested first. A verified TEE is
   the only fallback.
3. Verify the imported public point and Android `KeyInfo` hardware/auth policy.
4. Encrypt the transient PKCS#8 recovery copy under a separate hardware-backed
   AES-GCM AndroidKeyStore wrapping key and store only that encrypted escrow
   locally. Plaintext PKCS#8 arrays are wiped on the normal paths.
5. Normal FIDO signatures use only the imported AndroidKeyStore key through a
   real `BiometricPrompt.CryptoObject`.

Recovery export decrypts the local escrow only inside the process, constructs
a FIDO-CXF-shaped Passkey record containing credential ID, RP ID, user handle,
display data and PKCS#8 key, then encrypts the entire archive using a
passphrase-derived AES-256-GCM key. Recovery import verifies the archived
private/public pair, imports the same credential key into the destination
StrongBox/TEE, verifies the imported point/policy and restores the original
credential ID/RP/user metadata.

This is sufficient in principle for recovery after app-data loss or factory
reset because the cloud/local archive, not the destroyed device-local escrow,
contains the encrypted credential private key.

## WebAuthn portability state

Recoverable credentials are represented as backup-eligible (`BE=1`), use a
zero signature counter, and switch to backed-up (`BS=1`) after a successful
archive write. Legacy credentials retain their pre-existing counter and do not
gain backup eligibility.

The archive plaintext follows FIDO Credential Exchange Format 1.0 Passkey
fields. MobileFIDO's optional `mobileFido` hint carries the non-standard
discoverable/public-point convenience metadata; import derives the public
point directly from standard PKCS#8 and therefore does not require this hint.
Pre-rename `pocoKey` hints remain importable.

## Compatibility boundaries deliberately preserved

The Android package `org.pocof7.ctap3b`, Keystore alias namespace, local
recovery wrapping alias, Unix socket, KernelSU module ID and development AAGUID
must remain stable while existing users still have 4.x/early-5.x credentials.
They are legacy implementation identifiers, not current product branding.

The cryptographic strings `PocoKeyEscrowV1\0`, `PocoKeyPairV1\0` and the old
CXF Item-ID derivation prefix are also intentionally unchanged; changing a
domain separator would make existing encrypted escrow or stable IDs
incompatible merely because of a product rename.

## Security and test gaps before enabling this by default in a release

- **Real StrongBox import proof:** verify on actual supported devices that an
  externally generated/imported P-256 private key receives the claimed
  StrongBox/TEE security level and per-use hardware-enforced biometric policy.
- **True destruction/recovery round-trip:** register a disposable WebAuthn
  credential, export, delete the live AndroidKeyStore alias and local escrow,
  restore the archive, then authenticate the same RP/account successfully.
- **Fresh-device test:** repeat on a second compatible Android device or a
  deliberately wiped test device, not the owner's only authenticator.
- **Crash/atomicity tests:** force-stop during key creation, archive write and
  multi-credential restore; no path may leave metadata claiming recoverability
  without either valid escrow or a successfully written recovery archive.
- **Archive KDF review:** PBKDF2-HMAC-SHA256 at 600k iterations is implemented,
  but a file containing actual private keys deserves an independent review and
  likely a high-entropy recovery-key option rather than relying only on a
  human password.
- **Memory hygiene limits:** Java cannot guarantee that immutable/provider
  objects never contain extra copies of key material even when explicit byte
  arrays are wiped. This must be documented as part of the recoverability
  tradeoff.
- **CXF conformance:** current structures are CXF-shaped and strict-parsed;
  validate against external CXF fixtures/implementations before claiming
  standards interoperability.
- **Extensions:** import currently fails closed for non-empty FIDO extension
  state because silently dropping PRF/hmac-secret/credBlob/largeBlob state
  would produce an incomplete restored credential.
- **Independent security audit and production signing** remain mandatory
  before public release.

## OnlyKey relationship

OnlyKey's open-source recovery design is useful architectural prior art, but
it restores a FIDO master state plus resident-key records and deterministically
re-derives credential private keys. MobileFIDO currently archives each
credential's PKCS#8 key in a CXF-aligned encrypted container. The two recovery
models are therefore not file-compatible today.

## Key-origin conclusion and source evidence

The answer to the central implementation question is **yes: the active
MobileFIDO 5 registration path generates the recoverable credential outside
AndroidKeyStore first, then imports it into AndroidKeyStore/StrongBox or TEE**.

`CryptoKeyManager.prepareRegistration(...)` currently does this in order:

1. `KeyPairGenerator.getInstance("EC")` with no `AndroidKeyStore` provider;
2. P-256 (`secp256r1`) key generation into `transientPair`;
3. `transientPair.getPrivate().getEncoded()` to obtain exportable PKCS#8;
4. `importRecoverable(..., true)` for the StrongBox-requested import;
5. on an exception from that attempt, a fresh alias and
   `importRecoverable(..., false)` for the TEE-eligible import;
6. post-import `KeyInfo` verification plus public/private-pair verification;
7. creation of the encrypted local recovery escrow;
8. normal signing through the imported AndroidKeyStore handle.

`importRecoverable(...)` uses `KeyStore.setEntry()` with a `PrivateKeyEntry`
and `KeyProtection`; this is an import, not a hardware-origin key generation.
The separate `generate(alias, strongBox)` method still present in
`CryptoKeyManager` directly generates inside AndroidKeyStore, but repository
search found no current caller. It is legacy/dead code in the active
`makeCredential` path and should be removed or clearly labelled so future
reviewers do not mistake it for the MobileFIDO 5 lifecycle.

Consequently, accurate security wording is: **the working signing copy is
hardware-backed and hardware-policy-verified after import**. It would be
incorrect to claim that a recoverable credential was generated inside
StrongBox, that its private scalar never existed in application memory, or
that StrongBox makes the archived key impossible to clone.

## Additional concrete findings from this audit

- **Archive envelope:** current exports use `MFRCV001`; restore also accepts
  the pre-rename `PKRCV001` envelope. The new format uses PBKDF2-HMAC-SHA256
  (600,000 iterations), a random 16-byte salt, a random 12-byte GCM nonce,
  AES-256-GCM with the fixed header as AAD, a 16-character minimum passphrase,
  a 512 KiB encrypted limit and a 448 KiB plaintext limit.
- **Local wrap-key boundary:** `ctap3b-recovery-wrap-v1` is an AES-256-GCM
  AndroidKeyStore key requested in StrongBox first and TEE second. It requires
  the device to be unlocked, but it does not itself require biometric auth.
  The strong-biometric check for archive export/import is a separate
  application-flow gate. A compromise executing as the app after device
  unlock therefore has a weaker boundary for escrow decrypt than normal
  per-operation FIDO signing.
- **Non-wipeable secret Strings:** `encodeCxf()` converts PKCS#8 to base64url
  Java `String` values and `JSONObject.toString()` creates another immutable
  JSON String containing key material. Restore likewise receives the `key`
  member as a Java `String`. Explicit byte arrays are wiped, but these String
  copies cannot be reliably zeroed and may remain until garbage collection.
- **Restore orphan window:** after importing and verifying a fresh hardware
  alias, `restoreRecovery()` calls `encryptEscrow()` before adding that alias
  to its rollback `staged` list. If escrow creation throws in that interval,
  the catch block does not know about the newly imported alias, so it can be
  left orphaned in AndroidKeyStore. Process death between Keystore import and
  metadata commit creates a similar cross-store transaction gap. Rollback's
  `delete(alias)` also suppresses deletion exceptions.
- **Post-import policy checking:** `KeyInfo` checking correctly rejects
  software/unknown security levels and verifies hardware-enforced per-use
  strong biometric auth. It does not currently post-verify every requested
  `KeyProtection` property such as SIGN-only purpose, SHA-256-only digest,
  biometric-enrollment invalidation, or the imported handle's nonexportability.
  Adding those defensive assertions/tests would make OEM/provider behavior
  easier to audit.
- **Broad StrongBox downgrade condition:** StrongBox signing-key import and
  recovery-wrap-key creation catch broad `Exception` and then try TEE, rather
  than falling back only for a specific StrongBox-unavailable condition. TEE
  remains a hardware-backed accepted level, so this is not a software
  fallback, but unexpected StrongBox/provider failures can silently become a
  TEE credential and mask the original reason for the downgrade.
- **SAF backup-state semantics:** `BS=1` is marked after the selected SAF
  output stream has successfully written/flushed/closed. For a cloud-backed
  document provider this proves provider acceptance, not independently
  confirmed remote replication. There is no Google Drive SDK/OAuth/background
  sync or cloud durability acknowledgement; Drive works only through the
  user-selected SAF provider.
- **Archive cloning is intrinsic:** archive + passphrase is sufficient to
  reconstruct the same credential on another compatible device. That is the
  intended recovery property and also means the credential is cloneable by
  anyone who obtains both factors. StrongBox protects post-import use on each
  destination; it cannot retroactively restore single-device uniqueness.

## Tests and build artifacts inspected

`tests/test_recoverable_passkeys_50.py` is a source-invariant suite rather than
an Android crypto integration test. Running it against the current post-rename
source with bytecode-cache writes disabled produced **11/11 passing tests**.
It checks for the expected generation/import policy calls, hardware-wrapped
escrow, BE/BS behavior, CXF fields/parser guards, maintenance serialization,
passphrase policy and recovery UI wiring.

`tests.test_dynamic_color_backup_ui` produced **6/6 passing tests** earlier in
the audit; it is likewise source/UI oriented. `tests.test_backup_codec`
produced one passing static policy test and skipped its executable host Java
codec test with `host-only Java 17 unavailable`; that codec test targets the
legacy metadata-only `BackupManager`, not `RecoverableBackupManager`.

No executable host round-trip test for the new `RecoverableBackupManager`, no
Android instrumentation recovery test, and no independent CXF interoperability
test were found. Those are material missing validation layers.

The existing manual artifact
`android-helper/app/build/manual/ctap3b-helper-debug.apk` was inspected without
installing it. At the time inspected it was 78,300 bytes with SHA-256
`af751068390eb5e49c62940492e1910a5170e092aa7c659e499f843096e2e9f7`.
Its embedded `classes.dex` matched the standalone manual dex at SHA-256
`525f380caa5b88759c4a1a0900841bb228f45a38bba9c143639d73ee0c44b9e9f7`.
The dex contains `RecoverableBackupManager`, the old `PKRCV001` magic,
`ctap3b-recovery-wrap-v1`, `PocoKeyEscrowV1` and recovery UI strings, so an
earlier form of the recovery implementation was definitely compiled into it.

That APK/dex was built around **12:31:47 +01:00**. The audited live source was
newer: `MainActivity.java` 15:04:13, the recovery test 15:05:58,
`CryptoKeyManager.java` 15:06:47 and `RecoverableBackupManager.java` 15:07:03.
The existing APK therefore does **not** prove that the exact current source
compiles or works. This audit did not rebuild it because the task permitted no
workspace mutation other than this report.
