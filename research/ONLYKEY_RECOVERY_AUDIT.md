# MobileFIDO research: OnlyKey FIDO2 recovery source audit

Date: 2026-09-24

This is a source audit of the public OnlyKey implementation, not black-box
reverse engineering. Source snapshots inspected:

- `trustcrypto/OnlyKey-Firmware` commit
  `9600daa8ffc8a0d727808fcb561911eed6dc0bfb`
- `trustcrypto/libraries` commit
  `20e1623faf69c560864c746cd697a83dcb238e26`

The purpose was to answer a narrow interoperability question: can a
MobileFIDO passkey containing an arbitrary ES256 private key be translated to
an OnlyKey backup and restored by stock OnlyKey firmware?

## How OnlyKey FIDO credential keys work

OnlyKey's FIDO code is based on the SoloKeys authenticator implementation.
The resident-key record itself does **not** contain a per-credential P-256
private scalar. `libraries/fido2/ctap.h` defines `CredentialId`,
`CTAP_userEntity`, and `CTAP_residentKey`; the resident record contains the
credential ID/entropy, user data and RP data, but no private-key field.

The authenticator maintains master key material in
`AuthenticatorState.key_space[128]` (`libraries/fido2/storage.h`). During
initialization `ctap_state_init()` fills that key space with random data.
`crypto_load_master_secret()` (`libraries/fido2/crypto.cpp`) loads the first
64 bytes as `master_secret` and another 32 bytes as `transport_secret`.

When an ES256 credential is used, `crypto_ecc256_load_key()` calls
`generate_private_key()`. That function deterministically derives the 32-byte
credential signing scalar from the credential bytes plus the authenticator's
master secret (HMAC-SHA256 followed by the OnlyKey AES transform). In other
words, restoring the same authenticator master state and credential record
reconstructs the same FIDO private key; the individual private scalar does not
need to be stored in every resident-key record.

## What OnlyKey actually backs up

`libraries/onlykey/okcore.cpp::backup()` creates a whole-device backup. Among
the other OnlyKey slots/settings, the FIDO-specific records are:

1. a `0xFE, 0` record containing the complete `AuthenticatorState`, including
   `key_space` and `rk_stored`;
2. a `0xFE, 200 + index` record containing each raw `CTAP_residentKey`.

`RESTORE()` performs the inverse operation: it restores the authenticator
state using `ctap_flash(..., mode 4)` and restores resident-key records using
`ctap_flash(index, ..., mode 2)`. Once the state is loaded, normal FIDO signing
derives credential private keys again from the restored master state.

The backup container is an OnlyKey device-backup protocol rather than a FIDO
credential interchange protocol. The source emits a textual
`-----BEGIN ONLYKEY BACKUP-----` envelope, chunks the ciphertext as base64 and
includes an integrity hash. Depending on the configured backup key it uses an
OnlyKey ECC/ECDH- or RSA-based key-wrapping path around AES-GCM encryption.

## External-key path in the FIDO source

The Solo-derived `libraries/fido2/ctaphid.cpp` contains an experimental
`CTAPHID_LOADKEY` handler behind `SOLO_EXPERIMENTAL`. Its own comment says
"Load external key. Useful for enabling backups." It feeds a master key into
`ctap_load_external_keys()`, which replaces `STATE.key_space` and reloads the
master secret.

This is a **master-authenticator-state import**, not a standard CTAP command
for importing one arbitrary WebAuthn/ES256 private key. Its presence therefore
does not make stock OnlyKey a generic CXF/PKCS#8 passkey importer.

## Interoperability conclusion

An existing arbitrary MobileFIDO passkey cannot be converted into a stock
OnlyKey resident credential merely by writing its PKCS#8 private key into an
OnlyKey backup. Stock OnlyKey expects to derive the signing key from its FIDO
master state and the credential ID.

There are three technically different future paths:

1. **Standards-first MobileFIDO recovery (current direction).** Keep the
   credential's actual PKCS#8 key in the encrypted MobileFIDO/CXF recovery
   archive and re-import it into Android StrongBox/TEE after a reset. This is
   the most direct fit for FIDO Credential Exchange.
2. **OnlyKey-style deterministic recovery.** MobileFIDO could introduce its
   own random recovery master seed and derive new credential keys from that
   seed. This borrows the architecture, not the OnlyKey file format. It could
   reduce backup size, but creates a high-value master secret whose compromise
   compromises every derived credential.
3. **Actual OnlyKey migration compatibility.** This would require deliberately
   creating credentials from an OnlyKey-compatible master state/KDF and
   credential structure, then constructing/restoring compatible device state,
   or obtaining firmware support for CXF/arbitrary credential import. This is
   not implemented and must not be advertised as compatible until tested on
   real OnlyKey hardware.

Because an OnlyKey backup restores broad device state, using it as our primary
MobileFIDO archive format would also risk overwriting unrelated state on a
destination OnlyKey. A separate migration adapter, if ever implemented, is a
safer boundary than making MobileFIDO's native backup an OnlyKey backup.

## Licensing notes

The inspected FIDO core files under `libraries/fido2` carry the SoloKeys
dual-license header: Apache-2.0 or MIT.

The OnlyKey-specific `libraries/onlykey/okcore.cpp` carries CryptoTrust LLC's
custom redistribution license. Among other conditions it requires retaining
copyright/license notices, an advertising acknowledgment for features using
that software, source availability, and it prohibits using the names
"OnlyKey" or "CryptoTrust" to endorse/promote a derived product or in a
derived product's name without written permission.

Therefore MobileFIDO should prefer an independent implementation based on the
documented behavior/facts or on permissively licensed Solo/FIDO components.
If CryptoTrust-specific code is copied/adapted, its exact license and
attribution/source obligations must ship with the resulting distribution.

## Source locations inspected

- `libraries/fido2/ctap.h`
- `libraries/fido2/storage.h`
- `libraries/fido2/crypto.cpp`
- `libraries/fido2/ctap.cpp`
- `libraries/fido2/ctaphid.cpp`
- `libraries/fido2/device.cpp`
- `libraries/onlykey/okcore.cpp`
- `libraries/onlykey/okcore.h`
