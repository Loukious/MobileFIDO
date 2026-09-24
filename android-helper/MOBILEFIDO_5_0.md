# MobileFIDO 5.0–5.0.1-dev — recoverable FIDO passkeys

For 5.0.1's read-back-verified exports, backup freshness, crash-import journal
and second-device/OnlyKey release gates, see
[`MOBILEFIDO_5_1_RECOVERY_QA.md`](MOBILEFIDO_5_1_RECOVERY_QA.md).

MobileFIDO 5 changes the default for **new** credentials from an irreversibly
device-bound key to a recoverable credential whose working copy is still used
only through AndroidKeyStore StrongBox/TEE with per-operation
`BIOMETRIC_STRONG` authorization.

This is experimental development software, not a FIDO-certified product.
Keep another recovery method on important accounts while validating the new
recovery path.

## Key lifecycle

For a new credential, MobileFIDO generates one P-256/ES256 keypair transiently,
creates the FIDO credential ID and recovery material, then imports the private
key into AndroidKeyStore using `KeyProtection` with SIGN-only SHA-256,
per-use strong biometric authorization and StrongBox requested first (verified
TEE is the only fallback). The plaintext PKCS#8 byte array is wiped after the
hardware import/local recovery escrow is prepared. Normal WebAuthn signing
uses only the AndroidKeyStore private-key handle and a
`BiometricPrompt.CryptoObject` exactly as before.

The unavoidable security-model change is deliberate: a credential cannot be
both cryptographically impossible to copy and recoverable after total device
loss. MobileFIDO 5's encrypted recovery archive therefore becomes sensitive
credential material and must be protected like a second security key.

Existing 4.x credentials are **not converted**. Their private keys were born
nonexportable in AndroidKeyStore and remain device-bound forever.

## FIDO Credential Exchange alignment

The decrypted recovery payload follows **FIDO Credential Exchange Format
(CXF) 1.0** passkey fields (`credentialId`, `rpId`, `username`,
`userDisplayName`, `userHandle`, and PKCS#8 `key`) inside the required
Version/Account/Item structure. MobileFIDO adds an unknown `mobileFido` hint only to
preserve its discoverable/non-discoverable distinction and public-point check;
import does not require that hint and unknown CXF fields are ignored.

The file saved by the Android document picker is **not raw CXF and not CXP**.
It is a MobileFIDO encrypted envelope (`MFRCV001`) whose authenticated plaintext
is the CXF JSON. This avoids ever writing raw portable private keys to cloud or
local storage. Future CXP/provider interoperability can consume the same CXF
records after decrypting them in memory.

Development archives written before the MobileFIDO rename used the outer magic
`PKRCV001` and an optional `pocoKey` CXF hint. Import accepts both legacy forms;
new exports use `MFRCV001` and `mobileFido`. Stable cryptographic domain
separators, Keystore aliases, package ID and development AAGUID are intentionally
not renamed because they are compatibility boundaries, not user-facing branding.

FIDO CXF excludes passkeys with non-zero signature counters. Therefore:

* new Recoverable credentials use `signCount = 0` at registration and forever;
* legacy device-bound 4.x credentials retain their existing monotonic counter;
* new Recoverable credentials set WebAuthn `BE=1`;
* `BS=0` until a recovery archive containing that credential is successfully
  written, then `BS=1` on subsequent assertions;
* `BS=1` is never emitted with `BE=0`.

Credential IDs from CXF imports are accepted from 16 through the WebAuthn
maximum of 1023 bytes. MobileFIDO-created IDs remain 32 random bytes.

## Encrypted recovery envelope

`MFRCV001` uses:

* PBKDF2-HMAC-SHA256, 600,000 iterations;
* independent random 16-byte salt and 12-byte AES-GCM nonce;
* AES-256-GCM with the complete fixed header as AAD;
* minimum 16-character passphrase for newly-created recovery archives;
* strict size, JSON type, duplicate-member, canonical-base64url, RP-ID,
  P-256/PKCS#8, credential-ID and user-handle validation.

The app additionally retains the recovery material for each new credential in
an app-private AES-GCM escrow wrapped by a StrongBox/TEE AndroidKeyStore AES
key. The wrapping key is unavailable before normal device unlock. Recovery
export/import additionally requires an explicit foreground
`BIOMETRIC_STRONG` prompt and is serialized against CTAP signing/registration
and credential deletion.

The local wrapping key is deliberately a different security boundary from the
per-use FIDO signing key: current 5.0 uses one biometric confirmation for a
whole archive operation, not one fingerprint per credential in the archive.
An independent security review of this recovery boundary is still required.

**Android Keystore GCM IV compatibility:** local recovery escrow encryption
must initialize the hardware-backed AES key without an explicit caller nonce.
`setRandomizedEncryptionRequired(true)` requires Keystore to generate the IV;
the IV is then read via `Cipher.getIV()` and stored alongside the ciphertext.
Decrypting existing escrow continues to supply the stored IV explicitly. The
initial 5.0.0-dev build incorrectly supplied an encryption IV and received
`CALLER_NONCE_PROHIBITED` on the tested Android 17 device; the repaired build
uses the Keystore-generated IV and adds a regression test.

## Recovery after deletion/reset/new phone

For a recoverable credential, restore validates the archive and passphrase,
derives and checks the P-256 public key from the archived PKCS#8 material,
re-imports the exact private key into the destination device's StrongBox/TEE,
and restores the original FIDO credential ID, RP binding and user handle. The
website therefore continues to see the same credential public key and ID.

Restore fails closed on conflicts, malformed archives, wrong RP binding,
wrong public/private pair, software/unknown AndroidKeyStore security levels,
unsupported key type, or failure to obtain the required hardware/per-use
biometric policy. It never silently leaves the signing key in software.

Legacy `CTAP3BM1` through `CTAP3BM4` metadata-only files remain importable.
Their historical 12-character minimum passphrase is accepted for import, but
they still cannot recreate a deleted 4.x private key.

## Required real-device acceptance test

Before treating 5.0 recovery as working rather than implemented:

1. Verify at least one existing 4.x credential still authenticates unchanged.
2. Register a disposable **new** discoverable credential on WebAuthn.io and
   verify its catalog status says Recoverable / Backup needed.
3. Export a recovery archive and verify the credential changes to Included in
   a recovery archive.
4. Authenticate the new credential again and verify the RP accepts BE/BS and
   zero signature counter behavior.
5. Delete only that disposable credential.
6. Restore the recovery archive.
7. Authenticate the same website account again. This is the key proof that the
   original credential ID/private key was restored, rather than only metadata.
8. Repeat restore on a second compatible Android device or an intentionally
   wiped test device before claiming factory-reset/device-migration recovery.

Do not wipe the primary phone merely to prove step 8.

## OnlyKey source-audit result

OnlyKey's open-source backup proves that recoverable hardware-authenticator
credentials are practical, but its mechanism is different from MobileFIDO's
current CXF design. OnlyKey backs up the authenticator's FIDO master state plus
resident-key records; individual FIDO private keys are deterministically
re-derived from that restored state rather than stored as arbitrary PKCS#8
per-credential keys. Stock OnlyKey therefore is **not** currently a generic
import target for a MobileFIDO CXF passkey.

See `../research/ONLYKEY_RECOVERY_AUDIT.md` for the exact source paths, pinned
repository commits and license notes. No OnlyKey compatibility claim should be
made until a migration format has been implemented and verified on real
OnlyKey hardware.
