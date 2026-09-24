# PocoKey 4.6.2-dev — credential management and Dynamic Color (development build)

**Not FIDO certified; do not make this your only recovery method.** The
same-signer package `org.pocof7.ctap3b`, StrongBox/TEE hardware-bound private
keys and per-operation BIOMETRIC_STRONG authorization remain unchanged.

## Changes

- Android 12+ wallpaper-derived Dynamic Color now styles every native dialog
  and programmatic app surface for light and dark mode. The Local Test Tools
  section is no longer displayed; USB/WebAuthn protocol tests remain available
  in the developer workspace.
- For encrypted backup export, pick the file destination **first**, then enter
  the passphrase and confirmation and tap **Encrypt and save backup**. Invalid
  or mismatched passphrases show inline errors without dismissing/recreating
  the password dialog. The passphrase is not held across the external Android
  document picker. Cancel wipes the fields; export/import wipe transient
  arrays after processing. The backup format/security policy is unchanged.
- Secondary actions such as **Notification settings**, **Refresh credentials**
  and **Restore surviving backup metadata** now use a visible Dynamic Color
  tonal container and outline instead of looking like plain text. Restore also
  presents an explicit result dialog when backup entries cannot be recovered
  because their original Android Keystore private key was deleted/invalidated.

- The credential catalog groups credentials by exact RP ID (website), supports
  local search, and labels each entry as discoverable/non-discoverable, available
  or original private key unavailable, and StrongBox/TEE security level.
- **New registrations** retain up to 128 UTF-8 bytes each of the RP-supplied
  `user.name` and `user.displayName`, plus creation time, separately from the
  actual 1–64 byte opaque WebAuthn `user.id`. Bad/control/bidi account labels
  are rejected; they never change credential identity or authorize signing.
- The discoverable account picker shows the provided account name and RP
  instead of an ID when available. Older registrations have no stored name or
  reliable creation date, so they retain a shortened-ID fallback. The app
  does NOT guess account names from user IDs or contact websites to recover
  historical labels.
- Deletion requires explicit confirmation and STRONG biometric approval on
  the phone. The app checks the exact RP/credential/alias mapping, refuses
  aliases referenced by another account and never deletes other credentials.
  Android Keystore alias deletion occurs before the atomic metadata edit;
  if metadata commit fails, an unavailable catalog row may remain until a
  subsequent deletion attempt. The global sign counter is never reset.
- Encrypted *metadata* backups now use `CTAP3BM4` / `CTAPCAT4`, with authenticated
  labels/date, 320 KiB maximum envelope and 256 KiB maximum decrypted catalog.
  v1/v2/v3 archives remain importable. v1/v2 remain non-discoverable; v3
  keeps authenticated discoverability but has no historical labels/date.

## Safety and test plan

1. Save your working 4.5 ZIP and an encrypted catalog archive. The archive
   cannot recover a deleted hardware key. Register an alternate authenticator
   with important sites before testing deletion.
2. Update with the **same signer**, **same package**, and an in-place install
   preserving UID/app data. Never uninstall or clear `org.pocof7.ctap3b`.
3. Verify the existing 4.4 and 4.5 credentials still authenticate after the
   update, including WebAuthn.io and two different RP IDs. Only new credentials
   have user-supplied account names/date; older ones show ID fallback.
4. Register two **test-only** discoverable keys for one RP with different
   user.name values, then start username-less login. Phone picker should
   list the two supplied account names; choose one, approve fingerprint, and
   confirm its exact user.id and RP binding on the relying party.
5. Delete one **test-only** credential, deliberately cancel the confirmation
   or fingerprint once, then approve. Verify the other remains usable, the
   deleted one cannot sign, and a prior backup cannot resurrect its key.
6. Test USB disconnect/Android service reset during deletion and simultaneous
   Windows authentication: never allow credential deletion while an active
   CTAP operation is pending. Test an unavailable alias and verify a stale
   metadata row can be removed only after strong biometric approval.
7. Exercise v4 backup/export/import on the same phone plus genuine v1/v2/v3
   archives, incorrect passphrase, malformed name UTF-8, duplicate alias/ID,
   wrong RP and public point, truncated files and stale-sign-counter warning.

**Status:** host-built, compile/test checks may pass; end-to-end physical
Poco F7 deletion, account picker, backup v4 import, and Windows interop are
not established until separately tested. Production signing identity,
independent audit, CTAP2.1/PIN and FIDO certification remain separate work.
