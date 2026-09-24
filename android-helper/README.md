# MobileFIDO: development Android helper

Android Java **development prototype** for Android 12+ (API 31+). Legacy 4.x
credentials use nonexportable P-256 ES256 keys generated in AndroidKeyStore.
New MobileFIDO 5 Recoverable credentials are generated transiently and imported
into verified StrongBox/TEE so a user-encrypted FIDO-CXF-shaped archive can
recreate them after deletion, reset or device replacement. Its AAGUID,
`PocoF7-BIO-DEV01`, is a local test identifier, **not** certified
hardware attestation. The installed 4.4.0-dev build accepts canonical ASCII
DNS RP IDs and the owner confirmed WebAuthn.io worked. The new HOST-ONLY
4.5.0-dev source adds explicitly discoverable registration, on-phone account
selection for omitted-allowList login, and authenticated v3 backup flags.
Older credentials remain non-discoverable; never use
credentials from this prototype for important accounts.

## Build and runtime status

Source is a Java Android Gradle project with `compileSdk=35`,
`minSdk=31`, `targetSdk=35`; `gradle :app:assembleDebug` with JDK 17,
Android SDK 35 and Gradle 8.10+ installed. A second reproducible manual
build path is `./build-local.sh`, with `JAVA_HOME`, `ANDROID_SDK_ROOT`,
`MOBILEFIDO_KEYSTORE`, and optional `ANDROID_BUILD_TOOLS` /
`MOBILEFIDO_KEY_ALIAS` configured. The manual output is
`app/build/manual/MobileFIDO-5.1.1-release.apk`, signed by the owner's long-term
release certificate, unrelated to FIDO credential keys.
**Do not install a Gradle-default debug signed APK on a phone with existing
credentials:** it has a different signer. The manual builder pins release cert
SHA-256 `c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da`,
requires the external JKS, keeps password material out of source/argv, and
refuses to auto-generate a replacement key.

The WSL workspace initially had no JDK, Gradle, or SDK. Temurin 17,
Android Platform 35 and Build-tools 35 were downloaded into `/tmp`;
`javac -Xlint:all` against Android API 35, D8, AAPT2, zipalign and
APK Signature Scheme v3 verification passed. This is **compile/package
validation**, not a device test. Hardware security level, Android biometric
prompt, SELinux root socket access and Windows behavior require an actual
Poco F7 test. This helper builder made **no phone or USB gadget changes**.

## Dashboard and user-controlled recovery

The Java-only dashboard uses Android-native views with responsive scrolling,
light/dark theme colors, minimum 48-dp touch targets, readable typography,
accessibility descriptions and a custom launcher icon. It exposes listener
status, permission/channel status for notification approval, current RP-bound
operation, asynchronous credential catalog, and encrypted recovery archive.
The warning is deliberately prominent: **development-only,
not a certified FIDO authenticator.**

The catalog calls `CryptoKeyManager.listCredentials()` on a background
executor to inspect existing metadata and hardware-key availability. It
shows only a shortened credential ID, hardware security level and availability;
no user ID, key alias or private-key material is displayed. Catalog refreshes
yield to pending biometric CTAP requests to avoid delaying signing.

**Export FIDO recovery archive** opens Android's `ACTION_CREATE_DOCUMENT`
picker first, then requests a 16+ character passphrase, confirmation and
explicit strong-biometric authorization. **Restore recovery archive** uses
`ACTION_OPEN_DOCUMENT`, the archive passphrase and the same biometric gate.
Google Drive may be an option if its document provider is installed,
signed in and enabled. This app neither authenticates to Google nor has the
INTERNET permission. A Drive selection is a user-directed provider action,
**not** automatic cloud backup or sync. Document I/O and password-based
authenticated encryption/decryption run off the UI thread. Passphrases are copied directly from
editable input to temporary `char[]` without creating an immutable Java
`String`, and are wiped where practical; they are not persisted or passed
through any Intent.

Legacy 4.x private keys remain nonexportable. **MobileFIDO 5 Recoverable keys are
different by design:** their working signing copy stays in StrongBox/TEE, but
an encrypted recovery copy of the PKCS#8 private key exists so the credential
can be restored after device loss. The saved `.mobilefido` file is a
password-encrypted MobileFIDO envelope whose plaintext follows FIDO CXF 1.0
passkey fields; it is not raw CXF/CXP. See `MOBILEFIDO_5_0.md`.

## Security boundary

* The app displays a foreground biometric prompt directly for each pending
  validated RP-bound request, including the RP ID, without an intermediate
  Continue button. Enrollment completes only
  after a signature using the authorized `BiometricPrompt.CryptoObject`.
* Working signing keys are `secp256r1`, sign-only and `SHA256withECDSA`; each requires
  `AUTH_BIOMETRIC_STRONG` with zero-second timeout (authentication per use).
  StrongBox is requested first and verified TEE is the only hardware fallback.
  Actual key `KeyInfo.getSecurityLevel()` must be `STRONGBOX` or
  `TRUSTED_ENVIRONMENT` and report a hardware-enforced per-use biometric
  requirement; software/unknown keys are rejected.
* Legacy keys retain their prior counter behavior. Recoverable keys set
  WebAuthn BE and permanently use a zero signature counter for CXF portability;
  BS is set only after a recovery archive write completes. Their app-private
  PKCS#8 escrow is AES-GCM encrypted under a hardware AndroidKeyStore wrapping
  key. Android platform backup remains disabled.
* The app uses a user-enabled `specialUse` foreground service to keep the
  root-only local socket reachable after the Activity is backgrounded. An
  operation without an attached Activity creates a high-importance, tappable
  notification; **only tapping/opening the visible Activity** can start the
  per-use `BiometricPrompt.CryptoObject`. Leaving the Activity during a prompt,
  socket EOF, denial and timeout cancel the operation and discard an
  uncommitted registration key. The notification contains no challenge,
  credential ID, signature or private key.
* **After a reboot:** the manifest `BOOT_COMPLETED` receiver restarts only
  the foreground listener after the user's **first device unlock**, when
  credential-encrypted preferences and AndroidKeyStore are available. An
  `MY_PACKAGE_REPLACED` receiver also recreates it after APK updates if
  the user is unlocked. Neither receiver launches the app Activity or a
  biometric prompt, accesses keys before unlock, or stores credentials in
  device-protected storage. Service promotion to the foreground happens
  before cold Keystore initialization to avoid its 5-second startup deadline.
  Keystore initialization now happens off the main thread with bounded
  post-unlock retries (12 attempts spaced by two seconds); the ongoing
  notification says "Starting" until the root-only socket is actually
  listening, then "Ready". Failed socket binding stops the service rather
  than leaving a misleading ongoing notification.
  The app must have been launched/activated at least once after its initial
  installation (Android does not deliver boot to an untouched/stopped app).
* **First request after boot:** a Binder established in `onStart()` is NOT
  interpreted as a visible, resumed consent screen. Activity onPause/onResume
  and Binder attach reconcile the one live CTAP request: an invisible Activity
  causes the service to post its tappable approval notification immediately,
  not wait for a successful foreground authentication to 'prime' the service.
* Android 13+ requires the user to grant `POST_NOTIFICATIONS` to receive
  background authorization alerts. If notifications are denied or the approval
  channel is disabled, background requests fail closed with `NOT_ALLOWED`;
  the user can still keep the Activity visible for requests. The foreground
  service is started on user-visible Activity launch and on permitted
  user-unlocked boot/package-replaced broadcasts. Android/OEM background
  restrictions, force-stop or battery policies can terminate/suppress it,
  including suppressing boot delivery for apps marked 'restricted'; launch
  the app again if its ready notification/socket is gone.
  There is no unsolicited background Activity launch and no biometric bypass.

## Root app-local IPC v1

AF_UNIX **abstract** socket `\0ctaphid-m3b-v1`, no TCP, no Internet
permission, `LocalSocket.getPeerCredentials().getUid()==0` required.
The Python peer should independently verify the server's app UID to
detect socket-name prebinding. The other IPC is an `exported=false`
app-private bound Binder for UI notifications and local demonstration.

One request/socket with a four-byte big-endian JSON byte length
(1..65536). Up to four root socket clients; at most one active biometric
operation. The app times out a pending approval after 60 seconds. The
native Rust IPC timeout must be longer (currently coordinated to 65 seconds),
with CTAPHID CBOR execution timeout longer still (70 seconds), so cancellation
and the final reply can propagate before the outer deadline. An older
Python bridge with a 28-second deadline must be updated separately. Messages:

```json
{"v":1,"id":"0123abcd","op":"getInfo","params":{}}
{"v":1,"id":"0123abcd","op":"makeCredential","params":{"rpId":"localhost","clientDataHash":"base64-32","userId":"base64-1-to-64","excludeIds":[],"up":true}}
{"v":1,"id":"0123abcd","op":"getAssertion","params":{"rpId":"localhost","clientDataHash":"base64-32","allowIds":["base64-credential-id"],"up":true}}
```

Before prompting, the service sends
`{"v":1,"id":"0123abcd","event":"user_presence_required"}`.
The final reply is `{"v":1,"id":"0123abcd","ok":true,"result":{...}}`
or `{"v":1,"id":"0123abcd","ok":false,"error":"NOT_ALLOWED"}`.
Possible errors include `NO_CREDENTIALS`, `CREDENTIAL_EXCLUDED`,
`CANCELLED`, `TIMEOUT`, and `OTHER`. `getInfo` returns
`up:true`, `uvEnforced:true`, `perUseCryptoObject:true`,
`silentSigning:false`, `rpIdPolicy:"ascii-dns-rp-v1"`, and base64 AAGUID.
`makeCredential` returns base64 32-byte `credentialId`,
`publicKey:{x:base64-32,y:base64-32}`, `userPresent:true`,
`userVerified:true` and `securityLevel:"TEE"|"STRONGBOX"`.
`getAssertion` returns matching `credentialId`, base64 37-byte
`authData`, DER ES256 `signature`, `userPresent` equal to request
`up`, and `userVerified:true`. The app constructs and signs
`SHA256(rpId) || flags || signCount || clientDataHash`. The RP ID is bound
to each credential on creation and checked for every allow/exclude-list
lookup and hardware signature; the original `localhost` record remains valid
only for `localhost`. ASCII DNS A-labels must be canonical lower-case and
contain no scheme/port/path, IP literal, Unicode or trailing dot. Browsers
validate website origin vs RP ID before sending a CTAP request.

## Windows silent preflight limitation

Windows may request `getAssertion` with `up=false` as a preflight.
A per-use biometric-protected hardware key **cannot sign silently**.
This helper requires a visible biometric prompt even for preflight
(notification tap first when backgrounded), then emits signed
`UP=false, UV=true` (flags 0x04).
The final `up=true` authentication may require a *second* biometric
prompt; Windows timeout/UX compatibility must be checked on the device.
No forged assertion or silent downgrade is implemented. A separate
timed-auth/device-unlocked key policy could allow signatures after recent
authentication, but that relaxes the policy and requires an explicit
future decision. The current code never creates such keys.
