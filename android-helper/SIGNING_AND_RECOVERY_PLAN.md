# MobileFIDO signing and account-recovery release gate

**Release status: release-signed but development/uncertified.** The primary
Poco F7 currently has `org.pocof7.ctap3b` / app UID 10271 signed by the owner's
long-term RSA-4096 release certificate:

`c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da`

The private JKS is external to the repository. The owner's custom/rooted ROM
accepted an in-place transition from the old development signer while retaining
UID/data, but stock Android normally rejects a same-package APK signed by an
unrelated certificate. Do not generalize that observed transition to other
devices. A working WebAuthn.io experiment is NOT external FIDO certification.

## Protect existing credentials before ANY production-signing experiment

1. Never publish/copy the private long-term release JKS to public CI, releases,
   documentation, public build archives or another person's device. The public
   APK certificate/fingerprint is safe to inspect; the JKS and its passwords
   are not. Losing the release JKS prevents normal future same-signer updates.
2. Record the installed APK certificate SHA-256, package, UID, version, module
   version, nonsecret public keys, credential IDs and actual successful
   assertions on **disposable test RPs**. For MobileFIDO 5 recoverable
   credentials, create and verify a password-encrypted `.mobilefido` recovery
   archive. Legacy 4.x hardware-generated private keys remain nonexportable and
   cannot be reconstructed from an archive.
3. Register a second independent authenticator/recovery method at EVERY
   important RP while access is still available. A reset, failed migration,
   lost phone, biometric enrollment change or app uninstall can make a
   hardware-backed key irrecoverable. The encrypted Drive archive contains
   ZERO private FIDO signing keys.
4. Treat the already-observed dev-signer → release-signer transition as specific
   to this owner's current ROM. On another device, validate signer migration
   only with disposable credentials and an independent recovery method first.
   Never uninstall or clear data to force a signature mismatch to install.
5. The KernelSU installer now accepts automatic APK updates only when the
   existing installed APK already carries the pinned release certificate. It
   deliberately refuses automatic migration from the legacy development signer.

## Release signing workflow

Keep the keystore outside the repository, for example:

```bash
export MOBILEFIDO_KEYSTORE="$HOME/mobilefido-signing/mobilefido-release.jks"
export MOBILEFIDO_KEY_ALIAS=mobilefido
export JAVA_HOME=/tmp/mobilefido-toolchain/jdk
export ANDROID_SDK_ROOT=/tmp/mobilefido-toolchain/android-sdk
export ANDROID_BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/35.0.0"
bash android-helper/build-local.sh
```

On an interactive terminal the script prompts without echo for the keystore
password. `MOBILEFIDO_STOREPASS` and, when different, `MOBILEFIDO_KEYPASS` may
be supplied by a secure local environment, but must never be committed or
printed to logs. The build refuses any certificate except the pinned release
SHA-256 above and writes `MobileFIDO-5.1.1-release.apk`.

## App/module compatibility and rollback

* The native backend requires the helper's
  `discoverablePolicy=rp-bound-account-picker-v1` handshake and rejects older
  app binaries rather than advertising resident keys against an incapable
  helper. `native-tools/customize.sh` explicitly permits updating from the
  owner's approved 4.4 APK with Android package/signature/UID continuity.
* The APK and native module must be evaluated together. Never treat an APK-only
  update as feature-complete when the resident-key capability lives in the
  native CTAP `getInfo` response.
* Do not auto-roll back the APK by uninstalling it: older builds do not parse
  the new v3 backup format, and downgrade may be rejected by Android.
  Module rollback must not delete any app data or AndroidKeyStore aliases.

## Required checks BEFORE a production label

* Real registration and authentication for existing 4.4 credentials plus new
  discoverable and non-discoverable 4.5 credentials on Chrome and Edge.
  Include multiple accounts per RP, RP isolation, cancellation and reconnect.
* Hardware security review of the rooted trust boundary, root-owned native
  daemon, app-private Unix socket, notification prompt and biometric CryptoObject;
  third-party review and supported ROM/kernel update threat model.
* Credential/account deletion UX, safe recovery flows, OEM-specific biometric
  invalidation testing, accessibility, and truthful attestation/AAGUID policy.
* Formal FIDO conformance/certification planning if distribution claims FIDO
  certification; automated host tests do not grant certification.
