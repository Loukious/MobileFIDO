# Contributing to MobileFIDO

Contributions are welcome, especially security review, Android compatibility
work, CTAP/WebAuthn interoperability fixes, accessibility and recovery testing.

## Before changing compatibility boundaries

Do not rename these values without a deliberate migration design:

- Android package `org.pocof7.ctap3b`
- KernelSU module ID `pocof7_ctap_native`
- socket `ctaphid-m3b-v1`
- development AAGUID `PocoF7-BIO-DEV01`
- established recovery/crypto domain separators and Android Keystore aliases

Changing them can strand existing credentials or installations.

## Security invariants

Patches must not introduce:

- software FIDO signing fallback;
- UV/UP spoofing;
- challenge replay after disconnect/cancellation;
- silent/background Activity launch as a consent bypass;
- credential deletion/data clearing during upgrade;
- release signing secrets in source, tests, logs or CI.

Every actual FIDO assertion signature, including `up=false` preflight, must
remain bound to genuine strong biometric authorization through the hardware-key
`BiometricPrompt.CryptoObject`.

## Testing

Run the host security gate before submitting changes when your local build
artifacts/toolchains are available:

```bash
bash tests/run_security_audit.sh
```

At minimum, Rust changes should pass:

```bash
cd native-ctaphid
cargo test --locked
```

Never use an important real account for destructive credential tests. Real
device deletion/restore tests should use disposable credentials and an
independent recovery method.

## Pull requests

Describe:

1. the problem and threat/compatibility impact;
2. what changed;
3. tests performed;
4. whether Android app data, key aliases, USB gadget state or release signing
   behavior are touched;
5. any manual/device testing still required.

No project-wide software license has been selected yet, so contribution/licensing
terms should be clarified before accepting substantial third-party code.
