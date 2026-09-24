# Changelog

## 5.1.1-dev — 2026-09-24

- Credential catalog creation timestamps now show both the local date and time
  instead of date only.

### Security and signing

- Migrated the maintained build/package pipeline to the owner's long-term
  release APK signer.
- Release certificate SHA-256 pinned to
  `c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da`.
- External JKS required; signing passwords are not stored in source or release
  packages.
- KernelSU packaging verifies the signed APK with Android SDK `apksigner`.
- Module installer verifies modern APK Signing Block certificate identity and
  refuses automatic migration from the historical development signer.
- UID/app-data continuity checks remain fail-closed; no uninstall or data clear.

### Recovery

- Read-back verification for saved encrypted recovery archives.
- Backup freshness metadata and read-only saved-archive verification.
- Staged recovery alias journal/cleanup for interrupted imports.
- User-chosen recovery passwords retained; new full-recovery archives require at
  least 16 characters.

### Android UI and compatibility

- Dynamic-color production-oriented dashboard cleanup.
- Compact per-credential delete action and redesigned app-owned dialogs.
- Conservative read-only Android/StrongBox/TEE/USB capability reporting.

### Validation

- Disposable same-device register → export → delete → restore → authenticate
  round trip verified by the owner.
- Automated non-destructive gate at release preparation: 120 Python tests
  (2 skipped), 25 Rust unit tests, 4 Rust integration tests, 9 native-module
  packaging tests.
- Second-device restore and formal FIDO conformance/certification remain open.
