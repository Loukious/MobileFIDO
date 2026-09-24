# Security policy

MobileFIDO is experimental security software. It handles authentication keys,
root-owned USB HID transport, Android Keystore operations and recovery archives,
so security reports are especially valuable.

## Supported development line

Security fixes are currently targeted at the latest `5.x` development line.
Older milestone/prototype code remains in the repository for history and tests
but should not be considered actively supported for deployment.

## Reporting a vulnerability

Please do **not** publish exploitable vulnerability details, private key
material, recovery archives, credential IDs, signing keystores or device/account
identifiers in a public issue.

Use GitHub's private vulnerability reporting / Security Advisory flow when it is
available for this repository. If the GitHub UI does not offer a private report
option yet, contact the repository owner privately through their GitHub profile
before posting technical exploit details publicly.

Useful reports include:

- a way to obtain an assertion signature without the required per-use
  `BiometricPrompt.CryptoObject`;
- a software-key fallback or incorrect StrongBox/TEE policy acceptance;
- cross-RP credential selection/binding failures;
- malformed CTAPHID/CBOR input causing memory safety or authorization problems;
- recovery archive tampering/conflict behavior that imports the wrong key;
- module/APK installer behavior that can clear or strand app data/credentials;
- root socket peer-validation bypasses;
- sensitive logging or backup material leakage.

## Scope and expectations

MobileFIDO runs on rooted/bootloader-unlocked Android devices. Reports should
distinguish attacks that require already-unrestricted root access from attacks
available to less-privileged apps, USB hosts, browsers or recovery-file inputs.
Root compromise remains a major trust-boundary limitation rather than something
the project claims to eliminate.

The project is not FIDO Alliance certified and no bounty program is currently
offered.
