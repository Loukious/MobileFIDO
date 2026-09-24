# Poco F7 CTAP3B KernelSU Next host packager

This builds an experimental, unsigned KernelSU module ZIP. The embedded APK
stays byte-identical to the already installed/signed development APK. The
host build never runs Gradle, adb, su, APK signing, or any phone command.

Host commands from the fido2 project root:

    python3 ksu-tools/build_module.py
    python3 -m unittest tests.test_ksu_module -v
    sha256sum ksu-tools/dist/PocoF7-CTAP3B-KSU-Next.zip

The host builder combines root scripts from ksu-module/ with ksu-tools'
module.prop and customize.sh, an empty skip_mount, the pure-Python ctaphid
package under payload/ctaphid, legacy launchers under payload/legacy, and
the exact signed APK at payload/helper.apk. A provenance.json and SHA256
manifest cover all payload bytes; final ZIP digest is printed separately.
Sort order, compression, file modes and ZIP timestamps are deterministic.
No local-debug.jks or any private credential file is bundled.

Approved existing signed APK SHA-256:

    b25cc48500549d42e2efc14e48cd48b6d398db14df2aba7ccfc94f295a8fa23c

Embedded APK signing certificate SHA-256 (debug signer, not FIDO attestation):

    3f133472fa0066963cc16ae19a6250e275e7f0f8265589dc5a0b05f746d20da2

KernelSU Next sources customize.sh after its default ZIP extraction. It
checks arm64, Android 17 API37, Poco F7 onyx, packaged checksums, installed
Kali /usr/bin/python3 and Kali's already-installed cryptography dependency.
Native Python wheels are deliberately not shipped: the extension ABI must
match the Kali aarch64 Python 3.14 interpreter. No pip/network/boot downloads.
No system overlay (skip_mount); meta-overlayfs is not needed for this module.

The stable module ID is pocof7_ctap3b. On install the installer checks
pm path org.pocof7.ctap3b: if present it NEVER reinstalls/uninstalls/clears
the Android app, preserving signing identity, UID, private credential
metadata and Android KeyStore keys. The current installed base.apk must be
byte-for-byte identical to the pinned bundle or installation aborts without
touching the existing app. If absent it first-installs the pinned
signed APK once, and aborts on failure without any fallback. The user must
open the app for biometric prompts. Existing daemon is not stopped during
module installation.

Module action/runtime contract for worker-owned ksu-module/:

    $MODDIR/payload/ctaphid/*.py
    $MODDIR/payload/helper.apk
    $MODDIR/payload/legacy/ctaphid_start.sh
    $MODDIR/payload/legacy/ctaphid_stop.sh
    $MODDIR/provenance.json
    $MODDIR/sha256sums.txt

Worker-owned root service.sh, action.sh, uninstall.sh and lib/*.sh must
resolve the same stable module ID. They must never remove the independent
Kali /root/ctap-dev-credentials.json, Android app/private metadata, or
StrongBox keys. KernelSU stages upgrades under /data/adb/modules_update;
ephemeral state under the replaced module directory must not be assumed to
survive upgrades. Runtime scripts handle safe daemon/code handoff.
