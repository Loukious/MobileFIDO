"""Host-only release safety checks; NEVER access ADB, a phone, or USB gadget."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "android-helper/build-local.sh"
MANIFEST = ROOT / "android-helper/app/src/main/AndroidManifest.xml"
GRADLE = ROOT / "android-helper/app/build.gradle"
MODULE = ROOT / "native-tools/module.prop"
INSTALLER = ROOT / "native-tools/customize.sh"
RELEASE_GATE = ROOT / "native-tools/verify_release_candidate.sh"
EXPECTED_CERT = "c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da"
LEGACY_DEV_CERT = "3f133472fa0066963cc16ae19a6250e275e7f0f8265589dc5a0b05f746d20da2"


class ReleaseSigningTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"),
                         "POSIX shell required for the isolated build harness")
    def test_clean_checkout_creates_private_output_before_compiling(self):
        # All signing/SDK tools are inert doubles. No real APK, key or phone
        # is used; reaching the fake compiler proves clean output setup works.
        with tempfile.TemporaryDirectory(prefix="mobilefido-clean-build-") as root:
            working = Path(root)
            helper = working / "android-helper"
            (helper / "app/src/main/java").mkdir(parents=True)
            script = helper / "build-local.sh"
            script.write_text(BUILD.read_text(), encoding="utf-8")
            sdk = working / "sdk"
            tools = sdk / "build-tools/35.0.0"
            tools.mkdir(parents=True)
            platform = sdk / "platforms/android-35/android.jar"
            platform.parent.mkdir(parents=True)
            platform.touch()
            jdk_bin = working / "jdk/bin"
            jdk_bin.mkdir(parents=True)
            mocks = working / "mock-bin"
            mocks.mkdir()
            for path, body in (
                (tools / "aapt2", "exit 0"),
                (jdk_bin / "keytool", "printf 'test certificate'"),
                (jdk_bin / "javac", "echo COMPILER_REACHED >&2; exit 37"),
                (mocks / "sha256sum", f"cat >/dev/null; echo '{EXPECTED_CERT}  -'"),
            ):
                path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
                path.chmod(0o755)
            keystore = working / "inert-test-keystore"
            keystore.write_text("not a signing key", encoding="utf-8")
            env = dict(os.environ)
            env.update({
                "JAVA_HOME": str(jdk_bin.parent),
                "ANDROID_SDK_ROOT": str(sdk),
                "ANDROID_BUILD_TOOLS": str(tools),
                "MOBILEFIDO_KEYSTORE": str(keystore),
                "MOBILEFIDO_STOREPASS": "inert-test-only",
                "MOBILEFIDO_KEYPASS": "inert-test-only",
                "PATH": str(mocks) + os.pathsep + env.get("PATH", ""),
            })
            attempt = subprocess.run(["bash", str(script)], env=env,
                                     text=True, capture_output=True, check=False,
                                     timeout=10)
            self.assertEqual(attempt.returncode, 37, attempt.stderr)
            self.assertIn("COMPILER_REACHED", attempt.stderr)
            output = helper / "app/build/manual"
            self.assertTrue((output / "classes").is_dir())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_release_gate_uses_release_signed_artifact_without_claiming_certification(self):
        gate = RELEASE_GATE.read_text()
        self.assertIn("release-SIGNED development candidate", gate)
        self.assertIn("MobileFIDO-5.1.1-release.apk", gate)
        self.assertNotIn("local-debug.jks", gate)
        self.assertNotIn("production signing/migration, hardware QA", gate)

    def test_installer_pins_release_signer_and_never_resets_data(self):
        installer = INSTALLER.read_text()
        self.assertIn(EXPECTED_CERT, installer)
        self.assertIn(LEGACY_DEV_CERT, installer)
        self.assertIn("native_apk_signer_sha256", installer)
        self.assertIn("automatic signer migration is refused", installer)
        self.assertIn('pm install -r "$MODPATH/payload/helper.apk"', installer)
        self.assertIn('"$native_uid" = "$native_new_uid"', installer)
        self.assertNotIn(
            "db829f69f889d5b554ff2ef87e83f423f1a5d4173590d4825e31a9be04647ecb",
            installer)
        self.assertNotIn("pm clear", installer)
        self.assertNotIn("pm uninstall", installer)

    def test_missing_original_signing_keystore_never_silently_creates_another(self):
        # A real device's AndroidKeyStore credential aliases depend on the
        # same installed app and signing identity. A clean checkout may not
        # silently manufacture a new certificate, inviting uninstall/data loss.
        with tempfile.TemporaryDirectory(prefix="ctap-release-signing-") as root:
            working = Path(root)
            (working / "android-helper").mkdir()
            (working / "android-helper/build-local.sh").write_bytes(BUILD.read_bytes())
            env = dict(os.environ)
            jdk = Path(os.environ.get("JAVA_HOME", "/tmp/mobilefido-toolchain/jdk"))
            sdk = Path(os.environ.get("ANDROID_SDK_ROOT",
                                      "/tmp/mobilefido-toolchain/android-sdk"))
            env.update({
                "JAVA_HOME": str(jdk),
                "ANDROID_SDK_ROOT": str(sdk),
                "ANDROID_BUILD_TOOLS": str(sdk / "build-tools/35.0.0"),
            })
            for name in ("MOBILEFIDO_KEYSTORE", "MOBILEFIDO_STOREPASS", "MOBILEFIDO_KEYPASS"):
                env.pop(name, None)
            if not Path(env["JAVA_HOME"], "bin/javac").is_file():
                self.skipTest("local host Java 17 test toolchain unavailable")
            attempt = subprocess.run(["bash", str(working / "android-helper/build-local.sh")],
                                     env=env, text=True, capture_output=True, check=False)
            self.assertNotEqual(attempt.returncode, 0)
            self.assertIn("REFUSED: set MOBILEFIDO_KEYSTORE", attempt.stderr)
            self.assertIn("NEVER uninstall", attempt.stderr)
            self.assertFalse((working / "android-helper/app/build/manual/local-debug.jks").exists())

    def test_approved_cert_pinned_and_no_key_material_shipped(self):
        build = BUILD.read_text()
        self.assertIn(EXPECTED_CERT, build)
        self.assertNotIn(LEGACY_DEV_CERT, build)
        self.assertIn("MOBILEFIDO_KEYSTORE", build)
        self.assertIn("MOBILEFIDO_KEY_ALIAS", build)
        self.assertIn("-storepass:env MOBILEFIDO_STOREPASS", build)
        self.assertIn("--ks-pass env:MOBILEFIDO_STOREPASS", build)
        self.assertIn("--key-pass env:MOBILEFIDO_KEYPASS", build)
        self.assertNotIn("pass:android", build)
        self.assertNotIn("local-debug.jks", build)
        self.assertNotIn("-genkeypair", build)
        self.assertIn('SIGNING_JKS="${MOBILEFIDO_KEYSTORE:-}"', build)
        self.assertIn("if [[ \"${CERT_SHA}\" != \"${APPROVED_CERT_SHA}\"", build)
        self.assertIn('rm -rf -- "${OUTPUT}/classes" "${OUTPUT}/dex"', build)
        self.assertIn('"${OUTPUT}/MobileFIDO-5.1.1-release.apk.new"', build)
        self.assertIn('mv -f -- "${OUTPUT}/MobileFIDO-5.1.1-release.apk.new"', build)
        self.assertIn("--print-certs", build)
        self.assertIn('zipfile.ZipInfo(entry.filename, (2020, 1, 1, 0, 0, 0))', build)
        self.assertIn('android:allowBackup="false"', MANIFEST.read_text())
        self.assertNotIn('android.permission.INTERNET', MANIFEST.read_text())
        self.assertIn('DEVELOPMENT BUILD',
                      (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/MainActivity.java")
                      .read_text())

    def test_android_and_ksu_release_identifiers_stay_coordinated(self):
        module = MODULE.read_text()
        version = re.search(r"^version=(\S+)$", module, flags=re.M).group(1)
        code = int(re.search(r"^versionCode=(\d+)$", module, flags=re.M).group(1))
        gradle = GRADLE.read_text()
        builder = BUILD.read_text()
        self.assertIn(f"versionCode {code}", gradle)
        self.assertIn(f"versionName '{version}'", gradle)
        self.assertIn(f"--version-code {code} --version-name {version}", builder)


if __name__ == "__main__":
    unittest.main()
