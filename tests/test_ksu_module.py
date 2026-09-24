"""Host-only KernelSU module ZIP tests: never invoke adb, pm, su or the gadget.

Run: python3 -m unittest tests.test_ksu_module -v
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "ksu-tools/build_module.py"
spec = importlib.util.spec_from_file_location("ctap_ksu_builder", BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class HostModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not builder.DEFAULT_APK.is_file():
            raise unittest.SkipTest(
                "historical approved-legacy-helper.apk fixture is intentionally not distributed"
            )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.module_src = self.folder / "source"
        (self.module_src / "lib").mkdir(parents=True)
        for script in ("service.sh", "action.sh", "uninstall.sh"):
            (self.module_src / script).write_text("#!/system/bin/sh\nexit 0\n")
        (self.module_src / "lib/common.sh").write_text("#!/system/bin/sh\ntrue\n")
        self.out = self.folder / "generated.zip"

    def build(self):
        return builder.build(ROOT, self.module_src, output=self.out)

    def test_build_twice_is_byte_identical_and_reproducible(self):
        archive, first_sha = self.build()
        original = archive.read_bytes()
        (self.module_src / "service.sh").touch()  # mtime must never leak to ZIP.
        again, second_sha = self.build()
        self.assertEqual(first_sha, second_sha)
        self.assertEqual(again.read_bytes(), original)
        with zipfile.ZipFile(again) as bundle:
            self.assertEqual(bundle.namelist(), sorted(bundle.namelist()))
            self.assertEqual(len(bundle.namelist()), len(set(bundle.namelist())))
            self.assertEqual(bundle.testzip(), None)
            self.assertTrue(all(info.date_time == builder.TIMESTAMP
                                for info in bundle.infolist()))
            self.assertTrue(all(info.create_system == 3
                                for info in bundle.infolist()))

    def test_signed_apk_is_byte_for_byte_preserved(self):
        self.build()
        with zipfile.ZipFile(self.out) as archive:
            apk = archive.read("payload/helper.apk")
            source = builder.DEFAULT_APK.read_bytes()
            self.assertEqual(apk, source)
            self.assertEqual(hashlib.sha256(apk).hexdigest(),
                             builder.PINNED_APK_SHA256)
            self.assertEqual(builder._apk_signer_sha256(apk),
                             builder.PINNED_SIGNER_SHA256)
            self.assertFalse(any("local-debug.jks" in entry
                                 or entry.endswith((".jks", ".pem", ".so", ".pyc"))
                                 for entry in archive.namelist()))
            self.assertEqual(archive.read("skip_mount"), b"")

    def test_content_manifest_covers_exact_payload_without_self_reference(self):
        self.build()
        with zipfile.ZipFile(self.out) as archive:
            provenance = json.loads(archive.read("provenance.json"))
            self.assertEqual(provenance["id"], "pocof7_ctap3b")
            self.assertEqual(provenance["apkPackage"], "org.pocof7.ctap3b")
            self.assertEqual(provenance["apkSignerCertSha256"],
                             builder.PINNED_SIGNER_SHA256)
            self.assertEqual(provenance["apkSha256"],
                             builder.PINNED_APK_SHA256)
            files = {name: hashlib.sha256(archive.read(name)).hexdigest()
                     for name in archive.namelist()
                     if name not in ("provenance.json", "sha256sums.txt")}
            self.assertEqual(files, provenance["files"])
            manifest = archive.read("sha256sums.txt").decode()
            self.assertEqual(
                manifest,
                "".join(hashlib.sha256(archive.read(name)).hexdigest()
                        + "  " + name + "\n"
                        for name in sorted(archive.namelist())
                        if name != "sha256sums.txt"),
            )
            self.assertIn("payload/ctaphid/android_backend.py", files)
            self.assertIn("payload/ctaphid/server.py", files)
            self.assertIn("service.sh", files)
            self.assertIn("action.sh", files)
            self.assertIn("uninstall.sh", files)

    def test_zip_permissions_and_module_identity(self):
        self.build()
        with zipfile.ZipFile(self.out) as archive:
            for entry in archive.infolist():
                expected = 0o100755 if entry.filename.endswith(".sh") else 0o100644
                self.assertEqual(entry.external_attr >> 16, expected,
                                 entry.filename)
            properties = dict(line.split("=", 1)
                              for line in archive.read("module.prop").decode().splitlines())
            self.assertRegex(properties["id"], r"^[a-zA-Z][a-zA-Z0-9._-]+$")
            self.assertEqual(properties["id"], "pocof7_ctap3b")
            self.assertEqual(properties["versionCode"], "30000")
            self.assertNotIn("system/", "".join(archive.namelist()))

    def test_fails_closed_for_unapproved_apk_signer_and_no_clobber(self):
        self.out.write_bytes(b"KNOWN GOOD OUTPUT")
        tampered = self.folder / "not-the-installed-apk.apk"
        tampered.write_bytes(builder.DEFAULT_APK.read_bytes() + b"x")
        with self.assertRaisesRegex(builder.BuildError, "approved build"):
            builder.build(ROOT, self.module_src, tampered, output=self.out)
        with self.assertRaisesRegex(builder.BuildError, "signing identity differs"):
            builder.build(ROOT, self.module_src, output=self.out,
                          expected_signer_sha256="a" * 64)
        self.assertEqual(self.out.read_bytes(), b"KNOWN GOOD OUTPUT")

    def test_refuses_missing_scripts_and_unsafe_module_sources(self):
        (self.module_src / "action.sh").unlink()
        with self.assertRaisesRegex(builder.BuildError, "action.sh"):
            self.build()
        (self.module_src / "action.sh").write_text("true\n")
        (self.module_src / "module.prop").write_text("id=evil\n")
        with self.assertRaisesRegex(builder.BuildError, "ID mismatches"):
            self.build()
        (self.module_src / "module.prop").unlink()
        (self.module_src / "debug.jks").write_text("PRIVATE KEY")
        with self.assertRaisesRegex(builder.BuildError, "hidden/secret"):
            self.build()
        (self.module_src / "debug.jks").unlink()
        (self.module_src / "lib/link.sh").symlink_to(
            self.module_src / "service.sh")
        with self.assertRaisesRegex(builder.BuildError, "non-symlink"):
            self.build()

    def test_installer_is_shell_valid_and_never_autoinstalls_or_reboots(self):
        script = ROOT / "ksu-tools/customize.sh"
        result = subprocess.run(["sh", "-n", str(script)], capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        content = script.read_text()
        for phrase in ("sha256sum -c sha256sums.txt", "skip_mount",
                       "set_perm_recursive", "set_perm", "ARCH",
                       "API", "onyx", "/usr/bin/python3", "cryptography"):
            self.assertIn(phrase, content)
        self.assertIn('pm install "$MODPATH/payload/helper.apk"', content)
        self.assertIn("pm path org.pocof7.ctap3b", content)
        self.assertIn('sha256sum "$installed_apk"', content)
        self.assertIn('sha256sum "$MODPATH/payload/helper.apk"', content)
        self.assertIn('[ "$bundle_sha" = "$existing_sha" ]', content)
        forbidden = ("pm install -r", "pm uninstall", "pm clear",
                     "reboot -", "setprop sys.usb.config",
                     "rm -rf /data", "udc=", "rm -rf \"$CHROOT", "pip install")
        for value in forbidden:
            self.assertNotIn(value, content)

    def test_installer_preserves_existing_apk_and_first_installs_only_if_absent(self):
        self.build()
        installed = self.folder / "installed.apk"
        pointer = self.folder / "installed-path"
        install_log = self.folder / "pm-install-count"
        fake_kali = self.folder / "kali"
        (fake_kali / "usr/bin").mkdir(parents=True)
        (fake_kali / "root").mkdir()
        (fake_kali / "usr/bin/python3").write_bytes(b"host test placeholder")
        (fake_kali / "usr/bin/python3").chmod(0o755)
        stage = self.folder / "installed-module"
        stage.mkdir()
        with zipfile.ZipFile(self.out) as archive:
            archive.extractall(stage)
        approved = (stage / "payload/helper.apk").read_bytes()
        shell = """
pm() {
    case "$1" in
        path)
            [ -f "$MOCK_POINTER" ] &&
                printf 'package:%s\\n' "$(cat "$MOCK_POINTER")"
            return 0 ;;
        install)
            cp "$2" "$MOCK_INSTALLED" || return 1
            printf '%s\\n' "$MOCK_INSTALLED" > "$MOCK_POINTER"
            printf 'install\\n' >> "$MOCK_PM_LOG"
            return 0 ;;
    esac
    return 1
}
getprop() {
    case "$1" in
        ro.product.device|ro.product.vendor.device) echo onyx ;;
        ro.build.version.sdk) echo 37 ;;
    esac
}
chroot() { return 0; }
set_perm_recursive() { :; }
set_perm() { :; }
ui_print() { :; }
abort() { echo "$*" >&2; exit 87; }
"""
        # The installer is unchanged apart from the host-only Kali path; the
        # module payload/manifest verified by sha256sum -c stays untouched.
        content = (ROOT / "ksu-tools/customize.sh").read_text().replace(
            "CHROOT=/data/local/nhsystem/kali-arm64", f"CHROOT={fake_kali}",
        )
        environment = {
            **os.environ, "KSU": "true", "ARCH": "arm64", "API": "37",
            "MODPATH": str(stage), "MOCK_POINTER": str(pointer),
            "MOCK_INSTALLED": str(installed), "MOCK_PM_LOG": str(install_log),
        }

        def simulate():
            return subprocess.run(["sh", "-c", shell + "\n" + content],
                                  cwd=stage, env=environment,
                                  capture_output=True, text=True)

        installed.write_bytes(approved)
        pointer.write_text(str(installed))
        result = simulate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(install_log.exists(), "existing app was reinstalled")
        self.assertEqual(installed.read_bytes(), approved)

        installed.write_bytes(approved + b"tampered")
        result = simulate()
        self.assertEqual(result.returncode, 87)
        self.assertIn("differs from approved signed build", result.stderr)
        self.assertFalse(install_log.exists())
        self.assertEqual(installed.read_bytes(), approved + b"tampered")

        installed.unlink()
        pointer.unlink()
        result = simulate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(install_log.read_text(), "install\n")
        self.assertEqual(installed.read_bytes(), approved)


if __name__ == "__main__":
    unittest.main()
