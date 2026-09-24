"""Host-only standalone Android CTAPHID package tests; never run adb/pm/su."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "native_module_build", ROOT / "native-tools/build_native_module.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class NativeModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.zip = Path(self.tmp.name) / "standalone.zip"

    def test_deterministic_no_runtime_dependency_and_no_secrets(self):
        out, first = BUILDER.build(self.zip)
        original = out.read_bytes()
        out, second = BUILDER.build(self.zip)
        self.assertEqual(first, second)
        self.assertEqual(out.read_bytes(), original)
        with zipfile.ZipFile(out) as bundle:
            self.assertIsNone(bundle.testzip())
            self.assertEqual(bundle.namelist(), sorted(bundle.namelist()))
            self.assertTrue(all(item.date_time == BUILDER.STAMP for item in bundle.infolist()))
            self.assertEqual(bundle.read("skip_mount"), b"")
            self.assertEqual(bundle.read("payload/helper.apk"), BUILDER.APK.read_bytes())
            self.assertNotIn("payload/ctaphid/server.py", bundle.namelist())
            self.assertFalse(any(name.startswith("system/") or "python" in name.lower()
                                 or "kali" in name.lower() or "nethunter" in name.lower()
                                 or name.endswith((".jks", ".pem", ".pyc", ".so"))
                                 for name in bundle.namelist()))
            self.assertEqual(bundle.read("module.prop").splitlines()[0],
                             b"id=pocof7_ctap_native")

    def test_binary_is_actual_bionic_aarch64_not_host_elf(self):
        entries = BUILDER.collect()
        binary = entries["bin/pocof7-native-ctaphid"]
        self.assertEqual(binary[:4], b"\x7fELF")
        self.assertEqual(binary[4], 2)
        self.assertEqual(binary[5], 1)
        self.assertEqual(int.from_bytes(binary[18:20], "little"), 183)
        self.assertIn(b"/system/bin/linker64", binary)
        self.assertGreater(len(binary), 100_000)

    def test_provenance_manifest_enumerates_approved_data(self):
        self.zip, _ = BUILDER.build(self.zip)
        with zipfile.ZipFile(self.zip) as bundle:
            provenance = json.loads(bundle.read("provenance.json"))
            self.assertTrue(provenance["noKaliNetHunterPythonRuntime"])
            self.assertEqual(provenance["appSha256"], BUILDER.sha(BUILDER.APK.read_bytes()))
            self.assertEqual(provenance["appSignerSha256"], BUILDER.SIGNER_SHA)
            self.assertEqual(provenance["appSignerVerification"],
                             "Android SDK apksigner verify --print-certs")
            actual_files = {name: BUILDER.sha(bundle.read(name))
                            for name in bundle.namelist()
                            if name not in ("sha256sums.txt", "provenance.json")}
            self.assertEqual(provenance["files"], actual_files)
            self.assertIn("bin/pocof7-native-ctaphid", actual_files)
            self.assertEqual(provenance["binarySha256"],
                             actual_files["bin/pocof7-native-ctaphid"])
            manifest = "".join(f"{BUILDER.sha(bundle.read(name))}  {name}\n"
                               for name in sorted(bundle.namelist())
                               if name != "sha256sums.txt")
            self.assertEqual(bundle.read("sha256sums.txt").decode(), manifest)

    def test_installer_and_module_shells_are_valid_and_standalone(self):
        scripts = [ROOT / "native-tools/customize.sh"]
        scripts += list((ROOT / "ksu-native-module").rglob("*.sh"))
        for script in scripts:
            process = subprocess.run(["sh", "-n", str(script)], capture_output=True,
                                     text=True, check=False)
            self.assertEqual(process.returncode, 0, f"{script}: {process.stderr}")
            body = script.read_text()
            for forbidden in ("/data/local/nhsystem", "/usr/bin/python3", "pip install",
                              "pm clear", "pm uninstall", "reboot -"):
                self.assertNotIn(forbidden, body, f"{script}: {forbidden}")
        installer = (ROOT / "native-tools/customize.sh").read_text()
        self.assertIn("--self-test", installer)
        self.assertIn("sha256sum -c sha256sums.txt", installer)
        self.assertIn("pm install", installer)
        self.assertIn("pm install -r", installer)
        self.assertIn("native_new_uid", installer)
        daemon = (ROOT / "ksu-native-module/lib/daemon.sh").read_text()
        self.assertIn("ps -A -o PID,NAME", daemon)
        self.assertIn("ps -A -o PID,ARGS", daemon)
        self.assertNotIn("for _native_proc in /proc/[0-9]*/exe", daemon)
        self.assertNotIn("for _native_f in /proc/[0-9]*/cmdline", daemon)

    def test_uninstalled_app_store_not_shipped_and_current_module_separate(self):
        entries = BUILDER.collect()
        self.assertFalse(any("credentials" in name or name.endswith(".jks")
                             for name in entries))
        self.assertIn("/data/adb/modules/pocof7_ctap3b/disable",
                      entries["lib/daemon.sh"].decode())
        self.assertIn("org.pocof7.ctap3b", entries["customize.sh"].decode())
        self.assertIn("pocof7_ctap_native", entries["module.prop"].decode())

    def test_boot_receiver_and_release_signer_upgrade_are_fail_closed(self):
        manifest = (ROOT / "android-helper/app/src/main/AndroidManifest.xml").read_text()
        receiver = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/BootReceiver.java").read_text()
        installer = (ROOT / "native-tools/customize.sh").read_text()
        self.assertIn("android.permission.RECEIVE_BOOT_COMPLETED", manifest)
        self.assertIn("android.intent.action.BOOT_COMPLETED", manifest)
        self.assertIn("android.intent.action.MY_PACKAGE_REPLACED", manifest)
        self.assertIn("android:directBootAware=\"false\"", manifest)
        self.assertIn("users.isUserUnlocked()", receiver)
        self.assertIn("context.startForegroundService(service)", receiver)
        self.assertNotIn("MainActivity.class", receiver)
        self.assertIn(BUILDER.SIGNER_SHA, installer)
        self.assertIn("native_apk_signer_sha256", installer)
        self.assertIn("automatic signer migration is refused", installer)
        self.assertNotIn(
            "b25cc48500549d42e2efc14e48cd48b6d398db14df2aba7ccfc94f295a8fa23c",
            installer)
        self.assertIn("native_new_uid", installer)

    def test_release_apk_is_cryptographically_verified_by_android_apksigner(self):
        self.assertEqual(BUILDER.verify_apk_signer(BUILDER.APK), BUILDER.SIGNER_SHA)

    def test_module_shell_extracts_v3_release_certificate_and_rejects_trailing_tamper(self):
        helper = ROOT / "ksu-native-module/lib/apk_signer.sh"
        command = '. "$1"; native_apk_signer_sha256 "$2"'
        result = subprocess.run(["sh", "-c", command, "sh", str(helper), str(BUILDER.APK)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), BUILDER.SIGNER_SHA)

        tampered = Path(self.tmp.name) / "release-tampered.apk"
        tampered.write_bytes(BUILDER.APK.read_bytes() + b"x")
        result = subprocess.run(["sh", "-c", command, "sh", str(helper), str(tampered)],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_supervisor_recovers_after_unplug_without_usb_writes_or_replay(self):
        """Run the real shell supervisor with an isolated mock UDC/daemon.

        Reproduces observed physical unplug: UDC empty -> biometric's old
        socket cancelled, UDC bound again -> new module-owned responder. No
        `usb_setup`, ConfigFS writes, credential requests or phone access.
        """
        env = Path(self.tmp.name)
        gadget = env / "gadget"
        state = env / "state"
        gadget.mkdir()
        state.mkdir()
        (gadget / "UDC").write_text("")
        module = ROOT / "ksu-native-module"
        script = r'''
MODDIR="$1"
. "$MODDIR/lib/daemon.sh"
PATH=/usr/bin:/bin:$PATH
G="$2/gadget"
STATE="$2/state"
DPID="$STATE/daemon.pid"
SPID="$STATE/supervisor.pid"
LOG="$STATE/module.log"
stop_count=0
launch_count=0
step=0
m_init() { :; }
m_log() { printf '%s\n' "$*" >> "$LOG"; }
usb_healthy() { [ "$(cat "$G/UDC")" = a600000.dwc3 ]; }
daemon_stop() { stop_count=$((stop_count + 1)); }
daemon_owned_pid() { return 1; }
daemon_helper_socket() { return 0; }
daemon_launch() { launch_count=$((launch_count + 1)); }
sleep() {
    step=$((step + 1))
    case "$step" in
        1) printf 'a600000.dwc3\n' > "$G/UDC" ;;
        2) : > "$G/UDC" ;;
        3) printf 'a600000.dwc3\n' > "$G/UDC" ;;
        4) : > "$STATE/stopping" ;;
        *) echo 'UNEXPECTED SUPERVISOR SLEEP' >&2; exit 65 ;;
    esac
}
daemon_supervise
[ "$launch_count" -eq 2 ] || exit 66
[ "$stop_count" -eq 2 ] || exit 67
[ "$step" -eq 4 ] || exit 68
[ ! -e "$SPID" ] || exit 69
grep -q 'USB FIDO gadget restored; accepting new host CTAP requests' "$LOG"
'''
        result = subprocess.run(["sh", "-c", script, "sh", str(module), str(env)],
                                capture_output=True, text=True, timeout=10,
                                check=False)
        self.assertEqual(result.returncode, 0,
                         f"supervisor mock failed: {result.stdout} {result.stderr}; "
                         f"log={(state / 'module.log').read_text() if (state / 'module.log').exists() else ''}")
        log = (state / "module.log").read_text()
        self.assertEqual(log.count("USB FIDO gadget unavailable"), 2)
        self.assertEqual(log.count("USB FIDO gadget restored"), 2)


if __name__ == "__main__":
    unittest.main()
