"""Host-only checks for the read-only DeviceCapabilities probe."""

from pathlib import Path
import re
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "android-helper/app/src/main/java"
          / "org/pocof7/ctap3b/DeviceCapabilities.java").read_text()


class DeviceCapabilitiesTests(unittest.TestCase):
    def test_probes_strong_biometrics_and_feature(self):
        self.assertIn("BiometricManager.Authenticators.BIOMETRIC_STRONG", SOURCE)
        self.assertIn("PackageManager.FEATURE_STRONGBOX_KEYSTORE", SOURCE)

    def test_keystore_evidence_uses_security_level(self):
        self.assertIn('KeyStore.getInstance("AndroidKeyStore")', SOURCE)
        self.assertIn("factory.getKeySpec((PrivateKey) key, KeyInfo.class)", SOURCE)
        self.assertIn("KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT", SOURCE)
        self.assertIn("KeyProperties.SECURITY_LEVEL_STRONGBOX", SOURCE)
        self.assertIn('alias.matches("ctap3b-[0-9a-fA-F-]{36}")', SOURCE)
        self.assertRegex(SOURCE, r"tee \? State\.AVAILABLE : State\.UNKNOWN")
        self.assertRegex(SOURCE, r"strongBox \? State\.AVAILABLE : State\.UNKNOWN")

    def test_no_mutating_operations_or_root_execution(self):
        for forbidden in ("generateKeyPair(", "generateKey(", "setIsStrongBoxBacked(",
                          "deleteEntry(", "Runtime.getRuntime(", "ProcessBuilder(",
                          "exec(", "mkdir(", "createNewFile(", "Files.write(",
                          "setWritable("):
            self.assertNotIn(forbidden, SOURCE)

    def test_restricted_capabilities_are_not_assumed_absent(self):
        self.assertIn('new File("/sys/kernel/config/usb_gadget")', SOURCE)
        self.assertIn('new File("/sys/kernel/ksu").exists()', SOURCE)
        self.assertIn('new File("/dev/hidg0")', SOURCE)
        self.assertIn("Process.myUid() == 0 ? State.AVAILABLE : State.UNKNOWN", SOURCE)


if __name__ == "__main__":
    unittest.main()
