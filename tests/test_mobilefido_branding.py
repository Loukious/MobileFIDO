"""MobileFIDO rename invariants: new branding, stable credential boundaries."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = (ROOT / "android-helper/app/src/main/AndroidManifest.xml").read_text()
ACTIVITY = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/MainActivity.java").read_text()
CRYPTO = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/CryptoKeyManager.java").read_text()
RECOVERY = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/RecoverableBackupManager.java").read_text()
HELPER = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/HelperService.java").read_text()
MODULE = (ROOT / "ksu-native-module/module.prop").read_text()
NATIVE = (ROOT / "native-ctaphid/src/backend.rs").read_text()


class MobileFidoBrandingTests(unittest.TestCase):
    def test_user_facing_android_brand_is_mobilefido(self):
        self.assertIn('android:label="MobileFIDO DEV"', MANIFEST)
        self.assertIn('android:theme="@style/MobileFIDOTheme"', MANIFEST)
        self.assertIn('"ANDROID SECURITY KEY"', ACTIVITY)
        self.assertIn('"MobileFIDO"', ACTIVITY)
        self.assertIn('"MobileFIDO • " + operation.op', ACTIVITY)
        self.assertIn('"MobileFIDO-Recovery-" + suffix', ACTIVITY)
        self.assertIn('".mobilefido"', ACTIVITY)
        self.assertNotIn('"POCO F7  /  LOCAL AUTHENTICATOR"', ACTIVITY)

    def test_new_recovery_brand_accepts_pre_rename_archive(self):
        self.assertIn('MAGIC = "MFRCV001"', RECOVERY)
        self.assertIn('LEGACY_MAGIC = "PKRCV001"', RECOVERY)
        self.assertIn('header.put("exporterDisplayName", "MobileFIDO")', RECOVERY)
        self.assertIn('header.put("exporterRpId", "mobilefido.localhost")', RECOVERY)
        self.assertIn('passkey.put("mobileFido"', RECOVERY)
        self.assertIn('case "pocoKey":', RECOVERY)
        self.assertIn('case "mobileFido":', RECOVERY)

    def test_credential_critical_legacy_identifiers_are_not_renamed(self):
        # Changing any of these in a cosmetic rename can strand existing users.
        self.assertIn('package="org.pocof7.ctap3b"', MANIFEST)
        self.assertIn('AAGUID = "PocoF7-BIO-DEV01"', CRYPTO)
        self.assertIn('RECOVERY_WRAP_ALIAS = "ctap3b-recovery-wrap-v1"', CRYPTO)
        self.assertIn('"PocoKeyEscrowV1\\0"', CRYPTO)
        self.assertIn('"PocoKeyPairV1\\0"', CRYPTO)
        self.assertIn('SOCKET_NAME = "ctaphid-m3b-v1"', HELPER)
        self.assertIn('id=pocof7_ctap_native', MODULE)
        self.assertIn('b"PocoF7-BIO-DEV01"', NATIVE)


if __name__ == "__main__":
    unittest.main()
