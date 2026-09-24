"""Non-device UI regressions for dynamic day/night and the SAF backup flow."""

from pathlib import Path
import re
import unittest
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "android-helper/app/src/main"
MAIN = (APP / "java/org/pocof7/ctap3b/MainActivity.java").read_text()
ANDROID = "{http://schemas.android.com/apk/res/android}"


class DynamicColorBackupUiTests(unittest.TestCase):
    def test_app_and_native_alerts_use_day_night_dynamic_palette(self):
        manifest = ElementTree.parse(APP / "AndroidManifest.xml").getroot()
        application = manifest.find("application")
        self.assertEqual(application.get(ANDROID + "theme"), "@style/MobileFIDOTheme")

        light = ElementTree.parse(APP / "res/values/styles.xml").getroot().find("style")
        dark = ElementTree.parse(APP / "res/values-night/styles.xml").getroot().find("style")
        self.assertEqual(light.get("name"), "MobileFIDOTheme")
        self.assertEqual(dark.get("name"), "MobileFIDOTheme")
        self.assertIn("Theme.Material.Light.NoActionBar", light.get("parent"))
        self.assertIn("Theme.Material.NoActionBar", dark.get("parent"))
        for style, primary in ((light, "600"), (dark, "200")):
            names = {element.attrib.get("name"): element.text for element in style}
            self.assertEqual(names["android:colorAccent"],
                             f"@android:color/system_accent1_{primary}")
            for attr in ("android:colorBackgroundFloating", "android:windowBackground",
                         "android:textColorPrimary", "android:statusBarColor"):
                self.assertTrue(names[attr].startswith("@android:color/system_neutral1_"))

    def test_programmatic_ui_follows_system_colors_without_hardcoded_brand_palette(self):
        self.assertIn("android.R.color.system_neutral1_900", MAIN)
        self.assertIn("android.R.color.system_accent1_600", MAIN)
        self.assertIn("android.R.color.system_accent1_200", MAIN)
        self.assertIn("warningSurface", MAIN)
        self.assertIn("developmentSurface", MAIN)
        self.assertIn("secondaryButtonSurface", MAIN)
        self.assertIn("secondaryButtonText", MAIN)
        self.assertIn("secondaryButtonBorder", MAIN)
        self.assertIn("shape(filled ? accent : secondaryButtonSurface", MAIN)
        self.assertNotIn("Color.parseColor(", MAIN)
        self.assertNotRegex(MAIN, r"#[0-9a-fA-F]{6}")
        self.assertIn("catalogSearch.setHintTextColor(muted)", MAIN)
        self.assertIn("field.setHintTextColor(muted)", MAIN)

    def test_local_test_tools_removed_only_from_user_interface(self):
        for wording in ("LOCAL TEST TOOLS", "Create localhost test credential",
                        "Sign using last local test credential"):
            self.assertNotIn(wording, MAIN)

    def test_saf_export_selects_destination_before_collecting_password(self):
        export = MAIN.split("private void startExport()", 1)[1].split(
            "private void startImport()", 1)[0]
        result = MAIN.split("@Override protected void onActivityResult", 1)[1].split(
            "private void endBackupFlow()", 1)[0]
        self.assertIn('setPositiveButton("Choose save location"', export)
        self.assertIn("Intent.ACTION_CREATE_DOCUMENT", export)
        self.assertIn("startActivityForResult(picker, CREATE_BACKUP)", export)
        self.assertNotIn("showPasswordDialog", export)
        self.assertNotIn("exportPassphrase", MAIN)
        self.assertIn("if (requestCode == CREATE_BACKUP)", result)
        self.assertIn("showPasswordDialog(true, passphrase ->", result)
        self.assertIn("authorizeRecoveryOperation(\"Authorize recovery export\"", result)
        self.assertIn("exportRecovery(document, authorized)", result)
        self.assertIn("endBackupFlow()", result)

    def test_invalid_password_keeps_same_dialog_and_secure_buffers_are_wiped(self):
        prompt = MAIN.split("private void showPasswordDialog(", 1)[1].split(
            "private void EditText passwordField", 1)[0] if (
                "private void EditText passwordField" in MAIN) else MAIN.split(
            "private void showPasswordDialog(", 1)[1].split(
                "private EditText passwordField", 1)[0]
        self.assertIn('"Encrypt and save archive"', prompt)
        self.assertIn(".setPositiveButton(exporting ?", prompt)
        self.assertIn("dialog.show()", prompt)
        self.assertIn("dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener", prompt)
        self.assertIn("int minimum = exporting ? 16 : 12", prompt)
        self.assertIn("passphrase.length < minimum", prompt)
        self.assertIn("!Arrays.equals(passphrase, repeated)", prompt)
        self.assertIn("password.setError", prompt)
        self.assertIn("confirmation.setError", prompt)
        self.assertEqual(prompt.count("dialog.dismiss()"), 1)
        self.assertNotIn("showPasswordDialog(exporting,", prompt)
        self.assertIn("Arrays.fill(passphrase, '\\0')", prompt)
        self.assertIn("Arrays.fill(repeated, '\\0')", prompt)
        self.assertIn("field.setSaveEnabled(false)", MAIN)

    def test_restore_copy_distinguishes_recoverable_and_legacy_credentials(self):
        self.assertIn("Restore from backup", MAIN)
        self.assertIn("re-import the original FIDO", MAIN)
        self.assertIn("Older 4.x metadata-only archives", MAIN)
        self.assertIn("legacy device-bound credential", MAIN)
        self.assertIn("cannot be recreated", MAIN)


if __name__ == "__main__":
    unittest.main()
