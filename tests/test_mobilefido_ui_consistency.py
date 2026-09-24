"""Host-only regression tests for the simplified user-facing MobileFIDO UI."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/MainActivity.java").read_text()


class MobileFidoUiConsistencyTests(unittest.TestCase):
    def test_key_status_has_one_typography_role_for_each_live_row(self):
        self.assertIn('card(content, "KEY STATUS", null)', SOURCE)
        self.assertIn('return text(value, 14, muted, false);', SOURCE)
        for row in ("listenerStatus", "notificationStatus", "status"):
            self.assertIn(f'{row} = statusLine(', SOURCE)
        self.assertNotIn('listenerStatus = text(', SOURCE)
        self.assertNotIn('notificationStatus = text(', SOURCE)
        self.assertNotIn('status = text(', SOURCE)

    def test_duplicate_status_and_unnecessary_settings_button_are_hidden(self):
        self.assertIn('if (!binder.status().startsWith("root-only socket ready:"))', SOURCE)
        self.assertIn('showStatus("Local security-key service unavailable.")', SOURCE)
        self.assertIn('notificationSettingsButton.setVisibility(ready ? View.GONE', SOURCE)
        self.assertIn('"○  Waiting for a request from your computer"', SOURCE)
        self.assertNotIn('"●  Local AndroidKeyStore listener ready · USB responder separate"', SOURCE)

    def test_security_critical_approvals_and_recovery_actions_remain_visible(self):
        self.assertIn('BiometricPrompt.CryptoObject(signature)', SOURCE)
        self.assertIn('"Export recovery archive"', SOURCE)
        self.assertIn('"Restore from backup"', SOURCE)
        self.assertIn('"Verify saved backup"', SOURCE)
        self.assertIn('credentialDeleteAction(account, entry.rpId)', SOURCE)
        self.assertIn('"DEVELOPMENT BUILD  ·  Not FIDO-certified"', SOURCE)

    def test_credential_delete_is_compact_trailing_action(self):
        self.assertIn('credentialDeleteAction(account, entry.rpId)', SOURCE)
        self.assertIn('text("×", 25, destructive, false)', SOURCE)
        self.assertIn('row.setOrientation(LinearLayout.HORIZONTAL)', SOURCE)
        self.assertIn('row.setGravity(Gravity.CENTER_VERTICAL)', SOURCE)
        self.assertIn('deleteParams.gravity = Gravity.CENTER_VERTICAL', SOURCE)
        self.assertIn('deleteParams.setMarginStart(dp(12))', SOURCE)
        self.assertNotIn('button("Delete this credential", false)', SOURCE)

    def test_app_owned_dialogs_share_styled_surface_and_actions(self):
        self.assertIn('private LinearLayout dialogContent(', SOURCE)
        self.assertIn('private AlertDialog.Builder styledDialog(', SOURCE)
        self.assertIn('private void styleDialog(AlertDialog dialog, boolean destructiveAction)', SOURCE)
        self.assertIn('dialog.getWindow().setBackgroundDrawable(shape(surface, 26, border))', SOURCE)
        self.assertIn('styleDialog(promptDialog, true)', SOURCE)
        self.assertIn('styleDialog(resultDialog, false)', SOURCE)
        # BiometricPrompt remains Android system UI and should not be replaced
        # with a custom fake biometric dialog.
        self.assertIn('new BiometricPrompt.Builder(this)', SOURCE)

    def test_capability_probe_is_nonblocking_and_does_not_sign(self):
        self.assertIn('diagnosticsExecutor.execute(() -> {', SOURCE)
        self.assertIn('DeviceCapabilities.detect(this)', SOURCE)
        self.assertIn('diagnosticsExecutor.shutdownNow()', SOURCE)
        self.assertIn('"DEVICE SUPPORT"', SOURCE)
        capability_ui = SOURCE.split('private void refreshDeviceSupport()', 1)[1].split(
            'private static void space(', 1)[0]
        self.assertNotIn('prepareRegistration(', capability_ui)
        self.assertNotIn('restoreEncrypted(', capability_ui)
        self.assertNotIn('deleteCredential(', capability_ui)


if __name__ == '__main__':
    unittest.main()
