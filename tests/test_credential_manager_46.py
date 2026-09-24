"""Host-only PocoKey 4.6 manager invariant checks; never touches a phone."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
JAVA = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b"
NATIVE = ROOT / "native-ctaphid/src/backend.rs"


class CredentialManager46Tests(unittest.TestCase):
    def test_delete_is_single_alias_scoped_and_avoids_misleading_partial_success(self):
        source = (JAVA / "CryptoKeyManager.java").read_text()
        method = source.split("synchronized boolean deleteCredential(", 1)[1]
        method = method.split("/** Fail rather than output", 1)[0]
        self.assertIn("encode(decode(credentialId, MIN_CREDENTIAL_ID_BYTES,", method)
        self.assertIn("MAX_CREDENTIAL_ID_BYTES)).equals(credentialId)", method)
        self.assertIn("RelyingPartyPolicy.require(expectedRpId)", method)
        self.assertIn("aliasFor(credentialId, rpId)", method)
        self.assertIn("Hardware alias is referenced elsewhere", method)
        self.assertIn("keyStore.deleteEntry(alias)", method)
        self.assertLess(method.index("keyStore.deleteEntry(alias)"),
                        method.index("metadata.edit()"))
        for field in ("credential.", "user.", "resident.", "accountName.",
                      "accountDisplayName.", "created."):
            self.assertIn('.remove("' + field + '" + credentialId)', method)
        self.assertNotIn('remove("globalSignCount")', method)
        self.assertIn("if (!metadata.edit()", method)
        self.assertIn("catalog update failed", method)

    def test_service_serializes_delete_vs_live_webauthn_operation(self):
        service = (JAVA / "HelperService.java").read_text()
        segment = service.split("public void deleteCredential(", 1)[1]
        segment = segment.split("public static final class Operation", 1)[0]
        self.assertIn("getCallingUid() != Process.myUid()", segment)
        self.assertIn("synchronized (operationLock)", segment)
        self.assertIn("active != null || maintenanceActive || keys == null", segment)
        self.assertIn("keys.deleteCredential(credentialId, rpId)", segment)

    def test_ui_requires_explicit_confirmation_and_strong_biometric(self):
        activity = (JAVA / "MainActivity.java").read_text()
        segment = activity.split("private void confirmCredentialDeletion(", 1)[1]
        segment = segment.split("private void scheduleCatalogRefresh()", 1)[0]
        self.assertIn("Permanently delete this security key?", segment)
        self.assertIn("recovery archive", segment)
        self.assertIn("legacy device-bound credential", segment)
        self.assertIn("BiometricManager.Authenticators.BIOMETRIC_STRONG", segment)
        self.assertIn("onAuthenticationSucceeded", segment)
        self.assertIn("authorizedBinder.deleteCredential", segment)
        self.assertIn("deletionBusy = true", segment)
        self.assertIn("signal.isCanceled()", segment)
        self.assertNotIn("pm clear", activity)

    def test_names_are_non_authorizing_rp_scoped_metadata(self):
        crypto = (JAVA / "CryptoKeyManager.java").read_text()
        service = (JAVA / "HelperService.java").read_text()
        native = NATIVE.read_text()
        for field in ("userName", "displayName", "createdAtMillis"):
            self.assertIn(field, crypto)
        self.assertIn("entry.rpId", crypto)
        self.assertIn("safeAccountLabel", crypto)
        self.assertIn('userName = CryptoKeyManager.safeAccountLabel', service)
        self.assertIn('displayName = CryptoKeyManager.safeAccountLabel', service)
        self.assertIn('"userName": account_name', native)
        self.assertIn('"displayName": display_name', native)
        self.assertIn("value.as_bytes().len() > 128", native)
        self.assertIn('format!("', native)
        self.assertIn("if !discoverable && !allow.iter().any(|id| id == &credential_id)", native)

    def test_version4_encrypted_labels_and_prior_archives_preserved(self):
        backup = (JAVA / "BackupManager.java").read_text()
        for value in ("CTAP3BM4", "CTAPCAT4", "CTAP3BM3", "CTAPCAT3",
                      "CTAP3BM2", "CTAP3BM1", "writeLabel", "readLabel",
                      "entry.createdAtMillis", "Arrays.equals", "cipher.updateAAD"):
            self.assertIn(value, backup)
        self.assertNotIn("getPrivateKey().getEncoded()", backup)


if __name__ == "__main__":
    unittest.main()
