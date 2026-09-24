"""Source-level recovery guards plus JVM functional provider-readback cases.

Never uses ADB, handles user archives, creates/deletes phone keys or prints
passphrases. Functional readback cases are in test_archive_verifier_java.py.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
JAVA = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b"
APP = (JAVA / "MainActivity.java").read_text()
KEYS = (JAVA / "CryptoKeyManager.java").read_text()
ARCHIVE = (JAVA / "RecoverableBackupManager.java").read_text()
VERIFIER = (JAVA / "RecoveryArchiveVerifier.java").read_text()


class RecoveryReliability51Tests(unittest.TestCase):
    def test_verified_export_requires_saved_provider_readback_and_cxf_decrypt(self):
        export = APP.split("private void exportRecovery(", 1)[1].split(
            "private static byte[] readRecoveryDocument(", 1)[0]
        self.assertIn('openOutputStream(document, "wt")', export)
        self.assertIn("output.flush()", export)
        self.assertIn("openInputStream(document)", export)
        self.assertIn("RecoveryArchiveVerifier.verifyReadback(", export)
        self.assertIn("RecoverableBackupManager.verifyEncrypted(exported.blob,", export)
        self.assertIn("keys.markRecoveryArchiveVerified(exported.credentialIds,", export)
        self.assertLess(export.index("output.flush()"),
                        export.index("RecoveryArchiveVerifier.verifyReadback("))
        self.assertLess(export.index("RecoveryArchiveVerifier.verifyReadback("),
                        export.index("RecoverableBackupManager.verifyEncrypted("))
        self.assertLess(export.index("RecoverableBackupManager.verifyEncrypted("),
                        export.index("keys.markRecoveryArchiveVerified("))
        self.assertIn("Arrays.fill(verifyPassword, '\\0')", export)
        self.assertIn("Do not delete credentials", export)
        self.assertNotIn("markRecoveryArchiveWritten", export)

    def test_ciphertext_matches_provider_bytes_and_size_before_success(self):
        self.assertIn('MessageDigest.getInstance("SHA-256")', VERIFIER)
        self.assertIn("MessageDigest.isEqual(expectedHash, readbackHash)", VERIFIER)
        self.assertIn("total != expected.length", VERIFIER)
        self.assertIn('throw new IOException("Archive readback exceeds limit")', VERIFIER)
        self.assertIn('saved.read(buf)', VERIFIER)

    def test_archive_authentication_and_duplicate_credential_checks_are_readonly(self):
        check = ARCHIVE.split("static InspectionResult inspectEncrypted(", 1)[1].split(
            "/** Decrypts authenticated archive", 1)[0]
        self.assertIn("decryptAndValidate(blob, password)", check)
        self.assertIn("keys.inspectRecoveryCoverage(entries)", check)
        self.assertNotIn("restoreRecovery", check)
        self.assertIn("clearRecoveryEntries(entries)", check)
        self.assertIn("Arrays.fill(password, '\\0')", check)
        self.assertIn("Archived credentials differ from export snapshot", ARCHIVE)
        self.assertIn("Incorrect passphrase or damaged archive", ARCHIVE)
        self.assertIn("Duplicate CXF member", ARCHIVE)

    def test_freshness_dates_are_written_only_after_verification(self):
        mark = KEYS.split("synchronized boolean markRecoveryArchiveVerified(", 1)[1].split(
            "private static final class StagedRecoveryImport", 1)[0]
        self.assertIn('!sha256.matches("[0-9a-f]{64}")', mark)
        self.assertIn("metadata.contains(\"escrow.\" + id)", mark)
        self.assertIn('putLong("verifiedBackupAt." + id, verifiedAt)', mark)
        self.assertIn('putLong("lastVerifiedBackupAt", verifiedAt)', mark)
        self.assertIn('putInt("lastVerifiedBackupCount", credentialIds.size())', mark)
        self.assertIn('putString("lastVerifiedBackupSha256", sha256)', mark)
        self.assertIn("if (!edit.commit())", mark)
        self.assertIn("return false", mark)
        self.assertIn('remove("verifiedBackupAt." + credentialId)', KEYS)
        self.assertIn('edit.remove("verifiedBackupAt." + id)', KEYS)
        self.assertIn("entry.verifiedBackupAtMillis <= 0L", KEYS)

    def test_import_journal_cleans_only_unreferenced_new_aliases(self):
        journal = KEYS.split("private void cleanupStagedRecoveryAliases()", 1)[1].split(
            "private void journalRecoveryAlias(", 1)[0]
        self.assertIn('item.getKey().startsWith("credential.")', journal)
        self.assertIn('((String) item.getValue()).startsWith(alias + "|")', journal)
        self.assertIn("if (!committed && keyStore.containsAlias(alias))", journal)
        self.assertIn("if (committed || !keyStore.containsAlias(alias))", journal)
        self.assertIn("cleanupStagedRecoveryAliases();", KEYS)
        restoring = KEYS.split("synchronized RecoveryRestoreResult restoreRecovery(", 1)[1].split(
            "private boolean aliasReferencedByAnotherCredential", 1)[0]
        self.assertIn("journalRecoveryAlias(alias);", restoring)
        self.assertIn("Live key differs from recovery archive", restoring)
        self.assertIn("Imported recovery key verification failed", restoring)
        self.assertIn("if (item.newHardwareAlias) delete(item.alias)", restoring)
        self.assertIn("cleanupStagedRecoveryAliases()", restoring)

    def test_readonly_verification_requires_strong_biometric_and_never_imports(self):
        self.assertIn('button("Verify saved backup", false)', APP)
        self.assertIn('private static final int VERIFY_BACKUP = 783;', APP)
        self.assertIn('authorizeRecoveryOperation("Authorize archive verification",', APP)
        inspect = APP.split("private void verifySavedRecovery(", 1)[1].split(
            "private void restoreRecovery(", 1)[0]
        self.assertIn("RecoverableBackupManager.inspectEncrypted(keys, archive, passphrase)", inspect)
        self.assertIn("Arrays.fill(archive, (byte) 0)", inspect)
        self.assertNotIn("restoreEncrypted", inspect)
        self.assertNotIn("deleteCredential", inspect)
        self.assertIn("no signing keys or credentials were modified".lower(),
                      inspect.lower())
        self.assertIn("coverage.missingFromArchive == 0", inspect)
        self.assertIn("coverage.conflictsOnPhone == 0", inspect)
        self.assertIn("coverage.archivedNotOnPhone == 0", inspect)
        self.assertIn("keys.markRecoveryArchiveVerified(", inspect)
        self.assertIn("RecoveryArchiveVerifier.encryptedFingerprint(", inspect)


if __name__ == "__main__":
    unittest.main()
