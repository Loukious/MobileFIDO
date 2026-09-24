"""MobileFIDO 5 recoverable-passkey invariants; host-only, no phone mutation."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
JAVA = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b"
CRYPTO = (JAVA / "CryptoKeyManager.java").read_text()
RECOVERY = (JAVA / "RecoverableBackupManager.java").read_text()
ACTIVITY = (JAVA / "MainActivity.java").read_text()
HELPER = (JAVA / "HelperService.java").read_text()
BACKEND = (ROOT / "native-ctaphid/src/backend.rs").read_text()


class RecoverablePasskeys50Tests(unittest.TestCase):
    def test_new_credentials_are_imported_into_hardware_with_per_use_biometric(self):
        registration = CRYPTO.split("CreatedKey prepareRegistration(", 1)[1].split(
            "private KeyPair generate(", 1)[0]
        self.assertIn('KeyPairGenerator.getInstance("EC")', registration)
        self.assertIn('new ECGenParameterSpec("secp256r1")', registration)
        self.assertIn("transientPair.getPrivate().getEncoded()", registration)
        self.assertIn("importRecoverable", registration)
        self.assertIn("encryptEscrow", registration)
        self.assertIn("Arrays.fill(pkcs8, (byte) 0)", registration)
        imported = CRYPTO.split("private String importRecoverable(", 1)[1].split(
            "/** Device-local hardware key", 1)[0]
        for required in (
            "KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)",
            "setDigests(KeyProperties.DIGEST_SHA256)",
            "setUserAuthenticationRequired(true)",
            "setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)",
            "setInvalidatedByBiometricEnrollment(true)",
            "setIsStrongBoxBacked(strongBox)",
            "requireHardwareAndPerUseAuth",
        ):
            self.assertIn(required, imported)
        self.assertNotIn("software fallback", registration.lower())

    def test_local_private_key_escrow_is_hardware_wrapped_and_rp_bound(self):
        self.assertIn('RECOVERY_WRAP_ALIAS = "ctap3b-recovery-wrap-v1"', CRYPTO)
        self.assertIn('KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"', CRYPTO)
        self.assertIn("KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT", CRYPTO)
        self.assertIn("setUnlockedDeviceRequired(true)", CRYPTO)
        self.assertIn("SECURITY_LEVEL_STRONGBOX", CRYPTO)
        self.assertIn("SECURITY_LEVEL_TRUSTED_ENVIRONMENT", CRYPTO)
        self.assertIn('Cipher.getInstance("AES/GCM/NoPadding")', CRYPTO)
        self.assertIn('"PocoKeyEscrowV1\\0"', CRYPTO)
        self.assertIn("credentialId", CRYPTO.split("private byte[] escrowAad", 1)[1])
        self.assertIn("rpId", CRYPTO.split("private byte[] escrowAad", 1)[1])

    def test_hardware_wrapped_escrow_uses_keystore_generated_gcm_iv(self):
        encryption = CRYPTO.split("private byte[] encryptEscrow(", 1)[1].split(
            "private byte[] decryptEscrow(", 1)[0]
        decryption = CRYPTO.split("private byte[] decryptEscrow(", 1)[1].split(
            "private void verifyPair(", 1)[0]
        # Android Keystore enforces setRandomizedEncryptionRequired(true),
        # rejecting an explicitly supplied ENCRYPT_MODE nonce with
        # CALLER_NONCE_PROHIBITED on the target StrongBox/TEE device.
        self.assertIn("cipher.init(Cipher.ENCRYPT_MODE, recoveryWrappingKey());", encryption)
        self.assertIn("byte[] nonce = cipher.getIV();", encryption)
        self.assertIn("nonce.length != ESCROW_NONCE_BYTES", encryption)
        self.assertIn(".put(nonce).put(encrypted).array()", encryption)
        self.assertNotIn("random.nextBytes(nonce)", encryption)
        self.assertNotIn("new GCMParameterSpec(128, nonce)", encryption)
        self.assertIn("cipher.init(Cipher.DECRYPT_MODE, recoveryWrappingKey(),", decryption)
        self.assertIn("new GCMParameterSpec(128, nonce)", decryption)

    def test_recoverable_assertions_are_be_and_zero_counter_legacy_unchanged(self):
        method = CRYPTO.split("synchronized byte[] assertionData(", 1)[1].split(
            "ExistingKey prepareAssertion", 1)[0]
        self.assertIn('metadata.getBoolean("recoverable." + credentialId, false)', method)
        self.assertIn("long counter = 0L", method)
        self.assertIn("if (!recoverable)", method)
        self.assertIn("flags |= 0x08", method)  # BE
        self.assertIn("flags |= 0x10", method)  # BS
        self.assertIn("globalSignCount", method)
        self.assertIn("const BE: u8 = 0x08", BACKEND)
        self.assertIn("const BS: u8 = 0x10", BACKEND)
        self.assertIn("backup_eligible && auth[33..37] != [0, 0, 0, 0]", BACKEND)

    def test_archive_plaintext_uses_cxf_passkey_fields_and_pkcs8(self):
        for field in (
            '"version"', '"accounts"', '"items"', '"credentials"',
            '"type", "passkey"', '"credentialId"', '"rpId"', '"username"',
            '"userDisplayName"', '"userHandle"', '"key"',
        ):
            self.assertIn(field, RECOVERY)
        self.assertIn("privateKeyPkcs8", RECOVERY)
        self.assertIn("PKCS#8", RECOVERY)
        self.assertIn("reader.skipValue()", RECOVERY)  # CXF forward compatibility
        self.assertIn("Duplicate CXF member", RECOVERY)
        self.assertIn("RecoveryEntry", RECOVERY)
        self.assertIn("publicFromPrivatePkcs8", RECOVERY)
        self.assertIn("boolean discoverable = true", RECOVERY)
        self.assertIn("if (vendorHintSeen)", RECOVERY)

    def test_standard_cxf_import_does_not_require_pocokey_hint(self):
        parse = RECOVERY.split("private static CryptoKeyManager.RecoveryEntry readPasskey", 1)[1]
        parse = parse.split("private static String uniqueName", 1)[0]
        self.assertNotIn("|| !vendorHintSeen", parse)
        self.assertIn("CryptoKeyManager.publicFromPrivatePkcs8(pkcs8)", parse)
        self.assertIn("boolean discoverable = true", parse)
        self.assertIn("CXF public key hint mismatch", parse)
        self.assertIn("Noncanonical CXF base64url", RECOVERY)
        self.assertIn("MAX_CREDENTIAL_ID_BYTES = 1023", CRYPTO)
        self.assertIn('item.put("id", b64url(itemId(entry.credentialId)))', RECOVERY)
        self.assertIn("CXF passkey uses unsupported FIDO2 extensions", RECOVERY)

    def test_recovery_maintenance_serializes_with_live_ctap(self):
        self.assertIn("private boolean maintenanceActive", HELPER)
        begin = HELPER.split("public boolean beginRecoveryMaintenance()", 1)[1].split(
            "public void endRecoveryMaintenance", 1)[0] if (
                "public boolean beginRecoveryMaintenance()" in HELPER) else HELPER.split(
            "public long beginRecoveryMaintenance()", 1)[1].split(
                "public void endRecoveryMaintenance", 1)[0]
        self.assertIn("active != null || maintenanceActive || keys == null", begin)
        prepare = HELPER.split("private Operation prepare(JSONObject request)", 1)[1]
        self.assertIn("if (active != null || maintenanceActive) return null", prepare)
        deletion = HELPER.split("public void deleteCredential(", 1)[1].split(
            "public boolean beginRecoveryMaintenance", 1)[0]
        self.assertIn("active != null || maintenanceActive || keys == null", deletion)
        flow = ACTIVITY.split("private void authorizeRecoveryOperation(", 1)[1].split(
            "private void exportRecovery", 1)[0]
        self.assertIn("beginRecoveryMaintenance()", flow)
        self.assertIn("maintenanceToken == 0L", flow)
        end = ACTIVITY.split("private void endBackupFlow()", 1)[1].split(
            "private void authorizeRecoveryOperation", 1)[0]
        self.assertIn("owner.endRecoveryMaintenance(token)", end)
        self.assertIn("token != 0L", end)
        self.assertIn("token == maintenanceToken", HELPER)

    def test_legacy_12_character_backup_password_remains_importable(self):
        dialog = ACTIVITY.split("private void showPasswordDialog(", 1)[1].split(
            "private EditText passwordField", 1)[0]
        self.assertIn("int minimum = exporting ? 16 : 12", dialog)
        self.assertIn("legacy 4.x metadata archives may use", dialog)
        self.assertIn('"Archive contains passkey recovery material", 16, passphrase', ACTIVITY)
        self.assertIn('"Recovered keys will be imported into StrongBox/TEE", 12, passphrase', ACTIVITY)

    def test_static_archive_is_password_encrypted_bounded_and_authenticated(self):
        self.assertIn('"MFRCV001"', RECOVERY)
        self.assertIn('"PKRCV001"', RECOVERY)  # pre-rename archives stay importable
        self.assertRegex(RECOVERY, r"ITERATIONS\s*=\s*600_000")
        self.assertIn("PBKDF2WithHmacSHA256", RECOVERY)
        self.assertIn("AES/GCM/NoPadding", RECOVERY)
        self.assertIn("cipher.updateAAD(header)", RECOVERY)
        self.assertIn("cipher.updateAAD(blob, 0, HEADER_BYTES)", RECOVERY)
        self.assertIn("password.length < 16", RECOVERY)
        self.assertIn("MAX_BLOB = 512 * 1024", RECOVERY)
        self.assertIn("Arrays.fill(password, '\\0')", RECOVERY)
        self.assertIn("clearRecoveryEntries", RECOVERY)

    def test_delete_removes_live_key_and_local_escrow_but_archive_can_restore(self):
        delete = CRYPTO.split("synchronized boolean deleteCredential(", 1)[1].split(
            "synchronized boolean isRecoverable", 1)[0]
        self.assertIn("keyStore.deleteEntry(alias)", delete)
        self.assertIn('.remove("escrow." + credentialId)', delete)
        restore = CRYPTO.split("synchronized RecoveryRestoreResult restoreRecovery(", 1)[1].split(
            "private void validateRecoveryEntry", 1)[0]
        self.assertIn("generatePrivate(new PKCS8EncodedKeySpec", restore)
        self.assertIn("importRecoverable", restore)
        self.assertIn("Live key differs from recovery archive", restore)
        self.assertIn("Imported recovery key verification failed", restore)
        self.assertIn('putBoolean("backedUp." + id, true)', restore)
        self.assertIn("if (item.newHardwareAlias) delete(item.alias)", restore)
        self.assertIn("Never destroy an already-working key", restore)

    def test_export_and_import_require_explicit_strong_biometric(self):
        flow = ACTIVITY.split("private void authorizeRecoveryOperation(", 1)[1].split(
            "private void exportRecovery", 1)[0]
        self.assertIn("BIOMETRIC_STRONG", flow)
        self.assertIn("BiometricPrompt.Builder", flow)
        self.assertIn("onAuthenticationSucceeded", flow)
        self.assertIn("onAuthenticationError", flow)
        self.assertIn("Arrays.fill(passphrase, '\\0')", flow)
        self.assertIn("RecoverableBackupManager.exportEncrypted", ACTIVITY)
        self.assertIn("RecoverableBackupManager.restoreEncrypted", ACTIVITY)
        self.assertIn("BackupManager.restoreEncrypted", ACTIVITY)  # old archives remain importable

    def test_ui_does_not_promise_legacy_recovery(self):
        self.assertIn("Device-bound legacy · Not recoverable", ACTIVITY)
        self.assertIn("Recoverable · Backup needed", ACTIVITY)
        self.assertIn("Recoverable · Verified archive", ACTIVITY)
        self.assertIn("Legacy 4.x keys are excluded", ACTIVITY)
        self.assertIn("cannot be converted after the fact", ACTIVITY)


if __name__ == "__main__":
    unittest.main()
