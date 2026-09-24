package org.pocof7.ctap3b;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProtection;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Credential signing keys are always used through AndroidKeyStore. Legacy
 * credentials are generated nonexportable inside StrongBox/TEE. MobileFIDO 5
 * recoverable credentials are generated transiently, imported into secure
 * hardware with identical per-use BIOMETRIC_STRONG policy, then the PKCS#8
 * recovery copy is encrypted under a device-local hardware wrapping key.
 */
final class CryptoKeyManager {
    private static final String LOG_TAG = "Ctap3bHelper";
    static final String RP_ID = RelyingPartyPolicy.LEGACY_RP;
    static final byte[] AAGUID = "PocoF7-BIO-DEV01".getBytes(StandardCharsets.US_ASCII);
    private static final String RECOVERY_WRAP_ALIAS = "ctap3b-recovery-wrap-v1";
    private static final byte ESCROW_VERSION = 1;
    private static final int ESCROW_NONCE_BYTES = 12;
    private static final int ESCROW_TAG_BYTES = 16;
    static final int MIN_CREDENTIAL_ID_BYTES = 16;
    static final int MAX_CREDENTIAL_ID_BYTES = 1023;
    private final Context context;
    private final SharedPreferences metadata;
    private final KeyStore keyStore;
    private final SecureRandom random = new SecureRandom();

    static final class CreatedKey {
        final String alias;
        final String credentialId;
        final String rpId;
        final byte[] cosePublicKey;
        final byte[] x;
        final byte[] y;
        final String securityLevel;
        final Signature signature;
        final byte[] userId;
        final boolean discoverable;
        final String userName;
        final String displayName;
        final long createdAtMillis;
        final boolean recoverable;
        final boolean backedUp;
        final byte[] encryptedEscrow;

        CreatedKey(String alias, String credentialId, String rpId, byte[] cose,
                   byte[] x, byte[] y, String level, Signature signature, byte[] userId,
                   boolean discoverable, String userName, String displayName,
                   long createdAtMillis, boolean recoverable, boolean backedUp,
                   byte[] encryptedEscrow) {
            this.alias = alias;
            this.credentialId = credentialId;
            this.rpId = RelyingPartyPolicy.require(rpId);
            this.cosePublicKey = cose;
            this.x = x;
            this.y = y;
            this.securityLevel = level;
            this.signature = signature;
            this.userId = userId.clone();
            this.discoverable = discoverable;
            this.userName = userName;
            this.displayName = displayName;
            this.createdAtMillis = createdAtMillis;
            this.recoverable = recoverable;
            this.backedUp = backedUp;
            this.encryptedEscrow = encryptedEscrow == null ? null : encryptedEscrow.clone();
        }
    }

    static final class ExistingKey {
        final String credentialId;
        final String alias;
        final String securityLevel;
        final Signature signature;

        ExistingKey(String id, String alias, String level, Signature signature) {
            this.credentialId = id;
            this.alias = alias;
            this.securityLevel = level;
            this.signature = signature;
        }
    }

    /** UI-safe metadata. An unavailable entry does NOT imply its private key is recoverable. */
    static final class CredentialInfo {
        final String credentialId;
        final String rpId;
        final String securityLevel;
        final boolean available;
        final boolean discoverable;
        final String userName;
        final String displayName;
        final long createdAtMillis;
        final boolean recoverable;
        final boolean backedUp;
        final boolean recoveryMaterialAvailable;
        final long verifiedBackupAtMillis;

        CredentialInfo(String id, String rpId, String level, boolean available,
                       boolean discoverable, String userName, String displayName,
                       long createdAtMillis, boolean recoverable, boolean backedUp,
                       boolean recoveryMaterialAvailable, long verifiedBackupAtMillis) {
            this.credentialId = id;
            this.rpId = rpId;
            this.securityLevel = level;
            this.available = available;
            this.discoverable = discoverable;
            this.userName = userName;
            this.displayName = displayName;
            this.createdAtMillis = createdAtMillis;
            this.recoverable = recoverable;
            this.backedUp = backedUp;
            this.recoveryMaterialAvailable = recoveryMaterialAvailable;
            this.verifiedBackupAtMillis = verifiedBackupAtMillis;
        }
    }

    /** Local status only: no password, private key, RP ID or archive path. */
    static final class BackupStatus {
        final long lastVerifiedAtMillis;
        final int lastVerifiedCount;
        final int recoverableCount;
        final int needVerifiedBackup;
        final int legacyCount;

        BackupStatus(long at, int count, int recoverable, int pending, int legacy) {
            lastVerifiedAtMillis = at;
            lastVerifiedCount = count;
            recoverableCount = recoverable;
            needVerifiedBackup = pending;
            legacyCount = legacy;
        }
    }

    static final class ArchiveCoverage {
        final int matchingOnPhone;
        final int missingFromArchive;
        final int conflictsOnPhone;
        final int archivedNotOnPhone;

        ArchiveCoverage(int matching, int missing, int conflicts, int others) {
            matchingOnPhone = matching;
            missingFromArchive = missing;
            conflictsOnPhone = conflicts;
            archivedNotOnPhone = others;
        }
    }

    /** Decrypted only transiently while creating/restoring a recovery archive. */
    static final class RecoveryEntry {
        final byte[] credentialId;
        final String rpId;
        final byte[] userId;
        final String userName;
        final String displayName;
        final boolean discoverable;
        final long createdAtMillis;
        final byte[] publicX;
        final byte[] publicY;
        final byte[] privateKeyPkcs8;

        RecoveryEntry(byte[] credentialId, String rpId, byte[] userId,
                      String userName, String displayName, boolean discoverable,
                      long createdAtMillis, byte[] publicX, byte[] publicY,
                      byte[] privateKeyPkcs8) {
            this.credentialId = credentialId.clone();
            this.rpId = RelyingPartyPolicy.require(rpId);
            this.userId = userId.clone();
            this.userName = safeAccountLabel(userName);
            this.displayName = safeAccountLabel(displayName);
            this.discoverable = discoverable;
            this.createdAtMillis = createdAtMillis;
            this.publicX = publicX.clone();
            this.publicY = publicY.clone();
            this.privateKeyPkcs8 = privateKeyPkcs8.clone();
        }

        void clearPrivate() {
            Arrays.fill(privateKeyPkcs8, (byte) 0);
        }
    }

    static final class RecoverySnapshot {
        final List<RecoveryEntry> entries;
        final int legacySkipped;
        final byte[] accountId;

        RecoverySnapshot(List<RecoveryEntry> entries, int legacySkipped, byte[] accountId) {
            this.entries = entries;
            this.legacySkipped = legacySkipped;
            this.accountId = accountId.clone();
        }
    }

    static final class RecoveryRestoreResult {
        final int restored;
        final int alreadyPresent;

        RecoveryRestoreResult(int restored, int alreadyPresent) {
            this.restored = restored;
            this.alreadyPresent = alreadyPresent;
        }
    }

    /** Catalog metadata only: NO private key, signing object or exportable key material. */
    static final class BackupEntry {
        final byte[] credentialId;
        final String rpId;
        final String alias;
        final byte[] userId;
        final byte[] publicX;
        final byte[] publicY;
        final String securityLevel;
        final boolean discoverable;
        final String userName;
        final String displayName;
        final long createdAtMillis;

        BackupEntry(byte[] id, String rpId, String alias, byte[] user,
                    byte[] x, byte[] y, String level) {
            this(id, rpId, alias, user, x, y, level, false);
        }

        BackupEntry(byte[] id, String rpId, String alias, byte[] user,
                    byte[] x, byte[] y, String level, boolean discoverable) {
            this(id, rpId, alias, user, x, y, level, discoverable, null, null, 0L);
        }

        BackupEntry(byte[] id, String rpId, String alias, byte[] user,
                    byte[] x, byte[] y, String level, boolean discoverable,
                    String userName, String displayName, long createdAtMillis) {
            this.credentialId = id.clone();
            this.rpId = RelyingPartyPolicy.require(rpId);
            this.alias = alias;
            this.userId = user.clone();
            this.publicX = x.clone();
            this.publicY = y.clone();
            this.securityLevel = level;
            this.discoverable = discoverable;
            this.userName = safeAccountLabel(userName);
            this.displayName = safeAccountLabel(displayName);
            if (createdAtMillis < 0) throw new IllegalArgumentException("Invalid creation date");
            this.createdAtMillis = createdAtMillis;
        }
    }

    static final class BackupCatalog {
        final List<BackupEntry> entries;
        final long counter;

        BackupCatalog(List<BackupEntry> entries, long counter) {
            this.entries = entries;
            this.counter = counter;
        }
    }

    private static final class LiveKey {
        final byte[] x;
        final byte[] y;
        final String level;

        LiveKey(byte[] x, byte[] y, String level) {
            this.x = x;
            this.y = y;
            this.level = level;
        }
    }

    CryptoKeyManager(Context context) throws Exception {
        this.context = context.getApplicationContext();
        this.metadata = this.context.getSharedPreferences("ctap3b-credentials", Context.MODE_PRIVATE);
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        cleanupStagedRecoveryAliases();
    }

    /**
     * A process can die between hardware import and catalog commit. These
     * candidate aliases were journaled BEFORE import. Never delete any alias
     * referenced by a committed credential; unreferenced candidates can be
     * retried safely on the next service start, even after a power loss.
     */
    private void cleanupStagedRecoveryAliases() {
        for (String key : metadata.getAll().keySet()) {
            if (!key.startsWith("stagedRecoveryAlias.")) continue;
            String alias = key.substring("stagedRecoveryAlias.".length());
            if (!alias.matches("ctap3b-[0-9a-fA-F-]{36}")) {
                Log.w(LOG_TAG, "Invalid staged recovery journal entry ignored");
                continue;
            }
            boolean committed = false;
            for (Map.Entry<String, ?> item : metadata.getAll().entrySet()) {
                if (item.getKey().startsWith("credential.")
                    && item.getValue() instanceof String
                    && ((String) item.getValue()).startsWith(alias + "|")) {
                    committed = true;
                    break;
                }
            }
            try {
                if (!committed && keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias);
                }
                if (committed || !keyStore.containsAlias(alias)) {
                    if (!metadata.edit().remove(key).commit()) {
                        Log.w(LOG_TAG, "Recovery alias cleanup journal could not be persisted");
                    }
                }
            } catch (Exception unavailable) {
                Log.w(LOG_TAG, "Recovery alias cleanup deferred (" +
                    safeExceptionClasses(unavailable) + ")");
            }
        }
    }

    private void journalRecoveryAlias(String alias) {
        if (alias == null || !alias.matches("ctap3b-[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Invalid staged recovery alias");
        }
        if (!metadata.edit().putBoolean("stagedRecoveryAlias." + alias, true).commit()) {
            throw new IllegalStateException("Recovery alias journal could not be persisted");
        }
    }

    static byte[] decode(String text, int min, int max) {
        if (text == null || text.length() > ((max + 2) / 3) * 4 + 8) {
            throw new IllegalArgumentException("invalid base64 length");
        }
        byte[] result = Base64.decode(text, Base64.NO_WRAP);
        if (result.length < min || result.length > max) {
            throw new IllegalArgumentException("invalid decoded length");
        }
        return result;
    }

    static String encode(byte[] data) {
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    /**
     * Diagnostics deliberately reveal only Java exception class names. Never
     * log Throwable.toString(), getMessage(), stack traces, aliases or keys:
     * some provider exceptions include keystore operation IDs in messages.
     */
    static String safeExceptionClasses(Throwable failure) {
        Throwable root = failure;
        int depth = 0;
        while (root.getCause() != null && root.getCause() != root && depth++ < 16) {
            root = root.getCause();
        }
        return failure.getClass().getSimpleName() + " / root " +
            root.getClass().getSimpleName();
    }

    /**
     * Only a KeyPolicyFailure produced from KeyInfo may add diagnostic
     * details. Never display arbitrary provider exception messages.
     */
    static String safeDiagnostic(Throwable failure) {
        String classes = safeExceptionClasses(failure);
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth++ < 16) {
            if (current instanceof KeyPolicyFailure) {
                return classes + "\n" + ((KeyPolicyFailure) current).diagnostic;
            }
            if (current.getCause() == current) break;
            current = current.getCause();
        }
        return classes;
    }

    static final class KeyPolicyFailure extends InvalidKeySpecException {
        private static final long serialVersionUID = 1L;
        final String diagnostic;

        KeyPolicyFailure(String diagnostic) {
            // The message consists entirely of nonsecret KeyInfo values.
            super("AndroidKeyStore KeyInfo policy rejected");
            this.diagnostic = diagnostic;
        }
    }

    static byte[] rpHash(String rpId) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(RelyingPartyPolicy.require(rpId).getBytes(StandardCharsets.UTF_8));
    }

    /** Generate StrongBox first, then TEE only if StrongBox is unavailable. */
    CreatedKey prepareRegistration(String rpId, byte[] userId) throws Exception {
        return prepareRegistration(rpId, userId, false);
    }

    CreatedKey prepareRegistration(String rpId, byte[] userId,
                                   boolean discoverable) throws Exception {
        return prepareRegistration(rpId, userId, discoverable, null, null);
    }

    /** Account labels are untrusted RP-supplied UI metadata, never identity or auth policy. */
    static String safeAccountLabel(String label) {
        if (label == null || label.trim().isEmpty()) return null;
        if (label.getBytes(StandardCharsets.UTF_8).length > 128) {
            throw new IllegalArgumentException("Account label too long");
        }
        for (int i = 0; i < label.length();) {
            int codepoint = label.codePointAt(i);
            if (Character.isISOControl(codepoint)
                || codepoint == 0x061c || codepoint == 0x200e || codepoint == 0x200f
                || (codepoint >= 0x202a && codepoint <= 0x202e)
                || (codepoint >= 0x2066 && codepoint <= 0x2069)
                || (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
                throw new IllegalArgumentException("Account label contains controls");
            }
            i += Character.charCount(codepoint);
        }
        return label.trim();
    }

    CreatedKey prepareRegistration(String rpId, byte[] userId,
                                   boolean discoverable, String userName,
                                   String displayName) throws Exception {
        RelyingPartyPolicy.require(rpId);
        if (userId == null || userId.length < 1 || userId.length > 64) {
            throw new IllegalArgumentException("userId must be 1..64 bytes");
        }
        String safeName = safeAccountLabel(userName);
        String safeDisplay = safeAccountLabel(displayName);
        byte[] credentialId = new byte[32];
        random.nextBytes(credentialId);
        String encodedId = encode(credentialId);
        String alias = "ctap3b-" + UUID.randomUUID();
        KeyPairGenerator softwareGenerator = KeyPairGenerator.getInstance("EC");
        softwareGenerator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair transientPair = softwareGenerator.generateKeyPair();
        byte[] pkcs8 = transientPair.getPrivate().getEncoded();
        if (pkcs8 == null || pkcs8.length < 64 || pkcs8.length > 512) {
            throw new IllegalStateException("Software provider did not expose bounded PKCS#8");
        }
        byte[] escrow = null;
        try {
            Certificate certificate = selfSignedCertificate(transientPair);
            String level;
            try {
                journalRecoveryAlias(alias);
                level = importRecoverable(alias, transientPair.getPrivate(), certificate, true);
            } catch (Exception strongBoxFailure) {
                Log.w(LOG_TAG, "StrongBox import failed (" +
                    safeExceptionClasses(strongBoxFailure) + "); trying TEE");
                if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias);
                alias = "ctap3b-" + UUID.randomUUID();
                journalRecoveryAlias(alias);
                level = importRecoverable(alias, transientPair.getPrivate(), certificate, false);
            }
            escrow = encryptEscrow(encodedId, rpId, pkcs8);
            KeyStore.Entry imported = keyStore.getEntry(alias, null);
            if (!(imported instanceof KeyStore.PrivateKeyEntry)) {
                throw new IllegalStateException("Imported recovery key unavailable");
            }
            PrivateKey hardwarePrivate = ((KeyStore.PrivateKeyEntry) imported).getPrivateKey();
            ECPublicKey publicKey = (ECPublicKey) keyStore.getCertificate(alias).getPublicKey();
            verifyPair(pkcs8, publicKey, encodedId, rpId);
            byte[] cose = coseEs256(publicKey);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(hardwarePrivate);
            CreatedKey created = new CreatedKey(alias, encodedId, rpId, cose,
                coordinate(publicKey.getW().getAffineX()),
                coordinate(publicKey.getW().getAffineY()),
                level, signature, userId, discoverable, safeName, safeDisplay,
                System.currentTimeMillis(), true, false, escrow);
            // CreatedKey owns a defensive copy. Do not leave another encrypted
            // recovery blob reachable from this registration stack frame.
            Arrays.fill(escrow, (byte) 0);
            escrow = null;
            return created;
        } catch (Exception failure) {
            keyStore.deleteEntry(alias);
            if (escrow != null) Arrays.fill(escrow, (byte) 0);
            throw failure;
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
            Arrays.fill(credentialId, (byte) 0);
        }
    }

    private KeyPair generate(String alias, boolean strongBox) throws Exception {
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(spec.build());
        return generator.generateKeyPair();
    }

    private String importRecoverable(String alias, PrivateKey privateKey,
                                     Certificate certificate, boolean strongBox)
            throws Exception {
        KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .build();
        keyStore.setEntry(alias,
            new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {certificate}),
            protection);
        KeyStore.Entry imported = keyStore.getEntry(alias, null);
        if (!(imported instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalStateException("Imported key pair unavailable");
        }
        return requireHardwareAndPerUseAuth(
            ((KeyStore.PrivateKeyEntry) imported).getPrivateKey());
    }

    /** Device-local hardware key protects the recoverable PKCS#8 escrow at rest. */
    private SecretKey recoveryWrappingKey() throws Exception {
        KeyStore.Entry existing = keyStore.getEntry(RECOVERY_WRAP_ALIAS, null);
        if (existing instanceof KeyStore.SecretKeyEntry) {
            SecretKey key = ((KeyStore.SecretKeyEntry) existing).getSecretKey();
            requireHardwareWrapKey(key);
            return key;
        }
        if (existing != null) {
            throw new IllegalStateException("Recovery wrapping alias has unexpected type");
        }
        try {
            return generateRecoveryWrappingKey(true);
        } catch (Exception strongBoxFailure) {
            Log.w(LOG_TAG, "StrongBox recovery-wrap generation failed (" +
                safeExceptionClasses(strongBoxFailure) + "); trying TEE");
            if (keyStore.containsAlias(RECOVERY_WRAP_ALIAS)) {
                keyStore.deleteEntry(RECOVERY_WRAP_ALIAS);
            }
            return generateRecoveryWrappingKey(false);
        }
    }

    private SecretKey generateRecoveryWrappingKey(boolean strongBox) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            RECOVERY_WRAP_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            // Local escrow exists only to let an already-unlocked owner make
            // a recovery archive later. Do not make it usable in Direct Boot
            // or while the device is locked; export itself additionally
            // requires an explicit foreground BIOMETRIC_STRONG confirmation.
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build();
        generator.init(spec);
        SecretKey key = generator.generateKey();
        requireHardwareWrapKey(key);
        return key;
    }

    private void requireHardwareWrapKey(SecretKey key) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(
            key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        int level = info.getSecurityLevel();
        boolean hardware = level == KeyProperties.SECURITY_LEVEL_STRONGBOX
            || level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
        int required = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        if (!hardware || (info.getPurposes() & required) != required) {
            throw new KeyPolicyFailure("Recovery wrap key not hardware ENCRYPT|DECRYPT");
        }
    }

    private byte[] escrowAad(String credentialId, String rpId) {
        // Legacy cryptographic domain separator. Keep byte-for-byte stable so
        // recovery escrow written by pre-MobileFIDO development builds remains
        // decryptable after the user-facing rename.
        byte[] prefix = "PocoKeyEscrowV1\0".getBytes(StandardCharsets.US_ASCII);
        byte[] id = credentialId.getBytes(StandardCharsets.US_ASCII);
        byte[] rp = RelyingPartyPolicy.require(rpId).getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(prefix.length + id.length + 1 + rp.length)
            .put(prefix)
            .put(id).put((byte) 0).put(rp).array();
    }

    private byte[] encryptEscrow(String credentialId, String rpId, byte[] pkcs8)
            throws Exception {
        if (pkcs8 == null || pkcs8.length < 64 || pkcs8.length > 512) {
            throw new IllegalArgumentException("Invalid recoverable PKCS#8 size");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // AndroidKeyStore's hardware wrapping key has
        // setRandomizedEncryptionRequired(true): caller-provided encryption
        // nonces are forbidden (KeyMint CALLER_NONCE_PROHIBITED). Let Keystore
        // generate its own fresh GCM IV and store THAT IV alongside the
        // ciphertext. Decryption must still pass the archived IV explicitly.
        cipher.init(Cipher.ENCRYPT_MODE, recoveryWrappingKey());
        byte[] nonce = cipher.getIV();
        if (nonce == null || nonce.length != ESCROW_NONCE_BYTES) {
            throw new IllegalStateException("AndroidKeyStore returned invalid recovery IV");
        }
        byte[] aad = escrowAad(credentialId, rpId);
        byte[] encrypted = null;
        try {
            cipher.updateAAD(aad);
            encrypted = cipher.doFinal(pkcs8);
            return ByteBuffer.allocate(2 + nonce.length + encrypted.length)
                .put(ESCROW_VERSION).put((byte) nonce.length)
                .put(nonce).put(encrypted).array();
        } finally {
            Arrays.fill(aad, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
        }
    }

    private byte[] decryptEscrow(String credentialId, String rpId, byte[] escrow)
            throws Exception {
        if (escrow == null || escrow.length < 2 + ESCROW_NONCE_BYTES + ESCROW_TAG_BYTES + 64
            || escrow.length > 2 + ESCROW_NONCE_BYTES + ESCROW_TAG_BYTES + 512) {
            throw new IllegalArgumentException("Invalid local recovery escrow");
        }
        ByteBuffer input = ByteBuffer.wrap(escrow);
        if (input.get() != ESCROW_VERSION) {
            throw new IllegalArgumentException("Unsupported local recovery escrow");
        }
        int nonceLength = Byte.toUnsignedInt(input.get());
        if (nonceLength != ESCROW_NONCE_BYTES || input.remaining() <= nonceLength + ESCROW_TAG_BYTES) {
            throw new IllegalArgumentException("Invalid local recovery escrow framing");
        }
        byte[] nonce = new byte[nonceLength];
        input.get(nonce);
        byte[] encrypted = new byte[input.remaining()];
        input.get(encrypted);
        byte[] aad = escrowAad(credentialId, rpId);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, recoveryWrappingKey(),
                new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            byte[] pkcs8 = cipher.doFinal(encrypted);
            if (pkcs8.length < 64 || pkcs8.length > 512) {
                Arrays.fill(pkcs8, (byte) 0);
                throw new IllegalArgumentException("Invalid recovered PKCS#8 size");
            }
            return pkcs8;
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(aad, (byte) 0);
        }
    }

    private void verifyPair(byte[] pkcs8, ECPublicKey publicKey,
                            String credentialId, String rpId) throws Exception {
        PrivateKey privateKey = KeyFactory.getInstance("EC")
            .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        byte[] challenge = java.security.MessageDigest.getInstance("SHA-256")
            // Legacy verification-domain string is deliberately stable across
            // the MobileFIDO rename; it is not user-visible branding.
            .digest(("PocoKeyPairV1\0" + credentialId + "\0" + rpId)
                .getBytes(StandardCharsets.US_ASCII));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(challenge);
        byte[] proof = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(challenge);
        boolean valid = verifier.verify(proof);
        Arrays.fill(challenge, (byte) 0);
        Arrays.fill(proof, (byte) 0);
        if (!valid) throw new IllegalArgumentException("Recovery key/public point mismatch");
    }

    private static Certificate selfSignedCertificate(KeyPair pair) throws Exception {
        byte[] algorithm = derSequence(derOid(new byte[] {
            0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02
        })); // ecdsa-with-SHA256 1.2.840.10045.4.3.2
        byte[] version = derExplicit(0, derInteger(BigInteger.valueOf(2)));
        byte[] serial = new byte[8];
        new SecureRandom().nextBytes(serial);
        serial[0] &= 0x7F;
        if (serial[0] == 0) serial[0] = 1;
        byte[] serialDer = derInteger(new BigInteger(1, serial));
        // X.509 permits a minimal self-signed leaf for KeyStore import, but
        // mainstream CertificateFactory implementations reject an empty DN.
        // Use a fixed non-identifying CN; this certificate is local metadata,
        // never FIDO attestation and never sent to a relying party.
        byte[] name = derSequence(derSet(derSequence(
            derOid(new byte[] {0x55, 0x04, 0x03}), // commonName 2.5.4.3
            derUtf8("MobileFIDO Imported Credential"))));
        byte[] validity = derSequence(
            derUtcTime("240101000000Z"), derUtcTime("491231235959Z"));
        byte[] tbs = derSequence(version, serialDer, algorithm, name, validity,
            name, pair.getPublic().getEncoded());
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(tbs);
        byte[] signature = signer.sign();
        byte[] certificateDer = derSequence(tbs, algorithm, derBitString(signature));
        Arrays.fill(signature, (byte) 0);
        Certificate certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certificateDer));
        Arrays.fill(certificateDer, (byte) 0);
        return certificate;
    }

    private static byte[] derSequence(byte[]... parts) throws IOException {
        return derConstructed(0x30, parts);
    }

    private static byte[] derSet(byte[]... parts) throws IOException {
        return derConstructed(0x31, parts);
    }

    private static byte[] derExplicit(int tag, byte[] value) throws IOException {
        return derConstructed(0xA0 | (tag & 0x1F), value);
    }

    private static byte[] derConstructed(int tag, byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] part : parts) body.write(part);
        return derTlv(tag, body.toByteArray());
    }

    private static byte[] derInteger(BigInteger value) throws IOException {
        if (value.signum() < 0) throw new IllegalArgumentException("negative DER integer");
        return derTlv(0x02, value.toByteArray());
    }

    private static byte[] derOid(byte[] encodedOid) throws IOException {
        return derTlv(0x06, encodedOid);
    }

    private static byte[] derUtcTime(String value) throws IOException {
        return derTlv(0x17, value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derUtf8(String value) throws IOException {
        return derTlv(0x0C, value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] derBitString(byte[] value) throws IOException {
        byte[] contents = new byte[value.length + 1];
        System.arraycopy(value, 0, contents, 1, value.length);
        return derTlv(0x03, contents);
    }

    private static byte[] derTlv(int tag, byte[] value) throws IOException {
        if (value.length > 65535) throw new IllegalArgumentException("DER object too large");
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 5);
        out.write(tag);
        if (value.length < 128) {
            out.write(value.length);
        } else if (value.length <= 255) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write((value.length >>> 8) & 0xff);
            out.write(value.length & 0xff);
        }
        out.write(value);
        return out.toByteArray();
    }

    String requireHardwareAndPerUseAuth(PrivateKey privateKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("EC", "AndroidKeyStore");
        KeyInfo info = factory.getKeySpec(privateKey, KeyInfo.class);
        int level = info.getSecurityLevel();
        String name;
        if (level == KeyProperties.SECURITY_LEVEL_STRONGBOX) {
            name = "STRONGBOX";
        } else if (level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
            name = "TEE";
        } else if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
            name = "SOFTWARE";
        } else if (level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE) {
            name = "UNKNOWN_SECURE";
        } else if (level == KeyProperties.SECURITY_LEVEL_UNKNOWN) {
            name = "UNKNOWN";
        } else {
            name = "UNRECOGNIZED";
        }

        // Read each KeyInfo property before evaluating anything. A single
        // boolean expression previously hid which Android 17/OEM property
        // differed; UNKNOWN_SECURE must remain distinct from confirmed TEE.
        boolean supportedLevel = level == KeyProperties.SECURITY_LEVEL_STRONGBOX
            || level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
        boolean authRequired = info.isUserAuthenticationRequired();
        int authDuration = info.getUserAuthenticationValidityDurationSeconds();
        boolean biometricAllowed = (info.getUserAuthenticationType()
            & KeyProperties.AUTH_BIOMETRIC_STRONG) != 0;
        boolean hardwareEnforcedAuth =
            info.isUserAuthenticationRequirementEnforcedBySecureHardware();
        // Android's current setUserAuthenticationParameters(0,
        // AUTH_BIOMETRIC_STRONG) specifies authentication for EVERY operation.
        // On this Poco F7 / Android 17, KeyInfo reports that back as 0.
        // The legacy KeyInfo API documentation also describes -1 as the
        // every-use sentinel. Accept ONLY these two representations, never a
        // positive time window, and require hardware-enforced biometric auth
        // plus the actual BiometricPrompt.CryptoObject for each signature.
        boolean perUse = authDuration == 0 || authDuration == -1;

        if (!supportedLevel || !authRequired || !perUse
            || !biometricAllowed || !hardwareEnforcedAuth) {
            String failed = "";
            if (!supportedLevel) failed += "securityLevel,";
            if (!authRequired) failed += "authRequired,";
            if (!perUse) failed += "authDuration,";
            if (!biometricAllowed) failed += "biometricAllowed,";
            if (!hardwareEnforcedAuth) failed += "hardwareEnforcedAuth,";
            String diagnostic =
                "KeyInfo level=" + level + "/" + name +
                " authRequired=" + authRequired +
                " authDuration=" + authDuration +
                " biometricAllowed=" + biometricAllowed +
                " hardwareEnforcedAuth=" + hardwareEnforcedAuth +
                "\nFAILED=" + failed.substring(0, failed.length() - 1);
            // These are policy booleans and Android security-level metadata
            // only. Do not log the alias, key object, RP or clientDataHash.
            Log.w(LOG_TAG, "KeyInfo rejected: " + diagnostic);
            throw new KeyPolicyFailure(diagnostic);
        }
        return name;
    }

    /** Called only after the biometric CryptoObject operation succeeds. */
    synchronized boolean commitRegistration(CreatedKey key) {
        if (key == null || !RelyingPartyPolicy.valid(key.rpId)
            || metadata.contains("credential." + key.credentialId)
            || metadata.contains("user." + key.credentialId)) {
            // Even a theoretically possible random ID collision must never
            // overwrite another RP's live credential or its user metadata.
            // Credential ID collisions must not orphan the NEW hardware key,
            // and must NEVER delete the original key behind the old ID.
            if (key != null) delete(key.alias);
            cleanupStagedRecoveryAliases();
            return false;
        }
        int total = 0;
        for (String preference : metadata.getAll().keySet()) {
            if (preference.startsWith("credential.")) total++;
        }
        if (total >= BackupManager.MAX_CREDENTIALS) {
            discardUncommitted(key);
            return false;
        }
        SharedPreferences.Editor edit = metadata.edit()
            .putString("credential." + key.credentialId, key.alias + "|" + key.rpId)
            .putString("user." + key.credentialId, encode(key.userId))
            .putBoolean("resident." + key.credentialId, key.discoverable)
            .putLong("created." + key.credentialId, key.createdAtMillis)
            .putBoolean("recoverable." + key.credentialId, key.recoverable)
            .putBoolean("backedUp." + key.credentialId, key.backedUp);
        if (key.recoverable) {
            if (key.encryptedEscrow == null || key.encryptedEscrow.length == 0) {
                discardUncommitted(key);
                return false;
            }
            edit.putString("escrow." + key.credentialId, encode(key.encryptedEscrow));
        }
        if (key.userName != null) edit.putString("accountName." + key.credentialId, key.userName);
        if (key.displayName != null) {
            edit.putString("accountDisplayName." + key.credentialId, key.displayName);
        }
        boolean saved = edit.commit();
        if (!saved) delete(key.alias);
        cleanupStagedRecoveryAliases();
        if (key.encryptedEscrow != null) Arrays.fill(key.encryptedEscrow, (byte) 0);
        return saved;
    }

    synchronized boolean hasCredential(String credentialId, String rpId) {
        if (!RelyingPartyPolicy.valid(rpId)) return false;
        try {
            return (aliasFor(credentialId, rpId) != null);
        } catch (IllegalArgumentException unknown) {
            return false;
        }
    }

    /** An omitted CTAP allowList may select ONLY explicitly discoverable keys.
     * Pre-4.5 registrations are non-discoverable by default. All candidates
     * must be live, RP-bound and hardware-policy verified before prompting.
     */
    synchronized List<CredentialInfo> discoverableForRp(String rpId) {
        RelyingPartyPolicy.require(rpId);
        List<CredentialInfo> result = new ArrayList<>();
        for (CredentialInfo info : listCredentials()) {
            if (info.available && info.discoverable && rpId.equals(info.rpId)) {
                result.add(info);
            }
        }
        return result;
    }

    synchronized byte[] userForDiscoverable(String id, String rpId) {
        if (!metadata.getBoolean("resident." + id, false)
            || aliasFor(id, rpId) == null) {
            throw new IllegalArgumentException("Not a discoverable credential for this RP");
        }
        return decode(metadata.getString("user." + id, null), 1, 64);
    }

    /** Existing entries are never guessed from a keystore alias alone. */
    synchronized List<CredentialInfo> listCredentials() {
        List<String> ids = new ArrayList<>();
        for (String name : metadata.getAll().keySet()) {
            if (name.startsWith("credential.")) ids.add(name.substring("credential.".length()));
        }
        Collections.sort(ids);
        List<CredentialInfo> result = new ArrayList<>();
        for (String id : ids) {
            String level = "UNAVAILABLE";
            boolean available = false;
            try {
                if (!encode(decode(id, MIN_CREDENTIAL_ID_BYTES,
                        MAX_CREDENTIAL_ID_BYTES)).equals(id)) {
                    throw new IllegalArgumentException("invalid credential ID");
                }
                String rpId = rpFor(id);
                String alias = aliasFor(id, rpId);
                byte[] user = decode(metadata.getString("user." + id, null), 1, 64);
                LiveKey live = inspectLiveKey(alias);
                available = live != null && user.length > 0;
                if (available) level = live.level;
            } catch (Exception ignored) {
                // A deleted, invalidated or software-backed hardware alias
                // stays visible as unavailable, never silently re-created.
            }
            String rpId;
            try { rpId = rpFor(id); }
            catch (IllegalArgumentException malformed) { rpId = "UNKNOWN"; }
            String accountName = null, accountDisplayName = null;
            long created = 0L;
            try {
                accountName = safeAccountLabel(metadata.getString("accountName." + id, null));
                accountDisplayName = safeAccountLabel(
                    metadata.getString("accountDisplayName." + id, null));
                created = metadata.getLong("created." + id, 0L);
                if (created < 0 || created > System.currentTimeMillis() + 86_400_000L) {
                    created = 0L;
                }
            } catch (Exception ignored) { // Malformed optional label never makes a key usable.
                accountName = null;
                accountDisplayName = null;
                created = 0L;
            }
            boolean recoverable = metadata.getBoolean("recoverable." + id, false);
            boolean backedUp = recoverable && metadata.getBoolean("backedUp." + id, false);
            boolean recoveryMaterialAvailable = recoverable
                && metadata.contains("escrow." + id);
            long verifiedAt = recoverable
                ? metadata.getLong("verifiedBackupAt." + id, 0L) : 0L;
            result.add(new CredentialInfo(id, rpId, level, available,
                metadata.getBoolean("resident." + id, false), accountName,
                accountDisplayName, created, recoverable, backedUp,
                recoveryMaterialAvailable, verifiedAt));
        }
        return result;
    }

    synchronized BackupStatus backupStatus(List<CredentialInfo> credentials) {
        int recoverable = 0, notVerified = 0, legacy = 0;
        for (CredentialInfo entry : credentials) {
            if (!entry.recoverable) {
                legacy++;
                continue;
            }
            recoverable++;
            if (entry.verifiedBackupAtMillis <= 0L) notVerified++;
        }
        return new BackupStatus(metadata.getLong("lastVerifiedBackupAt", 0L),
            metadata.getInt("lastVerifiedBackupCount", 0), recoverable,
            notVerified, legacy);
    }

    /** READ-ONLY coverage check: never imports, signs or replaces a key. */
    synchronized ArchiveCoverage inspectRecoveryCoverage(List<RecoveryEntry> entries)
            throws Exception {
        Set<String> archived = new HashSet<>();
        int matching = 0, conflicts = 0, other = 0, missing = 0;
        for (RecoveryEntry entry : entries) {
            validateRecoveryEntry(entry);
            String id = encode(entry.credentialId);
            if (!archived.add(id)) throw new IllegalArgumentException("Duplicate archive credential");
            String record = metadata.getString("credential." + id, null);
            if (record == null) {
                other++;
                continue;
            }
            if (!metadata.getBoolean("recoverable." + id, false)) {
                conflicts++;
                continue;
            }
            try {
                if (!entry.rpId.equals(rpFor(id))
                    || !encode(entry.userId).equals(metadata.getString("user." + id, null))) {
                    conflicts++;
                    continue;
                }
                LiveKey live = inspectLiveKey(aliasFor(id, entry.rpId));
                if (live == null || !Arrays.equals(live.x, entry.publicX)
                    || !Arrays.equals(live.y, entry.publicY)) {
                    conflicts++;
                    continue;
                }
                matching++;
            } catch (Exception invalidLocal) {
                conflicts++;
            }
        }
        for (CredentialInfo entry : listCredentials()) {
            if (entry.recoverable && !archived.contains(entry.credentialId)) missing++;
        }
        return new ArchiveCoverage(matching, missing, conflicts, other);
    }

    /**
     * Irreversible, individually scoped credential deletion. Caller MUST get
     * explicit foreground user confirmation and strong biometric approval.
     * Never delete a key that might back another metadata entry. Delete the
     * AndroidKeyStore alias BEFORE the metadata commit so an I/O failure or
     * process death can leave an unavailable entry, but never a falsely
     * successful delete with a still-live signing alias. A subsequent retry
     * can remove the unavailable record. Sign counter remains untouched.
     */
    synchronized boolean deleteCredential(String credentialId, String expectedRpId)
            throws Exception {
        if (!encode(decode(credentialId, MIN_CREDENTIAL_ID_BYTES,
                MAX_CREDENTIAL_ID_BYTES)).equals(credentialId)) {
            throw new IllegalArgumentException("Noncanonical credential ID");
        }
        String rpId = RelyingPartyPolicy.require(expectedRpId);
        String alias = aliasFor(credentialId, rpId);
        String record = alias + "|" + rpId;
        if (!record.equals(metadata.getString("credential." + credentialId, null))) {
            throw new IllegalArgumentException("Credential mapping changed");
        }
        for (Map.Entry<String, ?> entry : metadata.getAll().entrySet()) {
            if (entry.getKey().startsWith("credential.")
                && !entry.getKey().equals("credential." + credentialId)
                && entry.getValue() instanceof String) {
                String value = (String) entry.getValue();
                if (value.startsWith(alias + "|")) {
                    throw new IllegalStateException("Hardware alias is referenced elsewhere");
                }
            }
        }
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
            if (keyStore.containsAlias(alias)) {
                throw new IllegalStateException("Keystore alias deletion was not confirmed");
            }
        }
        if (!metadata.edit()
            .remove("credential." + credentialId)
            .remove("user." + credentialId)
            .remove("resident." + credentialId)
            .remove("accountName." + credentialId)
            .remove("accountDisplayName." + credentialId)
            .remove("created." + credentialId)
            .remove("recoverable." + credentialId)
            .remove("backedUp." + credentialId)
            .remove("verifiedBackupAt." + credentialId)
            .remove("escrow." + credentialId)
            .commit()) {
            throw new IllegalStateException(
                "Hardware alias deleted but catalog update failed; retry to remove stale entry");
        }
        return true;
    }

    synchronized boolean isRecoverable(String credentialId) {
        try {
            if (!encode(decode(credentialId, MIN_CREDENTIAL_ID_BYTES,
                    MAX_CREDENTIAL_ID_BYTES)).equals(credentialId)) return false;
            return metadata.getBoolean("recoverable." + credentialId, false);
        } catch (Exception invalid) {
            return false;
        }
    }

    synchronized boolean isBackedUp(String credentialId) {
        return isRecoverable(credentialId)
            && metadata.getBoolean("backedUp." + credentialId, false);
    }

    /**
     * Export only MobileFIDO 5 recoverable credentials. Legacy 4.x credentials
     * used a nonexportable private key and cannot be made portable after the
     * fact. Any missing escrow aborts the entire snapshot rather than silently
     * producing a partial recovery archive.
     */
    synchronized RecoverySnapshot snapshotRecovery() throws Exception {
        List<RecoveryEntry> entries = new ArrayList<>();
        int legacySkipped = 0;
        try {
            for (CredentialInfo info : listCredentials()) {
                if (!info.recoverable) {
                    legacySkipped++;
                    continue;
                }
                if (!info.available || !info.recoveryMaterialAvailable) {
                    throw new IllegalStateException(
                        "Recoverable credential is missing hardware or escrow state");
                }
                String id = info.credentialId;
                String rpId = rpFor(id);
                String alias = aliasFor(id, rpId);
                LiveKey live = inspectLiveKey(alias);
                if (live == null) {
                    throw new IllegalStateException("Recoverable hardware key unavailable");
                }
                byte[] user = decode(metadata.getString("user." + id, null), 1, 64);
                byte[] escrow = decode(metadata.getString("escrow." + id, null),
                    2 + ESCROW_NONCE_BYTES + ESCROW_TAG_BYTES + 64,
                    2 + ESCROW_NONCE_BYTES + ESCROW_TAG_BYTES + 512);
                byte[] pkcs8 = decryptEscrow(id, rpId, escrow);
                Arrays.fill(escrow, (byte) 0);
                try {
                    ECPublicKey publicKey = (ECPublicKey) keyStore.getCertificate(alias)
                        .getPublicKey();
                    verifyPair(pkcs8, publicKey, id, rpId);
                    entries.add(new RecoveryEntry(decode(id, MIN_CREDENTIAL_ID_BYTES,
                        MAX_CREDENTIAL_ID_BYTES), rpId, user,
                        info.userName, info.displayName, info.discoverable,
                        info.createdAtMillis, live.x, live.y, pkcs8));
                } finally {
                    Arrays.fill(user, (byte) 0);
                    Arrays.fill(pkcs8, (byte) 0);
                }
                if (entries.size() > BackupManager.MAX_CREDENTIALS) {
                    throw new IllegalStateException("Recovery archive credential limit exceeded");
                }
            }
            if (entries.isEmpty()) {
                throw new IllegalStateException("No recoverable MobileFIDO 5 credentials exist");
            }
            return new RecoverySnapshot(entries, legacySkipped, recoveryProviderAccountId());
        } catch (Exception failure) {
            clearRecoveryEntries(entries);
            throw failure;
        }
    }

    private byte[] recoveryProviderAccountId() {
        String encoded = metadata.getString("recoveryAccountId", null);
        if (encoded != null) {
            try { return decode(encoded, 16, 16); }
            catch (IllegalArgumentException ignored) {
                throw new IllegalStateException("Invalid recovery account identifier");
            }
        }
        byte[] account = new byte[16];
        random.nextBytes(account);
        if (!metadata.edit().putString("recoveryAccountId", encode(account)).commit()) {
            Arrays.fill(account, (byte) 0);
            throw new IllegalStateException("Cannot persist recovery account identifier");
        }
        return account;
    }

    static void clearRecoveryEntries(List<RecoveryEntry> entries) {
        if (entries == null) return;
        for (RecoveryEntry entry : entries) {
            if (entry == null) continue;
            Arrays.fill(entry.credentialId, (byte) 0);
            Arrays.fill(entry.userId, (byte) 0);
            Arrays.fill(entry.publicX, (byte) 0);
            Arrays.fill(entry.publicY, (byte) 0);
            entry.clearPrivate();
        }
    }

    /** Only after SAF byte-for-byte readback AND authenticated CXF verification. */
    synchronized boolean markRecoveryArchiveVerified(List<String> credentialIds,
                                                      String sha256, long verifiedAt) {
        if (credentialIds == null || credentialIds.isEmpty()
            || sha256 == null || !sha256.matches("[0-9a-f]{64}")
            || verifiedAt <= 0L || verifiedAt > System.currentTimeMillis() + 86_400_000L) {
            return false;
        }
        SharedPreferences.Editor edit = metadata.edit();
        Set<String> distinct = new HashSet<>();
        for (String id : credentialIds) {
            if (!distinct.add(id) || !isRecoverable(id)
                || !metadata.contains("escrow." + id)) {
                // Conservative BS semantics: if state changed during export,
                // leave all flags unchanged rather than claiming backup.
                return false;
            }
        }
        for (String id : credentialIds) {
            edit.putBoolean("backedUp." + id, true)
                .putLong("verifiedBackupAt." + id, verifiedAt);
        }
        edit.putLong("lastVerifiedBackupAt", verifiedAt)
            .putInt("lastVerifiedBackupCount", credentialIds.size())
            .putString("lastVerifiedBackupSha256", sha256);
        if (!edit.commit()) {
            Log.w(LOG_TAG, "Verified recovery archive but freshness status was not persisted");
            return false;
        }
        return true;
    }

    private static final class StagedRecoveryImport {
        final RecoveryEntry entry;
        final String alias;
        final String securityLevel;
        final byte[] escrow;
        final String replacedAlias;
        final boolean newHardwareAlias;

        StagedRecoveryImport(RecoveryEntry entry, String alias, String securityLevel,
                             byte[] escrow, String replacedAlias,
                             boolean newHardwareAlias) {
            this.entry = entry;
            this.alias = alias;
            this.securityLevel = securityLevel;
            this.escrow = escrow;
            this.replacedAlias = replacedAlias;
            this.newHardwareAlias = newHardwareAlias;
        }
    }

    /**
     * Import CXF recovery entries as fresh StrongBox/TEE aliases. This is the
     * operation that makes factory-reset/new-device recovery possible. The
     * private scalar is transient in the app process only for validation and
     * KeyStore import; afterwards only encrypted escrow + hardware key remain.
     */
    synchronized RecoveryRestoreResult restoreRecovery(List<RecoveryEntry> entries)
            throws Exception {
        if (entries == null || entries.isEmpty()
            || entries.size() > BackupManager.MAX_CREDENTIALS) {
            throw new IllegalArgumentException("Invalid recoverable credential set");
        }
        Set<String> ids = new HashSet<>();
        List<StagedRecoveryImport> staged = new ArrayList<>();
        int already = 0;
        try {
            for (RecoveryEntry entry : entries) {
                validateRecoveryEntry(entry);
                String id = encode(entry.credentialId);
                if (!ids.add(id)) throw new IllegalArgumentException("Duplicate credential ID");
                ECPublicKey archivedPublic = publicFromCoordinates(entry.publicX, entry.publicY);
                verifyPair(entry.privateKeyPkcs8, archivedPublic, id, entry.rpId);

                String storedRecord = metadata.getString("credential." + id, null);
                String replacedAlias = null;
                if (storedRecord != null) {
                    if (!metadata.getBoolean("recoverable." + id, false)
                        || !entry.rpId.equals(rpFor(id))
                        || !encode(entry.userId).equals(metadata.getString("user." + id, null))) {
                        throw new IllegalStateException("Local credential conflicts with archive");
                    }
                    replacedAlias = aliasFor(id, entry.rpId);
                    LiveKey live = inspectLiveKey(replacedAlias);
                    if (live != null) {
                        if (!Arrays.equals(live.x, entry.publicX)
                            || !Arrays.equals(live.y, entry.publicY)) {
                            throw new IllegalStateException("Live key differs from recovery archive");
                        }
                        // Re-wrap recovery material on THIS device even if an
                        // escrow field already exists. This repairs a damaged
                        // local escrow after import and binds it to the current
                        // hardware wrapping key, while keeping the live signing
                        // alias untouched.
                        byte[] escrow = encryptEscrow(id, entry.rpId,
                            entry.privateKeyPkcs8);
                        staged.add(new StagedRecoveryImport(
                            entry, replacedAlias, live.level, escrow, null, false));
                        already++;
                        continue;
                    }
                }

                PrivateKey privateKey = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(entry.privateKeyPkcs8));
                PublicKey publicKey = archivedPublic;
                Certificate certificate = selfSignedCertificate(new KeyPair(publicKey, privateKey));
                String alias = "ctap3b-" + UUID.randomUUID();
                String level;
                try {
                    journalRecoveryAlias(alias);
                    level = importRecoverable(alias, privateKey, certificate, true);
                } catch (Exception strongBoxFailure) {
                    if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias);
                    alias = "ctap3b-" + UUID.randomUUID();
                    journalRecoveryAlias(alias);
                    level = importRecoverable(alias, privateKey, certificate, false);
                }
                LiveKey imported = inspectLiveKey(alias);
                if (imported == null || !Arrays.equals(imported.x, entry.publicX)
                    || !Arrays.equals(imported.y, entry.publicY)) {
                    delete(alias);
                    throw new IllegalStateException("Imported recovery key verification failed");
                }
                byte[] escrow = encryptEscrow(id, entry.rpId, entry.privateKeyPkcs8);
                staged.add(new StagedRecoveryImport(
                    entry, alias, level, escrow, replacedAlias, true));
            }

            // Validate every stale alias before committing the catalog switch.
            // After commit, recovery must not discover a new reason to fail or
            // we could leave metadata pointing at a cleanup-deleted new key.
            for (StagedRecoveryImport item : staged) {
                if (item.replacedAlias != null && !item.replacedAlias.equals(item.alias)
                    && aliasReferencedByAnotherCredential(item.replacedAlias,
                        encode(item.entry.credentialId))) {
                    throw new IllegalStateException(
                        "Stale alias is referenced by another credential");
                }
            }

            SharedPreferences.Editor edit = metadata.edit();
            for (StagedRecoveryImport item : staged) {
                RecoveryEntry entry = item.entry;
                String id = encode(entry.credentialId);
                edit.putString("credential." + id, item.alias + "|" + entry.rpId)
                    .putString("user." + id, encode(entry.userId))
                    .putBoolean("resident." + id, entry.discoverable)
                    .putBoolean("recoverable." + id, true)
                    .putBoolean("backedUp." + id, true)
                    .putString("escrow." + id, encode(item.escrow));
                if (item.newHardwareAlias) edit.remove("verifiedBackupAt." + id);
                if (entry.createdAtMillis > 0) {
                    edit.putLong("created." + id, entry.createdAtMillis);
                } else {
                    edit.remove("created." + id);
                }
                if (entry.userName != null) edit.putString("accountName." + id, entry.userName);
                else edit.remove("accountName." + id);
                if (entry.displayName != null) {
                    edit.putString("accountDisplayName." + id, entry.displayName);
                } else {
                    edit.remove("accountDisplayName." + id);
                }
            }
            if (!edit.commit()) {
                throw new IllegalStateException("Could not commit recovered credentials");
            }
            for (StagedRecoveryImport item : staged) {
                if (item.replacedAlias != null && !item.replacedAlias.equals(item.alias)) {
                    delete(item.replacedAlias);
                }
                Arrays.fill(item.escrow, (byte) 0);
            }
            int restored = 0;
            for (StagedRecoveryImport item : staged) {
                if (item.newHardwareAlias) restored++;
            }
            return new RecoveryRestoreResult(restored, already);
        } catch (Exception failure) {
            for (StagedRecoveryImport item : staged) {
                // Never destroy an already-working key merely because adding
                // recovery escrow metadata failed to commit.
                if (item.newHardwareAlias) delete(item.alias);
                Arrays.fill(item.escrow, (byte) 0);
            }
            throw failure;
        } finally {
            cleanupStagedRecoveryAliases();
        }
    }

    private boolean aliasReferencedByAnotherCredential(String alias, String credentialId) {
        if (!validAlias(alias)) return true;
        for (Map.Entry<String, ?> local : metadata.getAll().entrySet()) {
            if (!local.getKey().startsWith("credential.")
                || local.getKey().equals("credential." + credentialId)
                || !(local.getValue() instanceof String)) continue;
            if (((String) local.getValue()).startsWith(alias + "|")) return true;
        }
        return false;
    }

    private void validateRecoveryEntry(RecoveryEntry entry) {
        if (entry == null
            || entry.credentialId.length < MIN_CREDENTIAL_ID_BYTES
            || entry.credentialId.length > MAX_CREDENTIAL_ID_BYTES
            || entry.userId.length < 1 || entry.userId.length > 64
            || entry.publicX.length != 32 || entry.publicY.length != 32
            || entry.privateKeyPkcs8.length < 64 || entry.privateKeyPkcs8.length > 512
            || !RelyingPartyPolicy.valid(entry.rpId)
            || entry.createdAtMillis < 0 || entry.createdAtMillis > 253402300799000L) {
            throw new IllegalArgumentException("Invalid recoverable credential");
        }
    }

    private static ECPublicKey publicFromCoordinates(byte[] x, byte[] y) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicSpec = new ECPublicKeySpec(
            new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), spec);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(publicSpec);
    }

    /**
     * Derive the P-256 public point from a CXF PKCS#8 private key. CXF carries
     * the private key but does not duplicate its public coordinates, so this
     * lets MobileFIDO import a standards-only Passkey dictionary rather than
     * depending on a proprietary field. BigInteger arithmetic is used only
     * on transient recovery material that is already present in app memory;
     * normal authentication remains entirely inside AndroidKeyStore.
     */
    static ECPublicKey publicFromPrivatePkcs8(byte[] pkcs8) throws Exception {
        if (pkcs8 == null || pkcs8.length < 64 || pkcs8.length > 512) {
            throw new IllegalArgumentException("Invalid P-256 PKCS#8 size");
        }
        PrivateKey privateKey = KeyFactory.getInstance("EC")
            .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("CXF passkey is not an EC private key");
        }
        ECPrivateKey ec = (ECPrivateKey) privateKey;
        ECParameterSpec actual = ec.getParams();
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
        if (actual == null || !sameEcParameters(actual, expected)) {
            throw new IllegalArgumentException("Only ES256 P-256 CXF passkeys are supported");
        }
        BigInteger scalar = ec.getS();
        if (scalar == null || scalar.signum() <= 0
            || scalar.compareTo(expected.getOrder()) >= 0) {
            throw new IllegalArgumentException("Invalid P-256 private scalar");
        }
        ECPoint point = multiplyPoint(expected.getGenerator(), scalar, expected.getCurve());
        if (point == null) throw new IllegalArgumentException("Invalid P-256 derived point");
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
            new ECPublicKeySpec(point, expected));
    }

    private static boolean sameEcParameters(ECParameterSpec a, ECParameterSpec b) {
        return a.getCurve().equals(b.getCurve())
            && a.getGenerator().equals(b.getGenerator())
            && a.getOrder().equals(b.getOrder())
            && a.getCofactor() == b.getCofactor();
    }

    /** Affine double-and-add for the fixed P-256 generator. null = infinity. */
    private static ECPoint multiplyPoint(ECPoint base, BigInteger scalar,
                                         EllipticCurve curve) {
        if (!(curve.getField() instanceof ECFieldFp)) {
            throw new IllegalArgumentException("Expected prime-field P-256 curve");
        }
        BigInteger prime = ((ECFieldFp) curve.getField()).getP();
        ECPoint result = null;
        ECPoint addend = base;
        for (int bit = 0; bit < scalar.bitLength(); bit++) {
            if (scalar.testBit(bit)) result = addPoints(result, addend, curve, prime);
            addend = addPoints(addend, addend, curve, prime);
        }
        return result;
    }

    private static ECPoint addPoints(ECPoint left, ECPoint right,
                                     EllipticCurve curve, BigInteger prime) {
        if (left == null) return right;
        if (right == null) return left;
        BigInteger x1 = left.getAffineX().mod(prime);
        BigInteger y1 = left.getAffineY().mod(prime);
        BigInteger x2 = right.getAffineX().mod(prime);
        BigInteger y2 = right.getAffineY().mod(prime);
        BigInteger slope;
        if (x1.equals(x2)) {
            if (y1.add(y2).mod(prime).signum() == 0) return null;
            BigInteger numerator = x1.multiply(x1).multiply(BigInteger.valueOf(3))
                .add(curve.getA()).mod(prime);
            BigInteger denominator = y1.shiftLeft(1).mod(prime);
            if (denominator.signum() == 0) return null;
            slope = numerator.multiply(denominator.modInverse(prime)).mod(prime);
        } else {
            BigInteger numerator = y2.subtract(y1).mod(prime);
            BigInteger denominator = x2.subtract(x1).mod(prime);
            slope = numerator.multiply(denominator.modInverse(prime)).mod(prime);
        }
        BigInteger x3 = slope.multiply(slope).subtract(x1).subtract(x2).mod(prime);
        BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(prime);
        return new ECPoint(x3, y3);
    }

    /** Fail rather than output a misleading incomplete backup for missing hardware keys. */
    synchronized BackupCatalog snapshotBackup() throws Exception {
        List<BackupEntry> entries = new ArrayList<>();
        Set<String> seenAliases = new HashSet<>();
        try {
            for (CredentialInfo info : listCredentials()) {
                if (!info.available) {
                    throw new IllegalStateException("An unavailable hardware credential prevents a complete catalog backup");
                }
                String id = info.credentialId;
                String rpId = rpFor(id);
                String alias = aliasFor(id, rpId);
                if (!seenAliases.add(alias)) {
                    throw new IllegalStateException("Multiple credentials reference the same hardware alias");
                }
                LiveKey live = inspectLiveKey(alias);
                if (live == null) throw new IllegalStateException("Hardware credential became unavailable");
                byte[] user = decode(metadata.getString("user." + id, null), 1, 64);
                entries.add(new BackupEntry(decode(id, 32, 32), rpId, alias, user,
                    live.x, live.y, live.level,
                    metadata.getBoolean("resident." + id, false),
                    info.userName, info.displayName, info.createdAtMillis));
                Arrays.fill(user, (byte) 0);
                if (entries.size() > BackupManager.MAX_CREDENTIALS) {
                    throw new IllegalStateException("Credential catalog exceeds backup limit");
                }
            }
            if (entries.isEmpty()) {
                throw new IllegalStateException("No hardware credentials available to back up");
            }
            long count = metadata.getLong("globalSignCount", 0L);
            if (count < 0 || count > 0xFFFFFFFFL) {
                throw new IllegalStateException("Invalid signature counter");
            }
            return new BackupCatalog(entries, count);
        } catch (Exception failed) {
            for (BackupEntry item : entries) {
                Arrays.fill(item.credentialId, (byte) 0);
                Arrays.fill(item.userId, (byte) 0);
                Arrays.fill(item.publicX, (byte) 0);
                Arrays.fill(item.publicY, (byte) 0);
            }
            throw failed;
        }
    }

    /**
     * Imported metadata is useful ONLY while the ORIGINAL nonexportable
     * AndroidKeyStore alias still exists with the EXACT public point and
     * per-use hardware biometric policy. Never generate or delete a key here.
     * Changes and counter advance are committed in one SharedPreferences edit.
     */
    synchronized int[] restoreBackupCatalog(List<BackupEntry> entries, long backupCounter)
            throws Exception {
        if (entries == null || entries.size() > BackupManager.MAX_CREDENTIALS
            || backupCounter < 0 || backupCounter > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Invalid backup catalog");
        }
        Set<String> existingAliases = new HashSet<>();
        for (String preference : metadata.getAll().keySet()) {
            if (!preference.startsWith("credential.")) continue;
            String record = metadata.getString(preference, null);
            if (record != null && record.indexOf('|') > 0) {
                // Reserve aliases referenced even by malformed or foreign-RP
                // local mappings: importing must never bind one key twice.
                String owned = record.substring(0, record.indexOf('|'));
                if (validAlias(owned)) existingAliases.add(owned);
            }
        }
        Set<String> importedAliases = new HashSet<>();
        Set<String> importedIds = new HashSet<>();
        SharedPreferences.Editor edit = metadata.edit();
        int restored = 0, already = 0, unavailable = 0;
        for (BackupEntry entry : entries) {
            if (entry == null || entry.credentialId.length != 32
                || entry.userId.length < 1 || entry.userId.length > 64
                || entry.publicX.length != 32 || entry.publicY.length != 32
                || !validAlias(entry.alias) || !RelyingPartyPolicy.valid(entry.rpId)
                || !("TEE".equals(entry.securityLevel)
                    || "STRONGBOX".equals(entry.securityLevel))) {
                throw new IllegalArgumentException("Invalid backup entry");
            }
            String id = encode(entry.credentialId);
            if (!importedIds.add(id) || !importedAliases.add(entry.alias)) {
                throw new IllegalArgumentException("Duplicate backup identity");
            }
            String storedRecord = metadata.getString("credential." + id, null);
            boolean hasUserRecord = metadata.contains("user." + id);
            String storedUser = metadata.getString("user." + id, null);
            String expectedRecord = entry.alias + "|" + entry.rpId;
            String expectedUser = encode(entry.userId);
            if ((storedRecord != null || hasUserRecord)
                && (!expectedRecord.equals(storedRecord)
                    || !expectedUser.equals(storedUser)
                    || metadata.getBoolean("resident." + id, false)
                        != entry.discoverable)) {
                unavailable++; // Conflicting local state: NEVER overwrite it.
                continue;
            }
            // Even when metadata was deleted, an alias already assigned to
            // another credential must not be rebound to this credential ID.
            if (storedRecord == null && existingAliases.contains(entry.alias)) {
                unavailable++;
                continue;
            }
            LiveKey live = inspectLiveKey(entry.alias);
            if (live == null || !live.level.equals(entry.securityLevel)
                || !Arrays.equals(live.x, entry.publicX)
                || !Arrays.equals(live.y, entry.publicY)) {
                unavailable++;
                continue;
            }
            if (storedRecord != null) {
                already++;
            } else {
                edit.putString("credential." + id, expectedRecord);
                edit.putString("user." + id, expectedUser);
                edit.putBoolean("resident." + id, entry.discoverable);
                if (entry.userName != null) {
                    edit.putString("accountName." + id, entry.userName);
                }
                if (entry.displayName != null) {
                    edit.putString("accountDisplayName." + id, entry.displayName);
                }
                if (entry.createdAtMillis > 0) {
                    edit.putLong("created." + id, entry.createdAtMillis);
                }
                restored++;
                existingAliases.add(entry.alias);
            }
        }
        // Do not accept a backup's global count on a different device with
        // zero verifiably matching hardware aliases. Never DECREASE it.
        if (restored + already > 0) {
            long existing = metadata.getLong("globalSignCount", 0L);
            if (existing < 0 || existing > 0xFFFFFFFFL) {
                throw new IllegalStateException("Invalid existing signature counter");
            }
            if (backupCounter > existing) {
                edit.putLong("globalSignCount", backupCounter);
            }
        }
        if (!edit.commit()) throw new IllegalStateException("Could not commit restored metadata");
        return new int[] {restored, already, unavailable};
    }

    private String rpFor(String credentialId) {
        String record = metadata.getString("credential." + credentialId, null);
        if (record == null || record.indexOf('|') != record.lastIndexOf('|')
            || record.indexOf('|') < 1) {
            throw new IllegalArgumentException("Invalid local credential metadata");
        }
        String rpId = record.substring(record.indexOf('|') + 1);
        return RelyingPartyPolicy.require(rpId);
    }

    private String aliasFor(String credentialId, String rpId) {
        RelyingPartyPolicy.require(rpId);
        String record = metadata.getString("credential." + credentialId, null);
        if (record == null || record.indexOf('|') != record.lastIndexOf('|')
            || !record.endsWith("|" + rpId)) {
            throw new IllegalArgumentException("Credential unknown for requested RP");
        }
        String alias = record.substring(0, record.indexOf('|'));
        if (!validAlias(alias)) throw new IllegalArgumentException("Invalid alias");
        return alias;
    }

    static boolean validAlias(String alias) {
        if (alias == null || !alias.startsWith("ctap3b-")) return false;
        try {
            return UUID.fromString(alias.substring(7)).toString()
                .equals(alias.substring(7));
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    /** Inspect public certificate + hardware policy without signing or prompting. */
    private LiveKey inspectLiveKey(String alias) {
        if (!validAlias(alias)) return null;
        try {
            KeyStore.Entry entry = keyStore.getEntry(alias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) return null;
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            String level = requireHardwareAndPerUseAuth(privateKey);
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            if (cert == null || !(cert.getPublicKey() instanceof ECPublicKey)) return null;
            ECPublicKey point = (ECPublicKey) cert.getPublicKey();
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec expected = params.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec actual = point.getParams();
            if (actual == null
                || !expected.getCurve().equals(actual.getCurve())
                || !expected.getGenerator().equals(actual.getGenerator())
                || !expected.getOrder().equals(actual.getOrder())
                || expected.getCofactor() != actual.getCofactor()) return null;
            return new LiveKey(coordinate(point.getW().getAffineX()),
                coordinate(point.getW().getAffineY()), level);
        } catch (Exception unavailable) {
            return null;
        }
    }

    ExistingKey prepareAssertion(String credentialId, String rpId) throws Exception {
        decode(credentialId, MIN_CREDENTIAL_ID_BYTES, MAX_CREDENTIAL_ID_BYTES);
        String alias = aliasFor(credentialId, rpId);
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalArgumentException("private key missing or invalidated");
        }
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        String level = requireHardwareAndPerUseAuth(privateKey);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        return new ExistingKey(credentialId, alias, level, signature);
    }

    synchronized byte[] assertionData(String credentialId, String rpId, boolean requireUp)
            throws Exception {
        // Recheck exact RP binding before deriving credential-specific backup flags.
        aliasFor(credentialId, rpId);
        boolean recoverable = metadata.getBoolean("recoverable." + credentialId, false);
        boolean backedUp = recoverable && metadata.getBoolean("backedUp." + credentialId, false);
        long counter = 0L;
        if (!recoverable) {
            long previous = metadata.getLong("globalSignCount", 0L);
            if (previous >= 0xFFFFFFFFL) throw new IllegalStateException("counter exhausted");
            counter = previous + 1;
            if (!metadata.edit().putLong("globalSignCount", counter).commit()) {
                throw new IllegalStateException("cannot persist counter");
            }
        }
        // WebAuthn L3: UP=0x01, UV=0x04, BE=0x08, BS=0x10. Recoverable
        // credentials use a permanently-zero signature counter as required
        // for CXF-exportable passkeys. Legacy device-bound keys keep their
        // monotonic global counter and BE=BS=0.
        int flags = (requireUp ? 0x01 : 0x00) | 0x04;
        if (recoverable) flags |= 0x08;
        if (backedUp) flags |= 0x10;
        ByteBuffer data = ByteBuffer.allocate(37);
        data.put(rpHash(rpId));
        data.put((byte) flags);
        data.putInt((int) counter);
        return data.array();
    }

    byte[] registrationProof(String rpId, byte[] clientDataHash, byte[] userId)
            throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write("CTAP3B-REGISTER".getBytes(StandardCharsets.US_ASCII));
        stream.write(rpHash(rpId));
        stream.write(clientDataHash);
        stream.write(userId);
        return stream.toByteArray();
    }

    void discardUncommitted(CreatedKey key) {
        if (key != null && !metadata.contains("credential." + key.credentialId)) {
            delete(key.alias);
            if (key.encryptedEscrow != null) Arrays.fill(key.encryptedEscrow, (byte) 0);
        }
        cleanupStagedRecoveryAliases();
    }

    private void delete(String alias) {
        try {
            keyStore.deleteEntry(alias);
        } catch (Exception ignored) {
            // No private-key material or alias appears in logs.
        }
    }

    private static byte[] coordinate(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 33 || (raw.length == 33 && raw[0] != 0)) {
            throw new IllegalArgumentException("invalid P-256 coordinate");
        }
        byte[] result = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, 1, result, 0, 32);
        } else {
            System.arraycopy(raw, 0, result, 32 - raw.length, raw.length);
        }
        return result;
    }

    /** Canonical CBOR EC2 public key {1:2,3:-7,-1:1,-2:x,-3:y}. */
    static byte[] coseEs256(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();
        ByteBuffer output = ByteBuffer.allocate(77);
        output.put(new byte[] {
            (byte) 0xA5, 0x01, 0x02, 0x03, 0x26,
            0x20, 0x01,
            0x21, 0x58, 0x20
        });
        output.put(coordinate(point.getAffineX()));
        output.put(new byte[] {0x22, 0x58, 0x20});
        output.put(coordinate(point.getAffineY()));
        return output.array();
    }
}
