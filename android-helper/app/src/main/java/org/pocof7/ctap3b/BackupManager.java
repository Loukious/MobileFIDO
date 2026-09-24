package org.pocof7.ctap3b;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Password-encrypted METADATA catalog, NOT a backup of a hardware security key.
 *
 * AndroidKeyStore StrongBox/TEE private keys are NONEXPORTABLE. This file may
 * only relink an accidentally lost app metadata record on the ORIGINAL device
 * when its exact hardware alias/key is STILL PRESENT, with an identical public
 * P-256 point and hardware-enforced, per-use strong-biometric KeyInfo policy.
 * It CANNOT recover deleted keys, an uninstalled app's deleted Keystore keys,
 * reset hardware, or a new phone. Google Drive, if chosen by the user through
 * SAF, merely stores these encrypted metadata bytes, not usable key material.
 *
 * Version 4 wire format:
 *  magic[8]="CTAP3BM4", version[1]=4, PBKDF2 iterations[4] BE,
 *  salt[16], AES-GCM nonce[12], ciphertext+128-bit-tag length[4] BE,
 *  ciphertext+tag. The 45-byte header is GCM authenticated additional data.
 *  Plaintext: magic[8]="CTAPCAT4", globalSignCount[4] BE, entryCount[2] BE,
 *  sorted entries: credentialId[32], rpIdLength[1], rpId ASCII,
 *  aliasLength[1], alias ASCII,
 *  userIdLength[1], userId[1..64], discoverable[1] (0 or 1),
 *  hardwareLevel[1] (1=TEE,2=StrongBox),
 *  public P-256 x[32], y[32], accountNameLen[1], accountName UTF-8 [0..128],
 *  displayNameLen[1], displayName UTF-8 [0..128], createdAtEpochMillis[8] BE.
 *
 * Legacy v1, v2 and v3 archives are import-only; v1 and v2 lack a
 * discoverability flag and all imported credentials remain non-discoverable.
 * Version 1 is explicitly bound to "localhost".
 * Strict sizes and duplicate checks precede ANY preference mutation. Invalid
 * passphrase, malformed/trailing data, policy mismatch and conflicts fail
 * closed; there is NEVER a generated-key/software-key fallback.
 */
final class BackupManager {
    static final int MAX_CREDENTIALS = 256;
    private static final byte[] MAGIC = "CTAP3BM4".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] V3_MAGIC = "CTAP3BM3".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] V2_MAGIC = "CTAP3BM2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_MAGIC = "CTAP3BM1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CATALOG_MAGIC = "CTAPCAT4".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] V3_CATALOG_MAGIC = "CTAPCAT3".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] V2_CATALOG_MAGIC = "CTAPCAT2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_CATALOG_MAGIC = "CTAPCAT1".getBytes(StandardCharsets.US_ASCII);
    private static final int VERSION = 4;
    private static final int ITERATIONS = 240_000;
    private static final int MIN_ITERATIONS = 150_000;
    private static final int MAX_ITERATIONS = 1_000_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    // 256 entries with a 253-byte DNS RP and 64-byte user ID can exceed
    // 64 KiB. Reserve room for EVERY credential permitted by MAX_CREDENTIALS.
    private static final int MAX_BLOB = 320 * 1024;
    private static final int MAX_PLAIN = 256 * 1024;
    private static final int HEADER_LENGTH = 8 + 1 + 4 + SALT_BYTES + NONCE_BYTES + 4;

    static final class RestoreResult {
        final int restored;
        final int alreadyPresent;
        final int unavailable;

        RestoreResult(int restored, int alreadyPresent, int unavailable) {
            this.restored = restored;
            this.alreadyPresent = alreadyPresent;
            this.unavailable = unavailable;
        }
    }

    private BackupManager() {}

    /** Consumes/clears the supplied password char[] even on failure. */
    static byte[] exportEncrypted(CryptoKeyManager keys, char[] password) throws Exception {
        byte[] plain = null;
        byte[] rawKey = null;
        try {
            requirePassword(password);
            if (keys == null) throw new IllegalArgumentException("Missing hardware-key manager");
            CryptoKeyManager.BackupCatalog catalog = keys.snapshotBackup();
            try {
                plain = encodeCatalog(catalog);
            } finally {
                clearEntries(catalog.entries);
            }
            byte[] salt = new byte[SALT_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(salt);
            secureRandom.nextBytes(nonce);
            byte[] header = ByteBuffer.allocate(HEADER_LENGTH).order(ByteOrder.BIG_ENDIAN)
                .put(MAGIC).put((byte) VERSION).putInt(ITERATIONS)
                .put(salt).put(nonce).putInt(plain.length + GCM_TAG_BYTES)
                .array();
            rawKey = deriveKey(password, salt, ITERATIONS);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BYTES * 8, nonce));
            cipher.updateAAD(header);
            byte[] ciphertext = cipher.doFinal(plain);
            byte[] result = ByteBuffer.allocate(header.length + ciphertext.length)
                .put(header).put(ciphertext).array();
            Arrays.fill(ciphertext, (byte) 0);
            if (result.length > MAX_BLOB) throw new IllegalStateException("Catalog too large");
            return result;
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
            if (rawKey != null) Arrays.fill(rawKey, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Consumes/clears the supplied password char[] even on failure. */
    static RestoreResult restoreEncrypted(CryptoKeyManager keys, byte[] blob, char[] password)
            throws Exception {
        byte[] plain = null;
        byte[] rawKey = null;
        List<CryptoKeyManager.BackupEntry> entries = null;
        try {
            requirePassword(password);
            if (keys == null || blob == null
                || blob.length < HEADER_LENGTH + GCM_TAG_BYTES
                || blob.length > MAX_BLOB) {
                throw new IllegalArgumentException("Missing or invalid metadata catalog");
            }
            ByteBuffer file = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[MAGIC.length];
            file.get(magic);
            int version = Byte.toUnsignedInt(file.get());
            int iterations = file.getInt();
            byte[] salt = new byte[SALT_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            file.get(salt);
            file.get(nonce);
            int cipherLength = file.getInt();
            if (!((version == VERSION && Arrays.equals(magic, MAGIC))
                || (version == 3 && Arrays.equals(magic, V3_MAGIC))
                || (version == 2 && Arrays.equals(magic, V2_MAGIC))
                || (version == 1 && Arrays.equals(magic, LEGACY_MAGIC)))
                || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                || cipherLength < GCM_TAG_BYTES + CATALOG_MAGIC.length + 6
                || cipherLength > MAX_PLAIN + GCM_TAG_BYTES
                || cipherLength != file.remaining()) {
                throw new IllegalArgumentException("Unsupported or invalid metadata catalog");
            }
            rawKey = deriveKey(password, salt, iterations);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BYTES * 8, nonce));
            cipher.updateAAD(blob, 0, HEADER_LENGTH);
            try {
                plain = cipher.doFinal(blob, HEADER_LENGTH, cipherLength);
            } catch (GeneralSecurityException wrongPasswordOrTampering) {
                throw new IllegalArgumentException("Incorrect passphrase or damaged catalog");
            }
            ParsedCatalog parsed = decodeCatalog(plain, version);
            entries = parsed.entries;
            // In the same-device-only import, CryptoKeyManager verifies the
            // live hardware key/public point/policy before any metadata write.
            int[] counts = keys.restoreBackupCatalog(entries, parsed.counter);
            return new RestoreResult(counts[0], counts[1], counts[2]);
        } finally {
            clearEntries(entries);
            if (plain != null) Arrays.fill(plain, (byte) 0);
            if (rawKey != null) Arrays.fill(rawKey, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length < 12 || password.length > 1024) {
            throw new IllegalArgumentException("Passphrase must contain 12..1024 characters");
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] encodeCatalog(CryptoKeyManager.BackupCatalog catalog) throws IOException {
        if (catalog.counter < 0 || catalog.counter > 0xFFFFFFFFL
            || catalog.entries.size() > MAX_CREDENTIALS) {
            throw new IllegalArgumentException("Catalog out of bounds");
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(bytes);
        data.write(CATALOG_MAGIC);
        data.writeInt((int) catalog.counter);
        data.writeShort(catalog.entries.size());
        Set<String> ids = new HashSet<>();
        Set<String> aliases = new HashSet<>();
        for (CryptoKeyManager.BackupEntry entry : catalog.entries) {
            if (!validEntry(entry) || !ids.add(CryptoKeyManager.encode(entry.credentialId))
                || !aliases.add(entry.alias)) {
                throw new IllegalArgumentException("Invalid or duplicate catalog entry");
            }
            byte[] alias = entry.alias.getBytes(StandardCharsets.US_ASCII);
            byte[] rp = entry.rpId.getBytes(StandardCharsets.US_ASCII);
            data.write(entry.credentialId);
            data.writeByte(rp.length);
            data.write(rp);
            data.writeByte(alias.length);
            data.write(alias);
            data.writeByte(entry.userId.length);
            data.write(entry.userId);
            data.writeByte(entry.discoverable ? 1 : 0);
            data.writeByte("STRONGBOX".equals(entry.securityLevel) ? 2 : 1);
            data.write(entry.publicX);
            data.write(entry.publicY);
            writeLabel(data, entry.userName);
            writeLabel(data, entry.displayName);
            data.writeLong(entry.createdAtMillis);
        }
        data.flush();
        if (bytes.size() > MAX_PLAIN) throw new IllegalStateException("Catalog exceeds size limit");
        return bytes.toByteArray();
    }

    private static void writeLabel(DataOutputStream data, String value) throws IOException {
        String safe = CryptoKeyManager.safeAccountLabel(value);
        byte[] utf8 = safe == null ? new byte[0] : safe.getBytes(StandardCharsets.UTF_8);
        if (utf8.length > 128) throw new IllegalArgumentException("Invalid account label");
        data.writeByte(utf8.length);
        data.write(utf8);
    }

    private static String readLabel(DataInputStream in) throws IOException {
        int length = in.readUnsignedByte();
        if (length > 128) throw new IllegalArgumentException("Invalid account label size");
        byte[] utf8 = new byte[length];
        in.readFully(utf8);
        if (length == 0) return null;
        String label = new String(utf8, StandardCharsets.UTF_8);
        if (!Arrays.equals(label.getBytes(StandardCharsets.UTF_8), utf8)) {
            throw new IllegalArgumentException("Invalid UTF-8 account label");
        }
        String safe = CryptoKeyManager.safeAccountLabel(label);
        if (safe == null || !safe.equals(label)) {
            throw new IllegalArgumentException("Invalid account label contents");
        }
        return safe;
    }

    private static final class ParsedCatalog {
        final List<CryptoKeyManager.BackupEntry> entries;
        final long counter;

        ParsedCatalog(List<CryptoKeyManager.BackupEntry> entries, long counter) {
            this.entries = entries;
            this.counter = counter;
        }
    }

    private static ParsedCatalog decodeCatalog(byte[] plain) {
        return decodeCatalog(plain, VERSION);
    }

    private static ParsedCatalog decodeCatalog(byte[] plain, int version) {
        List<CryptoKeyManager.BackupEntry> entries = new ArrayList<>();
        try {
            if (plain.length < CATALOG_MAGIC.length + 6 || plain.length > MAX_PLAIN) {
                throw new IllegalArgumentException("Invalid catalog plaintext size");
            }
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain));
            byte[] magic = new byte[CATALOG_MAGIC.length];
            in.readFully(magic);
            if (!((version == VERSION && Arrays.equals(magic, CATALOG_MAGIC))
                || (version == 3 && Arrays.equals(magic, V3_CATALOG_MAGIC))
                || (version == 2 && Arrays.equals(magic, V2_CATALOG_MAGIC))
                || (version == 1 && Arrays.equals(magic, LEGACY_CATALOG_MAGIC)))) {
                throw new IllegalArgumentException("Invalid catalog plaintext version");
            }
            long counter = Integer.toUnsignedLong(in.readInt());
            int count = in.readUnsignedShort();
            if (count > MAX_CREDENTIALS) throw new IllegalArgumentException("Too many credentials");
            Set<String> ids = new HashSet<>();
            Set<String> aliases = new HashSet<>();
            for (int i = 0; i < count; i++) {
                byte[] id = new byte[32];
                in.readFully(id);
                String rpId;
                if (version == 1) {
                    rpId = RelyingPartyPolicy.LEGACY_RP;
                } else {
                    int rpLength = in.readUnsignedByte();
                    if (rpLength < 1 || rpLength > 253) {
                        throw new IllegalArgumentException("Invalid RP ID length");
                    }
                    byte[] rpBytes = new byte[rpLength];
                    in.readFully(rpBytes);
                    rpId = new String(rpBytes, StandardCharsets.US_ASCII);
                    if (!RelyingPartyPolicy.valid(rpId)) {
                        throw new IllegalArgumentException("Invalid RP ID");
                    }
                }
                int aliasLength = in.readUnsignedByte();
                if (aliasLength != 43) {
                    throw new IllegalArgumentException("Invalid hardware alias length");
                }
                byte[] aliasBytes = new byte[aliasLength];
                in.readFully(aliasBytes);
                String alias = new String(aliasBytes, StandardCharsets.US_ASCII);
                int userLength = in.readUnsignedByte();
                if (userLength < 1 || userLength > 64) {
                    throw new IllegalArgumentException("Invalid user ID length");
                }
                byte[] user = new byte[userLength];
                in.readFully(user);
                boolean discoverable = false;
                if (version >= 3) {
                    int encodedDiscoverable = in.readUnsignedByte();
                    if (encodedDiscoverable > 1) {
                        throw new IllegalArgumentException("Invalid discoverability flag");
                    }
                    discoverable = encodedDiscoverable == 1;
                }
                int encodedLevel = in.readUnsignedByte();
                if (encodedLevel != 1 && encodedLevel != 2) {
                    throw new IllegalArgumentException("Invalid hardware security level");
                }
                byte[] x = new byte[32];
                byte[] y = new byte[32];
                in.readFully(x);
                in.readFully(y);
                String userName = null;
                String displayName = null;
                long createdAtMillis = 0L;
                if (version >= 4) {
                    userName = readLabel(in);
                    displayName = readLabel(in);
                    createdAtMillis = in.readLong();
                    if (createdAtMillis < 0 || createdAtMillis > 253402300799000L) {
                        throw new IllegalArgumentException("Invalid credential creation date");
                    }
                }
                CryptoKeyManager.BackupEntry entry = new CryptoKeyManager.BackupEntry(
                    id, rpId, alias, user, x, y,
                    encodedLevel == 2 ? "STRONGBOX" : "TEE", discoverable,
                    userName, displayName, createdAtMillis);
                Arrays.fill(user, (byte) 0);
                if (!validEntry(entry)
                    || !ids.add(CryptoKeyManager.encode(entry.credentialId))
                    || !aliases.add(alias)) {
                    throw new IllegalArgumentException("Duplicate or invalid catalog entry");
                }
                entries.add(entry);
            }
            if (in.available() != 0) throw new IllegalArgumentException("Trailing catalog data");
            return new ParsedCatalog(entries, counter);
        } catch (IOException invalid) {
            clearEntries(entries);
            throw new IllegalArgumentException("Truncated catalog metadata");
        } catch (RuntimeException invalid) {
            clearEntries(entries);
            throw invalid;
        }
    }

    private static boolean validEntry(CryptoKeyManager.BackupEntry entry) {
        return entry != null && entry.credentialId.length == 32
            && entry.publicX.length == 32 && entry.publicY.length == 32
            && entry.userId.length >= 1 && entry.userId.length <= 64
            && CryptoKeyManager.validAlias(entry.alias)
            && RelyingPartyPolicy.valid(entry.rpId)
            && ("TEE".equals(entry.securityLevel) || "STRONGBOX".equals(entry.securityLevel))
            && entry.createdAtMillis >= 0 && entry.createdAtMillis <= 253402300799000L
            && safeLabel(entry.userName) && safeLabel(entry.displayName);
    }

    private static boolean safeLabel(String value) {
        try {
            return value == null || value.equals(CryptoKeyManager.safeAccountLabel(value));
        } catch (IllegalArgumentException rejected) {
            return false;
        }
    }

    private static void clearEntries(List<CryptoKeyManager.BackupEntry> entries) {
        if (entries == null) return;
        for (CryptoKeyManager.BackupEntry entry : entries) {
            Arrays.fill(entry.credentialId, (byte) 0);
            Arrays.fill(entry.userId, (byte) 0);
            Arrays.fill(entry.publicX, (byte) 0);
            Arrays.fill(entry.publicY, (byte) 0);
        }
    }
}
