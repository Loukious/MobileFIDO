package org.pocof7.ctap3b;

import android.util.Base64;
import android.util.JsonReader;
import android.util.JsonToken;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
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
 * MobileFIDO 5 recovery archive.
 *
 * The encrypted plaintext is a FIDO Credential Exchange Format 1.0 JSON
 * document. Passkey records use the standard CXF credentialId/rpId/username/
 * userDisplayName/userHandle/key fields; key is PKCS#8 DER encoded as base64url.
 * MobileFIDO adds one forward-compatible optional `mobileFido` member solely to
 * preserve whether an external-authenticator credential was discoverable.
 * Standard CXF import does NOT depend on that member: P-256 public coordinates
 * are derived from the mandatory PKCS#8 `key`, and an archive without MobileFIDO
 * metadata imports as a discoverable passkey. CXF 1.0 requires participants to
 * ignore unknown optional fields, so another provider can ignore this hint.
 * The legacy `pocoKey` hint and PKRCV001 outer magic remain importable so
 * development archives created before the rename are not stranded.
 *
 * Static archive encryption is intentionally separate from CXP transport:
 * PBKDF2-HMAC-SHA256 -> AES-256-GCM, random salt/nonce, authenticated header,
 * strict size bounds and no plaintext private key on disk. CXP support can
 * later transport the same CXF payload directly between credential providers.
 */
final class RecoverableBackupManager {
    static final int MAX_BLOB = 512 * 1024;
    private static final int MAX_PLAIN = 448 * 1024;
    private static final byte[] MAGIC = "MFRCV001".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_MAGIC = "PKRCV001".getBytes(StandardCharsets.US_ASCII);
    private static final int VERSION = 1;
    private static final int ITERATIONS = 600_000;
    private static final int MIN_ITERATIONS = 400_000;
    private static final int MAX_ITERATIONS = 2_000_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int HEADER_BYTES = 8 + 1 + 4 + SALT_BYTES + NONCE_BYTES + 4;

    static final class ExportResult {
        final byte[] blob;
        final List<String> credentialIds;
        final int legacySkipped;

        ExportResult(byte[] blob, List<String> credentialIds, int legacySkipped) {
            this.blob = blob;
            this.credentialIds = credentialIds;
            this.legacySkipped = legacySkipped;
        }
    }

    static final class RestoreResult {
        final int restored;
        final int alreadyPresent;

        RestoreResult(int restored, int alreadyPresent) {
            this.restored = restored;
            this.alreadyPresent = alreadyPresent;
        }
    }

    /** Archive contents checked without importing/deleting a signing key. */
    static final class InspectionResult {
        final List<String> credentialIds;
        final CryptoKeyManager.ArchiveCoverage coverage;

        InspectionResult(List<String> ids, CryptoKeyManager.ArchiveCoverage coverage) {
            credentialIds = ids;
            this.coverage = coverage;
        }
    }

    private RecoverableBackupManager() {}

    static boolean looksLikeArchive(byte[] blob) {
        if (blob == null || blob.length < MAGIC.length + 1) return false;
        return hasMagic(blob, MAGIC) || hasMagic(blob, LEGACY_MAGIC);
    }

    private static boolean hasMagic(byte[] blob, byte[] magic) {
        if (blob == null || magic == null || blob.length < magic.length) return false;
        for (int i = 0; i < magic.length; i++) {
            if (blob[i] != magic[i]) return false;
        }
        return true;
    }

    /** Consumes and clears password on every path. */
    static ExportResult exportEncrypted(CryptoKeyManager keys, char[] password) throws Exception {
        byte[] plain = null;
        byte[] derived = null;
        CryptoKeyManager.RecoverySnapshot snapshot = null;
        try {
            requirePassword(password);
            if (keys == null) throw new IllegalArgumentException("Missing credential manager");
            snapshot = keys.snapshotRecovery();
            plain = encodeCxf(snapshot);
            if (plain.length == 0 || plain.length > MAX_PLAIN) {
                throw new IllegalStateException("CXF recovery payload exceeds limit");
            }
            byte[] salt = new byte[SALT_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            random.nextBytes(nonce);
            byte[] header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN)
                .put(MAGIC).put((byte) VERSION).putInt(ITERATIONS)
                .put(salt).put(nonce).putInt(plain.length + TAG_BYTES).array();
            derived = derive(password, salt, ITERATIONS);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, "AES"),
                new GCMParameterSpec(128, nonce));
            cipher.updateAAD(header);
            byte[] encrypted = cipher.doFinal(plain);
            byte[] blob = ByteBuffer.allocate(header.length + encrypted.length)
                .put(header).put(encrypted).array();
            Arrays.fill(encrypted, (byte) 0);
            if (blob.length > MAX_BLOB) {
                Arrays.fill(blob, (byte) 0);
                throw new IllegalStateException("Recovery archive exceeds limit");
            }
            List<String> ids = new ArrayList<>();
            for (CryptoKeyManager.RecoveryEntry entry : snapshot.entries) {
                ids.add(CryptoKeyManager.encode(entry.credentialId));
            }
            return new ExportResult(blob, ids, snapshot.legacySkipped);
        } finally {
            if (snapshot != null) {
                CryptoKeyManager.clearRecoveryEntries(snapshot.entries);
                Arrays.fill(snapshot.accountId, (byte) 0);
            }
            if (plain != null) Arrays.fill(plain, (byte) 0);
            if (derived != null) Arrays.fill(derived, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Consumes and clears password on every path. */
    static RestoreResult restoreEncrypted(CryptoKeyManager keys, byte[] blob, char[] password)
            throws Exception {
        List<CryptoKeyManager.RecoveryEntry> entries = null;
        try {
            if (keys == null) throw new IllegalArgumentException("Missing credential manager");
            entries = decryptAndValidate(blob, password);
            CryptoKeyManager.RecoveryRestoreResult outcome = keys.restoreRecovery(entries);
            return new RestoreResult(outcome.restored, outcome.alreadyPresent);
        } finally {
            CryptoKeyManager.clearRecoveryEntries(entries);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Consumes password. Verifies authenticated CXF and EXACT credential set. */
    static InspectionResult verifyEncrypted(byte[] blob, char[] password,
                                            List<String> expectedIds) throws Exception {
        List<CryptoKeyManager.RecoveryEntry> entries = null;
        try {
            entries = decryptAndValidate(blob, password);
            Set<String> seen = new HashSet<>();
            List<String> ids = new ArrayList<>();
            for (CryptoKeyManager.RecoveryEntry entry : entries) {
                String id = CryptoKeyManager.encode(entry.credentialId);
                if (!seen.add(id)) throw new IllegalArgumentException("Duplicate archive credential");
                ids.add(id);
            }
            if (expectedIds != null) {
                Set<String> expected = new HashSet<>(expectedIds);
                if (expected.size() != expectedIds.size() || !seen.equals(expected)) {
                    throw new IllegalArgumentException("Archived credentials differ from export snapshot");
                }
            }
            return new InspectionResult(ids, null);
        } finally {
            CryptoKeyManager.clearRecoveryEntries(entries);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Standalone, read-only inspection of a selected saved recovery archive. */
    static InspectionResult inspectEncrypted(CryptoKeyManager keys, byte[] blob,
                                             char[] password) throws Exception {
        List<CryptoKeyManager.RecoveryEntry> entries = null;
        try {
            if (keys == null) throw new IllegalArgumentException("Missing credential manager");
            entries = decryptAndValidate(blob, password);
            List<String> ids = new ArrayList<>();
            for (CryptoKeyManager.RecoveryEntry entry : entries) {
                ids.add(CryptoKeyManager.encode(entry.credentialId));
            }
            CryptoKeyManager.ArchiveCoverage coverage =
                keys.inspectRecoveryCoverage(entries);
            return new InspectionResult(ids, coverage);
        } finally {
            CryptoKeyManager.clearRecoveryEntries(entries);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Decrypts authenticated archive; caller MUST wipe returned entries. */
    private static List<CryptoKeyManager.RecoveryEntry> decryptAndValidate(
            byte[] blob, char[] password) throws Exception {
        byte[] plain = null;
        byte[] derived = null;
        try {
            requirePassword(password);
            if (blob == null || blob.length < HEADER_BYTES + TAG_BYTES
                || blob.length > MAX_BLOB) {
                throw new IllegalArgumentException("Invalid MobileFIDO recovery archive");
            }
            ByteBuffer input = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[MAGIC.length];
            input.get(magic);
            int version = Byte.toUnsignedInt(input.get());
            int iterations = input.getInt();
            byte[] salt = new byte[SALT_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            input.get(salt);
            input.get(nonce);
            int encryptedLength = input.getInt();
            if ((!Arrays.equals(magic, MAGIC) && !Arrays.equals(magic, LEGACY_MAGIC))
                || version != VERSION
                || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                || encryptedLength < TAG_BYTES + 2 || encryptedLength > MAX_PLAIN + TAG_BYTES
                || encryptedLength != input.remaining()) {
                throw new IllegalArgumentException("Unsupported or malformed recovery archive");
            }
            derived = derive(password, salt, iterations);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derived, "AES"),
                new GCMParameterSpec(128, nonce));
            cipher.updateAAD(blob, 0, HEADER_BYTES);
            try {
                plain = cipher.doFinal(blob, HEADER_BYTES, encryptedLength);
            } catch (GeneralSecurityException wrongPasswordOrTamper) {
                throw new IllegalArgumentException("Incorrect passphrase or damaged archive");
            }
            return decodeCxf(plain);
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
            if (derived != null) Arrays.fill(derived, (byte) 0);
        }
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length < 16 || password.length > 1024) {
            throw new IllegalArgumentException("Recovery passphrase must contain 16..1024 characters");
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static String b64url(byte[] bytes) {
        return Base64.encodeToString(bytes,
            Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private static byte[] fromB64url(String value, int min, int max) {
        if (value == null || value.length() > ((max + 2) / 3) * 4 + 8) {
            throw new IllegalArgumentException("Invalid CXF base64url size");
        }
        byte[] decoded = Base64.decode(value,
            Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        if (decoded.length < min || decoded.length > max) {
            Arrays.fill(decoded, (byte) 0);
            throw new IllegalArgumentException("Invalid CXF decoded field size");
        }
        if (!b64url(decoded).equals(value)) {
            Arrays.fill(decoded, (byte) 0);
            throw new IllegalArgumentException("Noncanonical CXF base64url");
        }
        return decoded;
    }

    private static byte[] encodeCxf(CryptoKeyManager.RecoverySnapshot snapshot)
            throws Exception {
        JSONObject header = new JSONObject();
        header.put("version", new JSONObject().put("major", 1).put("minor", 0));
        header.put("exporterRpId", "mobilefido.localhost");
        header.put("exporterDisplayName", "MobileFIDO");
        header.put("timestamp", System.currentTimeMillis() / 1000L);

        JSONObject account = new JSONObject();
        account.put("id", b64url(snapshot.accountId));
        account.put("username", "");
        account.put("email", "");
        account.put("collections", new JSONArray());
        JSONArray items = new JSONArray();
        Set<String> ids = new HashSet<>();
        for (CryptoKeyManager.RecoveryEntry entry : snapshot.entries) {
            String id = b64url(entry.credentialId);
            if (!ids.add(id)) throw new IllegalArgumentException("Duplicate recovery credential");
            JSONObject passkey = new JSONObject();
            passkey.put("type", "passkey");
            passkey.put("credentialId", id);
            passkey.put("rpId", entry.rpId);
            passkey.put("username", entry.userName == null ? "" : entry.userName);
            passkey.put("userDisplayName",
                entry.displayName == null ? "" : entry.displayName);
            passkey.put("userHandle", b64url(entry.userId));
            passkey.put("key", b64url(entry.privateKeyPkcs8));
            passkey.put("mobileFido", new JSONObject()
                .put("schema", 1)
                .put("publicX", b64url(entry.publicX))
                .put("publicY", b64url(entry.publicY))
                .put("discoverable", entry.discoverable));

            JSONObject item = new JSONObject();
            // CXF Item.id is its own opaque entity identifier (max 64 decoded
            // bytes), not the WebAuthn credential ID. Derive a stable 32-byte
            // item ID so imported 16..1023-byte credential IDs re-export
            // without violating the CXF Item.id size requirement.
            item.put("id", b64url(itemId(entry.credentialId)));
            if (entry.createdAtMillis > 0) {
                item.put("creationAt", entry.createdAtMillis / 1000L);
            }
            item.put("title", entry.rpId);
            if (entry.userName != null) item.put("subtitle", entry.userName);
            item.put("credentials", new JSONArray().put(passkey));
            items.put(item);
        }
        account.put("items", items);
        header.put("accounts", new JSONArray().put(account));
        byte[] encoded = header.toString().getBytes(StandardCharsets.UTF_8);
        if (encoded.length > MAX_PLAIN) {
            Arrays.fill(encoded, (byte) 0);
            throw new IllegalStateException("CXF payload too large");
        }
        return encoded;
    }

    private static byte[] itemId(byte[] credentialId) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // Stable pre-rename domain separator: changing this would make the
        // otherwise opaque CXF Item.id churn across upgrades for the same
        // credential. It is intentionally not user-facing branding.
        digest.update("PocoKey-CXF-Item-v1\0".getBytes(StandardCharsets.US_ASCII));
        return digest.digest(credentialId);
    }

    /** Strict streaming parser: duplicate members are rejected at every level. */
    private static List<CryptoKeyManager.RecoveryEntry> decodeCxf(byte[] plain)
            throws Exception {
        if (plain == null || plain.length < 2 || plain.length > MAX_PLAIN) {
            throw new IllegalArgumentException("Invalid CXF payload size");
        }
        List<CryptoKeyManager.RecoveryEntry> entries = new ArrayList<>();
        try (JsonReader reader = new JsonReader(new InputStreamReader(
                new ByteArrayInputStream(plain), StandardCharsets.UTF_8))) {
            reader.setLenient(false);
            Set<String> root = new HashSet<>();
            boolean versionSeen = false, exporterRpSeen = false;
            boolean exporterNameSeen = false, timestampSeen = false;
            boolean accountsSeen = false;
            reader.beginObject();
            while (reader.hasNext()) {
                String name = uniqueName(reader, root);
                switch (name) {
                    case "version":
                        readVersion(reader);
                        versionSeen = true;
                        break;
                    case "exporterRpId":
                        String exporter = boundedString(reader, 1, 253);
                        if (!RelyingPartyPolicy.valid(exporter)) {
                            throw new IllegalArgumentException("Invalid CXF exporter RP ID");
                        }
                        exporterRpSeen = true;
                        break;
                    case "exporterDisplayName":
                        boundedString(reader, 0, 256);
                        exporterNameSeen = true;
                        break;
                    case "timestamp":
                        boundedLong(reader, 0, 253402300799L);
                        timestampSeen = true;
                        break;
                    case "accounts":
                        if (accountsSeen) throw new IllegalArgumentException("Duplicate accounts");
                        readAccounts(reader, entries);
                        accountsSeen = true;
                        break;
                    default:
                        reader.skipValue(); // CXF 1.0 forward-compatibility rule.
                }
            }
            reader.endObject();
            if (!versionSeen || !exporterRpSeen || !exporterNameSeen
                || !timestampSeen || !accountsSeen
                || reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IllegalArgumentException("Incomplete CXF document");
            }
        }
        if (entries.isEmpty() || entries.size() > BackupManager.MAX_CREDENTIALS) {
            CryptoKeyManager.clearRecoveryEntries(entries);
            throw new IllegalArgumentException("Recovery archive has no supported passkeys");
        }
        Set<String> ids = new HashSet<>();
        for (CryptoKeyManager.RecoveryEntry entry : entries) {
            if (!ids.add(CryptoKeyManager.encode(entry.credentialId))) {
                CryptoKeyManager.clearRecoveryEntries(entries);
                throw new IllegalArgumentException("Duplicate passkey credentialId");
            }
        }
        return entries;
    }

    private static void readVersion(JsonReader reader) throws Exception {
        Set<String> names = new HashSet<>();
        Integer major = null, minor = null;
        reader.beginObject();
        while (reader.hasNext()) {
            String name = uniqueName(reader, names);
            if ("major".equals(name)) major = boundedInt(reader, 0, 255);
            else if ("minor".equals(name)) minor = boundedInt(reader, 0, 255);
            else reader.skipValue();
        }
        reader.endObject();
        if (major == null || minor == null || major != 1 || minor != 0) {
            throw new IllegalArgumentException("Unsupported CXF version");
        }
    }

    private static void readAccounts(JsonReader reader,
            List<CryptoKeyManager.RecoveryEntry> entries) throws Exception {
        int accounts = 0;
        requireToken(reader, JsonToken.BEGIN_ARRAY, "CXF accounts must be an array");
        reader.beginArray();
        while (reader.hasNext()) {
            if (++accounts > 16) throw new IllegalArgumentException("Too many CXF accounts");
            Set<String> names = new HashSet<>();
            boolean idSeen = false, usernameSeen = false, emailSeen = false;
            boolean collectionsSeen = false, itemsSeen = false;
            requireToken(reader, JsonToken.BEGIN_OBJECT, "CXF account must be an object");
            reader.beginObject();
            while (reader.hasNext()) {
                String name = uniqueName(reader, names);
                switch (name) {
                    case "id": {
                        byte[] id = fromB64url(boundedString(reader, 1, 96), 1, 64);
                        Arrays.fill(id, (byte) 0);
                        idSeen = true;
                        break;
                    }
                    case "username":
                        boundedString(reader, 0, 256);
                        usernameSeen = true;
                        break;
                    case "email":
                        boundedString(reader, 0, 320);
                        emailSeen = true;
                        break;
                    case "collections":
                        skipBoundedArray(reader, 256, "Too many CXF collections");
                        collectionsSeen = true;
                        break;
                    case "items":
                        readItems(reader, entries);
                        itemsSeen = true;
                        break;
                    default:
                        reader.skipValue();
                }
            }
            reader.endObject();
            if (!idSeen || !usernameSeen || !emailSeen || !collectionsSeen || !itemsSeen) {
                throw new IllegalArgumentException("Incomplete CXF account");
            }
        }
        reader.endArray();
    }

    private static void readItems(JsonReader reader,
            List<CryptoKeyManager.RecoveryEntry> entries) throws Exception {
        requireToken(reader, JsonToken.BEGIN_ARRAY, "CXF items must be an array");
        reader.beginArray();
        int itemCount = 0;
        while (reader.hasNext()) {
            if (++itemCount > 512) throw new IllegalArgumentException("Too many CXF items");
            if (entries.size() >= BackupManager.MAX_CREDENTIALS) {
                throw new IllegalArgumentException("Too many recovery items");
            }
            Set<String> names = new HashSet<>();
            long createdAt = 0L;
            List<CryptoKeyManager.RecoveryEntry> itemEntries = new ArrayList<>();
            boolean idSeen = false, titleSeen = false, credentialsSeen = false;
            requireToken(reader, JsonToken.BEGIN_OBJECT, "CXF item must be an object");
            reader.beginObject();
            while (reader.hasNext()) {
                String name = uniqueName(reader, names);
                switch (name) {
                    case "id": {
                        byte[] id = fromB64url(boundedString(reader, 1, 96), 1, 64);
                        Arrays.fill(id, (byte) 0);
                        idSeen = true;
                        break;
                    }
                    case "creationAt":
                        createdAt = boundedLong(reader, 0, 253402300799L) * 1000L;
                        break;
                    case "modifiedAt":
                        boundedLong(reader, 0, 253402300799L);
                        break;
                    case "title":
                        boundedString(reader, 0, 512);
                        titleSeen = true;
                        break;
                    case "subtitle":
                        boundedString(reader, 0, 512);
                        break;
                    case "credentials":
                        // JSON object member order is insignificant. Parse keys
                        // first with no timestamp, then apply the final creationAt
                        // after the whole item has been consumed.
                        readCredentials(reader, 0L, itemEntries);
                        credentialsSeen = true;
                        break;
                    default:
                        reader.skipValue();
                }
            }
            reader.endObject();
            if (!idSeen || !titleSeen || !credentialsSeen) {
                CryptoKeyManager.clearRecoveryEntries(itemEntries);
                throw new IllegalArgumentException("Incomplete CXF item");
            }
            for (CryptoKeyManager.RecoveryEntry entry : itemEntries) {
                CryptoKeyManager.RecoveryEntry ordered = new CryptoKeyManager.RecoveryEntry(
                    entry.credentialId, entry.rpId, entry.userId, entry.userName,
                    entry.displayName, entry.discoverable, createdAt,
                    entry.publicX, entry.publicY, entry.privateKeyPkcs8);
                entries.add(ordered);
            }
            CryptoKeyManager.clearRecoveryEntries(itemEntries);
        }
        reader.endArray();
    }

    private static void readCredentials(JsonReader reader, long createdAt,
            List<CryptoKeyManager.RecoveryEntry> entries) throws Exception {
        requireToken(reader, JsonToken.BEGIN_ARRAY, "CXF credentials must be an array");
        reader.beginArray();
        int count = 0;
        while (reader.hasNext()) {
            if (++count > 512) throw new IllegalArgumentException("Too many CXF credentials");
            CryptoKeyManager.RecoveryEntry entry = readPasskey(reader, createdAt);
            if (entry != null) entries.add(entry);
        }
        reader.endArray();
    }

    private static CryptoKeyManager.RecoveryEntry readPasskey(JsonReader reader,
            long createdAt) throws Exception {
        Set<String> names = new HashSet<>();
        String type = null, credentialId = null, rpId = null, username = null;
        String displayName = null, userHandle = null, privateKey = null;
        String publicX = null, publicY = null;
        boolean discoverable = true, vendorHintSeen = false;
        requireToken(reader, JsonToken.BEGIN_OBJECT, "CXF credential must be an object");
        reader.beginObject();
        while (reader.hasNext()) {
            String name = uniqueName(reader, names);
            switch (name) {
                case "type": type = boundedString(reader, 1, 32); break;
                case "credentialId": credentialId = boundedString(reader, 1, 1400); break;
                case "rpId": rpId = boundedString(reader, 1, 253); break;
                case "username": username = boundedString(reader, 0, 128); break;
                case "userDisplayName": displayName = boundedString(reader, 0, 128); break;
                case "userHandle": userHandle = boundedString(reader, 1, 128); break;
                case "key": privateKey = boundedString(reader, 1, 1024); break;
                case "fido2Extensions": {
                    // Importing a passkey while silently discarding PRF,
                    // hmac-secret, credBlob, largeBlob or payment state can
                    // produce a credential that authenticates but no longer
            // behaves like the original. MobileFIDO does not implement
                    // those extensions yet, so fail closed when any are
                    // present rather than claiming a complete CXF restore.
                    requireToken(reader, JsonToken.BEGIN_OBJECT,
                        "CXF fido2Extensions must be an object");
                    reader.beginObject();
                    if (reader.hasNext()) {
                        throw new IllegalArgumentException(
                            "CXF passkey uses unsupported FIDO2 extensions");
                    }
                    reader.endObject();
                    break;
                }
                case "mobileFido":
                case "pocoKey": {
                    if (vendorHintSeen) {
                        throw new IllegalArgumentException("Duplicate MobileFIDO CXF hint");
                    }
                    Set<String> extension = new HashSet<>();
                    Integer schema = null;
                    Boolean resident = null;
                    requireToken(reader, JsonToken.BEGIN_OBJECT,
                        "MobileFIDO CXF hint must be an object");
                    reader.beginObject();
                    while (reader.hasNext()) {
                        String field = uniqueName(reader, extension);
                        if ("schema".equals(field)) schema = boundedInt(reader, 1, 1);
                        else if ("publicX".equals(field)) publicX = boundedString(reader, 1, 64);
                        else if ("publicY".equals(field)) publicY = boundedString(reader, 1, 64);
                        else if ("discoverable".equals(field)) {
                            requireToken(reader, JsonToken.BOOLEAN,
                                "MobileFIDO discoverable hint must be boolean");
                            resident = reader.nextBoolean();
                        }
                        else reader.skipValue();
                    }
                    reader.endObject();
                    if (schema == null || schema != 1 || resident == null) {
                        throw new IllegalArgumentException("Invalid MobileFIDO CXF extension");
                    }
                    discoverable = resident;
                    vendorHintSeen = true;
                    break;
                }
                default: reader.skipValue();
            }
        }
        reader.endObject();
        if (!"passkey".equals(type)) return null; // Ignore other CXF credential types.
        if (credentialId == null || rpId == null || username == null || displayName == null
            || userHandle == null || privateKey == null || !RelyingPartyPolicy.valid(rpId)) {
            throw new IllegalArgumentException("Incomplete CXF passkey");
        }
        byte[] id = fromB64url(credentialId,
            CryptoKeyManager.MIN_CREDENTIAL_ID_BYTES,
            CryptoKeyManager.MAX_CREDENTIAL_ID_BYTES);
        byte[] user = fromB64url(userHandle, 1, 64);
        byte[] pkcs8 = fromB64url(privateKey, 64, 512);
        byte[] x = null, y = null, hintedX = null, hintedY = null;
        try {
            java.security.interfaces.ECPublicKey derived =
                CryptoKeyManager.publicFromPrivatePkcs8(pkcs8);
            x = coordinate(derived.getW().getAffineX());
            y = coordinate(derived.getW().getAffineY());
            if (vendorHintSeen) {
                if (publicX == null || publicY == null) {
                    throw new IllegalArgumentException("Incomplete MobileFIDO CXF hint");
                }
                hintedX = fromB64url(publicX, 32, 32);
                hintedY = fromB64url(publicY, 32, 32);
                if (!Arrays.equals(x, hintedX) || !Arrays.equals(y, hintedY)) {
                    throw new IllegalArgumentException("CXF public key hint mismatch");
                }
            }
            return new CryptoKeyManager.RecoveryEntry(id, rpId, user,
                username.isEmpty() ? null : username,
                displayName.isEmpty() ? null : displayName,
                discoverable, createdAt, x, y, pkcs8);
        } finally {
            Arrays.fill(id, (byte) 0);
            Arrays.fill(user, (byte) 0);
            Arrays.fill(pkcs8, (byte) 0);
            if (x != null) Arrays.fill(x, (byte) 0);
            if (y != null) Arrays.fill(y, (byte) 0);
            if (hintedX != null) Arrays.fill(hintedX, (byte) 0);
            if (hintedY != null) Arrays.fill(hintedY, (byte) 0);
        }
    }

    private static String uniqueName(JsonReader reader, Set<String> names) throws Exception {
        String name = reader.nextName();
        if (!names.add(name)) throw new IllegalArgumentException("Duplicate CXF member");
        return name;
    }

    private static String boundedString(JsonReader reader, int min, int max) throws Exception {
        requireToken(reader, JsonToken.STRING, "CXF member must be a string");
        String value = reader.nextString();
        int bytes = value.getBytes(StandardCharsets.UTF_8).length;
        if (bytes < min || bytes > max) throw new IllegalArgumentException("CXF string out of bounds");
        return value;
    }

    private static int boundedInt(JsonReader reader, int min, int max) throws Exception {
        requireToken(reader, JsonToken.NUMBER, "CXF member must be an integer");
        long value = reader.nextLong();
        if (value < min || value > max) throw new IllegalArgumentException("CXF integer out of bounds");
        return (int) value;
    }

    private static long boundedLong(JsonReader reader, long min, long max) throws Exception {
        requireToken(reader, JsonToken.NUMBER, "CXF member must be an integer");
        long value = reader.nextLong();
        if (value < min || value > max) throw new IllegalArgumentException("CXF integer out of bounds");
        return value;
    }

    private static void requireToken(JsonReader reader, JsonToken expected, String message)
            throws Exception {
        if (reader.peek() != expected) throw new IllegalArgumentException(message);
    }

    private static void skipBoundedArray(JsonReader reader, int max, String message)
            throws Exception {
        requireToken(reader, JsonToken.BEGIN_ARRAY, "CXF member must be an array");
        reader.beginArray();
        int count = 0;
        while (reader.hasNext()) {
            if (++count > max) throw new IllegalArgumentException(message);
            reader.skipValue();
        }
        reader.endArray();
    }

    private static byte[] coordinate(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 33 || (raw.length == 33 && raw[0] != 0)) {
            throw new IllegalArgumentException("Invalid P-256 public coordinate");
        }
        byte[] result = new byte[32];
        if (raw.length > 32) System.arraycopy(raw, 1, result, 0, 32);
        else System.arraycopy(raw, 0, result, 32 - raw.length, raw.length);
        return result;
    }
}
