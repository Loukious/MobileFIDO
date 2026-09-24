package org.pocof7.ctap3b;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Read back the encrypted bytes from the chosen document provider before
 * declaring a backup verified. No credential plaintext, password or RP names
 * are written to the provider by this verifier. No large second blob is kept.
 * The caller separately decrypts and validates the authenticated CXF payload.
 */
final class RecoveryArchiveVerifier {
    private RecoveryArchiveVerifier() {}

    static String encryptedFingerprint(byte[] archive, int maximum)
            throws IOException {
        if (archive == null || archive.length == 0 || archive.length > maximum) {
            throw new IOException("Missing or oversized recovery archive");
        }
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(archive));
        } catch (NoSuchAlgorithmException missing) {
            throw new IOException("SHA-256 unavailable for recovery verification", missing);
        }
    }

    private static String hex(byte[] digest) {
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(Character.forDigit((b >>> 4) & 15, 16))
                .append(Character.forDigit(b & 15, 16));
        }
        return hex.toString();
    }

    static String verifyReadback(InputStream saved, byte[] expected, int maximum)
            throws IOException {
        if (saved == null || expected == null || expected.length == 0
            || maximum < 1 || expected.length > maximum) {
            throw new IOException("Missing or oversized recovery archive");
        }
        try {
            MessageDigest fileDigest = MessageDigest.getInstance("SHA-256");
            MessageDigest expectedDigest = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = expectedDigest.digest(expected);
            byte[] buf = new byte[8192];
            int total = 0;
            int count;
            while ((count = saved.read(buf)) != -1) {
                if (count == 0) {
                    int one = saved.read();
                    if (one == -1) break;
                    if (++total > maximum) throw new IOException("Archive readback exceeds limit");
                    fileDigest.update((byte) one);
                    continue;
                }
                if (count > maximum - total) {
                    throw new IOException("Archive readback exceeds limit");
                }
                fileDigest.update(buf, 0, count);
                total += count;
            }
            byte[] readbackHash = fileDigest.digest();
            if (total != expected.length
                || !MessageDigest.isEqual(expectedHash, readbackHash)) {
                throw new IOException("Saved archive is missing, incomplete or differs from export");
            }
            return hex(expectedHash);
        } catch (NoSuchAlgorithmException missing) {
            throw new IOException("SHA-256 unavailable for recovery readback", missing);
        }
    }
}
