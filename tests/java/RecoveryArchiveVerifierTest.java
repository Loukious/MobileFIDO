package org.pocof7.ctap3b;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/** Runs against the shipped, Android-independent verifier source on host JDK. */
public final class RecoveryArchiveVerifierTest {
    private static int passed;

    private static void expectFailure(String name, InputStream data,
                                      byte[] expected, int limit) throws Exception {
        try {
            RecoveryArchiveVerifier.verifyReadback(data, expected, limit);
            throw new AssertionError(name + " accepted a broken archive");
        } catch (IOException correct) {
            passed++;
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] blob = new byte[65541];
        for (int i = 0; i < blob.length; i++) blob[i] = (byte) (i * 17 + 3);
        String hash = RecoveryArchiveVerifier.verifyReadback(
            new ByteArrayInputStream(blob), blob, 512 * 1024);
        if (!hash.matches("[0-9a-f]{64}")) throw new AssertionError("Invalid hash");
        passed++;
        if (!hash.equals(RecoveryArchiveVerifier.encryptedFingerprint(
                blob, 512 * 1024))) {
            throw new AssertionError("Existing-file fingerprint differs from export digest");
        }
        passed++;

        byte[] truncated = Arrays.copyOf(blob, blob.length - 1);
        expectFailure("truncated", new ByteArrayInputStream(truncated), blob, 512 * 1024);
        byte[] altered = blob.clone();
        altered[altered.length / 2] ^= 0x01;
        expectFailure("altered", new ByteArrayInputStream(altered), blob, 512 * 1024);
        byte[] appended = Arrays.copyOf(blob, blob.length + 1);
        expectFailure("appended", new ByteArrayInputStream(appended), blob, 512 * 1024);
        expectFailure("provider missing", null, blob, 512 * 1024);
        expectFailure("provider limit", new ByteArrayInputStream(blob), blob, 2048);
        try {
            RecoveryArchiveVerifier.encryptedFingerprint(blob, 2048);
            throw new AssertionError("Oversized saved archive hashed");
        } catch (IOException correct) {
            passed++;
        }
        expectFailure("empty", new ByteArrayInputStream(new byte[0]), blob, 512 * 1024);
        expectFailure("provider throws", new InputStream() {
            @Override public int read() throws IOException { throw new IOException("offline"); }
        }, blob, 512 * 1024);
        InputStream occasionallyZero = new ByteArrayInputStream(blob) {
            private boolean zero = true;
            @Override public int read(byte[] b, int off, int len) {
                if (zero) { zero = false; return 0; }
                return super.read(b, off, len);
            }
        };
        if (!hash.equals(RecoveryArchiveVerifier.verifyReadback(
                occasionallyZero, blob, 512 * 1024))) {
            throw new AssertionError("Zero-byte provider read changed digest");
        }
        passed++;
        System.out.println("RecoveryArchiveVerifier: " + passed + " functional cases passed");
    }
}
