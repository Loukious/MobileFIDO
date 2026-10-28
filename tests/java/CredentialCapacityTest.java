package org.pocof7.ctap3b;

import java.util.HashSet;
import java.util.Set;

public final class CredentialCapacityTest {
    private static Set<String> ids(int from, int to, String prefix) {
        Set<String> values = new HashSet<>();
        for (int i = from; i < to; i++) values.add(prefix + i);
        return values;
    }

    public static void main(String[] args) {
        Set<String> full = ids(0, 256, "credential.");
        Set<String> original = new HashSet<>(full);
        // An existing credential can be repaired/restored even at capacity.
        CredentialCapacity.requireRestoreFits(full, Set.of("42"), 256);
        CredentialCapacity.requireRestoreFits(full, ids(0, 256, ""), 256);
        CredentialCapacity.requireRestoreFits(Set.of(), ids(0, 256, ""), 256);
        CredentialCapacity.requireRestoreFits(
            ids(0, 128, "credential."), ids(128, 256, ""), 256);
        Set<String> metadata = ids(0, 255, "credential.");
        metadata.add("user.255");
        metadata.add("lastVerifiedBackupAt");
        CredentialCapacity.requireRestoreFits(metadata, Set.of("255"), 256);
        try {
            // Each input fits independently; their union does not.
            CredentialCapacity.requireRestoreFits(full, Set.of("new"), 256);
            throw new AssertionError("Restore overflow was accepted");
        } catch (IllegalStateException expected) {
            if (!expected.getMessage().contains("catalog limit")) throw expected;
        }
        if (!full.equals(original)) throw new AssertionError("Existing catalog was mutated");
        System.out.println("6 capacity cases passed; existing catalog unchanged");
    }
}
