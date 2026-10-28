package org.pocof7.ctap3b;

import java.util.HashSet;
import java.util.Set;

/** Check the merged catalog before recovery creates any hardware aliases. */
final class CredentialCapacity {
    private static final String PREFIX = "credential.";

    private CredentialCapacity() {}

    static void requireRestoreFits(Set<String> preferenceNames,
                                   Set<String> incomingIds, int maximum) {
        if (maximum < 1) throw new IllegalArgumentException("Invalid credential limit");
        Set<String> merged = new HashSet<>(incomingIds);
        for (String name : preferenceNames) {
            if (name.startsWith(PREFIX)) merged.add(name.substring(PREFIX.length()));
        }
        if (merged.size() > maximum) {
            throw new IllegalStateException(
                "Restored and existing credentials exceed the catalog limit");
        }
    }
}
