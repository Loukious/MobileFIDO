package org.pocof7.ctap3b;

/**
 * Conservative canonical RP identifier boundary for the rooted USB CTAP bridge.
 * A WebAuthn client (not this authenticator) verifies origin vs RP ID; our
 * responsibility is to store and sign for the EXACT, validated RP ID supplied
 * by that client, and never treat a credential ID as cross-RP authority.
 *
 * WebAuthn DNS RP IDs are canonical lower-case ASCII (IDNA A-labels). No
 * schemes, URLs, ports, paths, Unicode, whitespace or IP literals. The sole
 * single-label exception is the existing development/test RP "localhost".
 */
final class RelyingPartyPolicy {
    static final String VERSION = "ascii-dns-rp-v1";
    static final String LEGACY_RP = "localhost";

    private RelyingPartyPolicy() {}

    static boolean valid(String rp) {
        if (rp == null || rp.length() == 0 || rp.length() > 253) return false;
        if (LEGACY_RP.equals(rp)) return true;
        if (rp.indexOf('.') < 0 || rp.startsWith(".") || rp.endsWith(".")) return false;
        String[] labels = rp.split("\\.", -1);
        if (labels.length < 2) return false;
        boolean numeric = true;
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63
                || label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char character = label.charAt(i);
                boolean digit = character >= '0' && character <= '9';
                if (!digit && !(character >= 'a' && character <= 'z')
                    && character != '-') return false;
                if (!digit) numeric = false;
            }
        }
        // Exclude IPv4-looking values and numeric-only pseudo-hosts. Other IP
        // forms (IPv6/brackets/ports) were rejected by the label checks.
        return !numeric;
    }

    static String require(String rp) {
        if (!valid(rp)) throw new IllegalArgumentException("Invalid RP ID");
        return rp;
    }
}
