"""Host-only multi-RP policy regression: no phone, adb, or private key access."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b"
POLICY = PACKAGE / "RelyingPartyPolicy.java"
CRYPTO = PACKAGE / "CryptoKeyManager.java"
SERVICE = PACKAGE / "HelperService.java"
ACTIVITY = PACKAGE / "MainActivity.java"
BACKEND = ROOT / "native-ctaphid/src/backend.rs"
JDK = Path("/tmp/jdk-17.0.20.1+1/bin")


HARNESS = '''
package org.pocof7.ctap3b;
final class RpPolicyHostTest {
    static void yes(String rp) {
        if (!RelyingPartyPolicy.valid(rp)) throw new AssertionError("Rejected: " + rp);
        if (!RelyingPartyPolicy.require(rp).equals(rp)) throw new AssertionError("Noncanonical");
    }
    static void no(String rp) {
        if (RelyingPartyPolicy.valid(rp)) throw new AssertionError("Accepted: " + rp);
        try { RelyingPartyPolicy.require(rp); throw new AssertionError("Did not fail closed"); }
        catch (IllegalArgumentException expected) { }
    }
    public static void main(String[] args) {
        for (String rp : new String[] {"localhost", "example.com", "login.example.com",
             "xn--bcher-kva.example", "a-b.example", "a.localhost"}) yes(rp);
        for (String rp : new String[] {"", ".example.com", "example.com.", "EXAMPLE.com",
             "https://example.com", "example.com:443", "example.com/path", "a..example",
             "127.0.0.1", "[::1]", "foo", "foo_.example", "bücher.example",
             "-foo.example", "foo-.example", "foo.example\\n", "a".repeat(64) + ".com",
             "a".repeat(250)+".test", "9.9.9.9", "xn--.example"}) no(rp);
        System.out.println("PASS: canonical ASCII DNS RP policy including legacy localhost");
    }
}
'''


class RpBindingTests(unittest.TestCase):
    def test_java_policy_host_runtime(self):
        javac = str(JDK / "javac") if (JDK / "javac").exists() else shutil.which("javac")
        java = str(JDK / "java") if (JDK / "java").exists() else shutil.which("java")
        if not javac or not java:
            self.skipTest("Java 17 unavailable")
        with tempfile.TemporaryDirectory(prefix="pocokey-rp-") as root:
            sources = Path(root) / "org/pocof7/ctap3b"
            sources.mkdir(parents=True)
            (sources / POLICY.name).write_bytes(POLICY.read_bytes())
            (sources / "RpPolicyHostTest.java").write_text(HARNESS)
            command = subprocess.run([javac, "-d", root, *map(str, sources.glob("*.java"))],
                                     capture_output=True, text=True, check=False)
            self.assertEqual(command.returncode, 0, command.stderr)
            command = subprocess.run([java, "-cp", root, "org.pocof7.ctap3b.RpPolicyHostTest"],
                                     capture_output=True, text=True, check=False)
            self.assertEqual(command.returncode, 0, command.stderr)
            self.assertIn("PASS: canonical ASCII DNS RP policy", command.stdout)

    def test_rp_binding_crosses_android_registration_assertion_and_backup(self):
        source = CRYPTO.read_text()
        for invariant in (
            'key.alias + "|" + key.rpId',
            'aliasFor(credentialId, rpId)',
            'RelyingPartyPolicy.require(rpId)',
            'rpHash(rpId)',
            'entry.alias + "|" + entry.rpId',
            'new BackupEntry(decode(id, 32, 32), rpId, alias',
        ):
            self.assertIn(invariant, source)
        service = SERVICE.read_text()
        self.assertIn('keys.hasCredential(id, rpId)', service)
        self.assertIn('RelyingPartyPolicy.require(rpId)', service)
        self.assertIn('"rpIdPolicy", RelyingPartyPolicy.VERSION', service)
        self.assertIn('"discoverablePolicy", "rp-bound-account-picker-v1"', service)
        self.assertIn('keys.discoverableForRp(rpId)', service)
        self.assertIn('Collections.unmodifiableList(accountChoices)', service)
        self.assertIn('account.credentialId.equals(credentialId)', service)
        activity = ACTIVITY.read_text()
        self.assertIn('prepareRegistration(operation.rpId, operation.userId,', activity)
        self.assertIn('operation.discoverable)', activity)
        self.assertIn('keys.userForDiscoverable(', activity)
        self.assertIn('chooseDiscoverableAccount(operation)', activity)
        self.assertIn('operation.selectAccount(choices.get(index).credentialId)', activity)
        self.assertIn('operation.promptClaimed.compareAndSet(false, true)', activity)
        self.assertIn('new BiometricPrompt.CryptoObject(signature)', activity)
        self.assertIn('prepareAssertion(operation.credentialId, operation.rpId)', activity)
        self.assertIn('assertionData(\n            operation.credentialId, operation.rpId, operation.up)', activity)
        backend = BACKEND.read_text()
        self.assertIn('ascii-dns-rp-v1', backend)
        self.assertIn('valid_rp_id(rp)', backend)
        self.assertIn('"residentKey":resident', backend)
        self.assertIn('"discoverable") != Some(&json!(true))', backend)
        self.assertIn('response.push((key(4), cmap([(text("id"), bytes(user))])))', backend)
        self.assertIn('metadata.getBoolean("resident." + id, false)', source)
        self.assertNotIn('if rp == "localhost" => Ok(rp)', backend)


if __name__ == "__main__":
    unittest.main()
