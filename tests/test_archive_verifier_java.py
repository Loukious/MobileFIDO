"""Compile/run the exact shipped Android-independent readback verifier on JDK17."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
JAVA_DIR = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b"
TEST = ROOT / "tests/java/RecoveryArchiveVerifierTest.java"


class ArchiveVerifierJavaTests(unittest.TestCase):
    def test_real_java_verifier_fails_closed_on_corrupt_provider_reads(self):
        jdk = Path(os.environ.get("JAVA_HOME", "/tmp/mobilefido-toolchain/jdk"))
        compiler = str(jdk / "bin/javac") if (jdk / "bin/javac").exists() else shutil.which("javac")
        runtime = str(jdk / "bin/java") if (jdk / "bin/java").exists() else shutil.which("java")
        if not compiler or not runtime:
            self.skipTest("JDK17 is needed for the shipped Java verifier test")
        with tempfile.TemporaryDirectory(prefix="mobilefido-verifier-") as out:
            subprocess.run([compiler, "-source", "17", "-target", "17", "-d", out,
                str(JAVA_DIR / "RecoveryArchiveVerifier.java"), str(TEST)],
                check=True, capture_output=True, text=True)
            result = subprocess.run([runtime, "-cp", out,
                "org.pocof7.ctap3b.RecoveryArchiveVerifierTest"],
                check=True, capture_output=True, text=True)
            self.assertIn("11 functional cases passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
