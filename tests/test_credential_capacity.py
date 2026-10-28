"""Exercise the shipped restore-capacity policy without Android or a phone."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/CredentialCapacity.java"
HARNESS = ROOT / "tests/java/CredentialCapacityTest.java"


class CredentialCapacityTests(unittest.TestCase):
    def test_merged_restore_fits_without_losing_existing_credentials(self):
        compiler = shutil.which("javac")
        runtime = shutil.which("java")
        if not compiler or not runtime:
            self.skipTest("JDK needed for the shipped capacity policy test")
        with tempfile.TemporaryDirectory(prefix="mobilefido-capacity-") as out:
            subprocess.run([compiler, "-source", "17", "-target", "17", "-d", out,
                            str(SOURCE), str(HARNESS)], check=True,
                           capture_output=True, text=True, timeout=30)
            result = subprocess.run([runtime, "-cp", out,
                                    "org.pocof7.ctap3b.CredentialCapacityTest"],
                                   check=True, capture_output=True, text=True,
                                   timeout=10)
            self.assertIn("6 capacity cases passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
