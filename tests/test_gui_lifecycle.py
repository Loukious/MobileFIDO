"""Host-only regressions for Android 17 consent screen startup.

Android's PhoneWindow.getInsetsController dereferences its DecorView, which
is absent until Activity.setContentView installs the window's content. The
4.3.0 UI put this call before setContentView and crashed on every launch,
including from the user-approval notification. Keep the guard explicit.
"""

from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parent.parent /
          "android-helper/app/src/main/java/org/pocof7/ctap3b/MainActivity.java")


class GuiLifecycleTests(unittest.TestCase):
    def test_window_insets_controller_only_after_content_view_initialized(self):
        source = SOURCE.read_text()
        start = source.index("@Override public void onCreate(Bundle state)")
        end = source.index("private int dp(", start)
        on_create = source[start:end]
        content = on_create.index("setContentView(scroll);")
        controller = on_create.index("getWindowInsetsController()")
        self.assertLess(content, controller,
                        "Accessing PhoneWindow insets controller before decor init crashes Android 17")
        self.assertIn("if (bars != null)", on_create)
        self.assertIn("onOperation(HelperService.Operation operation)", source)
        self.assertIn("BiometricPrompt.CryptoObject", source)


if __name__ == "__main__":
    unittest.main()
