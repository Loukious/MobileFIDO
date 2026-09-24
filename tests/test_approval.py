"""No-phone tests for physical key confirmation callback.

Synthetic Linux input events go into a pipe; these tests do not assert that
Android's real gpio-keys input driver or actual user presence was exercised.
"""

import os
import threading
import time
import unittest
from unittest.mock import patch

from ctaphid.approval import VolumeUpApproval, _INPUT_EVENT


class VolumeKeyApprovalTests(unittest.TestCase):
    def _run(self, events, cancel=False):
        read_fd, write_fd = os.pipe()
        actual_open = os.open

        def fake_open(path, *_args):
            if path == "/dev/input/event-synthetic":
                return os.dup(read_fd)
            return actual_open(path, *_args)

        cancelled = threading.Event()

        def writer():
            time.sleep(0.06)
            if cancel:
                cancelled.set()
            else:
                for event in events:
                    os.write(write_fd, _INPUT_EVENT.pack(0, 0, *event))

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        try:
            with patch("ctaphid.approval.find_phone_keypad", return_value="/dev/input/event-synthetic"), \
                    patch("ctaphid.approval.os.open", side_effect=fake_open):
                result = VolumeUpApproval(timeout=0.4)(
                    action="getAssertion", rp_id="localhost", cancel_event=cancelled,
                )
            return result
        finally:
            thread.join(timeout=0.5)
            os.close(read_fd)
            os.close(write_fd)

    def test_only_fresh_physical_volume_up_press_confirms(self):
        self.assertTrue(self._run([(1, 115, 1)]))

    def test_volume_down_not_a_confirmation(self):
        self.assertFalse(self._run([(1, 114, 1)]))

    def test_volume_up_release_and_repeat_not_confirmation(self):
        self.assertFalse(self._run([(1, 115, 0), (1, 115, 2)]))

    def test_cancellation_interrupts_wait(self):
        self.assertFalse(self._run([], cancel=True))


if __name__ == "__main__":
    unittest.main()
