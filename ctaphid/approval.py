"""Development-only physical user-presence confirmation on the Poco F7.

This is NOT biometric user verification.  A fresh press of the phone's own
Volume Up button constitutes user presence (UP); it must never set the UV bit.
Only use this with disposable test credentials.  A rooted OS can synthesize
input, and this does not give a YubiKey's tamper resistance.

The device is selected by its Linux input name (gpio-keys), *not* by assuming
/dev/input/event0 remains stable across reboot.  Bluetooth headset buttons
and connected smart bands are intentionally excluded.
"""

from __future__ import annotations

import glob
import logging
import os
import select
import struct
import time
from threading import Event

log = logging.getLogger("ctaphid.approval")

_INPUT_EVENT = struct.Struct("@llHHi")  # native timeval, type, code, value
_EV_KEY = 0x01
_KEY_VOLUMEUP = 115


def find_phone_keypad() -> str:
    """Find Poco F7's physical ``gpio-keys`` input event node."""
    for path in sorted(glob.glob("/sys/class/input/event*/device/name")):
        try:
            with open(path, encoding="utf-8") as stream:
                name = stream.read().strip()
        except OSError:
            continue
        if name == "gpio-keys":
            return "/dev/input/" + path.split("/")[4]
    raise RuntimeError("physical gpio-keys input device not found; refusing approval")


class VolumeUpApproval:
    """Callable suitable for DevCredentialBackend(approval=...).

    A request must be explicitly approved *after* it begins.  Each call opens
    a fresh event fd, so earlier button presses cannot be replayed.  Polls in
    short intervals to allow CANCEL and daemon shutdown to interrupt approval.
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def __call__(self, *, action: str, rp_id: str, cancel_event: Event | None = None) -> bool:
        try:
            device = find_phone_keypad()
            fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as exc:
            log.error("cannot open physical volume-key input: %s", exc)
            return False
        except RuntimeError as exc:
            log.error("%s", exc)
            return False

        log.warning("PRESENCE REQUIRED: %s for RP %r: press PHONE Volume Up within %.0fs",
                    action, rp_id, self.timeout)
        deadline = time.monotonic() + self.timeout
        buf = b""
        try:
            while time.monotonic() < deadline:
                if cancel_event is not None and cancel_event.is_set():
                    log.info("presence request cancelled")
                    return False
                timeout = min(0.15, max(0, deadline - time.monotonic()))
                ready, _, _ = select.select([fd], [], [], timeout)
                if not ready:
                    continue
                try:
                    chunk = os.read(fd, _INPUT_EVENT.size * 16)
                except BlockingIOError:
                    continue
                if not chunk:
                    return False
                buf += chunk
                while len(buf) >= _INPUT_EVENT.size:
                    record, buf = buf[:_INPUT_EVENT.size], buf[_INPUT_EVENT.size:]
                    _sec, _usec, event_type, code, value = _INPUT_EVENT.unpack(record)
                    # value=1 is a new physical press; value=2 is key repeat.
                    if event_type == _EV_KEY and code == _KEY_VOLUMEUP and value == 1:
                        if cancel_event is not None and cancel_event.is_set():
                            return False
                        log.info("presence confirmed by physical Volume Up key")
                        return True
            log.warning("presence request timed out; refusing")
            return False
        finally:
            os.close(fd)
