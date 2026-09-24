"""The only module that touches the HID gadget.

Everything above this file works on bytes and does not know a device exists.
That is deliberate: it is what makes the protocol logic testable on a laptop
and what would let the same rules be reimplemented in Kotlin behind an Android
FileDescriptor.

Two jobs live here:

**Discovery.** The milestone brief is explicit that the device node must be
read out of ConfigFS rather than assumed. The minor number a HID function gets
is allocated by the kernel when the function directory is created, so it
depends on how many HID functions already existed -- ``hid.2`` is ``/dev/hidg2``
today only because ``hid.0`` and ``hid.1`` were created first. Delete and
recreate a function and the numbering shifts. So the gadget is identified the
way the host identifies it, by the *report descriptor*: whichever ``hid.*``
function declares usage page 0xF1D0 / usage 0x0001 is the CTAP interface, and
its node is derived from the ``dev`` attribute (major:minor), never guessed.

Reading the descriptor rather than hard-coding ``hid.2`` also means this code
cannot accidentally open the NetHunter keyboard or mouse interface, which carry
different descriptors and different usage pages.

**I/O.** Opening the node, reading fixed-size reports, writing exactly
``report_length`` bytes, and -- the part that actually matters -- noticing when
the gadget has gone away and recovering when it comes back.
"""

from __future__ import annotations

import errno
import logging
import os
import select
import stat
import time
from dataclasses import dataclass

log = logging.getLogger("ctaphid.transport")

#: Where the composite gadget lives. Note this is ``/config``, not
#: ``/sys/kernel/config`` -- on this device ConfigFS is mounted at /config.
DEFAULT_CONFIGFS_ROOT = "/config/usb_gadget/g1"

#: The usage page and usage that identify a CTAP HID interface. The FIDO
#: Alliance usage page is 0xF1D0 and the CTAPHID usage is 0x0001; Windows
#: encodes these into the device's hardware IDs as ``HID_DEVICE_UP:F1D0_U:0001``.
FIDO_USAGE_PAGE = 0xF1D0
FIDO_USAGE = 0x0001

#: Used only when discovery cannot run and the operator has named a node
#: explicitly. Never guessed at otherwise.
DEFAULT_REPORT_LENGTH = 64


class TransportError(Exception):
    """The gadget could not be found, opened, or used."""


class Disconnected(TransportError):
    """The gadget went away mid-operation.

    The gadget is unbound whenever the UDC is unbound, which the vendor USB HAL
    does on its own schedule. The correct response is to close, rediscover and
    reopen, because the node may come back under a different name.
    """


# ---------------------------------------------------------------------------
# HID report descriptor scanning
# ---------------------------------------------------------------------------

# Item prefixes: bits 7-4 tag, bits 3-2 type, bits 1-0 size.
_TYPE_GLOBAL = 0x1
_TYPE_LOCAL = 0x2
_TAG_USAGE_PAGE = 0x0  # global
_TAG_USAGE = 0x0  # local


def _iter_items(desc: bytes):
    """Yield ``(type, tag, value)`` for each short item in a report descriptor.

    Long items (prefix 0xFE) are skipped. Short items whose declared size is 3
    carry four bytes; the value is assembled little-endian.
    """
    pos = 0
    end = len(desc)
    while pos < end:
        prefix = desc[pos]

        if prefix == 0xFE:  # long item: 0xFE, size, tag, data
            if pos + 2 >= end:
                return
            length = desc[pos + 1]
            pos += 3 + length
            continue

        item_type = (prefix >> 2) & 0x3
        tag = (prefix >> 4) & 0xF
        size = prefix & 0x3
        if size == 3:
            size = 4
        pos += 1

        if pos + size > end:
            return
        value = int.from_bytes(desc[pos:pos + size], "little") if size else 0
        pos += size
        yield item_type, tag, value


def describe_usage(desc: bytes) -> tuple[int | None, int | None]:
    """Return the top-level ``(usage_page, usage)`` of a report descriptor.

    "Top-level" means the first Usage item, which by HID convention is the one
    that names the collection the descriptor as a whole describes. That is the
    value Windows surfaces as ``HID_DEVICE_UP:xxxx_U:yyyy``.
    """
    usage_page = None
    for item_type, tag, value in _iter_items(desc):
        if item_type == _TYPE_GLOBAL and tag == _TAG_USAGE_PAGE:
            usage_page = value
        elif item_type == _TYPE_LOCAL and tag == _TAG_USAGE:
            return usage_page, value
    return usage_page, None


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HidGadget:
    """A discovered HID gadget function and the node it is reachable at."""

    #: ConfigFS directory, e.g. ``/config/usb_gadget/g1/functions/hid.2``.
    function: str
    #: Character device, e.g. ``/dev/hidg2``.
    node: str
    #: Major:minor as ConfigFS reports it, kept for diagnostics.
    dev: str
    report_length: int
    protocol: int
    subclass: int
    usage_page: int | None
    usage: int | None

    def describe(self) -> str:
        return (
            f"{self.function} -> {self.node} (dev {self.dev}, "
            f"report_length={self.report_length}, protocol={self.protocol}, "
            f"subclass={self.subclass}, usage_page=0x{self.usage_page:04X}, "
            f"usage=0x{self.usage:04X})"
            if self.usage_page is not None and self.usage is not None
            else f"{self.function} -> {self.node} (dev {self.dev})"
        )


def _read_text(path: str) -> str | None:
    """Read an ASCII configfs attribute (``dev``, ``protocol``, ...)."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _read_bytes(path: str) -> bytes | None:
    """Read a binary configfs attribute.

    ``report_desc`` must be read this way: configfs hands back the raw
    descriptor bytes, not a hex rendering of them, so opening it as text
    either raises a UnicodeDecodeError or -- worse, with error replacement --
    quietly yields mojibake that parses as nothing at all.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _node_for_dev(
    dev: str, report_length: int, function: str, linked: bool = True
) -> str | None:
    """Turn a ConfigFS ``dev`` attribute into a usable device path.

    The kernel names these ``hidg<minor>``, so ``448:2`` implies ``/dev/hidg2``.
    That is checked rather than assumed: the candidate is ``stat``ed and its
    ``st_rdev`` must decode to the same major:minor ConfigFS reported. If the
    conventional name is absent the whole of ``/dev`` is searched for a
    character device with that rdev, so a differently-named node still works.

    ``linked`` says whether this function is part of a configuration that is
    actually in use. It only affects logging. A HID function gets its minor at
    ``mkdir`` time, so an unlinked one still reports a ``dev`` attribute and
    yet has no node -- that is normal, not a fault, and warning about it would
    train the reader to ignore the message that matters, the one for a function
    that *is* linked and *has* lost its node.
    """
    try:
        major, minor = (int(part) for part in dev.split(":"))
    except ValueError:
        log.warning("function %s has an unparseable dev attribute %r", function, dev)
        return None

    rdev = os.makedev(major, minor)

    conventional = f"/dev/hidg{minor}"
    if _rdev_of(conventional) == rdev:
        return conventional

    # Fall back to a scan. /dev here has a few hundred entries, so this is
    # cheap, and it only runs when the conventional name is missing.
    try:
        names = os.listdir("/dev")
    except OSError as exc:
        log.warning("cannot list /dev: %s", exc)
        return None

    for name in names:
        candidate = os.path.join("/dev", name)
        if _rdev_of(candidate) == rdev:
            log.info("using %s for %s (conventional name %s was not present)",
                     candidate, function, conventional)
            return candidate

    if linked:
        log.warning("no device node found for %s (dev %s, expected %s)",
                    function, dev, conventional)
    else:
        log.debug("no device node for unlinked %s (dev %s); skipping",
                  function, dev)
    return None


def _rdev_of(path: str) -> int | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISCHR(info.st_mode):
        return None
    return info.st_rdev


def _linked_functions(configfs_root: str) -> set[str]:
    """Real paths of every function linked into a configuration.

    ConfigFS represents a link as a symlink under ``configs/<name>/`` named
    ``functionN`` pointing at the function directory. Only linked functions get
    a device node, so this is what distinguishes "this function is not part of
    the active gadget" from "this function is linked but its node is missing" --
    the first is ordinary, the second is a fault worth a warning.
    """
    linked: set[str] = set()
    configs_dir = os.path.join(configfs_root, "configs")
    try:
        config_names = os.listdir(configs_dir)
    except OSError:
        # No configurations readable: report nothing as linked, so discovery
        # stays quiet rather than crying wolf about every unlinked function.
        return linked

    for config_name in config_names:
        config_dir = os.path.join(configs_dir, config_name)
        try:
            entries = os.listdir(config_dir)
        except OSError:
            continue
        for entry in entries:
            if not entry.startswith("function"):
                continue
            linked.add(os.path.realpath(os.path.join(config_dir, entry)))
    return linked


def discover(configfs_root: str = DEFAULT_CONFIGFS_ROOT) -> list[HidGadget]:
    """Enumerate every HID function on the gadget.

    Returns them in directory order, whether or not they are linked into a
    configuration -- discovery must not filter by link state, because the
    descriptor is what decides which function is ours, and a function that is
    linked but mis-described should still be examined and rejected on the
    evidence rather than silently skipped. Link state is consulted only to keep
    the logging honest: a function outside the active configuration has no node
    by design, and saying so at WARNING level would be noise.
    """
    functions_dir = os.path.join(configfs_root, "functions")
    if not os.path.isdir(functions_dir):
        raise TransportError(
            f"{functions_dir} is not a directory -- is ConfigFS mounted and visible "
            f"in this mount namespace?"
        )

    linked_functions = _linked_functions(configfs_root)

    gadgets: list[HidGadget] = []
    for name in sorted(os.listdir(functions_dir)):
        if not name.startswith("hid."):
            continue

        function = os.path.join(functions_dir, name)

        raw_desc = _read_bytes(os.path.join(function, "report_desc"))
        dev = _read_text(os.path.join(function, "dev"))
        if dev is None:
            # No dev attribute means the function has not been bound, so there
            # is no node to open yet.
            log.debug("%s has no dev attribute; skipping", function)
            continue

        report_length_text = _read_text(os.path.join(function, "report_length"))
        protocol_text = _read_text(os.path.join(function, "protocol"))
        subclass_text = _read_text(os.path.join(function, "subclass"))
        try:
            report_length = int(report_length_text or DEFAULT_REPORT_LENGTH)
            protocol = int(protocol_text or 0)
            subclass = int(subclass_text or 0)
        except ValueError:
            log.warning("%s has non-numeric attributes; skipping", function)
            continue

        # An unreadable descriptor is not fatal here: the node can still be
        # used, and find_gadget() rejects the ambiguous case rather than
        # guessing. Logging at warning because it costs us the identity check.
        usage_page = usage = None
        if raw_desc:
            usage_page, usage = describe_usage(raw_desc)
            if usage_page is None:
                log.warning("%s has a report descriptor with no usage items", function)
        else:
            log.warning("%s has no readable report_desc; cannot verify it is the "
                        "CTAP interface", function)

        node = _node_for_dev(
            dev, report_length, function, linked=function in linked_functions
        )
        if node is None:
            continue

        gadgets.append(
            HidGadget(
                function=function,
                node=node,
                dev=dev,
                report_length=report_length,
                protocol=protocol,
                subclass=subclass,
                usage_page=usage_page,
                usage=usage,
            )
        )

    return gadgets


def find_gadget(
    configfs_root: str = DEFAULT_CONFIGFS_ROOT,
    device: str | None = None,
) -> HidGadget:
    """Locate the CTAP HID gadget.

    ``device`` short-circuits discovery and is intended for environments where
    ConfigFS is not visible. It is not a silent fallback -- using it logs a
    warning, because it gives up the guarantee that we picked the right
    interface.

    The matching function is the one whose *report descriptor* declares the
    FIDO usage page and CTAP usage. If exactly one HID function exists and its
    descriptor cannot be read, it is accepted with a warning; if several exist
    and none can be identified, that is an error rather than a coin flip --
    opening the wrong interface would mean writing CTAPHID frames into the
    NetHunter keyboard endpoint.
    """
    if device is not None:
        if not _rdev_of(device) and not os.path.exists(device):
            raise TransportError(f"{device} does not exist")
        report_length = _report_length_for_node(device, configfs_root)
        log.warning(
            "using explicitly supplied device %s; ConfigFS discovery bypassed",
            device,
        )
        return HidGadget(
            function="(explicit)",
            node=device,
            dev="?",
            report_length=report_length,
            protocol=0,
            subclass=0,
            usage_page=None,
            usage=None,
        )

    gadgets = discover(configfs_root)
    if not gadgets:
        raise TransportError(
            f"no HID gadget functions with a device node found under {configfs_root}"
        )

    matches = [g for g in gadgets if g.usage_page == FIDO_USAGE_PAGE and g.usage == FIDO_USAGE]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise TransportError(
            "more than one HID function declares the FIDO usage page: "
            + "; ".join(g.describe() for g in matches)
        )

    # No identifiable match. Only proceed if there is no ambiguity about which
    # interface is ours.
    if len(gadgets) == 1:
        only = gadgets[0]
        log.warning(
            "no function declared usage page 0x%04X/usage 0x%04X; falling back to the "
            "only HID function present: %s",
            FIDO_USAGE_PAGE, FIDO_USAGE, only.describe(),
        )
        return only

    raise TransportError(
        f"none of the {len(gadgets)} HID functions declares the FIDO usage page "
        f"0x{FIDO_USAGE_PAGE:04X}/usage 0x{FIDO_USAGE:04X}; refusing to guess. Found: "
        + "; ".join(g.describe() for g in gadgets)
    )


def _report_length_for_node(node: str, configfs_root: str) -> int:
    """Best-effort report length for an explicitly named node.

    ConfigFS may be readable even when discovery was skipped, so try to match
    the node back to a function before giving up and using the default.
    """
    try:
        for gadget in discover(configfs_root):
            if gadget.node == node:
                return gadget.report_length
    except TransportError:
        pass
    log.warning("cannot determine report_length for %s; assuming %d",
                node, DEFAULT_REPORT_LENGTH)
    return DEFAULT_REPORT_LENGTH


# ---------------------------------------------------------------------------
# The transport itself
# ---------------------------------------------------------------------------

class HidGadgetTransport:
    """Fixed-size report I/O against one ``/dev/hidgN``.

    The gadget is a character device that speaks in whole reports. Reads return
    one OUT report from the host; writes must supply exactly ``report_length``
    bytes or the kernel truncates.
    """

    def __init__(self, gadget: HidGadget):
        self.gadget = gadget
        self.fd: int | None = None

    @property
    def report_length(self) -> int:
        return self.gadget.report_length

    @property
    def is_open(self) -> bool:
        return self.fd is not None

    def open(self) -> None:
        if self.fd is not None:
            return
        try:
            # O_NONBLOCK matters: f_hid's read blocks indefinitely when there
            # is no data, which would leave the daemon unable to notice a
            # disconnect or act on a signal.
            self.fd = os.open(self.gadget.node, os.O_RDWR | os.O_NONBLOCK)
        except OSError as exc:
            raise TransportError(f"cannot open {self.gadget.node}: {exc}") from exc
        log.info("opened %s (report_length=%d)", self.gadget.node, self.report_length)

    def close(self) -> None:
        if self.fd is None:
            return
        try:
            os.close(self.fd)
        except OSError as exc:
            log.debug("error closing %s: %s", self.gadget.node, exc)
        finally:
            self.fd = None

    def read_packet(self, timeout: float) -> bytes | None:
        """Read one report, or ``None`` if none arrived within ``timeout``.

        Raises :class:`Disconnected` if the gadget has gone away, which the
        caller handles by re-running discovery rather than by reopening the
        same path -- the path may be different when it comes back.
        """
        if self.fd is None:
            raise TransportError("read on a closed transport")

        try:
            ready, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError) as exc:
            raise Disconnected(f"select failed: {exc}") from exc

        if not ready:
            return None

        try:
            data = os.read(self.fd, self.report_length)
        except BlockingIOError:
            # select said readable but the data went away; not an error.
            return None
        except OSError as exc:
            if exc.errno in (errno.ENODEV, errno.EIO, errno.ESHUTDOWN, errno.EBADF):
                raise Disconnected(f"read failed: {exc}") from exc
            raise

        if not data:
            # Zero bytes on a character device means end of file: the function
            # was unlinked or the UDC was unbound.
            raise Disconnected("device returned end-of-file")

        return data

    def write_packet(self, packet: bytes) -> None:
        """Write exactly one report.

        A short or interleaved write is a real possibility because the
        endpoint's request queue is finite and the host may not be draining it
        fast enough. Anything that is not a complete report is retried briefly
        and then treated as a disconnect, because once the framing is torn
        there is no way to resynchronise mid-report.
        """
        if self.fd is None:
            raise TransportError("write on a closed transport")

        if len(packet) != self.report_length:
            raise TransportError(
                f"refusing to write a {len(packet)}-byte packet to a "
                f"{self.report_length}-byte endpoint"
            )

        deadline = time.monotonic() + 1.0
        while True:
            try:
                written = os.write(self.fd, packet)
            except BlockingIOError:
                written = 0
            except OSError as exc:
                if exc.errno in (errno.ENODEV, errno.EIO, errno.ESHUTDOWN, errno.EBADF):
                    raise Disconnected(f"write failed: {exc}") from exc
                raise

            if written == len(packet):
                return
            if time.monotonic() >= deadline:
                raise Disconnected(
                    f"only {written} of {len(packet)} bytes written before timeout"
                )
            time.sleep(0.01)

    def write_packets(self, packets: list[bytes]) -> None:
        for packet in packets:
            self.write_packet(packet)


def wait_for_gadget(
    configfs_root: str = DEFAULT_CONFIGFS_ROOT,
    device: str | None = None,
    timeout: float | None = None,
    interval: float = 1.0,
) -> HidGadget:
    """Block until the CTAP gadget is discoverable.

    Called at startup and after a disconnect. ``timeout`` of ``None`` waits
    forever, which is the right behaviour for a daemon that must survive the
    vendor USB HAL unbinding and rebinding the gadget underneath it.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    warned = False
    while True:
        try:
            return find_gadget(configfs_root, device)
        except TransportError as exc:
            if deadline is not None and time.monotonic() >= deadline:
                raise
            if not warned:
                log.info("waiting for the CTAP HID gadget: %s", exc)
                warned = True
            time.sleep(interval)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_CTAP_DESCRIPTOR = bytes.fromhex(
    "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
)
_KEYBOARD_DESCRIPTOR = bytes.fromhex(
    "05010906a101050719e029e715002501750195088102950175088103950575010508"
)


def _selftest() -> None:
    page, usage = describe_usage(_CTAP_DESCRIPTOR)
    assert (page, usage) == (0xF1D0, 0x0001), (page, usage)

    page, usage = describe_usage(_KEYBOARD_DESCRIPTOR)
    assert (page, usage) == (0x0001, 0x0006), f"keyboard descriptor parsed as {page:#x}/{usage:#x}"

    # The keyboard descriptor must not be mistaken for the CTAP one.
    assert not (page == FIDO_USAGE_PAGE and usage == FIDO_USAGE)

    # Truncated and empty descriptors must not raise, only return nothing.
    assert describe_usage(b"") == (None, None)
    assert describe_usage(b"\x06") == (None, None)
    assert describe_usage(b"\x06\xd0") == (None, None)

    # A long item must be skipped rather than desynchronising the scan.
    assert describe_usage(b"\xfe\x02\x00\x00\x00" + _CTAP_DESCRIPTOR) == (0xF1D0, 0x0001)

    assert _rdev_of("/dev/null") is not None
    assert _rdev_of("/etc/hostname") is None, "a regular file was reported as a char device"
    assert _rdev_of("/nonexistent") is None

    print("transport selftest OK")


if __name__ == "__main__":
    _selftest()
