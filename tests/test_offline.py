"""End-to-end test of the CTAPHID server, without hardware.

The point of this file is that it does *not* reimplement the client side. It
loads Yubico's actual ``python-fido2`` and drives its real ``CtapHidDevice``
and ``Ctap2`` classes against our server over an in-process loopback link. If
our framing disagrees with the library we will test with on Windows, this test
fails here rather than on the phone.

Only the two platform-specific edges are faked:

* ``fido2.hid.linux`` is stubbed out, because the real one imports ``hidapi``,
  which is not installed and is not needed -- we are not talking to a device.
* the transport is replaced with a queue pair, so packets go
  host -> server in memory instead of over USB.

Everything in between -- packet framing, channel allocation, INIT semantics,
multi-packet reassembly, CBOR -- is the real code from both sides.

Run:  python3 -m tests.test_offline
"""

from __future__ import annotations

import os
import queue
import struct
import sys
import threading
import time
import types
import unittest

# ---------------------------------------------------------------------------
# Load the real python-fido2, with the platform backend stubbed
# ---------------------------------------------------------------------------

_FIDO2_SITE_PACKAGES = os.environ.get("FIDO2_SITE_PACKAGES", "")

if not _FIDO2_SITE_PACKAGES or not os.path.isdir(os.path.join(_FIDO2_SITE_PACKAGES, "fido2")):
    print(f"SKIP: python-fido2 not found at {_FIDO2_SITE_PACKAGES}")
    print("      set FIDO2_SITE_PACKAGES to a site-packages directory containing fido2/")
    raise unittest.SkipTest("optional python-fido2 interoperability dependency is unavailable")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Appended, not prepended: this directory holds Windows binaries (notably
# `cryptography`, whose Rust extension cannot load on Linux). Appending lets
# the native build of any shared dependency win while still finding fido2,
# which is not installed natively at all.
sys.path.append(_FIDO2_SITE_PACKAGES)

# Must be registered before fido2.hid is imported: fido2/hid/__init__.py does
# `from . import linux as backend` on Linux, and the real module needs hidapi.
_backend_stub = types.ModuleType("fido2.hid.linux")
_backend_stub.list_descriptors = lambda: []
_backend_stub.get_descriptor = lambda path: None
_backend_stub.open_connection = lambda descriptor: None
sys.modules["fido2.hid.linux"] = _backend_stub

import fido2  # noqa: E402
from fido2.ctap import CtapError  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from fido2.hid import CAPABILITY, CtapHidDevice  # noqa: E402
from fido2.hid.base import CtapHidConnection, HidDescriptor  # noqa: E402

from ctaphid import framing  # noqa: E402
from ctaphid.backend import DEVELOPMENT_AAGUID, GetInfoBackend  # noqa: E402
from ctaphid.constants import (  # noqa: E402
    CID_BROADCAST,
    CtapHidCommand,
    CtapHidError,
    Ctap2Error,
    TYPE_INIT,
)
from ctaphid.server import CtapHidServer  # noqa: E402
from ctaphid.transport import Disconnected, HidGadget  # noqa: E402

REPORT_SIZE = 64

# ---------------------------------------------------------------------------
# Loopback link
# ---------------------------------------------------------------------------


class Link:
    """A pair of queues standing in for the USB wire."""

    def __init__(self) -> None:
        self.to_device: queue.Queue[bytes] = queue.Queue()
        self.from_device: queue.Queue[bytes] = queue.Queue()
        #: Every packet the host wrote, in order, for the transcript.
        self.host_wrote: list[bytes] = []
        self.device_wrote: list[bytes] = []


class LoopbackTransport:
    """The device side of the link, shaped like HidGadgetTransport."""

    def __init__(self, link: Link):
        self.link = link
        self.report_length = REPORT_SIZE

    def read_packet(self, timeout: float) -> bytes | None:
        try:
            return self.link.to_device.get(timeout=timeout)
        except queue.Empty:
            return None

    def write_packet(self, packet: bytes) -> None:
        assert len(packet) == self.report_length, (
            f"device wrote a {len(packet)}-byte packet, expected {self.report_length}"
        )
        self.link.device_wrote.append(packet)
        self.link.from_device.put(packet)

    def write_packets(self, packets: list[bytes]) -> None:
        for packet in packets:
            self.write_packet(packet)

    def close(self) -> None:
        pass


class LoopbackConnection(CtapHidConnection):
    """The host side of the link, shaped like a fido2 HID connection."""

    def __init__(self, link: Link, descriptor: HidDescriptor):
        self.link = link
        self.descriptor = descriptor

    def write_packet(self, data: bytes) -> None:
        self.link.host_wrote.append(data)
        self.link.to_device.put(data)

    def read_packet(self) -> bytes:
        return self.link.from_device.get(timeout=5.0)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}" + (f"  -- {detail}" if detail else ""))


def expect_raises(name: str, exc_type, fn, *args, **kwargs) -> BaseException | None:
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        PASSED.append(name)
        print(f"  PASS  {name}  ({type(exc).__name__})")
        return exc
    except Exception as exc:  # noqa: BLE001
        FAILED.append((name, f"wrong exception {type(exc).__name__}: {exc}"))
        print(f"  FAIL  {name}  -- wrong exception {type(exc).__name__}: {exc}")
        return None
    FAILED.append((name, "no exception raised"))
    print(f"  FAIL  {name}  -- no exception raised")
    return None


class Harness:
    """A running server plus the raw-packet helpers to poke at it."""

    def __init__(self, **server_kwargs):
        self.link = Link()
        self.transport = LoopbackTransport(self.link)
        self.backend = GetInfoBackend(packet_size=REPORT_SIZE)
        self.server = CtapHidServer(self.backend, **server_kwargs)
        self.thread = threading.Thread(
            target=self.server._loop, args=(self.transport,), daemon=True
        )
        self.thread.start()

    def descriptor(self) -> HidDescriptor:
        return HidDescriptor(
            path=b"loopback",
            vid=0x1209,
            pid=0x0001,
            report_size_in=REPORT_SIZE,
            report_size_out=REPORT_SIZE,
            product_name="Poco F7 CTAP (loopback)",
            serial_number=None,
        )

    def connect(self) -> CtapHidDevice:
        """Build a real CtapHidDevice against this server."""
        descriptor = self.descriptor()
        return CtapHidDevice(descriptor, LoopbackConnection(self.link, descriptor))

    # -- raw packet helpers -------------------------------------------------

    def send_raw(self, packet: bytes) -> None:
        self.link.to_device.put(packet.ljust(REPORT_SIZE, b"\0"))

    def read_message(self, timeout: float = 2.0) -> tuple[int, int, bytes]:
        """Read one complete message off the device side.

        Returns ``(cid, command, payload)``. Raises on timeout so a missing
        response shows up as a failure rather than a hang.
        """
        deadline = time.monotonic() + timeout
        first = self.link.from_device.get(timeout=timeout)
        packet = framing.parse_packet(first)
        assert packet.is_init, "first packet of a response was not an initialization packet"

        txn = framing.Transaction.start(packet, REPORT_SIZE, 0.0)
        while not txn.complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("incomplete response")
            txn.feed(framing.parse_packet(self.link.from_device.get(timeout=remaining)))
        return txn.cid, txn.command, txn.data

    def drain(self) -> None:
        """Discard anything the server has sent but nobody read."""
        while True:
            try:
                self.link.from_device.get_nowait()
            except queue.Empty:
                return

    def stop(self) -> None:
        self.server.stop()
        self.thread.join(timeout=3.0)


def _assemble(packets: list[bytes], command: int) -> bytes:
    """Reassemble the last complete message with ``command`` from a packet log.

    Returns the message as header + payload, i.e. the initialization packet's
    seven header bytes followed by the whole reassembled body, so callers can
    read the declared length straight off it.
    """
    starts = [i for i, p in enumerate(packets) if p[4] == command]
    assert starts, f"no packet with command 0x{command:02x} in the log"
    start = starts[-1]

    first = packets[start]
    declared = struct.unpack_from(">H", first, 5)[0]
    body = first[7:7 + declared]

    index = start + 1
    while len(body) < declared:
        body += packets[index][5:5 + (declared - len(body))]
        index += 1

    return first[:7] + body


def alloc_channel(harness: Harness, nonce: bytes = b"12345678") -> tuple[int, bytes]:
    """Do a raw broadcast INIT and return (new_cid, raw_response_payload)."""
    packet = (
        struct.pack(">IBH", CID_BROADCAST, TYPE_INIT | CtapHidCommand.INIT, len(nonce))
        + nonce
    )
    harness.send_raw(packet)
    cid, command, payload = harness.read_message()
    assert cid == CID_BROADCAST, f"INIT reply came back on {cid:08x}, expected broadcast"
    assert command == CtapHidCommand.INIT
    return struct.unpack_from(">I", payload, 8)[0], payload


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_init_handshake() -> None:
    print("\n[1] CTAPHID_INIT handshake, driven by the real CtapHidDevice")
    harness = Harness()
    try:
        harness.drain()
        device = harness.connect()

        check("CtapHidDevice constructed (INIT succeeded)", True)
        check("protocol version is 2", device.version == 2, f"got {device.version}")
        check(
            "device version is 0.1.0",
            device.device_version == (0, 1, 0),
            f"got {device.device_version}",
        )
        check(
            "CBOR capability advertised",
            bool(device.capabilities & CAPABILITY.CBOR),
            f"capabilities=0x{device.capabilities:02x}",
        )
        check(
            "no unhonoured capability advertised",
            not (device.capabilities & (CAPABILITY.WINK | CAPABILITY.LOCK | CAPABILITY.NMSG)),
            f"capabilities=0x{device.capabilities:02x}",
        )
        check(
            "allocated channel is not broadcast",
            device._channel_id != CID_BROADCAST,
            f"cid={device._channel_id:08x}",
        )
        check(
            "product name came through the descriptor",
            device.product_name == "Poco F7 CTAP (loopback)",
        )

        print("\n  --- raw INIT exchange ---")
        request = harness.link.host_wrote[0]
        print(f"  request  ({len(request)} bytes): {request[:17].hex()}")
        print(f"           cid=0x{struct.unpack_from('>I', request)[0]:08X}"
              f" cmd=0x{request[4]:02x} len={struct.unpack_from('>H', request, 5)[0]}"
              f" nonce={request[7:15].hex()}")
        reply = harness.link.device_wrote[0]
        print(f"  response ({len(reply)} bytes): {reply[:24].hex()}")
        # Offset 7: past the CID(4) + CMD(1) + LEN(2) header. Unpacking from 0
        # would read the header back as the nonce.
        nonce, new_cid, version, v1, v2, v3, caps = struct.unpack_from(">8sIBBBBB", reply, 7)
        print(f"           nonce={nonce.hex()} (echoed={nonce == request[7:15]})"
              f" new_cid=0x{new_cid:08X} proto_version={version}"
              f" device={v1}.{v2}.{v3} capabilities=0x{caps:02x}")
        check("nonce echoed byte for byte", nonce == request[7:15],
              f"sent {request[7:15].hex()}, got {nonce.hex()}")
        check(
            "INIT reply declares 17 bytes",
            struct.unpack_from(">H", reply, 5)[0] == 17,
            f"declared {struct.unpack_from('>H', reply, 5)[0]}",
        )
        check(
            "INIT reply came back on broadcast",
            struct.unpack_from(">I", reply, 0)[0] == CID_BROADCAST,
        )
        check("new channel is not broadcast", new_cid != CID_BROADCAST, f"0x{new_cid:08X}")
        check("capabilities byte is CBOR only", caps == 0x04, f"0x{caps:02x}")
    finally:
        harness.stop()


def test_init_resync_and_errors() -> None:
    print("\n[2] INIT resynchronisation, nonce validation, broadcast misuse")
    harness = Harness()
    try:
        harness.drain()
        cid, _ = alloc_channel(harness)

        # INIT on an already-allocated channel must resynchronise, not allocate.
        nonce = b"RESYNC01"
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.INIT, len(nonce)) + nonce
        )
        reply_cid, command, payload = harness.read_message()
        returned = struct.unpack_from(">I", payload, 8)[0]
        check("resync reply arrives on the same channel", reply_cid == cid,
              f"got {reply_cid:08x}, sent on {cid:08x}")
        check("resync returns the same channel ID", returned == cid,
              f"got {returned:08x}, expected {cid:08x}")
        check("resync echoes the nonce", payload[:8] == nonce)
        check(
            "resync did not consume a channel slot",
            len(harness.server.channels) == 1,
            f"{len(harness.server.channels)} channels live",
        )

        # A nonce that is not 8 bytes is a length error.
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.INIT, 4) + b"shortnon"
        )
        _, command, payload = harness.read_message()
        check("short nonce -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("short nonce -> ERR_INVALID_LEN", payload == bytes([CtapHidError.INVALID_LEN]),
              f"got {payload.hex()}")

        # A non-INIT command on broadcast is invalid: no host is ever given it.
        harness.send_raw(
            struct.pack(">IBH", CID_BROADCAST, TYPE_INIT | CtapHidCommand.PING, 0)
        )
        reply_cid, command, payload = harness.read_message()
        check("PING on broadcast -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("PING on broadcast -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]), f"got {payload.hex()}")
        check("error was addressed to broadcast", reply_cid == CID_BROADCAST)

        # A packet for a channel that was never allocated.
        bogus = 0xDEADBEEF
        harness.send_raw(struct.pack(">IBH", bogus, TYPE_INIT | CtapHidCommand.PING, 0))
        reply_cid, command, payload = harness.read_message()
        check("unknown channel -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]), f"got {payload.hex()}")
        check("error echoed the unknown channel", reply_cid == bogus,
              f"got {reply_cid:08x}")
    finally:
        harness.stop()


def test_channel_exhaustion() -> None:
    print("\n[3] Channel exhaustion -> least-recently-used channel reclaimed")
    harness = Harness(max_channels=2)
    try:
        harness.drain()
        first_cid, _ = alloc_channel(harness, b"firstnon")
        second_cid, _ = alloc_channel(harness, b"secondnn")

        # Use the first channel, so the second is unambiguously the older one.
        harness.send_raw(
            struct.pack(">IBH", first_cid, TYPE_INIT | CtapHidCommand.PING, 1) + b"x"
        )
        _, command, _ = harness.read_message()
        check("live channel answers normally", command == CtapHidCommand.PING)

        # A third INIT on a full table must make progress. Answering
        # ERR_CHANNEL_BUSY is spec-legal and a host will retry, but it makes a
        # host that just re-enumerated wait out a timeout for no reason.
        third_cid, _ = alloc_channel(harness, b"thirdnon")
        check("third INIT on a full table still allocates a channel",
              third_cid != CID_BROADCAST, f"got 0x{third_cid:08x}")

        live = set(harness.server.channels.channels)
        check("the least recently used channel was the one reclaimed",
              second_cid not in live and first_cid in live,
              f"live: {sorted(f'{c:08x}' for c in live)}, "
              f"evicted 0x{second_cid:08x}")

        check("the new channel took the freed slot, so the table stays bounded",
              len(live) == 2, f"{len(live)} live channels")

        # The evicted host must be told plainly, so it can re-INIT rather than
        # waiting forever for a reply that is never coming.
        harness.send_raw(
            struct.pack(">IBH", second_cid, TYPE_INIT | CtapHidCommand.PING, 1) + b"y"
        )
        evicted_cid, command, payload = harness.read_message()
        check("evicted channel -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("evicted channel -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]),
              f"got {payload.hex()}")
        check("the error is addressed to the evicted channel",
              evicted_cid == second_cid, f"0x{evicted_cid:08x}")

        # And the channel that was actually in use is untouched.
        harness.send_raw(
            struct.pack(">IBH", first_cid, TYPE_INIT | CtapHidCommand.PING, 1) + b"z"
        )
        _, command, payload = harness.read_message()
        check("the channel in recent use survived and still works",
              command == CtapHidCommand.PING and payload == b"z")
    finally:
        harness.stop()


def test_ping() -> None:
    print("\n[4] CTAPHID_PING, via the real CtapHidDevice")
    harness = Harness()
    try:
        harness.drain()
        device = harness.connect()

        cases = [
            ("empty payload", b""),
            ("one byte", b"A"),
            ("fits in one packet (57)", b"B" * 57),
            ("needs one continuation (58)", b"C" * 58),
            ("several continuations (1000)", b"D" * 1000),
            ("maximum message size (7609)", b"E" * 7609),
        ]
        for label, payload in cases:
            echoed = device.ping(payload)
            check(f"PING {label} echoed exactly", echoed == payload,
                  f"sent {len(payload)}, got {len(echoed)}")

        # Repeated requests on the same channel must keep working.
        ok = all(device.ping(f"repeat-{i}".encode()) == f"repeat-{i}".encode() for i in range(20))
        check("20 sequential PINGs on one channel", ok)

        # Empty PING is a single packet carrying length 0.
        harness.drain()
        device.ping(b"")
        packet = harness.link.device_wrote[-1]
        declared = struct.unpack_from(">H", packet, 5)[0]
        check("empty PING reply declares length 0", declared == 0, f"declared {declared}")

        # A message one byte over the transport maximum must be refused, not
        # silently truncated.
        harness.drain()
        cid = device._channel_id
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 7610)
        )
        _, command, payload = harness.read_message()
        check("over-long declared length -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("over-long declared length -> ERR_INVALID_LEN",
              payload == bytes([CtapHidError.INVALID_LEN]), f"got {payload.hex()}")
    finally:
        harness.stop()


def test_cbor_getinfo() -> None:
    print("\n[5] CTAPHID_CBOR -> authenticatorGetInfo, via the real Ctap2 client")
    harness = Harness()
    try:
        harness.drain()
        device = harness.connect()

        try:
            info = Ctap2(device).get_info()
        except Exception as exc:  # noqa: BLE001
            check("Ctap2.get_info() succeeded", False, f"{type(exc).__name__}: {exc}")
            return

        check("Ctap2.get_info() succeeded", True)
        check("versions contains FIDO_2_0", "FIDO_2_0" in info.versions,
              f"got {info.versions}")
        check("aaguid is the development value", info.aaguid == DEVELOPMENT_AAGUID,
              f"got {info.aaguid!r}")
        check("aaguid is 16 bytes", len(info.aaguid) == 16)
        check("max_msg_size is 7609", info.max_msg_size == 7609,
              f"got {info.max_msg_size}")
        check("transports is ['usb']", list(info.transports or []) == ["usb"],
              f"got {info.transports}")
        check("no extensions advertised", not info.extensions,
              f"got {info.extensions}")

        # Nothing unsupported may be advertised.
        options = info.options or {}
        for option in ("rk", "uv", "clientPin"):
            check(f"option {option!r} not advertised as supported",
                  not options.get(option, False), f"options={options}")
        check("option 'up' not advertised as supported", not options.get("up", False),
              f"options={options}")

        print("\n  --- raw GetInfo exchange ---")
        # A GetInfo response is larger than one 64-byte report, so the message
        # has to be reassembled across packets rather than read off one of them.
        request = _assemble(harness.link.host_wrote, TYPE_INIT | CtapHidCommand.CBOR)
        response = _assemble(harness.link.device_wrote, TYPE_INIT | CtapHidCommand.CBOR)
        print(f"  request  cid=0x{struct.unpack_from('>I', request)[0]:08X}"
              f" cmd=0x{request[4]:02x} len={struct.unpack_from('>H', request, 5)[0]}"
              f" body={request[7:].hex()}")
        print(f"  response cid=0x{struct.unpack_from('>I', response)[0]:08X}"
              f" cmd=0x{response[4]:02x} len={struct.unpack_from('>H', response, 5)[0]}"
              f" ({len(response) - 7} bytes assembled)")
        print(f"           status=0x{response[7]:02x}")
        print(f"           cbor={response[8:].hex()}")

        # And a second call on the same channel must work.
        again = Ctap2(device).get_info()
        check("repeated GetInfo returns the same answer", again.aaguid == info.aaguid)
    finally:
        harness.stop()


def test_cbor_errors() -> None:
    print("\n[6] CTAP2 error handling")
    harness = Harness()
    try:
        harness.drain()
        cid, _ = alloc_channel(harness)

        def cbor_call(body: bytes) -> bytes:
            harness.send_raw(
                struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.CBOR, len(body)) + body
            )
            _, command, payload = harness.read_message()
            assert command == CtapHidCommand.CBOR, f"unexpected command 0x{command:02x}"
            return payload

        # Every unimplemented command returns CTAP2_ERR_INVALID_COMMAND.
        for name, code in (
            ("makeCredential 0x01", 0x01),
            ("getAssertion 0x02", 0x02),
            ("clientPin 0x06", 0x06),
            ("reset 0x07", 0x07),
            ("credentialManagement 0x0A", 0x0A),
        ):
            response = cbor_call(bytes([code]))
            check(f"{name} -> CTAP2_ERR_INVALID_COMMAND",
                  response == bytes([Ctap2Error.INVALID_COMMAND]), f"got {response.hex()}")

        # An unknown command byte is refused, not treated as GetInfo.
        response = cbor_call(b"\x99")
        check("unknown CTAP2 command -> CTAP2_ERR_INVALID_COMMAND",
              response == bytes([Ctap2Error.INVALID_COMMAND]), f"got {response.hex()}")

        # Malformed parameters are a CBOR error, distinct from an unknown command.
        response = cbor_call(b"\x04\xff")
        check("malformed CBOR parameters -> CTAP2_ERR_INVALID_CBOR",
              response == bytes([Ctap2Error.INVALID_CBOR]), f"got {response.hex()}")

        # An empty CBOR body cannot carry a command byte.
        harness.send_raw(struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.CBOR, 0))
        _, command, payload = harness.read_message()
        check("empty CBOR request -> CTAP2_ERR_INVALID_LENGTH",
              payload == bytes([Ctap2Error.INVALID_LENGTH]), f"got {payload.hex()}")

        # GetInfo with an explicit empty parameter map is accepted.
        response = cbor_call(b"\x04\xa0")
        check("GetInfo with an empty CBOR map parameter is accepted",
              response[0] == 0x00 and len(response) > 1, f"got {response.hex()}")
    finally:
        harness.stop()


def test_protocol_errors() -> None:
    print("\n[7] CTAPHID error handling: sequences, orphans, commands, cancel")
    harness = Harness()
    try:
        harness.drain()
        cid, _ = alloc_channel(harness)

        # An unsupported but well-known command.
        for name, code in (
            ("WINK 0x08", CtapHidCommand.WINK),
            ("LOCK 0x04", CtapHidCommand.LOCK),
            ("MSG 0x03", CtapHidCommand.MSG),
        ):
            harness.send_raw(struct.pack(">IBH", cid, TYPE_INIT | code, 0))
            _, command, payload = harness.read_message()
            check(f"{name} -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
            check(f"{name} -> ERR_INVALID_CMD",
                  payload == bytes([CtapHidError.INVALID_CMD]), f"got {payload.hex()}")

        # A vendor-defined command.
        harness.send_raw(struct.pack(">IBH", cid, TYPE_INIT | 0x40, 0))
        _, command, payload = harness.read_message()
        check("vendor command 0x40 -> ERR_INVALID_CMD",
              payload == bytes([CtapHidError.INVALID_CMD]), f"got {payload.hex()}")

        # An orphan continuation: nothing is in flight on this channel.
        harness.send_raw(struct.pack(">IB", cid, 0) + b"\0" * 59)
        _, command, payload = harness.read_message()
        check("orphan continuation -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("orphan continuation -> ERR_INVALID_SEQ",
              payload == bytes([CtapHidError.INVALID_SEQ]), f"got {payload.hex()}")

        # A continuation with the wrong sequence number mid-message.
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 200) + b"x" * 57
        )
        harness.send_raw(struct.pack(">IB", cid, 5) + b"y" * 59)  # should have been seq 0
        _, command, payload = harness.read_message()
        check("wrong continuation sequence -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
        check("wrong continuation sequence -> ERR_INVALID_SEQ",
              payload == bytes([CtapHidError.INVALID_SEQ]), f"got {payload.hex()}")
        check("the broken transaction was dropped", cid not in harness.server.pending)

        # A continuation on a channel that does not exist.
        harness.send_raw(struct.pack(">IB", 0x0BADF00D, 0) + b"\0" * 59)
        reply_cid, command, payload = harness.read_message()
        check("continuation on unknown channel -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]), f"got {payload.hex()}")

        # CANCEL discards a partial message and sends nothing back.
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 200) + b"z" * 57
        )
        time.sleep(0.1)
        check("a partial message is held pending", cid in harness.server.pending)
        harness.send_raw(struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.CANCEL, 0))
        time.sleep(0.3)
        check("CANCEL discarded the partial message", cid not in harness.server.pending)
        check("CANCEL produced no response", harness.link.from_device.empty(),
              f"{harness.link.from_device.qsize()} packets queued")
        check("the channel survives CANCEL", cid in harness.server.channels)

        # The channel still works afterwards.
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 4) + b"ping"
        )
        _, command, payload = harness.read_message()
        check("channel still usable after CANCEL",
              command == CtapHidCommand.PING and payload == b"ping", f"got {payload!r}")
    finally:
        harness.stop()


def test_restart_and_recovery() -> None:
    print("\n[8] Interrupted transactions and a fresh channel after loss")
    harness = Harness()
    try:
        harness.drain()
        cid, _ = alloc_channel(harness)

        # Start a multi-packet message, then abandon it by starting another on
        # the same channel. The half-sent message must not corrupt the new one.
        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 500) + b"a" * 57
        )
        time.sleep(0.1)
        check("first message is pending", cid in harness.server.pending)

        harness.send_raw(
            struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 9) + b"restarted"
        )
        _, command, payload = harness.read_message()
        check("restarted message is answered with its own payload",
              command == CtapHidCommand.PING and payload == b"restarted", f"got {payload!r}")
        check("the abandoned message was discarded", cid not in harness.server.pending)

        # A stalled transaction is expired and answered rather than left to
        # hang the host's read loop.
        harness2 = Harness(transaction_timeout=0.4)
        try:
            harness2.drain()
            cid2, _ = alloc_channel(harness2)
            harness2.send_raw(
                struct.pack(">IBH", cid2, TYPE_INIT | CtapHidCommand.PING, 500) + b"a" * 57
            )
            _, command, payload = harness2.read_message(timeout=3.0)
            check("stalled transaction -> CTAPHID_ERROR", command == CtapHidCommand.ERROR)
            check("stalled transaction -> ERR_MSG_TIMEOUT",
                  payload == bytes([CtapHidError.MSG_TIMEOUT]), f"got {payload.hex()}")
            check("the stalled transaction was cleared", cid2 not in harness2.server.pending)
        finally:
            harness2.stop()

        # A second channel is independent of the first.
        harness.drain()
        second, _ = alloc_channel(harness)
        check("a second channel gets a different ID", second != cid, f"{second:08x} vs {cid:08x}")
        harness.send_raw(
            struct.pack(">IBH", second, TYPE_INIT | CtapHidCommand.PING, 3) + b"two"
        )
        _, command, payload = harness.read_message()
        check("the second channel works", payload == b"two", f"got {payload!r}")
        check("both channels are live", len(harness.server.channels) == 2)

        # Dropping every channel (what a re-enumeration does) makes the old
        # channel invalid and a fresh INIT work again.
        dropped = harness.server.channels.clear()
        check("channels can be cleared", dropped == 2, f"cleared {dropped}")
        harness.send_raw(
            struct.pack(">IBH", second, TYPE_INIT | CtapHidCommand.PING, 0)
        )
        _, command, payload = harness.read_message()
        check("a packet on a dropped channel -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]), f"got {payload.hex()}")

        fresh, _ = alloc_channel(harness)
        check("a fresh INIT works after the drop", fresh not in (0, CID_BROADCAST))
    finally:
        harness.stop()


def test_idle_reclaim() -> None:
    print("\n[9] Idle channels are reclaimed rather than leaking")
    harness = Harness(idle_timeout=0.3)
    try:
        harness.drain()
        cid, _ = alloc_channel(harness)
        check("channel allocated", cid in harness.server.channels)

        # Silence longer than the idle timeout: the loop should reclaim it.
        time.sleep(1.2)
        check("idle channel was reclaimed", cid not in harness.server.channels,
              f"still {len(harness.server.channels)} channels")

        # A packet on the reclaimed channel is reported as invalid.
        harness.send_raw(struct.pack(">IBH", cid, TYPE_INIT | CtapHidCommand.PING, 0))
        _, command, payload = harness.read_message()
        check("reclaimed channel -> ERR_INVALID_CHANNEL",
              payload == bytes([CtapHidError.INVALID_CHANNEL]), f"got {payload.hex()}")
    finally:
        harness.stop()


class _SeverableTransport(LoopbackTransport):
    """The device side, with a switch that severs the link on demand.

    Stands in for the gadget disappearing -- an unplug, a re-enumeration, a UDC
    rebind. ``read_packet`` then raises ``Disconnected``, which is the one
    signal the server treats as fatal to the connection.
    """

    def __init__(self, link: Link) -> None:
        super().__init__(link)
        self.severed = threading.Event()

    def read_packet(self, timeout: float) -> bytes | None:
        if self.severed.is_set():
            raise Disconnected("simulated USB disconnect")
        return super().read_packet(timeout)


class _ReconnectingServer(CtapHidServer):
    """A server that rediscovers its device instead of opening a real one.

    ``_open_transport`` is the seam that normally calls ``wait_for_gadget``;
    handing out prepared transports lets the reconnect path be exercised with
    no hardware, which matters because the real device cannot be made to
    disconnect on demand (see the USB-HAL note in README-milestone2.md).
    """

    def __init__(self, backend, transports, **kwargs):
        super().__init__(backend, **kwargs)
        self._pending_transports = list(transports)
        self.opened = 0

    def _open_transport(self):
        self.opened += 1
        return self._pending_transports.pop(0)


def test_disconnect_recovery() -> None:
    print("\n[10] Disconnect -> channels invalidated, server reconnects on its own")
    link1, link2 = Link(), Link()
    first = _SeverableTransport(link1)
    second = LoopbackTransport(link2)
    backend = GetInfoBackend(packet_size=REPORT_SIZE)
    server = _ReconnectingServer(backend, [first, second], max_channels=4)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    def send(link, packet: bytes) -> None:
        link.to_device.put(packet.ljust(REPORT_SIZE, b"\0"))

    def read_message(link, timeout: float = 3.0):
        packet = framing.parse_packet(link.from_device.get(timeout=timeout))
        txn = framing.Transaction.start(packet, REPORT_SIZE, 0.0)
        while not txn.complete:
            txn.feed(framing.parse_packet(
                link.from_device.get(timeout=timeout)))
        return txn.cid, txn.command, txn.data

    def do_init(link, nonce: bytes):
        send(link, struct.pack(">IBH", CID_BROADCAST,
                               TYPE_INIT | CtapHidCommand.INIT, len(nonce)) + nonce)
        _, command, payload = read_message(link)
        assert command == CtapHidCommand.INIT, f"expected INIT, got 0x{command:02x}"
        return struct.unpack_from(">I", payload, 8)[0]

    try:
        cid1 = do_init(link1, b"before!!")
        check("channel allocated on the first connection",
              cid1 in server.channels, f"live: {len(server.channels)}")

        send(link1, struct.pack(">IBH", cid1, TYPE_INIT | CtapHidCommand.PING, 4) + b"ping")
        _, command, payload = read_message(link1)
        check("the first connection works", command == CtapHidCommand.PING
              and payload == b"ping")

        # Yank the cable.
        first.severed.set()

        # The server should notice, discard every channel, wait out the
        # reconnect interval and rediscover its device -- all by itself.
        deadline = time.monotonic() + 8.0
        while server.opened < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        check("server reopened the device after the disconnect",
              server.opened == 2, f"opened {server.opened} time(s)")
        check("every channel was invalidated on disconnect",
              len(server.channels) == 0,
              f"{len(server.channels)} channels survived: "
              f"{sorted(f'{c:08x}' for c in server.channels.channels)}")

        # A host reconnecting must be able to start over from scratch.
        cid2 = do_init(link2, b"after!!!")
        check("a fresh INIT works on the reconnected device", cid2 != CID_BROADCAST,
              f"got 0x{cid2:08x}")
        check("the new channel is usable", cid2 in server.channels)

        send(link2, struct.pack(">IBH", cid2, TYPE_INIT | CtapHidCommand.PING, 5) + b"alive")
        _, command, payload = read_message(link2)
        check("PING works after the reconnect",
              command == CtapHidCommand.PING and payload == b"alive")

        # And the stale channel is gone for good, not merely forgotten.
        send(link2, struct.pack(">IBH", cid1, TYPE_INIT | CtapHidCommand.PING, 2) + b"hi")
        _, command, payload = read_message(link2)
        check("the pre-disconnect channel -> ERR_INVALID_CHANNEL",
              command == CtapHidCommand.ERROR
              and payload == bytes([CtapHidError.INVALID_CHANNEL]),
              f"got cmd 0x{command:02x} {payload.hex()}")
    finally:
        server.stop()
        thread.join(timeout=5.0)


def main() -> int:
    # The error-path tests deliberately provoke warnings from the server. Those
    # are the feature working; keep them off the test's stdout.
    import logging

    logging.disable(logging.WARNING)

    print("CTAPHID offline end-to-end test")
    print(f"python-fido2 from {fido2.__file__}")
    print(f"loopback report size {REPORT_SIZE} bytes")

    test_init_handshake()
    test_init_resync_and_errors()
    test_channel_exhaustion()
    test_ping()
    test_cbor_getinfo()
    test_cbor_errors()
    test_protocol_errors()
    test_restart_and_recovery()
    test_idle_reclaim()
    test_disconnect_recovery()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nFailures:")
        for name, detail in FAILED:
            print(f"  - {name}" + (f": {detail}" if detail else ""))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
