#!/usr/bin/env python3
"""Windows-side CTAPHID test client for the Poco F7 authenticator.

Runs on Windows against the real USB device, using Yubico's python-fido2 as
the client library. It does not reimplement any part of the protocol: device
discovery, packet framing, channel handling, retries and CBOR decoding are all
python-fido2's, which is the point -- we are testing our authenticator against
an independent, widely deployed implementation, not against our own idea of
what the protocol says.

    pip install fido2
    python ctaphid_windows_test.py

MUST RUN ELEVATED. Since Windows 10 1903 the OS refuses raw CTAPHID access to
FIDO HID devices from non-Administrator processes -- a documented policy that
applies to every authenticator, including commercial security keys. Without
elevation python-fido2 sees no devices at all, because the handle it uses to
read the report descriptor cannot be opened. The script detects this and says
so rather than reporting a confusing "no device found".

Use --traffic to dump every packet sent and received in hex.
"""

from __future__ import annotations

import argparse
import ctypes
import logging
import struct
import subprocess
import sys
import time

try:
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from fido2.hid import CAPABILITY, CTAPHID, CtapHidDevice, list_descriptors
except ImportError:
    print("python-fido2 is required. Install it with:  pip install fido2")
    raise SystemExit(2)

#: Our development identity: the pid.codes test vendor ID, and PID 1.
VID = 0x1209
PID = 0x0001

#: FIDO usage page / usage, as Windows reports them.
FIDO_USAGE_PAGE = 0xF1D0
FIDO_USAGE = 0x0001

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def check(name: str, ok: bool, detail: str = "") -> bool:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def our_descriptors():
    """Every FIDO HID descriptor matching our VID/PID.

    ``list_descriptors`` is python-fido2's own Windows enumeration: it walks
    the HID class GUID via SetupAPI, opens each interface to read its report
    descriptor, and keeps the ones declaring usage page 0xF1D0 / usage 0x0001.
    """
    return [d for d in list_descriptors() if (d.vid, d.pid) == (VID, PID)]


def pnp_report() -> str:
    """Ask Windows' own PnP database what it thinks is attached.

    Used only when python-fido2 finds nothing, to distinguish "not enumerated"
    from "enumerated but not openable" -- two very different problems.
    """
    command = (
        "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InstanceId -like '*VID_1209*' } | "
        "Select-Object Status,Class,FriendlyName,InstanceId | Format-List"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as exc:  # noqa: BLE001
        return f"(could not query PnP: {exc})"
    return (result.stdout or "").strip() or "(no VID_1209 device present in the PnP database)"


def report_no_device() -> None:
    print("  no matching FIDO HID device was found.")
    print()
    print("  Windows PnP view:")
    for line in pnp_report().splitlines():
        print(f"    {line}")
    print()
    if not is_elevated():
        print("  This process is NOT elevated. Windows 10 1903 and later deny raw")
        print("  CTAPHID access to FIDO HID devices for non-Administrator processes,")
        print("  so python-fido2 cannot open the interface to read its descriptor and")
        print("  will report no devices. This affects every authenticator, including")
        print("  commercial security keys.")
        print()
        print("  Re-run this script from an Administrator terminal.")
    else:
        print("  This process IS elevated, so access denial is not the cause.")
        print("  Check that the phone still has the FIDO function provisioned and")
        print("  that /dev/hidg2 is being served.")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_discovery(descriptor) -> None:
    section("[1] Device discovery")
    all_descriptors = list(list_descriptors())
    print(f"  python-fido2 sees {len(all_descriptors)} CTAP HID device(s):")
    for d in all_descriptors:
        marker = "  <- ours" if (d.vid, d.pid) == (VID, PID) else ""
        print(f"    VID:PID {d.vid:04x}:{d.pid:04x}  {d.path!r}{marker}")

    check("target device discovered by VID/PID", True)
    print()
    print("  --- descriptor as Windows reports it ---")
    print(f"  product name     : {descriptor.product_name!r}")
    print(f"  serial number    : {descriptor.serial_number!r}")
    print(f"  report_size_in   : {descriptor.report_size_in}")
    print(f"  report_size_out  : {descriptor.report_size_out}")
    print(f"  device path      : {descriptor.path!r}")

    # python-fido2 subtracts a report ID byte from the HID capabilities before
    # storing these, so 64 here means Windows reported 65-byte reports -- i.e.
    # a 64-byte CTAPHID packet plus the report ID. A 63 would mean Windows
    # reported 64 and the library is expecting a byte our descriptor does not
    # define, which would mis-frame every packet. Worth asserting explicitly.
    check(
        "report_size_out is 64 (a full CTAPHID packet)",
        descriptor.report_size_out == 64,
        f"got {descriptor.report_size_out}",
    )
    check(
        "report_size_in is 64",
        descriptor.report_size_in == 64,
        f"got {descriptor.report_size_in}",
    )
    check("product name is populated", bool(descriptor.product_name))


def test_init() -> CtapHidDevice | None:
    section("[2] CTAPHID_INIT and channel allocation")
    descriptor = our_descriptors()[0]
    try:
        # Constructing CtapHidDevice performs the INIT exchange: an 8-byte
        # random nonce on the broadcast channel, then parsing of the reply.
        device = CtapHidDevice(descriptor, _open(descriptor))
    except Exception as exc:  # noqa: BLE001
        check("CTAPHID_INIT / channel allocation", False, f"{type(exc).__name__}: {exc}")
        return None

    check("CTAPHID_INIT succeeded and a channel was allocated", True)
    check("nonce was echoed (otherwise construction would have raised)", True)
    print()
    print(f"  allocated channel     : 0x{device._channel_id:08X}")
    print(f"  CTAPHID protocol ver  : {device.version}")
    print(f"  device version        : {'.'.join(str(v) for v in device.device_version)}")
    print(f"  capabilities          : 0x{device.capabilities:02x}"
          f" ({CAPABILITY(device.capabilities).name if device.capabilities else 'none'})")

    check("protocol version is 2", device.version == 2, f"got {device.version}")
    check(
        "CBOR capability advertised",
        bool(device.capabilities & CAPABILITY.CBOR),
        f"capabilities=0x{device.capabilities:02x}",
    )
    check(
        "WINK not advertised",
        not (device.capabilities & CAPABILITY.WINK),
        f"capabilities=0x{device.capabilities:02x}",
    )
    check(
        "channel is not the broadcast channel",
        device._channel_id != 0xFFFFFFFF,
        f"0x{device._channel_id:08X}",
    )
    return device


def _open(descriptor):
    from fido2.hid import open_connection
    return open_connection(descriptor)


def test_ping(device: CtapHidDevice) -> None:
    section("[3] CTAPHID_PING (transport, independent of CBOR)")

    def packets_for(payload: bytes) -> int:
        """How many 64-byte packets python-fido2 will send for this payload."""
        remaining = len(payload)
        if remaining == 0:
            return 1
        count = 1
        remaining -= min(remaining, 64 - 7)
        while remaining > 0:
            remaining -= min(remaining, 64 - 5)
            count += 1
        return count

    cases = [
        ("empty payload", b""),
        ("one byte", b"A"),
        ("exactly fills one packet (57)", b"B" * 57),
        ("one continuation packet (58)", b"C" * 58),
        ("several continuation packets (1000)", b"D" * 1000),
        ("maximum CTAPHID message (7609)", b"E" * 7609),
    ]
    for label, payload in cases:
        try:
            echoed = device.ping(payload)
        except Exception as exc:  # noqa: BLE001
            check(f"PING {label}", False, f"{type(exc).__name__}: {exc}")
            continue
        n_packets = packets_for(payload)
        check(
            f"PING {label} -> {len(payload)} bytes back in {n_packets} packet(s)",
            echoed == payload,
            f"sent {len(payload)}, got {len(echoed)}",
        )

    section("[4] Repeated requests on one channel")
    try:
        results = [device.ping(f"stress-{i:04d}".encode()) == f"stress-{i:04d}".encode()
                   for i in range(50)]
        check(f"50 sequential PINGs on channel 0x{device._channel_id:08X}",
              all(results), f"{results.count(False)} failed")
    except Exception as exc:  # noqa: BLE001
        check("50 sequential PINGs", False, f"{type(exc).__name__}: {exc}")


def test_getinfo(device: CtapHidDevice) -> None:
    section("[5] CTAPHID_CBOR -> authenticatorGetInfo")
    try:
        info = Ctap2(device).get_info()
    except Exception as exc:  # noqa: BLE001
        check("authenticatorGetInfo", False, f"{type(exc).__name__}: {exc}")
        return

    check("authenticatorGetInfo returned a decodable response", True)
    print()
    print("  --- GetInfo response ---")
    print(f"  versions     : {info.versions}")
    print(f"  aaguid       : {info.aaguid.hex()}  ({info.aaguid!r})")
    print(f"  options      : {info.options}")
    print(f"  max_msg_size : {info.max_msg_size}")
    print(f"  transports   : {info.transports}")
    print(f"  extensions   : {info.extensions}")

    check("FIDO_2_0 is a supported version", "FIDO_2_0" in info.versions,
          f"got {info.versions}")
    check("aaguid is 16 bytes", len(info.aaguid) == 16, f"got {len(info.aaguid)}")
    check("transports names usb", list(info.transports or []) == ["usb"],
          f"got {info.transports}")

    options = info.options or {}
    for option in ("rk", "uv", "clientPin", "up"):
        check(f"option {option!r} is not advertised as supported",
              not options.get(option, False), f"options={options}")

    # A second call on the same channel must give the same answer.
    try:
        again = Ctap2(device).get_info()
        check("repeated GetInfo returns the same values", again.aaguid == info.aaguid)
    except Exception as exc:  # noqa: BLE001
        check("repeated GetInfo", False, f"{type(exc).__name__}: {exc}")


def test_errors(device: CtapHidDevice) -> None:
    section("[6] Error handling")

    # An unsupported CTAPHID command: WINK is a real command we deliberately
    # do not implement and do not advertise.
    for name, command in (("WINK", CTAPHID.WINK), ("LOCK", CTAPHID.LOCK), ("MSG", CTAPHID.MSG)):
        try:
            device.call(command, b"")
            check(f"CTAPHID_{name} rejected", False, "no error raised")
        except CtapError as exc:
            check(f"CTAPHID_{name} -> CTAPHID_ERROR 0x{exc.code:02x}", exc.code == 0x01,
                  f"got 0x{exc.code:02x}")
        except Exception as exc:  # noqa: BLE001
            check(f"CTAPHID_{name} rejected", False, f"{type(exc).__name__}: {exc}")

    # An unsupported CTAP2 command byte. Note that CTAPHID is a transport: it
    # carries the status byte back without interpreting it, so the response is
    # a one-byte CTAPHID_CBOR message rather than an exception. Only the CTAP2
    # layer (Ctap2.send_cbor) turns a non-zero status into an error, and that
    # is checked separately below.
    for name, code in (("makeCredential", 0x01), ("getAssertion", 0x02),
                       ("clientPin", 0x06), ("credentialManagement", 0x0A),
                       ("unknown command 0x7f", 0x7F)):
        try:
            response = device.call(CTAPHID.CBOR, bytes([code]))
        except Exception as exc:  # noqa: BLE001
            check(f"CTAP2 {name} rejected", False, f"{type(exc).__name__}: {exc}")
            continue
        check(
            f"CTAP2 {name} -> status byte 0x01 (CTAP2_ERR_INVALID_COMMAND)",
            response == b"\x01",
            f"got {response.hex() if response else '(empty)'}",
        )

    # At the CTAP2 layer the same thing must surface as a CtapError, which is
    # what a relying-party client would actually see.
    try:
        Ctap2(device).send_cbor(0x01)
        check("Ctap2.send_cbor raises on an unsupported command", False,
              "no error raised")
    except CtapError as exc:
        check("Ctap2.send_cbor raises CtapError(0x01) for an unsupported command",
              exc.code == 0x01, f"got 0x{exc.code:02x}")
    except Exception as exc:  # noqa: BLE001
        check("Ctap2.send_cbor raises on an unsupported command", False,
              f"{type(exc).__name__}: {exc}")

    # The channel must still work after all of that.
    try:
        check("channel still usable after the error cases",
              device.ping(b"alive") == b"alive")
    except Exception as exc:  # noqa: BLE001
        check("channel still usable after the error cases", False,
              f"{type(exc).__name__}: {exc}")


def test_reconnect(descriptor) -> None:
    section("[7] Recovery after disconnect and reconnect")
    try:
        first = CtapHidDevice(descriptor, _open(descriptor))
        first_cid = first._channel_id
        check("initial connection", first.ping(b"before") == b"before")
    except Exception as exc:  # noqa: BLE001
        check("initial connection", False, f"{type(exc).__name__}: {exc}")
        return

    print("  closing the device handle...")
    try:
        first.close()
    except Exception as exc:  # noqa: BLE001
        print(f"    (close raised {type(exc).__name__}: {exc})")
    time.sleep(1.0)

    print("  reopening through Windows HID and re-running INIT...")
    try:
        second = CtapHidDevice(descriptor, _open(descriptor))
    except Exception as exc:  # noqa: BLE001
        check("reconnect and re-INIT", False, f"{type(exc).__name__}: {exc}")
        return

    check("reconnected and INIT allocated a channel", True)
    print(f"  previous channel 0x{first_cid:08X} -> new channel 0x{second._channel_id:08X}")
    try:
        check("PING works on the new connection", second.ping(b"after") == b"after")
        info = Ctap2(second).get_info()
        check("GetInfo works on the new connection", len(info.aaguid) == 16)
    except Exception as exc:  # noqa: BLE001
        check("connection usable after reconnect", False, f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--traffic", action="store_true",
                        help="log every CTAPHID packet sent and received, in hex")
    args = parser.parse_args()

    from fido2.utils import LOG_LEVEL_TRAFFIC

    logging.basicConfig(
        level=LOG_LEVEL_TRAFFIC if args.traffic else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("fido2").setLevel(
        LOG_LEVEL_TRAFFIC if args.traffic else logging.WARNING)

    print("Poco F7 CTAPHID authenticator -- Windows test client")
    print(f"python-fido2 {getattr(__import__('fido2'), '__version__', '(unknown version)')}")
    print(f"python {sys.version.split()[0]}  elevated={is_elevated()}")
    print(f"target VID:PID {VID:04x}:{PID:04x}"
          f"  (FIDO usage page 0x{FIDO_USAGE_PAGE:04X}, usage 0x{FIDO_USAGE:04X})")

    section("[0] Look for the device")
    found = our_descriptors()
    if not found:
        report_no_device()
        return 1

    descriptor = found[0]
    test_discovery(descriptor)

    device = test_init()
    if device is None:
        return 1
    try:
        test_ping(device)
        test_getinfo(device)
        test_errors(device)
    finally:
        try:
            device.close()
        except Exception:  # noqa: BLE001
            pass

    test_reconnect(descriptor)

    print(f"\n{'=' * 60}")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nFailures:")
        for name, detail in FAILED:
            print(f"  - {name}" + (f": {detail}" if detail else ""))
        return 1
    print("authenticatorGetInfo retrieved successfully over CTAPHID.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
