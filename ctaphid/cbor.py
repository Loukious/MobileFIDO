"""The slice of CBOR that CTAP2 needs, in pure Python.

Why hand-rolled: the daemon runs inside the Kali NetHunter chroot, whose
``python3`` has no ``cbor2``, and the whole point of this milestone is to add
no new dependencies to the phone. GetInfo needs a handful of CBOR types and
that is exactly what is implemented here -- no tags, no floats, no
indefinite-length items. Those raise rather than being silently mis-decoded.

Encoding follows the canonical form CTAP2 asks for: definite lengths
throughout, shortest possible argument encoding, and map keys sorted by their
encoded bytes. Decoding accepts any definite-length encoding, because a client
is not obliged to be canonical even if we are.

If this ever needs to grow beyond what GetInfo requires, replace it with
``cbor2`` rather than extending it -- the subset is a deliberate constraint, not
an accident.
"""

from __future__ import annotations

import struct
from typing import Any

# Major types, in the high three bits of the initial byte.
_UINT = 0
_NINT = 1
_BYTES = 2
_TEXT = 3
_ARRAY = 4
_MAP = 5
_TAG = 6
_SIMPLE = 7

# Simple values, in the low five bits of a _SIMPLE initial byte.
_FALSE = 20
_TRUE = 21
_NULL = 22

#: Depth limit while decoding. CTAP2 messages are shallow; this only exists so
#: that a hostile or corrupt message cannot blow the Python stack.
_MAX_DEPTH = 16


class CborError(ValueError):
    """A CBOR item was malformed, or outside the subset implemented here."""


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _head(major: int, argument: int) -> bytes:
    """Encode a major type and its argument using the shortest form."""
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument < 0x100:
        return bytes([(major << 5) | 24, argument])
    if argument < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", argument)
    if argument < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", argument)
    if argument < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", argument)
    raise CborError(f"integer {argument} does not fit in 64 bits")


def encode(value: Any) -> bytes:
    """Encode a Python value as canonical CBOR.

    Supported: ``int``, ``bytes``/``bytearray``, ``str``, ``list``/``tuple``,
    ``dict``, ``bool`` and ``None``. ``bool`` is checked before ``int``
    because Python makes ``bool`` a subclass of ``int``.
    """
    if value is False:
        return bytes([(_SIMPLE << 5) | _FALSE])
    if value is True:
        return bytes([(_SIMPLE << 5) | _TRUE])
    if value is None:
        return bytes([(_SIMPLE << 5) | _NULL])
    if isinstance(value, int):
        if value >= 0:
            return _head(_UINT, value)
        return _head(_NINT, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(_BYTES, len(value)) + bytes(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(_TEXT, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _head(_ARRAY, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        # Canonical CBOR orders map entries by the byte-wise ordering of their
        # encoded keys, not by the keys themselves. For the small integer keys
        # CTAP2 uses the two happen to coincide, but sorting the encoding is
        # the rule that stays correct if a text key is ever added.
        pairs = sorted((encode(k), encode(v)) for k, v in value.items())
        return _head(_MAP, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise CborError(f"cannot encode {type(value).__name__}")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.buf):
            raise CborError(
                f"truncated: wanted {count} bytes at offset {self.pos}, "
                f"only {len(self.buf) - self.pos} remain"
            )
        chunk = self.buf[self.pos:end]
        self.pos = end
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]


def _argument(reader: _Reader, info: int) -> int:
    """Read the argument that follows an initial byte."""
    if info < 24:
        return info
    if info == 24:
        return reader.byte()
    if info == 25:
        return struct.unpack(">H", reader.take(2))[0]
    if info == 26:
        return struct.unpack(">I", reader.take(4))[0]
    if info == 27:
        return struct.unpack(">Q", reader.take(8))[0]
    if info == 31:
        raise CborError("indefinite-length items are not supported")
    raise CborError(f"reserved additional information {info}")


def _decode(reader: _Reader, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise CborError("nesting too deep")

    initial = reader.byte()
    major, info = initial >> 5, initial & 0x1F

    if major == _UINT:
        return _argument(reader, info)
    if major == _NINT:
        return -1 - _argument(reader, info)
    if major == _BYTES:
        return reader.take(_argument(reader, info))
    if major == _TEXT:
        raw = reader.take(_argument(reader, info))
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CborError(f"invalid UTF-8 in text string: {exc}") from exc
    if major == _ARRAY:
        return [_decode(reader, depth + 1) for _ in range(_argument(reader, info))]
    if major == _MAP:
        count = _argument(reader, info)
        result = {}
        for _ in range(count):
            key = _decode(reader, depth + 1)
            if isinstance(key, (list, dict)):
                raise CborError("unhashable map key")
            result[key] = _decode(reader, depth + 1)
        return result
    if major == _TAG:
        raise CborError("tagged items are not supported")
    if major == _SIMPLE:
        if info == _FALSE:
            return False
        if info == _TRUE:
            return True
        if info == _NULL:
            return None
        raise CborError(f"simple value {info} is not supported")

    raise CborError(f"unknown major type {major}")


def decode(buf: bytes) -> Any:
    """Decode exactly one CBOR item, rejecting trailing bytes.

    Trailing data is an error rather than being ignored: in CTAP2 a request
    body should contain one map and nothing else, and silently ignoring extra
    bytes would hide a malformed message.
    """
    reader = _Reader(buf)
    value = _decode(reader, 0)
    if reader.pos != len(buf):
        raise CborError(f"{len(buf) - reader.pos} trailing byte(s) after the CBOR item")
    return value


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> None:
    # Round-trip every type GetInfo touches.
    for value in (
        {},
        {1: ["FIDO_2_0"]},
        {1: "FIDO_2_0", 3: bytes(range(16)), 4: {"rk": False, "up": False}},
        {5: 7609, 9: ["usb"]},
        [],
        [1, 2, 3],
        [b"\x00\x01", "text", True, False, None],
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        4294967296,
        -1,
        -24,
        -25,
        "unicode: é中文",
    ):
        encoded = encode(value)
        assert decode(encoded) == value, f"round-trip failed for {value!r}"

    # Shortest-form encoding: 23 stays one byte, 24 needs two.
    assert encode(23) == b"\x17"
    assert encode(24) == b"\x18\x18"

    # Canonical map key ordering is by encoded key bytes.
    assert encode({2: "b", 1: "a"}) == b"\xa2\x01\x61a\x02\x61b"

    # A GetInfo-shaped response survives a round trip intact.
    aaguid = b"PocoF7-CTAP2-DEV"
    assert len(aaguid) == 16, "development AAGUID must be exactly 16 bytes"
    info = {
        1: ["FIDO_2_0"],
        3: aaguid,
        4: {"rk": False, "up": False},
        5: 7609,
        9: ["usb"],
    }
    assert decode(encode(info)) == info

    # Malformed input raises CborError rather than returning something wrong.
    for bad, why in (
        (b"", "empty"),
        (b"\x18", "truncated argument"),
        (b"\x1f", "indefinite length"),
        (b"\x61", "truncated text"),
        (b"\x81", "truncated array"),
        (b"\x01\x01", "trailing bytes"),
        (b"\xc0\x00", "tag"),
        (b"\xfc", "unsupported simple value"),
    ):
        try:
            decode(bad)
        except CborError:
            pass
        else:
            raise AssertionError(f"{why} was accepted: {bad!r}")

    print("cbor selftest OK")


if __name__ == "__main__":
    _selftest()
