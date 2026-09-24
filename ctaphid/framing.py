"""CTAPHID packet framing.

Two layers live here, and it is worth keeping them separate in your head:

* **Packets** are what actually cross the USB wire. Exactly ``packet_size``
  bytes each (64 for this gadget). There are two shapes, told apart by bit 7 of
  the byte after the channel ID::

      initialization:  CID(4)  CMD|0x80(1)  LEN_H(1)  LEN_L(1)  DATA(<= n-7)
      continuation:    CID(4)  SEQ(1)                   DATA(<= n-5)

* **Messages** are the logical payloads (a PING body, a CTAP2 request) that get
  chopped into one initialization packet plus zero or more continuation
  packets, then glued back together at the far end.

Nothing here knows about USB, threads or the device node. The functions take
bytes and return bytes, which is what makes this testable without hardware and
what lets a Kotlin implementation reuse the same rules.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    CID_BROADCAST,
    CONT_HEADER_LENGTH,
    INIT_HEADER_LENGTH,
    MAX_SEQ,
    TYPE_INIT,
    max_message_size,
)


class FramingError(Exception):
    """A packet could not be parsed, or a message could not be framed."""


@dataclass(frozen=True)
class Packet:
    """One parsed packet off the wire.

    ``command`` is only meaningful when ``is_init`` is true -- otherwise the
    byte it came from is a sequence number and lives in ``seq``.
    """

    cid: int
    is_init: bool
    command: int
    seq: int
    data: bytes
    #: Length the host declared in an initialization packet. ``None`` for
    #: continuation packets, which do not carry one. Note that ``data`` is
    #: *not* truncated to this -- the host pads every report to the full packet
    #: size, and ``Transaction`` is what trims the padding away.
    expected_length: int | None = None
    #: Raw bytes as received, kept for logging and for error paths.
    raw: bytes = b""

    def describe(self) -> str:
        if self.is_init:
            return (
                f"INIT cid={self.cid:08x} cmd=0x{self.command:02x} "
                f"declared={self.expected_length}"
            )
        return f"CONT cid={self.cid:08x} seq={self.seq}"


def parse_packet(buf: bytes) -> Packet:
    """Parse one report read from the HID endpoint.

    ``buf`` must be at least :data:`INIT_HEADER_LENGTH` bytes -- that is the
    larger of the two headers, so checking it covers both shapes.
    """
    if len(buf) < INIT_HEADER_LENGTH:
        raise FramingError(f"packet too short: {len(buf)} bytes")

    cid = struct.unpack_from(">I", buf, 0)[0]
    marker = buf[4]

    if marker & TYPE_INIT:
        return Packet(
            cid=cid,
            is_init=True,
            command=marker & ~TYPE_INIT,
            seq=0,
            data=buf[INIT_HEADER_LENGTH:],
            expected_length=struct.unpack_from(">H", buf, 5)[0],
            raw=buf,
        )

    return Packet(
        cid=cid,
        is_init=False,
        command=0,
        seq=marker,
        data=buf[CONT_HEADER_LENGTH:],
        expected_length=None,
        raw=buf,
    )


def build_packets(cid: int, command: int, message: bytes, packet_size: int) -> list[bytes]:
    """Frame ``message`` into packets, each exactly ``packet_size`` bytes.

    The result always has at least one packet: a zero-length message still
    needs an initialization packet carrying ``LEN=0``, which is how an empty
    CTAPHID_PING is represented.
    """
    if packet_size < INIT_HEADER_LENGTH:
        raise FramingError(f"packet_size {packet_size} too small to hold a header")

    limit = max_message_size(packet_size)
    if len(message) > limit:
        raise FramingError(f"message of {len(message)} bytes exceeds the {limit}-byte maximum")

    packets: list[bytes] = []

    # Initialization packet.
    first_len = packet_size - INIT_HEADER_LENGTH
    head, remaining = message[:first_len], message[first_len:]
    header = struct.pack(">IBH", cid, TYPE_INIT | command, len(message))
    packets.append((header + head).ljust(packet_size, b"\0"))

    # Continuation packets, sequence numbers 0x00..0x7f.
    seq = 0
    body_len = packet_size - CONT_HEADER_LENGTH
    while remaining:
        if seq > MAX_SEQ:
            raise FramingError("message needs more than 128 continuation packets")
        chunk, remaining = remaining[:body_len], remaining[body_len:]
        cont_header = struct.pack(">IB", cid, seq & MAX_SEQ)
        packets.append((cont_header + chunk).ljust(packet_size, b"\0"))
        seq += 1

    return packets


def build_error(cid: int, error: int, packet_size: int) -> list[bytes]:
    """Frame a CTAPHID_ERROR response, which always carries one data byte."""
    return build_packets(cid, 0x3F, bytes([error]), packet_size)


@dataclass
class Transaction:
    """A message being reassembled from packets.

    Fed one initialization packet, then continuation packets in order. The
    caller is responsible for noticing that a transaction has gone quiet --
    see ``server.py``, which expires these on a timer.
    """

    cid: int
    command: int
    expected_length: int
    packet_size: int
    data: bytes = b""
    next_seq: int = 0
    started: float = 0.0
    #: Set once the final byte declared by ``expected_length`` has arrived.
    complete: bool = False

    @classmethod
    def start(cls, packet: Packet, packet_size: int, now: float) -> "Transaction":
        """Begin a transaction from an initialization packet.

        The first packet's payload is absorbed here rather than by a following
        :meth:`feed`, because it is the packet that *defines* the transaction.
        A message short enough to fit in one packet -- including the empty
        message, where the host declares length 0 -- comes back already
        ``complete``.
        """
        declared = packet.expected_length or 0
        if declared > max_message_size(packet_size):
            raise FramingError(
                f"declared length {declared} exceeds the "
                f"{max_message_size(packet_size)}-byte maximum"
            )

        txn = cls(
            cid=packet.cid,
            command=packet.command,
            expected_length=declared,
            packet_size=packet_size,
            started=now,
        )
        # Trim the host's zero padding: only `declared` bytes are real.
        txn.data = packet.data[:declared]
        if len(txn.data) >= declared:
            txn.complete = True
        return txn

    def feed(self, packet: Packet) -> None:
        """Append the payload of a continuation ``packet``.

        Raises :class:`FramingError` if the packet is out of sequence, which the
        caller turns into CTAPHID_ERROR(INVALID_SEQ).
        """
        if packet.is_init:
            raise FramingError("expected a continuation packet, got an initialization packet")
        if packet.seq != self.next_seq:
            raise FramingError(f"expected sequence {self.next_seq}, got {packet.seq}")

        self.next_seq += 1
        room = self.expected_length - len(self.data)
        self.data += packet.data[:room]

        if len(self.data) >= self.expected_length:
            self.complete = True


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> None:
    """Round-trip a few messages through the framer and reassembler.

    Deliberately dependency-free so it can run in a bare Python on either side.
    """
    size = 64
    for length in (0, 1, 57, 58, 63, 64, 200, 7609):
        cid = CID_BROADCAST
        msg = bytes((i * 7 + 3) & 0xFF for i in range(length))
        packets = build_packets(cid, 0x01, msg, size)
        for p in packets:
            assert len(p) == size, f"packet is {len(p)} bytes, expected {size}"

        first = parse_packet(packets[0])
        txn = Transaction.start(first, size, 0.0)
        for raw in packets[1:]:
            txn.feed(parse_packet(raw))
        assert txn.complete, f"{length}-byte message did not complete"
        assert txn.data == msg, f"{length}-byte message came back wrong"

    # Empty messages still produce exactly one packet.
    assert len(build_packets(1, 0x01, b"", size)) == 1

    # A message needing a continuation packet must actually produce one.
    assert len(build_packets(1, 0x01, b"z" * 58, size)) == 2

    # Oversized messages are rejected rather than silently truncated.
    try:
        build_packets(1, 0x01, b"x" * 7610, size)
    except FramingError:
        pass
    else:
        raise AssertionError("oversized message was accepted")

    # Out-of-order continuation packets are rejected.
    packets = build_packets(1, 0x01, b"y" * 200, size)
    first = parse_packet(packets[0])
    txn = Transaction.start(first, size, 0.0)
    try:
        txn.feed(parse_packet(packets[2]))
    except FramingError:
        pass
    else:
        raise AssertionError("out-of-order continuation was accepted")

    # An initialization packet arriving mid-transaction means the host
    # restarted the message. The reassembler refuses it rather than silently
    # splicing two different messages together; deciding to abandon the old
    # transaction is the server's job, not the framer's.
    txn2 = Transaction.start(parse_packet(packets[0]), size, 0.0)
    try:
        txn2.feed(parse_packet(packets[0]))
    except FramingError:
        pass
    else:
        raise AssertionError("initialization packet accepted mid-transaction")

    # A declared length larger than the transport allows is refused at start.
    bogus = bytearray(size)
    struct.pack_into(">IBH", bogus, 0, 1, TYPE_INIT | 0x01, 0xFFFF)
    try:
        Transaction.start(parse_packet(bytes(bogus)), size, 0.0)
    except FramingError:
        pass
    else:
        raise AssertionError("oversized declared length was accepted")

    print(f"framing selftest OK (max message {max_message_size(size)} bytes)")


if __name__ == "__main__":
    _selftest()
