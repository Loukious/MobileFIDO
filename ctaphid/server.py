"""The CTAPHID main loop.

Reads reports from the gadget, reassembles them into messages, dispatches, and
frames the answers back. One thread owns the gadget, while backend CBOR calls
run in cancellable workers -- see "liveness" below.

Message flow
------------
An incoming packet is first sorted by channel:

* **broadcast** -- only CTAPHID_INIT may arrive here. Anything else gets
  ``ERR_INVALID_CHANNEL``, because no host is ever *given* the broadcast
  channel and so nothing else can legitimately be addressed to it.
* **an allocated channel** -- normal dispatch. CTAPHID_INIT here is a
  resynchronisation; every other command starts (or continues) a transaction.
* **anything else** -- ``ERR_INVALID_CHANNEL`` on that channel. This is the
  case where a host kept using a channel after we dropped it, which happens
  after a re-enumeration, and the error tells it to re-INIT.

Liveness
--------
The brief asks explicitly for no deadlocks if Windows disconnects or a
transaction is interrupted, so nothing here blocks indefinitely:

* reads use a bounded ``select`` timeout, so the loop keeps turning even when
  the host has gone quiet, and a disconnect is noticed promptly;
* a transaction that stops making progress is expired and answered with
  ``ERR_MSG_TIMEOUT`` rather than being left to hang the host's read loop --
  python-fido2's read has no timeout of its own, so silence would hang it
  forever;
* writes have their own deadline, and a write that cannot complete is treated
  as a disconnect rather than retried indefinitely;
* abandoned channels are reclaimed after ``IDLE_TIMEOUT_SECONDS`` so that a
  host crashing repeatedly cannot exhaust the channel table permanently;
* channels in the middle of reassembly or backend execution are pinned against
  idle reclamation, and backend execution is bounded by ``CBOR_TIMEOUT_SECONDS``.
"""

from __future__ import annotations

import inspect
import logging
import math
import queue
import signal
import struct
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from . import framing
from .backend import AuthenticatorBackend
from .channels import ChannelTable
from .constants import (
    CID_BROADCAST,
    COMMAND_NAMES,
    CTAPHID_PROTOCOL_VERSION,
    DEVICE_VERSION,
    ERROR_NAMES,
    SUPPORTED_CAPABILITIES,
    Capability,
    CtapHidCommand,
    CtapHidError,
)
from .transport import (
    DEFAULT_CONFIGFS_ROOT,
    Disconnected,
    HidGadget,
    HidGadgetTransport,
    TransportError,
    wait_for_gadget,
)

log = logging.getLogger("ctaphid.server")

#: How long a single ``select`` waits before the loop comes back around to
#: check for expired transactions and for a shutdown request.
PACKET_TIMEOUT_SECONDS = 0.25

#: How long a partially received message may stall before it is abandoned.
#: python-fido2 writes every packet of a request back to back, so a gap this
#: long means the host is gone or the message was truncated on purpose.
TRANSACTION_TIMEOUT_SECONDS = 5.0

#: Pause before re-running discovery after the gadget disappears.
RECONNECT_INTERVAL_SECONDS = 1.0

# A backend may await a local physical approval; the USB loop must keep
# servicing CANCEL and send keepalives for the entire wait.
KEEPALIVE_INTERVAL_SECONDS = 0.25
CBOR_TIMEOUT_SECONDS = 30.0
KEEPALIVE_PROCESSING = 0x01
KEEPALIVE_UP_NEEDED = 0x02


@dataclass
class ActiveCbor:
    """One backend call; only the USB loop mutates the active-channel map."""

    cid: int
    started: float
    next_keepalive: float
    cancel_event: threading.Event = field(default_factory=threading.Event)
    awaiting_approval: threading.Event = field(default_factory=threading.Event)


class CtapHidServer:
    """A CTAPHID responder bound to one HID gadget."""

    def __init__(
        self,
        backend: AuthenticatorBackend,
        configfs_root: str = DEFAULT_CONFIGFS_ROOT,
        device: str | None = None,
        packet_timeout: float = PACKET_TIMEOUT_SECONDS,
        transaction_timeout: float = TRANSACTION_TIMEOUT_SECONDS,
        idle_timeout: float | None = None,
        max_channels: int | None = None,
        approval: Callable[..., bool] | None = None,
        cbor_timeout: float = CBOR_TIMEOUT_SECONDS,
        keepalive_interval: float = KEEPALIVE_INTERVAL_SECONDS,
    ):
        self.backend = backend
        self.configfs_root = configfs_root
        self.device = device
        self.packet_timeout = packet_timeout
        self.transaction_timeout = transaction_timeout
        self.approval = approval
        self.cbor_timeout = cbor_timeout
        self.keepalive_interval = keepalive_interval
        if cbor_timeout <= 0 or keepalive_interval <= 0:
            raise ValueError("CBOR and keepalive timeouts must be positive")

        channel_kwargs = {}
        if idle_timeout is not None:
            channel_kwargs["idle_timeout"] = idle_timeout
        if max_channels is not None:
            channel_kwargs["max_channels"] = max_channels
        self.channels = ChannelTable(**channel_kwargs)
        if self.channels.max_channels < 1:
            raise ValueError("max_channels must be positive")

        #: Channel ID -> transaction being reassembled.
        self.pending: dict[int, framing.Transaction] = {}
        self.active: dict[int, ActiveCbor] = {}
        self._completed: queue.SimpleQueue[tuple[ActiveCbor, bytes | None, Exception | None]] = queue.SimpleQueue()
        # A host can cancel/re-INIT repeatedly while an uncooperative backend
        # still runs. Cap detached workers so they cannot consume all memory.
        self._worker_slots = threading.BoundedSemaphore(self.channels.max_channels)
        signature = inspect.signature(backend.handle_cbor)
        parameters = signature.parameters
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())
        self._accepts_approval = "approval" in parameters or accepts_kwargs
        self._accepts_cancel = "cancel_event" in parameters or accepts_kwargs
        self._accepts_up_signal = "set_up_needed" in parameters or accepts_kwargs
        self.stats: Counter[str] = Counter()
        self._stop = threading.Event()
        self._gadget: HidGadget | None = None

    # -- lifecycle ----------------------------------------------------------

    def stop(self) -> None:
        """Ask the loop to exit at the next opportunity."""
        self._stop.set()

    def request_stop(self, *_args) -> None:
        """Signal handler. Setting an Event is async-signal-safe; the loop
        notices it on its next pass and shuts down cleanly."""
        self.stop()

    def run(self) -> None:
        """Serve forever, recovering from disconnects.

        A disconnect is not fatal. The gadget is unbound and rebound by the
        vendor USB HAL on its own schedule, and by our own provisioning
        scripts, so losing it is routine and the loop simply rediscovers it --
        possibly at a different ``/dev/hidgN`` -- and carries on.
        """
        while not self._stop.is_set():
            try:
                self._serve_forever()
            except Disconnected as exc:
                if self._stop.is_set():
                    break
                log.warning("gadget disconnected: %s", exc)
                self._stop.wait(RECONNECT_INTERVAL_SECONDS)
            except TransportError as exc:
                if self._stop.is_set():
                    break
                log.error("transport error: %s", exc)
                self._stop.wait(RECONNECT_INTERVAL_SECONDS)

        log.info("server stopped; %s", self._stats_summary())

    def _serve_forever(self) -> None:
        transport = self._open_transport()
        try:
            self._loop(transport)
        finally:
            transport.close()

    def _open_transport(self) -> HidGadgetTransport:
        """Discover and open the gadget.

        Split out so that the protocol loop can be exercised without hardware
        by substituting a transport that is not attached to a device.
        """
        gadget = wait_for_gadget(self.configfs_root, self.device)
        self._gadget = gadget
        transport = HidGadgetTransport(gadget)
        transport.open()
        log.info("serving CTAPHID on %s", gadget.describe())
        return transport

    def _loop(self, transport: HidGadgetTransport) -> None:
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                self._service_completed(transport)
                self._expire(transport, now)

                # Only this thread accesses the transport, including writes.
                # Shorten the read wait when a keepalive is due.
                wait = self.packet_timeout
                if self.active:
                    wait = min(wait, max(0.0, min(
                        tx.next_keepalive for tx in self.active.values()
                    ) - time.monotonic()))
                packet_bytes = transport.read_packet(wait)
                if packet_bytes is None:
                    continue

                try:
                    packet = framing.parse_packet(packet_bytes)
                except framing.FramingError as exc:
                    self.stats["malformed_packet"] += 1
                    log.warning("discarding malformed report (%d bytes): %s",
                                len(packet_bytes), exc)
                    continue

                try:
                    self._handle_packet(transport, packet)
                except TransportError as exc:
                    log.warning("could not deliver a response: %s", exc)
                    raise
        finally:
            # Invalidate in-flight work before the USB connection can reopen.
            # Late worker completions are ignored by identity on the next loop.
            for tx in self.active.values():
                tx.cancel_event.set()
            self.active.clear()
            self.pending.clear()
            # A write failure can indicate a reset too. Clearing on *every*
            # transport-loop exit ensures no stale CID crosses a reconnect.
            dropped = self.channels.clear()
            if dropped:
                log.info("dropped %d channel(s) after transport closure", dropped)

    # -- expiry -------------------------------------------------------------

    def _expire(self, transport: HidGadgetTransport, now: float) -> None:
        """Abandon stalled transactions and reclaim idle channels."""
        for cid, transaction in list(self.pending.items()):
            if now - transaction.started > self.transaction_timeout:
                del self.pending[cid]
                self.channels.unpin(cid)
                self.stats["transaction_timeout"] += 1
                log.warning(
                    "transaction on cid %08x (%s) stalled after %.1fs with %d of %d "
                    "bytes; answering ERR_MSG_TIMEOUT",
                    cid,
                    COMMAND_NAMES.get(transaction.command, hex(transaction.command)),
                    now - transaction.started,
                    len(transaction.data),
                    transaction.expected_length,
                )
                # Answering is deliberate. A host waiting on this channel has
                # no receive timeout of its own, so staying silent would hang
                # it rather than let it recover.
                self._send_error(transport, cid, CtapHidError.MSG_TIMEOUT)

        for cid, transaction in list(self.active.items()):
            if now - transaction.started > self.cbor_timeout:
                self._cancel_active(cid)
                self.stats["cbor_timeout"] += 1
                log.warning("CBOR on cid %08x exceeded %.1fs", cid, self.cbor_timeout)
                self._send_error(transport, cid, CtapHidError.MSG_TIMEOUT)
            elif now >= transaction.next_keepalive:
                status = (KEEPALIVE_UP_NEEDED if transaction.awaiting_approval.is_set()
                          else KEEPALIVE_PROCESSING)
                self._send(transport, cid, CtapHidCommand.KEEPALIVE, bytes([status]))
                transaction.next_keepalive = now + self.keepalive_interval

        for cid in self.channels.expire(now):
            self.pending.pop(cid, None)
            self.stats["channel_expired"] += 1
            log.info("reclaimed idle channel %08x", cid)

    # -- packet handling ----------------------------------------------------

    def _handle_packet(self, transport: HidGadgetTransport, packet: framing.Packet) -> None:
        now = time.monotonic()

        if packet.is_init:
            self._handle_init_packet(transport, packet, now)
        else:
            self._handle_continuation(transport, packet, now)

    def _handle_init_packet(
        self, transport: HidGadgetTransport, packet: framing.Packet, now: float
    ) -> None:
        cid = packet.cid
        command = packet.command

        if cid == CID_BROADCAST:
            # Only INIT is addressable here. A host is never handed the
            # broadcast channel, so nothing else can legitimately arrive.
            if command != CtapHidCommand.INIT:
                self.stats["command_on_broadcast"] += 1
                log.warning(
                    "command 0x%02x arrived on the broadcast channel; only INIT is valid there",
                    command,
                )
                self._send_error(transport, cid, CtapHidError.INVALID_CHANNEL)
                return
        else:
            channel = self.channels.get(cid)
            if channel is None:
                # Unknown channel: the host is out of sync, most likely
                # because it kept a channel across a re-enumeration. Tell it
                # so it can re-INIT rather than ignoring the packet and
                # leaving it waiting.
                self.stats["invalid_channel"] += 1
                log.warning("packet for unallocated channel %08x (cmd 0x%02x)",
                            cid, command)
                self._send_error(transport, cid, CtapHidError.INVALID_CHANNEL)
                return
            channel.touch(now)

            if cid in self.active:
                # CTAPHID_INIT resynchronises and CANCEL aborts; any other
                # command while CBOR is underway must leave it intact.
                if command == CtapHidCommand.INIT:
                    self._cancel_active(cid)
                elif command != CtapHidCommand.CANCEL:
                    self.stats["channel_busy"] += 1
                    self._send_error(transport, cid, CtapHidError.CHANNEL_BUSY)
                    return

        # An initialization packet always begins a new message. If one was
        # already in flight on this channel the host has restarted, so the old
        # one is abandoned. The alternative -- answering ERR_CHANNEL_BUSY --
        # would deadlock a host that is retrying a message it half-sent.
        previous = self.pending.pop(cid, None)
        if previous is not None:
            self.channels.unpin(cid)
            self.stats["transaction_restarted"] += 1
            log.info(
                "restarting message on cid %08x: %s replaced by %s",
                cid,
                COMMAND_NAMES.get(previous.command, hex(previous.command)),
                COMMAND_NAMES.get(command, hex(command)),
            )

        try:
            transaction = framing.Transaction.start(packet, transport.report_length, now)
        except framing.FramingError as exc:
            self.stats["invalid_length"] += 1
            log.warning("rejecting initialization packet on cid %08x: %s", cid, exc)
            self._send_error(transport, cid, CtapHidError.INVALID_LEN)
            return

        self._log_packet("<-", packet)

        if transaction.complete:
            self._dispatch(transport, cid, command, transaction.data, now)
        else:
            self.pending[cid] = transaction
            self.channels.pin(cid)

    def _handle_continuation(
        self, transport: HidGadgetTransport, packet: framing.Packet, now: float
    ) -> None:
        cid = packet.cid
        transaction = self.pending.get(cid)

        if transaction is None:
            if cid in self.active:
                self._send_error(transport, cid, CtapHidError.CHANNEL_BUSY)
                return
            # A continuation with nothing to continue. Usually the tail of a
            # message whose head was lost, or a duplicate delivered after the
            # transaction already completed.
            self.stats["orphan_continuation"] += 1
            log.warning("continuation packet seq=%d on cid %08x with no transaction in "
                        "flight", packet.seq, cid)
            if cid in self.channels or cid == CID_BROADCAST:
                self._send_error(transport, cid, CtapHidError.INVALID_SEQ)
            else:
                self._send_error(transport, cid, CtapHidError.INVALID_CHANNEL)
            return

        self._log_packet("<-", packet)
        self.channels.touch(cid, now)

        try:
            transaction.feed(packet)
        except framing.FramingError as exc:
            # Out-of-sequence. The message is unrecoverable -- there is no way
            # to know what was missed -- so drop it and say why.
            del self.pending[cid]
            self.channels.unpin(cid)
            self.stats["invalid_seq"] += 1
            log.warning("bad continuation on cid %08x: %s", cid, exc)
            self._send_error(transport, cid, CtapHidError.INVALID_SEQ)
            return

        if transaction.complete:
            del self.pending[cid]
            self.channels.unpin(cid)
            self._dispatch(transport, cid, transaction.command, transaction.data, now)

    # -- dispatch -----------------------------------------------------------

    def _dispatch(
        self,
        transport: HidGadgetTransport,
        cid: int,
        command: int,
        message: bytes,
        now: float,
    ) -> None:
        name = COMMAND_NAMES.get(command, f"0x{command:02x}")
        self.stats[f"command_{name}"] += 1
        log.info("dispatch %s on cid %08x (%d bytes)", name, cid, len(message))

        if command == CtapHidCommand.INIT:
            self._handle_init(transport, cid, message, now)
        elif command == CtapHidCommand.PING:
            # Echo the payload byte for byte. Deliberately not length-checked
            # against anything: the whole point of PING is that whatever the
            # transport can carry comes back unchanged.
            self._send(transport, cid, CtapHidCommand.PING, message)
        elif command == CtapHidCommand.CBOR:
            self._start_cbor(transport, cid, message, now)
        elif command == CtapHidCommand.CANCEL:
            self._handle_cancel(transport, cid)
        else:
            # CTAPHID_MSG, CTAPHID_LOCK, CTAPHID_WINK, vendor commands, and
            # anything unrecognised. None are implemented and none are
            # advertised as capabilities, so INVALID_CMD is the correct and
            # honest answer.
            log.info("unsupported CTAPHID command %s on cid %08x; answering ERR_INVALID_CMD",
                     name, cid)
            self._send_error(transport, cid, CtapHidError.INVALID_CMD)

    def _start_cbor(
        self, transport: HidGadgetTransport, cid: int, message: bytes, now: float
    ) -> None:
        """Run a CBOR request off the USB thread, with bounded worker count."""
        if not self._worker_slots.acquire(blocking=False):
            self.stats["worker_busy"] += 1
            self._send_error(transport, cid, CtapHidError.CHANNEL_BUSY)
            return

        transaction = ActiveCbor(cid, now, now + self.keepalive_interval)
        self.active[cid] = transaction
        self.channels.pin(cid)

        def execute() -> None:
            response: bytes | None = None
            error: Exception | None = None
            try:
                kwargs = {}
                if self._accepts_cancel:
                    kwargs["cancel_event"] = transaction.cancel_event
                if self._accepts_up_signal:
                    def set_up_needed(needed: bool) -> None:
                        if needed:
                            transaction.awaiting_approval.set()
                        else:
                            transaction.awaiting_approval.clear()
                    kwargs["set_up_needed"] = set_up_needed
                if self._accepts_approval and self.approval is not None:
                    def await_approval(*args, **approval_kwargs):
                        if transaction.cancel_event.is_set():
                            return False
                        transaction.awaiting_approval.set()
                        try:
                            return bool(self.approval(*args, **approval_kwargs))
                        finally:
                            transaction.awaiting_approval.clear()
                    kwargs["approval"] = await_approval

                response = self.backend.handle_cbor(message, **kwargs)
            except Exception as exc:
                error = exc
            finally:
                # The USB loop alone may send reports or edit active channels.
                self._completed.put((transaction, response, error))
                self._worker_slots.release()

        try:
            threading.Thread(
                target=execute, name=f"ctaphid-cbor-{cid:08x}", daemon=True
            ).start()
        except (RuntimeError, OSError) as exc:
            # Thread.start may fail under resource pressure. No worker owns the
            # slot yet, so return it and let the channel accept another request.
            self._worker_slots.release()
            self.active.pop(cid, None)
            self.channels.unpin(cid)
            self.stats["worker_start_error"] += 1
            log.error("could not start CBOR worker on cid %08x: %s", cid, exc)
            self._send_error(transport, cid, CtapHidError.OTHER)

    def _cancel_active(self, cid: int) -> bool:
        transaction = self.active.pop(cid, None)
        if transaction is None:
            return False
        transaction.cancel_event.set()
        self.channels.unpin(cid)
        return True

    def _service_completed(self, transport: HidGadgetTransport) -> None:
        """Flush worker results on the sole transport-owning thread."""
        while True:
            try:
                transaction, response, error = self._completed.get_nowait()
            except queue.Empty:
                return
            if self.active.get(transaction.cid) is not transaction:
                # CANCEL, INIT, timeout or disconnect superseded this work.
                self.stats["discarded_cbor_result"] += 1
                continue
            self.active.pop(transaction.cid)
            self.channels.unpin(transaction.cid)
            if error is not None or not isinstance(response, bytes):
                log.error("CBOR backend failed on cid %08x: %s", transaction.cid,
                          error if error is not None else "non-bytes response")
                self.stats["backend_error"] += 1
                self._send_error(transport, transaction.cid, CtapHidError.OTHER)
            else:
                try:
                    self._send(transport, transaction.cid, CtapHidCommand.CBOR, response)
                except framing.FramingError as exc:
                    self.stats["backend_error"] += 1
                    log.error("CBOR backend response could not be framed: %s", exc)
                    self._send_error(transport, transaction.cid, CtapHidError.OTHER)

    def _handle_init(
        self, transport: HidGadgetTransport, cid: int, message: bytes, now: float
    ) -> None:
        """Answer CTAPHID_INIT.

        The response goes out on the channel the request arrived on, *not* on
        the channel being handed out -- the new ID travels inside the payload.
        That is what makes the resynchronisation case work: a host that sends
        INIT on a channel it already holds gets its reply on that same channel,
        so it never has to change where it is listening. python-fido2 depends
        on this, checking the reply's channel against the one it sent to.
        """
        if len(message) != 8:
            self.stats["init_bad_nonce"] += 1
            log.warning("INIT carried a %d-byte nonce, expected 8", len(message))
            self._send_error(transport, cid, CtapHidError.INVALID_LEN)
            return

        if cid == CID_BROADCAST:
            allocated = self.channels.allocate(now)

            if allocated is None:
                # The table is full. Rather than making the host wait out the
                # idle timeout, reclaim the channel nobody is using: it is the
                # least-recently-used one by definition, so no live conversation
                # is interrupted, and its owner recovers by re-INITing. See
                # ChannelTable.evict_lru.
                victim = self.channels.evict_lru()
                if victim is not None:
                    self.stats["channel_evicted"] += 1
                    # Drop any half-assembled message along with it, or the
                    # transaction would outlive the channel it belongs to.
                    self.pending.pop(victim, None)
                    log.info("channel table full; evicted least-recently-used "
                             "channel %08x to serve a new INIT", victim)
                    allocated = self.channels.allocate(now)

            if allocated is None:
                self.stats["channel_busy"] += 1
                log.warning("all %d channels are in use; refusing INIT",
                            len(self.channels))
                self._send_error(transport, cid, CtapHidError.CHANNEL_BUSY)
                return
            new_cid = allocated
            self.stats["channel_allocated"] += 1
            log.info("allocated channel %08x (%d of %d in use)",
                     new_cid, len(self.channels), self.channels.max_channels)
        else:
            # Already allocated: resynchronise rather than allocate. Handing
            # back a different ID here would strand the host, which is still
            # listening on this one.
            self.channels.touch(cid, now)
            new_cid = cid
            self.stats["channel_resync"] += 1
            log.info("channel %08x resynchronised", cid)

        payload = message + struct.pack(
            ">IBBBBB",
            new_cid,
            CTAPHID_PROTOCOL_VERSION,
            DEVICE_VERSION[0],
            DEVICE_VERSION[1],
            DEVICE_VERSION[2],
            int(SUPPORTED_CAPABILITIES),
        )
        self._send(transport, cid, CtapHidCommand.INIT, payload)

    def _handle_cancel(self, transport: HidGadgetTransport, cid: int) -> None:
        """Cancel partial or executing work without sending a response."""
        dropped = self.pending.pop(cid, None)
        if dropped is not None:
            self.channels.unpin(cid)
        running = self._cancel_active(cid)
        self.stats["cancel"] += 1
        if running:
            log.info("CANCEL on cid %08x aborted active CBOR", cid)
        elif dropped is None:
            log.info("CANCEL on cid %08x with nothing in flight", cid)
        else:
            name = COMMAND_NAMES.get(dropped.command, hex(dropped.command))
            log.info("CANCEL on cid %08x discarded a partial %s (%d of %d bytes)",
                     cid, name, len(dropped.data), dropped.expected_length)

    # -- output -------------------------------------------------------------

    def _send(
        self, transport: HidGadgetTransport, cid: int, command: int, payload: bytes
    ) -> None:
        packets = framing.build_packets(cid, command, payload, transport.report_length)
        transport.write_packets(packets)
        name = COMMAND_NAMES.get(command, f"0x{command:02x}")
        # A waiting user can generate hundreds of KEEPALIVE reports; logging
        # every one at INFO buries the actual registration/audit events.
        log.log(logging.DEBUG if command == CtapHidCommand.KEEPALIVE else logging.INFO,
                "-> %s on cid %08x (%d bytes in %d packet(s))",
                name, cid, len(payload), len(packets))
        if log.isEnabledFor(logging.DEBUG):
            for index, packet in enumerate(packets):
                log.debug("-> pkt[%d/%d] %s", index + 1, len(packets), packet.hex())

    def _send_error(
        self, transport: HidGadgetTransport, cid: int, error: CtapHidError
    ) -> None:
        name = ERROR_NAMES.get(int(error), hex(int(error)))
        log.info("-> ERROR %s on cid %08x", name, cid)
        packets = framing.build_packets(
            cid, CtapHidCommand.ERROR, bytes([int(error)]), transport.report_length
        )
        transport.write_packets(packets)

    # -- logging helpers ----------------------------------------------------

    def _log_packet(self, arrow: str, packet: framing.Packet) -> None:
        """Log a received packet.

        At INFO this is shape only -- channel, command, how many bytes -- which
        is what a protocol trace needs. The bytes themselves are DEBUG-only:
        once this authenticator handles credentials there will be material on
        this wire that should not land in a default log, and it is easier to
        keep that line in place from the start than to add it later.
        """
        if packet.is_init:
            log.info(
                "%s INIT cid=%08x cmd=0x%02x %s declared=%d",
                arrow, packet.cid, packet.command,
                COMMAND_NAMES.get(packet.command, "?"), packet.expected_length,
            )
        else:
            log.debug("%s CONT cid=%08x seq=%d", arrow, packet.cid, packet.seq)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("%s raw %s", arrow, packet.raw.hex())

    def _stats_summary(self) -> str:
        if not self.stats:
            return "no traffic"
        interesting = ", ".join(f"{key}={value}" for key, value in sorted(self.stats.items()))
        return interesting


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_server(args) -> CtapHidServer:
    """Construct a server from parsed command-line arguments."""
    from .backend import GetInfoBackend

    # The backend's idea of the maximum message size has to match the framing
    # layer's. Discovery is the only thing that knows the real report length,
    # so resolve it first and fall back to the default if the gadget is not up
    # yet -- the server will rediscover at startup anyway and the two only need
    # to agree once a device is actually open.
    try:
        gadget = wait_for_gadget(args.configfs_root, args.device, timeout=0.1)
        packet_size = gadget.report_length
    except TransportError:
        packet_size = 64
        log.warning("gadget not present yet; assuming %d-byte reports for GetInfo",
                    packet_size)

    approval = None
    if getattr(args, "android_helper", False):
        if args.development_store or args.presence != "none":
            raise ValueError("--android-helper cannot be combined with --development-store or --presence")
        helper_uid = getattr(args, "android_helper_uid", None)
        if type(helper_uid) is not int or helper_uid < 10000:
            raise ValueError("--android-helper requires --android-helper-uid (installed APK UID)")
        from .android_backend import AndroidBackend
        backend = AndroidBackend(
            socket_name=args.android_socket,
            packet_size=packet_size,
            rpc_timeout=args.android_timeout,
            allowed_rp_ids={"localhost"},
            expected_helper_uid=helper_uid,
        )
        log.warning("Android Keystore helper mode enabled: RP limited to localhost; helper owns key storage and biometric UI")
    elif args.development_store:
        from .approval import VolumeUpApproval, find_phone_keypad
        from .dev_backend import DevCredentialBackend

        # Refuse to operate as a sign-capable authenticator without a fresh
        # physical user-presence check.  Never silently enable a test bypass.
        if args.presence != "volume-up":
            raise ValueError("development credentials require --presence volume-up")
        if not math.isfinite(args.presence_timeout) or args.presence_timeout <= 0:
            raise ValueError("--presence-timeout must be a positive finite number")
        keypad = find_phone_keypad()
        log.warning("DEVELOPMENT ONLY: unencrypted software keys; physical approval via %s", keypad)
        approval = VolumeUpApproval(timeout=args.presence_timeout)
        backend = DevCredentialBackend(
            args.development_store, packet_size=packet_size,
            allowed_rp_ids={"localhost"},
        )
    else:
        if args.presence != "none":
            raise ValueError("--presence requires --development-store")
        backend = GetInfoBackend(packet_size=packet_size)
    return CtapHidServer(
        backend,
        approval=approval,
        cbor_timeout=(max(CBOR_TIMEOUT_SECONDS, args.android_timeout + 5.0)
                      if getattr(args, "android_helper", False) else
                      max(CBOR_TIMEOUT_SECONDS, args.presence_timeout + 5.0)
                      if args.development_store else CBOR_TIMEOUT_SECONDS),
        configfs_root=args.configfs_root,
        device=args.device,
        transaction_timeout=args.transaction_timeout,
        idle_timeout=args.idle_timeout,
        max_channels=args.max_channels,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Serve CTAPHID over the FIDO HID gadget.",
    )
    parser.add_argument(
        "--configfs-root",
        default=DEFAULT_CONFIGFS_ROOT,
        help=f"composite gadget directory (default: {DEFAULT_CONFIGFS_ROOT})",
    )
    parser.add_argument(
        "--device",
        default=None,
        help="use this device node instead of discovering it from ConfigFS",
    )
    parser.add_argument(
        "--transaction-timeout",
        type=float,
        default=TRANSACTION_TIMEOUT_SECONDS,
        help="seconds a partial message may stall before it is abandoned",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=None,
        help="seconds before an unused channel is reclaimed (0 disables)",
    )
    parser.add_argument(
        "--max-channels",
        type=int,
        default=None,
        help="how many channels may be live at once",
    )
    parser.add_argument(
        "--development-store", metavar="PATH", default=None,
        help="enable LOCALHOST-ONLY development makeCredential/GetAssertion using software keys at PATH",
    )
    parser.add_argument(
        "--android-helper", action="store_true",
        help="use Android Keystore/BiometricPrompt helper; fail closed if app IPC is unavailable",
    )
    parser.add_argument(
        "--android-socket", default="ctaphid-m3b-v1",
        help="AF_UNIX abstract name of the root-checked Android helper socket",
    )
    parser.add_argument(
        "--android-helper-uid", type=int, default=None,
        help="trusted installed org.pocof7.ctap3b app Linux UID; required with --android-helper",
    )
    parser.add_argument(
        "--android-timeout", type=float, default=28.0,
        help="Android helper RPC timeout in seconds (default 28)",
    )
    parser.add_argument(
        "--presence", choices=("none", "volume-up"), default="none",
        help="require an actual Poco F7 physical Volume Up press per credential operation",
    )
    parser.add_argument(
        "--presence-timeout", type=float, default=25.0,
        help="seconds to wait for phone physical Volume Up press (default 25)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="DEBUG also logs packet bytes; INFO logs protocol shape only",
    )
    args = parser.parse_args(argv)
    if args.android_helper and (not math.isfinite(args.android_timeout) or args.android_timeout <= 0):
        parser.error("--android-timeout must be a positive finite number")

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    server = build_server(args)

    # SIGTERM/SIGINT stop the loop at the next pass rather than mid-packet, so
    # a response is never left half-written.
    signal.signal(signal.SIGTERM, server.request_stop)
    signal.signal(signal.SIGINT, server.request_stop)

    log.info("CTAPHID server starting (protocol version %d, capabilities 0x%02x)",
             CTAPHID_PROTOCOL_VERSION, int(SUPPORTED_CAPABILITIES))
    if args.android_helper:
        log.warning("Android helper signing mode ENABLED; do not use important accounts until independently validated")
    elif args.development_store:
        log.warning("Localhost-only development credential mode ENABLED; never use for important accounts")
    elif SUPPORTED_CAPABILITIES & Capability.CBOR:
        log.info("GetInfo implemented; all other CTAP2 commands are refused by design")

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
