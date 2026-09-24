"""Offline regression tests for asynchronous CTAPHID transactions.

Run: python3 -m unittest tests.test_async -v
"""

import queue
import math
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ctaphid import framing
from ctaphid.backend import GetInfoBackend
from ctaphid.channels import ChannelTable
from ctaphid.constants import CID_BROADCAST, CtapHidCommand as Cmd, CtapHidError as Err
from ctaphid.server import (
    CtapHidServer, KEEPALIVE_PROCESSING, KEEPALIVE_UP_NEEDED, build_server,
)
from ctaphid.transport import TransportError


class Loopback:
    report_length = 64

    def __init__(self):
        self.rx = queue.Queue()
        self.tx = queue.Queue()
        self.writers = []

    def read_packet(self, timeout):
        try:
            return self.rx.get(timeout=timeout)
        except queue.Empty:
            return None

    def write_packets(self, packets):
        self.writers.append(threading.get_ident())
        for packet in packets:
            self.tx.put(packet)

    def close(self):
        pass


class Backend:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.cancelled = threading.Event()

    def handle_cbor(self, request, approval=None, cancel_event=None):
        self.started.set()
        try:
            if request == b"approve":
                return (b"\x00ok" if approval is not None and approval(
                    action="makeCredential", rp_id="example.test", cancel_event=cancel_event,
                ) else b"\x2d")
            self.release.wait(3)
            if cancel_event is not None and cancel_event.is_set():
                self.cancelled.set()
            return b"\x00done"
        finally:
            self.finished.set()


class AsyncTests(unittest.TestCase):
    def setUp(self):
        self.transport = Loopback()
        self.backend = Backend()
        self.server = CtapHidServer(
            self.backend, packet_timeout=0.01, keepalive_interval=0.05,
            cbor_timeout=2, idle_timeout=0.2, max_channels=2,
        )
        self.thread = threading.Thread(
            target=self.server._loop, args=(self.transport,), daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.stop()
        self.backend.release.set()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def send(self, cid, cmd, payload=b""):
        for packet in framing.build_packets(cid, cmd, payload, 64):
            self.transport.rx.put(packet)

    def receive(self, timeout=2):
        packet = framing.parse_packet(self.transport.tx.get(timeout=timeout))
        txn = framing.Transaction.start(packet, 64, time.monotonic())
        while not txn.complete:
            txn.feed(framing.parse_packet(self.transport.tx.get(timeout=timeout)))
        return txn.cid, txn.command, txn.data

    def channel(self):
        self.send(CID_BROADCAST, Cmd.INIT, b"12345678")
        payload = self.until(CID_BROADCAST, Cmd.INIT)
        self.assertEqual(payload[:8], b"12345678")
        return struct.unpack_from(">I", payload, 8)[0]

    def until(self, cid, cmd, payload=None):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            source, command, body = self.receive()
            if (source, command) == (cid, cmd) and (payload is None or body == payload):
                return body
        self.fail(f"missing {cmd} on {cid:08x}")

    def test_approval_keepalive_and_independent_channel(self):
        allowed = threading.Event()
        observed = {}

        def approve(**kwargs):
            observed.update(kwargs)
            while not allowed.wait(0.01):
                if kwargs["cancel_event"].is_set():
                    return False
            return True

        self.server.approval = approve
        cid = self.channel()
        self.send(cid, Cmd.CBOR, b"approve")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_UP_NEEDED]))
        self.assertEqual(observed["rp_id"], "example.test")
        self.assertEqual(observed["action"], "makeCredential")
        self.assertTrue(self.server.channels.get(cid).pinned)
        other = self.channel()
        self.send(other, Cmd.PING, b"ping")
        self.until(other, Cmd.PING, b"ping")
        allowed.set()
        self.until(cid, Cmd.CBOR, b"\x00ok")
        self.assertFalse(self.server.channels.get(cid).pinned)
        self.assertEqual(set(self.transport.writers), {self.thread.ident})

    def test_cancel_discards_late_result(self):
        cid = self.channel()
        self.send(cid, Cmd.CBOR, b"wait")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.send(cid, Cmd.CANCEL)
        deadline = time.monotonic() + 1
        while cid in self.server.active and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertNotIn(cid, self.server.active)
        self.backend.release.set()
        self.assertTrue(self.backend.finished.wait(1))
        self.assertTrue(self.backend.cancelled.is_set())
        self.send(cid, Cmd.PING, b"alive")
        self.assertEqual(self.receive(), (cid, Cmd.PING, b"alive"))
        time.sleep(0.1)
        self.assertTrue(self.transport.tx.empty(), "late cancelled CBOR response leaked")

    def test_cancel_interrupts_approval_callback(self):
        entered = threading.Event()
        cancelled = threading.Event()

        def approval(**kwargs):
            entered.set()
            if kwargs["cancel_event"].wait(1):
                cancelled.set()
            return False

        self.server.approval = approval
        cid = self.channel()
        self.send(cid, Cmd.CBOR, b"approve")
        self.assertTrue(entered.wait(1))
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_UP_NEEDED]))
        self.send(cid, Cmd.CANCEL)
        self.assertTrue(cancelled.wait(1))
        self.assertTrue(self.backend.finished.wait(1))
        self.send(cid, Cmd.PING, b"safe")
        self.until(cid, Cmd.PING, b"safe")
        time.sleep(0.1)
        self.assertTrue(self.transport.tx.empty())

    def test_init_resync_cancels_active_cbor(self):
        cid = self.channel()
        self.send(cid, Cmd.CBOR, b"wait")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.send(cid, Cmd.INIT, b"newnonce")
        self.until(cid, Cmd.INIT)
        self.backend.release.set()
        self.assertTrue(self.backend.finished.wait(1))
        self.send(cid, Cmd.PING, b"resync")
        self.assertEqual(self.receive(), (cid, Cmd.PING, b"resync"))

    def test_timeout_drops_late_result(self):
        self.server.cbor_timeout = 0.16
        cid = self.channel()
        self.send(cid, Cmd.CBOR, b"wait")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.until(cid, Cmd.ERROR, bytes([Err.MSG_TIMEOUT]))
        self.backend.release.set()
        self.assertTrue(self.backend.finished.wait(1))
        self.send(cid, Cmd.PING, b"alive")
        self.assertEqual(self.receive(), (cid, Cmd.PING, b"alive"))
        time.sleep(0.1)
        self.assertTrue(self.transport.tx.empty())

    def test_active_channel_survives_idle_and_eviction(self):
        active = self.channel()
        self.send(active, Cmd.CBOR, b"wait")
        self.until(active, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.send(active, Cmd.PING, b"busy")
        self.until(active, Cmd.ERROR, bytes([Err.CHANNEL_BUSY]))
        other = self.channel()
        replacement = self.channel()
        self.assertIn(active, self.server.channels)
        self.assertNotIn(other, self.server.channels)
        self.assertIn(replacement, self.server.channels)
        time.sleep(0.35)
        self.assertIn(active, self.server.channels)
        self.backend.release.set()
        self.until(active, Cmd.CBOR, b"\x00done")

    def test_partial_message_is_pinned_until_cancelled(self):
        partial = self.channel()
        self.transport.rx.put(
            (struct.pack(">IBH", partial, Cmd.PING | 0x80, 200) + b"x" * 57)
        )
        deadline = time.monotonic() + 1
        while partial not in self.server.pending and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertIn(partial, self.server.pending)
        self.assertTrue(self.server.channels.get(partial).pinned)
        other = self.channel()
        replacement = self.channel()
        self.assertIn(partial, self.server.channels)
        self.assertNotIn(other, self.server.channels)
        self.assertIn(replacement, self.server.channels)
        time.sleep(0.35)
        self.assertIn(partial, self.server.pending)
        self.send(partial, Cmd.CANCEL)
        deadline = time.monotonic() + 1
        while partial in self.server.pending and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertNotIn(partial, self.server.pending)
        self.assertFalse(self.server.channels.get(partial).pinned)

    def test_thread_start_error_releases_slot_and_channel(self):
        cid = self.channel()
        with patch("ctaphid.server.threading.Thread.start",
                   side_effect=RuntimeError("simulated thread exhaustion")):
            self.send(cid, Cmd.CBOR, b"wait")
            self.until(cid, Cmd.ERROR, bytes([Err.OTHER]))
        self.assertNotIn(cid, self.server.active)
        self.assertFalse(self.server.channels.get(cid).pinned)
        self.assertEqual(self.server.stats["worker_start_error"], 1)
        self.send(cid, Cmd.CBOR, b"wait")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.backend.release.set()
        self.until(cid, Cmd.CBOR, b"\x00done")

    def test_invalid_backend_output_sends_error_and_server_recovers(self):
        original = self.server.backend.handle_cbor
        cid = self.channel()
        self.server.backend.handle_cbor = lambda request, **kwargs: None
        self.send(cid, Cmd.CBOR, b"wrong-type")
        self.until(cid, Cmd.ERROR, bytes([Err.OTHER]))
        self.server.backend.handle_cbor = lambda request, **kwargs: b"x" * 7610
        self.send(cid, Cmd.CBOR, b"oversized")
        self.until(cid, Cmd.ERROR, bytes([Err.OTHER]))
        self.assertEqual(self.server.stats["backend_error"], 2)
        self.server.backend.handle_cbor = original
        self.send(cid, Cmd.CBOR, b"wait")
        self.until(cid, Cmd.KEEPALIVE, bytes([KEEPALIVE_PROCESSING]))
        self.backend.release.set()
        self.until(cid, Cmd.CBOR, b"\x00done")

    def test_cancelled_workers_still_consume_slots_until_finished(self):
        starts = queue.Queue()
        release = threading.Event()

        def blocked(request, approval=None, cancel_event=None):
            starts.put(request)
            release.wait(3)
            return b"\x00done"

        self.server.backend.handle_cbor = blocked
        cid = self.channel()
        other = self.channel()
        for channel in (cid, other):
            self.send(channel, Cmd.CBOR, b"wait")
            self.assertEqual(starts.get(timeout=1), b"wait")
            self.send(channel, Cmd.CANCEL)
            deadline = time.monotonic() + 1
            while channel in self.server.active and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertNotIn(channel, self.server.active)
        self.send(other, Cmd.CBOR, b"wait")
        self.until(other, Cmd.ERROR, bytes([Err.CHANNEL_BUSY]))
        self.assertEqual(self.server.stats["worker_busy"], 1)
        release.set()
        deadline = time.monotonic() + 1
        while self.server._worker_slots._value != 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(self.server._worker_slots._value, 2)
        self.send(other, Cmd.CBOR, b"wait")
        self.until(other, Cmd.CBOR, b"\x00done")


class ReconnectTests(unittest.TestCase):
    def test_failed_write_clears_channels_and_rejects_old_cids(self):
        class Faulty(Loopback):
            def __init__(self):
                super().__init__()
                self.fail_next = False

            def write_packets(self, packets):
                if self.fail_next:
                    self.fail_next = False
                    raise TransportError("simulated USB write/reset failure")
                super().write_packets(packets)

        class Reconnecting(CtapHidServer):
            def __init__(self, transports):
                super().__init__(GetInfoBackend(), packet_timeout=0.01)
                self.available = list(transports)
                self.opened = 0

            def _open_transport(self):
                self.opened += 1
                return self.available.pop(0)

        first, second = Faulty(), Faulty()
        server = Reconnecting([first, second])
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        def send(transport, cid, command, payload=b""):
            for packet in framing.build_packets(cid, command, payload, 64):
                transport.rx.put(packet)

        def receive(transport):
            packet = framing.parse_packet(transport.tx.get(timeout=2))
            txn = framing.Transaction.start(packet, 64, time.monotonic())
            while not txn.complete:
                txn.feed(framing.parse_packet(transport.tx.get(timeout=2)))
            return txn.cid, txn.command, txn.data

        try:
            send(first, CID_BROADCAST, Cmd.INIT, b"12345678")
            _, _, response = receive(first)
            old = struct.unpack_from(">I", response, 8)[0]
            self.assertIn(old, server.channels)
            first.fail_next = True
            send(first, old, Cmd.PING, b"trigger")
            deadline = time.monotonic() + 3
            while server.opened < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(server.opened, 2)
            self.assertNotIn(old, server.channels)
            send(second, old, Cmd.PING, b"stale")
            self.assertEqual(receive(second), (old, Cmd.ERROR, bytes([Err.INVALID_CHANNEL])))
            send(second, CID_BROADCAST, Cmd.INIT, b"abcdefgh")
            self.assertEqual(receive(second)[1], Cmd.INIT)
        finally:
            server.stop()
            thread.join(2)
            self.assertFalse(thread.is_alive())

    def test_old_worker_cannot_reply_on_reused_cid_after_reconnect(self):
        class Droppable(Loopback):
            def __init__(self):
                super().__init__()
                self.lost = threading.Event()

            def read_packet(self, timeout):
                if self.lost.is_set():
                    raise TransportError("simulated link reset")
                return super().read_packet(timeout)

        class Reconnecting(CtapHidServer):
            def __init__(self, backend, transports):
                super().__init__(backend, max_channels=2, packet_timeout=0.01)
                self.available = list(transports)
                self.opened = 0

            def _open_transport(self):
                self.opened += 1
                return self.available.pop(0)

        class BackendWithLateResult:
            def __init__(self):
                self.old_started = threading.Event()
                self.old_cancel = None
                self.old_release = threading.Event()
                self.old_done = threading.Event()
                self.new_started = threading.Event()
                self.new_release = threading.Event()

            def handle_cbor(self, request, cancel_event=None):
                if request == b"old":
                    self.old_cancel = cancel_event
                    self.old_started.set()
                    self.old_release.wait(3)
                    self.old_done.set()
                    return b"\x00old"
                self.new_started.set()
                self.new_release.wait(3)
                return b"\x00new"

        def send(transport, cid, command, payload=b""):
            for packet in framing.build_packets(cid, command, payload, 64):
                transport.rx.put(packet)

        def receive(transport):
            packet = framing.parse_packet(transport.tx.get(timeout=2))
            transaction = framing.Transaction.start(packet, 64, time.monotonic())
            while not transaction.complete:
                transaction.feed(framing.parse_packet(transport.tx.get(timeout=2)))
            return transaction.cid, transaction.command, transaction.data

        backend = BackendWithLateResult()
        first, second = Droppable(), Droppable()
        server = Reconnecting(backend, [first, second])
        thread = threading.Thread(target=server.run, daemon=True)
        with patch("ctaphid.channels.os.urandom", return_value=b"\x12\x34\x56\x78"):
            thread.start()
            try:
                send(first, CID_BROADCAST, Cmd.INIT, b"12345678")
                old_cid = struct.unpack_from(">I", receive(first)[2], 8)[0]
                send(first, old_cid, Cmd.CBOR, b"old")
                self.assertTrue(backend.old_started.wait(1))
                first.lost.set()
                deadline = time.monotonic() + 3
                while server.opened < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(server.opened, 2)
                self.assertTrue(backend.old_cancel.is_set())
                send(second, CID_BROADCAST, Cmd.INIT, b"abcdefgh")
                new_cid = struct.unpack_from(">I", receive(second)[2], 8)[0]
                self.assertEqual(new_cid, old_cid, "test must force CID reuse")
                send(second, new_cid, Cmd.CBOR, b"new")
                self.assertTrue(backend.new_started.wait(1))
                backend.old_release.set()
                self.assertTrue(backend.old_done.wait(1))
                deadline = time.monotonic() + 1
                while server.stats["discarded_cbor_result"] < 1 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(server.stats["discarded_cbor_result"], 1)
                backend.new_release.set()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    source, command, payload = receive(second)
                    if command == Cmd.CBOR:
                        self.assertEqual((source, payload), (new_cid, b"\x00new"))
                        break
                else:
                    self.fail("new CBOR never completed")
            finally:
                backend.old_release.set()
                backend.new_release.set()
                server.stop()
                thread.join(2)
                self.assertFalse(thread.is_alive())


class CliTests(unittest.TestCase):
    def test_dev_mode_requires_presence_and_validates_phone_device(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                configfs_root="/nonexistent", device=None, transaction_timeout=5,
                idle_timeout=None, max_channels=None, development_store=None,
                presence="none", presence_timeout=25,
            )
            gadget = SimpleNamespace(report_length=64)
            with patch("ctaphid.server.wait_for_gadget", return_value=gadget), \
                 patch("ctaphid.approval.find_phone_keypad",
                       return_value="/dev/input/event-synthetic") as find:
                server = build_server(args)
                self.assertIsInstance(server.backend, GetInfoBackend)
                self.assertIsNone(server.approval)
                find.assert_not_called()
                args.presence = "volume-up"
                with self.assertRaises(ValueError):
                    build_server(args)
                args.development_store = directory + "/credentials.json"
                args.presence = "none"
                with self.assertRaises(ValueError):
                    build_server(args)
                args.presence = "volume-up"
                server = build_server(args)
                find.assert_called_once()
                from ctaphid.dev_backend import DevCredentialBackend
                self.assertIsInstance(server.backend, DevCredentialBackend)
                self.assertEqual(server.backend.allowed_rp_ids, frozenset({"localhost"}))
                self.assertIsNotNone(server.approval)
                self.assertEqual(server.cbor_timeout, 30)
                args.presence_timeout = 40
                self.assertEqual(build_server(args).cbor_timeout, 45)
                for invalid in (-1, 0, math.nan, math.inf):
                    args.presence_timeout = invalid
                    with self.subTest(invalid=invalid):
                        with self.assertRaises(ValueError):
                            build_server(args)
                args.presence_timeout = 25
                args.max_channels = 0
                with self.assertRaises(ValueError):
                    build_server(args)


class ChannelPins(unittest.TestCase):
    def test_expire_and_evict_skip_pinned_channels(self):
        table = ChannelTable(max_channels=2, idle_timeout=0.1)
        first = table.allocate(0)
        second = table.allocate(1)
        table.pin(first)
        self.assertEqual(table.expire(1.5), [second])
        self.assertIn(first, table)
        second = table.allocate(2)
        self.assertEqual(table.evict_lru(), second)
        self.assertIsNone(table.evict_lru())
        table.unpin(first)
        self.assertEqual(table.evict_lru(), first)

    def test_all_pinned_channels_cannot_be_evicted(self):
        table = ChannelTable(max_channels=2)
        first = table.allocate(0)
        second = table.allocate(0)
        table.pin(first)
        table.pin(second)
        self.assertIsNone(table.evict_lru())
        self.assertIsNone(table.allocate(1))
        self.assertEqual(set(table.channels), {first, second})


if __name__ == "__main__":
    unittest.main()
