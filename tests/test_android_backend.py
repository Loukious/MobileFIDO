"""No-phone Milestone 3B AF_UNIX mock helper, CBOR and policy regressions."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import secrets
import socket
import struct
import threading
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ctaphid import cbor, framing
from ctaphid.android_backend import (
    ANDROID_DEVELOPMENT_AAGUID, AndroidBackend, AndroidIpcClient,
    AndroidIpcError, AndroidIpcCancelled, MAX_FRAME_BYTES, _b64, _encode_frame,
)
from ctaphid.constants import CID_BROADCAST, Ctap2Error, CtapHidCommand
from ctaphid.server import CtapHidServer, KEEPALIVE_UP_NEEDED
from tests.test_async import Loopback


def _decode(value):
    return base64.b64decode(value, validate=True)


class MockAndroidHelper:
    """Mock Java LocalServerSocket: abstract socket, framed JSON, own P256 key."""

    def __init__(self, *, uv=False, handler=None):
        self.name = "ctaphid-test-" + secrets.token_hex(8)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind("\x00" + self.name)
        self.listener.settimeout(0.05)
        self.listener.listen(8)
        self.stopping = threading.Event()
        self.threads = []
        self.requests = queue.Queue()
        self.uv = uv
        self.handler = handler
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"\x11" * 32
        self.created = False
        self.counter = 0
        self.lock = threading.Lock()
        self.connection_count = 0
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(1)
        for thread in self.threads:
            thread.join(1)

    @staticmethod
    def _recv_exact(conn, size):
        value = b""
        while len(value) < size:
            chunk = conn.recv(size - len(value))
            if not chunk:
                raise EOFError()
            value += chunk
        return value

    def _accept(self):
        while not self.stopping.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connection_count += 1
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _serve(self, conn):
        with conn:
            try:
                size = struct.unpack(">I", self._recv_exact(conn, 4))[0]
                if size > MAX_FRAME_BYTES:
                    return
                message = json.loads(self._recv_exact(conn, size))
                self.requests.put(message)
                def respond(*, result=None, error=None, event=None,
                            bad_id=None, raw=None):
                    if raw is not None:
                        conn.sendall(raw)
                        return
                    reply = {"v": 1, "id": bad_id or message["id"]}
                    if event is not None:
                        reply["event"] = event
                    elif error is not None:
                        reply.update(ok=False, error=error)
                    else:
                        reply.update(ok=True, result=result)
                    conn.sendall(_encode_frame(reply))

                if self.handler is not None:
                    self.handler(self, message, respond)
                else:
                    self._default(message, respond)
            except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _default(self, message, respond):
        operation = message["op"]
        if operation == "getInfo":
            respond(result={
                "aaguid": _b64(ANDROID_DEVELOPMENT_AAGUID),
                "up": True, "uvEnforced": self.uv,
                "perUseCryptoObject": self.uv, "silentSigning": not self.uv,
                "securityLevel": "STRONGBOX", "rpIds": ["localhost"],
            })
            return
        params = message["params"]
        if params["rpId"] != "localhost":
            respond(error="NOT_ALLOWED")
            return
        if operation == "makeCredential":
            if self.credential_id in [_decode(x) for x in params["excludeIds"]]:
                respond(error="CREDENTIAL_EXCLUDED")
                return
            self.created = True
            pub = self.key.public_key().public_numbers()
            respond(result={
                "credentialId": _b64(self.credential_id),
                "publicKey": {"x": _b64(pub.x.to_bytes(32, "big")),
                              "y": _b64(pub.y.to_bytes(32, "big"))},
                "userPresent": True, "userVerified": self.uv,
            })
            return
        if operation == "getAssertion":
            if not self.created or self.credential_id not in [
                _decode(x) for x in params["allowIds"]
            ]:
                respond(error="NO_CREDENTIALS")
                return
            with self.lock:
                self.counter += 1
                count = self.counter
            flags = (0x01 if params["up"] else 0) | (0x04 if self.uv else 0)
            auth = hashlib.sha256(params["rpId"].encode()).digest()
            auth += bytes([flags]) + struct.pack(">I", count)
            signature = self.key.sign(
                auth + _decode(params["clientDataHash"]), ec.ECDSA(hashes.SHA256()),
            )
            respond(result={
                "credentialId": _b64(self.credential_id), "authData": _b64(auth),
                "signature": _b64(signature), "userPresent": params["up"],
                "userVerified": self.uv,
            })


def registration():
    return {
        1: bytes(range(32)),
        2: {"id": "localhost", "name": "Development"},
        3: {"id": b"local-user"}, 4: [{"type": "public-key", "alg": -7}],
    }


def assertion(*, up=True):
    return {
        1: "localhost", 2: bytes(range(32)),
        3: [{"type": "public-key", "id": b"\x11" * 32}],
        5: {"up": up},
    }


def send(backend, command, params=None, **kwargs):
    request = bytes([command]) + (cbor.encode(params) if params is not None else b"")
    response = backend.handle_cbor(request, **kwargs)
    return response[0], cbor.decode(response[1:]) if response[0] == 0 else None


class AndroidBackendTests(unittest.TestCase):
    def setUp(self):
        self.helper = MockAndroidHelper()
        self.addCleanup(self.helper.close)
        self.backend = AndroidBackend(
            socket_name=self.helper.name, rpc_timeout=1.5,
            expected_helper_uid=os.getuid(),
        )

    def test_hardware_storage_alone_does_not_advertise_uv(self):
        self.assertEqual(self.backend.security_level, "STRONGBOX")
        status, info = send(self.backend, 4)
        self.assertEqual(status, 0)
        self.assertEqual(info[3], ANDROID_DEVELOPMENT_AAGUID)
        self.assertEqual(info[4], {"rk": False, "up": True, "uv": False,
                                    "clientPin": False})
        self.assertEqual(info[10], [{"type": "public-key", "alg": -7}])
        self.assertEqual(self.helper.connection_count, 1, "cached GetInfo")

    def test_registration_and_signature_preflight_are_consistent(self):
        code, made = send(self.backend, 1, registration())
        self.assertEqual(code, 0)
        self.assertEqual(made[1], "none")
        auth = made[2]
        self.assertEqual(auth[:32], hashlib.sha256(b"localhost").digest())
        self.assertEqual(auth[32], 0x41)
        self.assertEqual(auth[37:53], ANDROID_DEVELOPMENT_AAGUID)
        self.assertEqual(auth[55:87], self.helper.credential_id)
        public = cbor.decode(auth[87:])
        x, y = public[-2], public[-3]
        pubkey = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"),
            ec.SECP256R1(),
        ).public_key()
        code, first = send(self.backend, 2, assertion(up=False))
        self.assertEqual(code, 0)
        self.assertEqual(first[2][32], 0, "silent probe must clear UP and UV")
        self.assertEqual(first[1]["id"], self.helper.credential_id)
        decode_dss_signature(first[3])
        pubkey.verify(first[3], first[2] + bytes(range(32)), ec.ECDSA(hashes.SHA256()))
        code, second = send(self.backend, 2, assertion(up=True))
        self.assertEqual(code, 0)
        self.assertEqual(second[2][32], 1)
        self.assertEqual(struct.unpack(">I", first[2][33:37])[0], 1)
        self.assertEqual(struct.unpack(">I", second[2][33:37])[0], 2)
        pubkey.verify(second[3], second[2] + bytes(range(32)),
                      ec.ECDSA(hashes.SHA256()))
        self.assertEqual(self.helper.connection_count, 4)

    def test_rejected_requests_never_reach_helper(self):
        for cmd, params, expected in [
            (1, {}, Ctap2Error.MISSING_PARAMETER),
            (1, registration() | {2: {"id": "remote.example"}},
             Ctap2Error.OPERATION_DENIED),
            (1, registration() | {7: {"up": False}}, Ctap2Error.INVALID_OPTION),
            (1, registration() | {7: {"uv": True}}, Ctap2Error.INVALID_OPTION),
            (1, registration() | {7: {"rk": True}}, Ctap2Error.UNSUPPORTED_OPTION),
            (1, registration() | {4: [{"type": "public-key", "alg": -257}]},
             Ctap2Error.UNSUPPORTED_ALGORITHM),
            (2, assertion() | {3: []}, Ctap2Error.NO_CREDENTIALS),
            (2, assertion() | {2: b"bad"}, Ctap2Error.CBOR_UNEXPECTED_TYPE),
            (2, assertion() | {4: {"secret": True}},
             Ctap2Error.UNSUPPORTED_EXTENSION),
        ]:
            with self.subTest(cmd=cmd, expected=expected):
                self.assertEqual(send(self.backend, cmd, params)[0], expected)
        self.assertEqual(self.helper.connection_count, 1)
        self.assertEqual(self.backend.handle_cbor(b"\x01\xff"),
                         bytes([Ctap2Error.INVALID_CBOR]))
        self.assertEqual(self.backend.handle_cbor(b""),
                         bytes([Ctap2Error.INVALID_LENGTH]))
        self.assertEqual(self.backend.handle_cbor(b"\x06"),
                         bytes([Ctap2Error.INVALID_COMMAND]))

    def test_helper_declines_unknown_credentials(self):
        self.assertEqual(send(self.backend, 2, assertion())[0],
                         Ctap2Error.NO_CREDENTIALS)
        send(self.backend, 1, registration())
        request = registration() | {5: [
            {"type": "public-key", "id": self.helper.credential_id},
        ]}
        self.assertEqual(send(self.backend, 1, request)[0],
                         Ctap2Error.CREDENTIAL_EXCLUDED)

    def test_helper_policy_inconsistency_fails_closed(self):
        for override in (
            {"uvEnforced": True, "silentSigning": True},
            {"uvEnforced": True, "perUseCryptoObject": False},
            {"aaguid": _b64(b"incorrect-m3b-tag")},
            {"rpIds": ["remote.example"]},
            {"up": False},
        ):
            def bad_info(helper, request, respond):
                result = {
                    "aaguid": _b64(ANDROID_DEVELOPMENT_AAGUID),
                    "up": True, "uvEnforced": False,
                    "perUseCryptoObject": False,
                    "silentSigning": True, "rpIds": ["localhost"],
                }
                result.update(override)
                respond(result=result)
            with self.subTest(override=override):
                mock = MockAndroidHelper(handler=bad_info)
                try:
                    with self.assertRaises(AndroidIpcError):
                        AndroidBackend(socket_name=mock.name, expected_helper_uid=os.getuid())
                finally:
                    mock.close()

    def test_uv_per_use_claim_and_flags(self):
        helper = MockAndroidHelper(uv=True)
        try:
            backend = AndroidBackend(socket_name=helper.name,
                                     expected_helper_uid=os.getuid())
            self.assertTrue(backend.get_info()[4]["uv"])
            code, registration_data = send(
                backend, 1, registration() | {7: {"uv": True}},
            )
            self.assertEqual(code, 0)
            self.assertEqual(registration_data[2][32], 0x45)
            code, probe = send(
                backend, 2, assertion(up=False) | {5: {"up": False, "uv": True}},
            )
            self.assertEqual(code, 0)
            self.assertEqual(probe[2][32], 0x04, "UV true; UP false on preflight")
            code, normal = send(
                backend, 2, assertion(up=True) | {5: {"up": True, "uv": True}},
            )
            self.assertEqual(code, 0)
            self.assertEqual(normal[2][32], 0x05)
        finally:
            helper.close()

    def test_rejects_helper_tampered_authdata_signature_and_public_key(self):
        # All helper bytes cross a process boundary. A malformed key or a
        # response whose flags differ from what CTAP asked for must fail shut.
        for field in ("signature", "rpHash", "upFlag", "uvFlag", "credentialId"):
            helper = MockAndroidHelper()
            try:
                backend = AndroidBackend(socket_name=helper.name,
                                         expected_helper_uid=os.getuid())
                self.assertEqual(send(backend, 1, registration())[0], 0)
                original = helper._default

                def tamper(message, respond):
                    def intercept(*, result=None, error=None, event=None, **kwargs):
                        if result is not None and message["op"] == "getAssertion":
                            result = dict(result)
                            if field == "signature":
                                result["signature"] = _b64(b"not-DER")
                            elif field == "credentialId":
                                result["credentialId"] = _b64(b"\x99" * 32)
                            else:
                                auth = bytearray(_decode(result["authData"]))
                                if field == "rpHash":
                                    auth[0] ^= 1
                                elif field == "upFlag":
                                    auth[32] = 0
                                elif field == "uvFlag":
                                    auth[32] = 5
                                result["authData"] = _b64(auth)
                        respond(result=result, error=error, event=event, **kwargs)
                    original(message, intercept)

                helper.handler = lambda _helper, msg, reply: tamper(msg, reply)
                with self.subTest(field=field):
                    self.assertEqual(send(backend, 2, assertion())[0],
                                     Ctap2Error.OTHER)
            finally:
                helper.close()

        helper = MockAndroidHelper()
        try:
            def bad_key(_helper, message, respond):
                if message["op"] == "getInfo":
                    helper._default(message, respond)
                else:
                    respond(result={
                        "credentialId": _b64(helper.credential_id),
                        "publicKey": {"x": _b64(bytes(32)), "y": _b64(bytes(32))},
                        "userPresent": True, "userVerified": False,
                    })
            helper.handler = bad_key
            backend = AndroidBackend(socket_name=helper.name,
                                     expected_helper_uid=os.getuid())
            self.assertEqual(send(backend, 1, registration())[0], Ctap2Error.OTHER)
        finally:
            helper.close()


class ProtocolTests(unittest.TestCase):
    def test_cancelled_request_never_retries(self):
        blocked = threading.Event()
        abandon = threading.Event()

        def handler(helper, request, reply):
            if request["op"] == "getInfo":
                helper._default(request, reply)
                return
            blocked.set()
            abandon.wait(1)
            # Closing the connection means user cancellation; the mock never
            # creates a credential, and the Python client cannot force the
            # Android helper to roll back an already-committed operation.

        helper = MockAndroidHelper(handler=handler)
        try:
            backend = AndroidBackend(socket_name=helper.name,
                                     expected_helper_uid=os.getuid())
            cancelled = threading.Event()
            output = []
            thread = threading.Thread(target=lambda: output.append(send(
                backend, 1, registration(), cancel_event=cancelled,
            )), daemon=True)
            thread.start()
            self.assertTrue(blocked.wait(1))
            cancelled.set()
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(output[0][0], Ctap2Error.KEEPALIVE_CANCEL)
            self.assertEqual(helper.connection_count, 2)
            self.assertFalse(helper.created)
        finally:
            abandon.set()
            helper.close()

    def test_event_drives_up_needed_and_clears_on_response(self):
        observed = []
        def handler(helper, request, reply):
            if request["op"] == "getInfo":
                helper._default(request, reply)
            else:
                reply(event="user_presence_required")
                reply(event="user_presence_done")
                helper._default(request, reply)
        helper = MockAndroidHelper(handler=handler)
        try:
            backend = AndroidBackend(socket_name=helper.name,
                                     expected_helper_uid=os.getuid())
            self.assertEqual(send(backend, 1, registration(),
                                  set_up_needed=observed.append)[0], 0)
            self.assertEqual(observed, [True, False])
        finally:
            helper.close()

    def test_bounded_framing_wrong_id_early_eof_and_invalid_json(self):
        def run_case(replier):
            def handler(helper, request, reply):
                replier(request, reply)
            helper = MockAndroidHelper(handler=handler)
            try:
                client = AndroidIpcClient(
                    helper.name, timeout=0.25, expected_uid=os.getuid(),
                )
                with self.assertRaises(AndroidIpcError):
                    client.call("getInfo")
                self.assertEqual(helper.connection_count, 1)
            finally:
                helper.close()
        run_case(lambda request, reply: reply(result={}, bad_id="wrong"))
        run_case(lambda request, reply: reply(raw=struct.pack(">I", MAX_FRAME_BYTES + 1)))
        run_case(lambda request, reply: reply(raw=struct.pack(">I", 5) + b"{bad}"))
        run_case(lambda request, reply: reply(raw=struct.pack(">I", 25) + b"{}"))
        run_case(lambda request, reply: reply(raw=_encode_frame({
            "v": 1, "id": request["id"], "ok": True, "result": None,
        })))

    def test_missing_helper_fails_at_startup(self):
        with self.assertRaises(AndroidIpcError):
            AndroidBackend(socket_name="ctaphid-absent-" + secrets.token_hex(8),
                           rpc_timeout=0.15, expected_helper_uid=os.getuid())

    def test_wrong_peer_uid_and_missing_uid_fail_closed(self):
        helper = MockAndroidHelper()
        try:
            with self.assertRaises(ValueError):
                AndroidBackend(socket_name=helper.name)
            with self.assertRaises(AndroidIpcError):
                AndroidBackend(socket_name=helper.name,
                               expected_helper_uid=os.getuid() + 10000)
            deadline = time.monotonic() + 1
            while helper.connection_count < 1 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(helper.connection_count, 1)
            self.assertTrue(helper.requests.empty(),
                            "untrusted helper must receive no JSON request")
        finally:
            helper.close()

    def test_server_keepalive_and_cancel_follow_helper_prompt(self):
        started = threading.Event()
        release = threading.Event()

        def handler(helper, request, reply):
            if request["op"] == "getInfo":
                helper._default(request, reply)
                return
            reply(event="user_presence_required")
            started.set()
            release.wait(1)
            if not release.is_set():
                return
            helper._default(request, reply)

        helper = MockAndroidHelper(handler=handler)
        backend = AndroidBackend(socket_name=helper.name, rpc_timeout=1.5,
                                 expected_helper_uid=os.getuid())
        link = Loopback()
        server = CtapHidServer(backend, packet_timeout=0.01,
                               keepalive_interval=0.03, cbor_timeout=2)
        thread = threading.Thread(target=server._loop, args=(link,), daemon=True)
        thread.start()

        def push(cid, command, payload=b""):
            for report in framing.build_packets(cid, command, payload, 64):
                link.rx.put(report)

        def pull(timeout=1):
            packet = framing.parse_packet(link.tx.get(timeout=timeout))
            tx = framing.Transaction.start(packet, 64, time.monotonic())
            while not tx.complete:
                tx.feed(framing.parse_packet(link.tx.get(timeout=timeout)))
            return tx.cid, tx.command, tx.data

        try:
            push(CID_BROADCAST, CtapHidCommand.INIT, b"12345678")
            cid = struct.unpack_from(">I", pull()[2], 8)[0]
            push(cid, CtapHidCommand.CBOR, bytes([1]) + cbor.encode(registration()))
            self.assertTrue(started.wait(1))
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                source, command, body = pull()
                if command == CtapHidCommand.KEEPALIVE:
                    self.assertEqual((source, body), (cid, bytes([KEEPALIVE_UP_NEEDED])))
                    break
            else:
                self.fail("helper prompt did not emit UP_NEEDED keepalive")
            push(cid, CtapHidCommand.CANCEL)
            deadline = time.monotonic() + 1
            while cid in server.active and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertNotIn(cid, server.active)
            release.set()
            deadline = time.monotonic() + 1
            while not helper.requests.empty() and time.monotonic() < deadline:
                time.sleep(0.005)
            push(cid, CtapHidCommand.PING, b"alive")
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                source, command, body = pull()
                if command == CtapHidCommand.PING:
                    self.assertEqual((source, body), (cid, b"alive"))
                    break
                self.assertEqual(command, CtapHidCommand.KEEPALIVE)
            else:
                self.fail("server did not recover from cancelled Android prompt")
        finally:
            server.stop()
            release.set()
            thread.join(2)
            helper.close()
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
