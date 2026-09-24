"""CTAP2-over-local-IPC adapter for the Android Keystore helper (Milestone 3B).

Protocol v1 (one request per AF_UNIX abstract stream):

    uint32_be length | UTF-8 JSON {"v":1,"id":<random hex>,"op":...,"params":{...}}
    uint32_be length | UTF-8 JSON {"v":1,"id":...,"event":"user_presence_required"}
    uint32_be length | UTF-8 JSON {"v":1,"id":...,"event":"user_presence_done"}
    uint32_be length | UTF-8 JSON {"v":1,"id":...,"ok":true,"result":{...}}

Error responses use ok:false, error:<fixed error name>. Binary values are
base64. Every frame is <= 64 KiB, and a failure never retries a potentially
committed create/sign operation. The Android server MUST verify peer UID 0
via LocalSocket.getPeerCredentials(), reject other clients, and cancel UI/work
when the request connection closes.

The Android helper owns credentials, credential-id -> Android Keystore keyAlias,
signCount, user-presence UI and all signing. Private keys and aliases are never
sent over IPC. Credential IDs and keyAliases are separate random opaque values.

Android Keystore hardware key storage alone DOES NOT prove user verification.
uv=True is advertised only for keys configured for per-use authentication via
BiometricPrompt.CryptoObject and only when no silent signing path exists. The
Windows up:false preflight either prompts biometrics for that same sign or runs
on a non-auth key with uv=False; the adapter never manufactures a UV bit.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import secrets
import socket
import struct
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from . import cbor
from .backend import GetInfoBackend
from .constants import Ctap2Command, Ctap2Error

log = logging.getLogger("ctaphid.android_backend")
SOCKET_NAME = "ctaphid-m3b-v1"
ANDROID_DEVELOPMENT_AAGUID = b"PocoF7-BIO-DEV01"
assert len(ANDROID_DEVELOPMENT_AAGUID) == 16
MAX_FRAME_BYTES = 65536
RPC_VERSION = 1
DEFAULT_RPC_TIMEOUT = 28.0
_POLL_SECONDS = 0.1
_UP = 0x01
_UV = 0x04
_AT = 0x40


class AndroidIpcError(Exception):
    """Helper unavailable, timed out, or sent an invalid frame/response."""


class AndroidIpcCancelled(AndroidIpcError):
    """The host cancelled an outstanding operation."""


class AndroidRemoteError(AndroidIpcError):
    """The helper refused a valid request with a fixed protocol error code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _json_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AndroidIpcError("duplicate JSON field")
        result[key] = value
    return result


def _encode_frame(value: dict) -> bytes:
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")
    if len(data) > MAX_FRAME_BYTES:
        raise AndroidIpcError("outgoing IPC frame too large")
    return struct.pack(">I", len(data)) + data


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, *, size: int | None = None,
           max_size: int = 8192) -> bytes:
    if not isinstance(value, str):
        raise AndroidIpcError("expected base64 string")
    if len(value) > (max_size + 2) // 3 * 4 + 4:
        raise AndroidIpcError("oversized base64 field")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AndroidIpcError("invalid base64 field") from exc
    if len(decoded) > max_size or (size is not None and len(decoded) != size):
        raise AndroidIpcError("invalid decoded binary field size")
    return decoded


class AndroidIpcClient:
    """Cancellable bounded AF_UNIX abstract RPC client; one socket/request."""

    def __init__(self, socket_name: str = SOCKET_NAME,
                 timeout: float = DEFAULT_RPC_TIMEOUT,
                 *, expected_uid: int):
        if (not isinstance(socket_name, str) or not socket_name or
                "\x00" in socket_name or len(socket_name.encode()) > 100):
            raise ValueError("invalid abstract socket name")
        if not isinstance(timeout, (int, float)) or not 0 < timeout < float("inf"):
            raise ValueError("RPC timeout must be finite and positive")
        if type(expected_uid) is not int or expected_uid < 0:
            raise ValueError("expected Android helper UID must be a nonnegative integer")
        self.socket_name = socket_name
        self.timeout = timeout
        self.expected_uid = expected_uid

    @staticmethod
    def _check(cancel_event: threading.Event | None, deadline: float) -> float:
        if cancel_event is not None and cancel_event.is_set():
            raise AndroidIpcCancelled("host cancelled operation")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AndroidIpcError("Android helper request timed out")
        return min(_POLL_SECONDS, remaining)

    def _recv_exact(self, conn: socket.socket, count: int,
                    cancel_event: threading.Event | None,
                    deadline: float) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            conn.settimeout(self._check(cancel_event, deadline))
            try:
                received = conn.recv(count - len(chunks))
            except socket.timeout:
                continue
            except OSError as exc:
                raise AndroidIpcError("Android helper read failed") from exc
            if not received:
                raise AndroidIpcError("Android helper closed request stream")
            chunks.extend(received)
        return bytes(chunks)

    def _read_frame(self, conn: socket.socket,
                    cancel_event: threading.Event | None,
                    deadline: float) -> dict:
        length = struct.unpack(">I", self._recv_exact(conn, 4, cancel_event, deadline))[0]
        if not 0 < length <= MAX_FRAME_BYTES:
            raise AndroidIpcError("invalid Android helper frame length")
        raw = self._recv_exact(conn, length, cancel_event, deadline)
        try:
            frame = json.loads(raw.decode("utf-8", errors="strict"),
                               object_pairs_hook=_json_no_duplicates,
                               parse_constant=lambda *_: (_ for _ in ()).throw(
                                   AndroidIpcError("invalid JSON constant")))
        except (UnicodeError, ValueError, TypeError) as exc:
            raise AndroidIpcError("invalid JSON reply from Android helper") from exc
        if not isinstance(frame, dict):
            raise AndroidIpcError("Android helper reply must be a JSON object")
        return frame

    def call(self, op: str, params: dict | None = None,
             *, cancel_event: threading.Event | None = None,
             set_up_needed: Callable[[bool], None] | None = None) -> dict:
        if op not in ("getInfo", "makeCredential", "getAssertion"):
            raise ValueError("unknown Android helper operation")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ValueError("Android helper params must be an object")
        request_id = secrets.token_hex(16)
        envelope = {"v": RPC_VERSION, "id": request_id, "op": op, "params": params}
        wire = _encode_frame(envelope)
        deadline = time.monotonic() + self.timeout
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        up_needed = False
        try:
            # Nonblocking connection keeps cancellation responsive while the
            # helper is unready. Neither local socket name nor IPC messages
            # imply authority: Android must check the kernel peer credentials.
            conn.setblocking(False)
            address = "\x00" + self.socket_name
            try:
                conn.connect(address)
            except BlockingIOError:
                import select
                while True:
                    _, writable, exceptional = select.select(
                        [], [conn], [conn], self._check(cancel_event, deadline)
                    )
                    if writable or exceptional:
                        break
                problem = conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if problem:
                    raise OSError(problem, "Android helper connect failed")
            except OSError as exc:
                raise AndroidIpcError("Android helper unavailable") from exc
            # Abstract socket names have no filesystem ownership/permissions.
            # A different Android app could bind the public name before the
            # helper. Check its *kernel-supplied* UID before sending requests.
            try:
                peer = conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
                _pid, uid, _gid = struct.unpack("3i", peer)
            except OSError as exc:
                raise AndroidIpcError("cannot authenticate Android helper UID") from exc
            if uid != self.expected_uid:
                raise AndroidIpcError("Android helper peer UID does not match trusted app")
            sent = 0
            while sent < len(wire):
                conn.settimeout(self._check(cancel_event, deadline))
                try:
                    chunk = conn.send(wire[sent:])
                except socket.timeout:
                    continue
                except OSError as exc:
                    raise AndroidIpcError("Android helper write failed") from exc
                if chunk == 0:
                    raise AndroidIpcError("Android helper closed while writing")
                sent += chunk
            while True:
                response = self._read_frame(conn, cancel_event, deadline)
                if (type(response.get("v")) is not int or
                        response["v"] != RPC_VERSION or response.get("id") != request_id):
                    raise AndroidIpcError("Android helper replied with wrong protocol/request ID")
                if "event" in response:
                    if (response.keys() != {"v", "id", "event"} or
                            response["event"] not in
                            ("user_presence_required", "user_presence_done")):
                        raise AndroidIpcError("invalid Android helper progress event")
                    needed = response["event"] == "user_presence_required"
                    if up_needed != needed and set_up_needed is not None:
                        set_up_needed(needed)
                    up_needed = needed
                    continue
                if "ok" not in response or type(response["ok"]) is not bool:
                    raise AndroidIpcError("Android helper response missing ok boolean")
                if response["ok"]:
                    if response.keys() != {"v", "id", "ok", "result"}:
                        raise AndroidIpcError("invalid success response envelope")
                    if not isinstance(response["result"], dict):
                        raise AndroidIpcError("Android helper result must be an object")
                    return response["result"]
                if response.keys() != {"v", "id", "ok", "error"}:
                    raise AndroidIpcError("invalid error response envelope")
                if not isinstance(response["error"], str):
                    raise AndroidIpcError("invalid helper error code")
                raise AndroidRemoteError(response["error"])
        except OSError as exc:
            raise AndroidIpcError("Android helper unavailable") from exc
        finally:
            if up_needed and set_up_needed is not None:
                set_up_needed(False)
            # EOF is the cancellation signal to Android. No automatic retry:
            # a missing reply could mean the helper already committed a key.
            conn.close()


class _RequestError(Exception):
    def __init__(self, status: Ctap2Error):
        self.status = status
        super().__init__(status.name)


def _need(valid: bool, status: Ctap2Error) -> None:
    if not valid:
        raise _RequestError(status)


def _descriptors(value: object) -> list[bytes]:
    _need(isinstance(value, list), Ctap2Error.CBOR_UNEXPECTED_TYPE)
    _need(len(value) <= 64, Ctap2Error.LIMIT_EXCEEDED)
    found = []
    for item in value:
        _need(isinstance(item, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _need(item.get("type") == "public-key" and
              isinstance(item.get("id"), bytes) and
              1 <= len(item["id"]) <= 1023, Ctap2Error.INVALID_PARAMETER)
        found.append(item["id"])
    return found


def _options(params: dict, key: int, *, make: bool,
             uv_supported: bool) -> bool:
    options = params.get(key, {})
    _need(isinstance(options, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
    _need(all(isinstance(k, str) and type(v) is bool
              for k, v in options.items()), Ctap2Error.CBOR_UNEXPECTED_TYPE)
    _need(not options.get("rk", False), Ctap2Error.UNSUPPORTED_OPTION)
    _need(not options.get("uv", False) or uv_supported, Ctap2Error.INVALID_OPTION)
    _need(all(k in ("up", "uv", "rk") for k in options), Ctap2Error.UNSUPPORTED_OPTION)
    if make:
        _need(options.get("up") is not False, Ctap2Error.INVALID_OPTION)
    return options.get("up", True)


_REMOTE_ERRORS = {
    "NOT_ALLOWED": Ctap2Error.OPERATION_DENIED,
    "NO_CREDENTIALS": Ctap2Error.NO_CREDENTIALS,
    "CREDENTIAL_EXCLUDED": Ctap2Error.CREDENTIAL_EXCLUDED,
    "CANCELLED": Ctap2Error.KEEPALIVE_CANCEL,
    "TIMEOUT": Ctap2Error.USER_ACTION_TIMEOUT,
    "STORE_FULL": Ctap2Error.KEY_STORE_FULL,
    "OTHER": Ctap2Error.OTHER,
}


class AndroidBackend(GetInfoBackend):
    """Hardware-key CTAP backend; Android owns UI, keys and signature counter."""

    def __init__(self, socket_name: str = SOCKET_NAME, packet_size: int = 64,
                 allowed_rp_ids: set[str] | frozenset[str] | None = None,
                 rpc_timeout: float = DEFAULT_RPC_TIMEOUT,
                 ipc_client: AndroidIpcClient | None = None,
                 expected_helper_uid: int | None = None):
        super().__init__(packet_size=packet_size, aaguid=ANDROID_DEVELOPMENT_AAGUID)
        self.allowed_rp_ids = frozenset(
            {"localhost"} if allowed_rp_ids is None else allowed_rp_ids
        )
        if not self.allowed_rp_ids or any(
            not isinstance(rp, str) or not rp or len(rp.encode()) > 253
            for rp in self.allowed_rp_ids
        ):
            raise ValueError("invalid allowed RP IDs")
        if ipc_client is None and expected_helper_uid is None:
            raise ValueError("trusted Android package UID required to authenticate helper")
        self.ipc = ipc_client if ipc_client is not None else AndroidIpcClient(
            socket_name, rpc_timeout, expected_uid=expected_helper_uid
        )
        info = self.ipc.call("getInfo")
        if _unb64(info.get("aaguid"), size=16) != self.aaguid:
            raise AndroidIpcError("Android helper AAGUID differs from Python M3B identity")
        for key in ("up", "uvEnforced", "perUseCryptoObject", "silentSigning"):
            if type(info.get(key)) is not bool:
                raise AndroidIpcError(f"missing helper policy field {key}")
        if not info["up"]:
            raise AndroidIpcError("Android helper does not support user presence")
        # A helper must never claim per-use UV while also permitting silent
        # signing. Reject a contradictory policy instead of silently downgrading.
        if info["uvEnforced"] and (
            not info["perUseCryptoObject"] or info["silentSigning"]
        ):
            raise AndroidIpcError("Android helper's UV security policy is inconsistent")
        if info.get("rpIds") != sorted(self.allowed_rp_ids):
            raise AndroidIpcError("Android helper RP allowlist differs from Python policy")
        self._uv_enforced = info["uvEnforced"]
        self.security_level = info.get("securityLevel", "UNKNOWN")
        # Keystore's claimed hardware level is informational; it never sets UV.
        if (not isinstance(self.security_level, str) or
                self.security_level not in
                ("UNKNOWN", "SOFTWARE", "TEE", "TRUSTED_ENVIRONMENT", "STRONGBOX")):
            raise AndroidIpcError("invalid Android helper security level")
        log.info("Android helper connected: UV per-use=%s; key security level=%s",
                 self._uv_enforced, self.security_level)

    def get_info(self) -> dict:
        info = super().get_info()
        info[4]["up"] = True
        info[4]["uv"] = self._uv_enforced
        info[10] = [{"type": "public-key", "alg": -7}]
        return info

    def _rp(self, value: object) -> str:
        _need(isinstance(value, str) and bool(value), Ctap2Error.INVALID_PARAMETER)
        _need(value in self.allowed_rp_ids, Ctap2Error.OPERATION_DENIED)
        return value

    def _verify_uv(self, result: dict) -> bool:
        verified = result.get("userVerified")
        if type(verified) is not bool or verified != self._uv_enforced:
            raise AndroidIpcError("helper response contradicts per-use UV policy")
        return verified

    def _make(self, params: dict, cancel_event: threading.Event | None,
              set_up_needed: Callable[[bool], None] | None) -> dict:
        _need(all(key in params for key in (1, 2, 3, 4)),
              Ctap2Error.MISSING_PARAMETER)
        _need(isinstance(params[1], bytes) and len(params[1]) == 32,
              Ctap2Error.CBOR_UNEXPECTED_TYPE)
        rp, user, algorithms = params[2], params[3], params[4]
        _need(isinstance(rp, dict) and isinstance(user, dict),
              Ctap2Error.CBOR_UNEXPECTED_TYPE)
        rp_id = self._rp(rp.get("id"))
        user_id = user.get("id")
        _need(isinstance(user_id, bytes) and len(user_id) <= 64,
              Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _need(isinstance(algorithms, list), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _need(any(isinstance(item, dict) and item.get("type") == "public-key"
                  and type(item.get("alg")) is int and item["alg"] == -7
                  for item in algorithms), Ctap2Error.UNSUPPORTED_ALGORITHM)
        exclude = _descriptors(params.get(5, []))
        _need(isinstance(params.get(6, {}), dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _need(not params.get(6, {}), Ctap2Error.UNSUPPORTED_EXTENSION)
        _options(params, 7, make=True, uv_supported=self._uv_enforced)
        _need(all(key not in params for key in (8, 9, 10)),
              Ctap2Error.UNSUPPORTED_OPTION)
        result = self.ipc.call("makeCredential", {
            "rpId": rp_id, "clientDataHash": _b64(params[1]),
            "userId": _b64(user_id), "excludeIds": [_b64(x) for x in exclude],
            "up": True,
        }, cancel_event=cancel_event, set_up_needed=set_up_needed)
        _need(result.get("userPresent") is True, Ctap2Error.OPERATION_DENIED)
        uv = self._verify_uv(result)
        credential_id = _unb64(result.get("credentialId"), size=32)
        public = result.get("publicKey")
        if not isinstance(public, dict):
            raise AndroidIpcError("missing Android ES256 public key")
        x = _unb64(public.get("x"), size=32)
        y = _unb64(public.get("y"), size=32)
        try:
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                ec.SECP256R1(),
            ).public_key()
        except ValueError as exc:
            raise AndroidIpcError("Android helper returned an invalid P-256 point") from exc
        cose = cbor.encode({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        attested = self.aaguid + struct.pack(">H", len(credential_id)) + credential_id + cose
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([_UP | _AT | (_UV if uv else 0)])
        auth += struct.pack(">I", 0) + attested
        return {1: "none", 2: auth, 3: {}}

    def _assert(self, params: dict, cancel_event: threading.Event | None,
                set_up_needed: Callable[[bool], None] | None) -> dict:
        _need(1 in params and 2 in params, Ctap2Error.MISSING_PARAMETER)
        rp_id = self._rp(params[1])
        _need(isinstance(params[2], bytes) and len(params[2]) == 32,
              Ctap2Error.CBOR_UNEXPECTED_TYPE)
        allow = _descriptors(params.get(3, []))
        _need(bool(allow), Ctap2Error.NO_CREDENTIALS)
        _need(isinstance(params.get(4, {}), dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _need(not params.get(4, {}), Ctap2Error.UNSUPPORTED_EXTENSION)
        require_up = _options(params, 5, make=False,
                              uv_supported=self._uv_enforced)
        _need(all(key not in params for key in (6, 7)),
              Ctap2Error.UNSUPPORTED_OPTION)
        result = self.ipc.call("getAssertion", {
            "rpId": rp_id, "clientDataHash": _b64(params[2]),
            "allowIds": [_b64(value) for value in allow],
            "up": require_up,
        }, cancel_event=cancel_event, set_up_needed=set_up_needed)
        if type(result.get("userPresent")) is not bool or result["userPresent"] != require_up:
            raise AndroidIpcError("Android helper's UP claim differs from CTAP request")
        uv = self._verify_uv(result)
        credential_id = _unb64(result.get("credentialId"), size=32)
        if credential_id not in allow:
            raise AndroidIpcError("helper selected a credential outside the allowList")
        auth = _unb64(result.get("authData"), size=37)
        signature = _unb64(result.get("signature"), max_size=128)
        if not signature:
            raise AndroidIpcError("missing assertion signature")
        try:
            r, s = decode_dss_signature(signature)
        except ValueError as exc:
            raise AndroidIpcError("invalid DER ECDSA assertion signature") from exc
        if not (0 < r < 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
                and 0 < s < 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551):
            raise AndroidIpcError("ECDSA signature has out-of-range scalar")
        expected_flags = (_UP if require_up else 0) | (_UV if uv else 0)
        if (auth[:32] != hashlib.sha256(rp_id.encode()).digest() or
                auth[32] != expected_flags):
            raise AndroidIpcError("Android signed unexpected RP/UP/UV flags")
        return {1: {"type": "public-key", "id": credential_id},
                2: auth, 3: signature}

    def handle_cbor(self, request: bytes, approval=None,
                    cancel_event: threading.Event | None = None,
                    set_up_needed: Callable[[bool], None] | None = None) -> bytes:
        """Serve CTAP2; Android owns prompt and signing, approval is unused."""
        if not request:
            return bytes([Ctap2Error.INVALID_LENGTH])
        cmd = request[0]
        if cmd not in (Ctap2Command.GET_INFO, Ctap2Command.MAKE_CREDENTIAL,
                       Ctap2Command.GET_ASSERTION):
            return bytes([Ctap2Error.INVALID_COMMAND])
        try:
            params = cbor.decode(request[1:]) if request[1:] else {}
            _need(isinstance(params, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
            if cmd == Ctap2Command.GET_INFO:
                _need(not params, Ctap2Error.INVALID_PARAMETER)
                return bytes([Ctap2Error.SUCCESS]) + cbor.encode(self.get_info())
            _need(bool(request[1:]), Ctap2Error.MISSING_PARAMETER)
            _need(all(type(key) is int for key in params), Ctap2Error.CBOR_UNEXPECTED_TYPE)
            if cancel_event is not None and cancel_event.is_set():
                raise AndroidIpcCancelled()
            if cmd == Ctap2Command.MAKE_CREDENTIAL:
                result = self._make(params, cancel_event, set_up_needed)
            else:
                result = self._assert(params, cancel_event, set_up_needed)
            if cancel_event is not None and cancel_event.is_set():
                raise AndroidIpcCancelled()
            return bytes([Ctap2Error.SUCCESS]) + cbor.encode(result)
        except cbor.CborError:
            return bytes([Ctap2Error.INVALID_CBOR])
        except _RequestError as exc:
            log.info("CTAP2 command 0x%02x rejected during validation: %s", cmd,
                     exc.status.name)
            return bytes([exc.status])
        except AndroidIpcCancelled:
            return bytes([Ctap2Error.KEEPALIVE_CANCEL])
        except AndroidRemoteError as exc:
            # Log only a fixed protocol error code; no RP account details,
            # challenge hashes, credentials, or signature bytes.
            log.info("CTAP2 command 0x%02x refused by Android helper: %s",
                     cmd, exc.code)
            return bytes([_REMOTE_ERRORS.get(exc.code, Ctap2Error.OTHER)])
        except AndroidIpcError as exc:
            log.warning("Android helper error during CTAP command 0x%02x: %s", cmd, exc)
            return bytes([Ctap2Error.OTHER])
