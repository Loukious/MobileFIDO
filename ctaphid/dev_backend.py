"""Milestone 3A development authenticator: local-only CTAP2 ES256 credentials.

Only makeCredential/getAssertion with allowList-backed (non-discoverable)
credentials are supported.  No PIN, UV, attestation identity, extensions,
resident credentials or remote account interaction are implemented.

Approval callback contract:

    approval(action="makeCredential" | "getAssertion",
             rp_id="localhost", cancel_event=threading.Event()) -> bool

Only a literal True grants user presence.  The caller must implement a real
interactive approval action; there is deliberately no implicit approval.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import threading
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import cbor
from .backend import DEVELOPMENT_AAGUID, GetInfoBackend
from .constants import Ctap2Command, Ctap2Error
from .credentials import Credential, CredentialOperationCancelled, CredentialStore


log = logging.getLogger("ctaphid.dev_backend")
_UP = 0x01
_AT = 0x40


class _CtapFailure(Exception):
    def __init__(self, status: Ctap2Error):
        super().__init__(status.name)
        self.status = status


def _require(condition: bool, status: Ctap2Error) -> None:
    if not condition:
        raise _CtapFailure(status)


def _bytes(value: object, size: int | None = None) -> bool:
    return isinstance(value, bytes) and (size is None or len(value) == size)


def _cose_es256(key: ec.EllipticCurvePrivateKey) -> dict:
    point = key.public_key().public_numbers()
    return {
        1: 2,       # kty EC2
        3: -7,      # alg ES256
        -1: 1,      # crv P-256
        -2: point.x.to_bytes(32, "big"),
        -3: point.y.to_bytes(32, "big"),
    }


def _auth_data(rp_id: str, flags: int, counter: int) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + struct.pack(">I", counter)


class DevCredentialBackend(GetInfoBackend):
    """Local-only roaming authenticator with persistent software credentials.

    Runs in one process.  The store serializes threads but intentionally does
    not support multiple daemons writing the same JSON file concurrently.
    """

    def __init__(
        self,
        store_path: str | Path,
        approval: Callable | None = None,
        packet_size: int = 64,
        aaguid: bytes = DEVELOPMENT_AAGUID,
        allowed_rp_ids: set[str] | frozenset[str] | None = None,
    ):
        super().__init__(packet_size=packet_size, aaguid=aaguid)
        self.store = CredentialStore(store_path)
        self.approval = approval
        self.allowed_rp_ids = frozenset({"localhost"} if allowed_rp_ids is None else allowed_rp_ids)
        if not self.allowed_rp_ids or any(
            not isinstance(rp, str) or not rp or len(rp.encode("utf-8")) > 253
            for rp in self.allowed_rp_ids
        ):
            raise ValueError("allowed_rp_ids must contain valid explicit RP identifiers")
        self._command_lock = threading.RLock()

    def get_info(self) -> dict:
        info = super().get_info()
        info[4]["up"] = True
        info[0x0A] = [{"type": "public-key", "alg": -7}]
        return info

    def _rp(self, rp_id: object) -> str:
        _require(isinstance(rp_id, str) and bool(rp_id), Ctap2Error.INVALID_PARAMETER)
        _require(rp_id in self.allowed_rp_ids, Ctap2Error.OPERATION_DENIED)
        return rp_id

    @staticmethod
    def _options(request: dict, key: int, *, make: bool) -> bool:
        options = request.get(key, {})
        _require(isinstance(options, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _require(all(isinstance(k, str) and type(v) is bool for k, v in options.items()),
                 Ctap2Error.CBOR_UNEXPECTED_TYPE)
        if options.get("uv", False):
            raise _CtapFailure(Ctap2Error.INVALID_OPTION)
        # MakeCredential always requires UP, but GetAssertion's up=False is
        # explicitly valid: Windows uses it for a silent credential-membership
        # probe before asking the user to touch the security key. Rejecting it
        # causes Windows to say "this security key doesn't look familiar" even
        # when the allowList contains a credential we really have.
        if make and options.get("up") is False:
            raise _CtapFailure(Ctap2Error.INVALID_OPTION)
        if options.get("rk", False):
            raise _CtapFailure(Ctap2Error.UNSUPPORTED_OPTION)
        _require(not any(k not in ("uv", "up", "rk") for k in options),
                 Ctap2Error.UNSUPPORTED_OPTION)
        return options.get("up", True)

    @staticmethod
    def _extensions(request: dict, key: int) -> None:
        extensions = request.get(key, {})
        _require(isinstance(extensions, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _require(not extensions, Ctap2Error.UNSUPPORTED_EXTENSION)

    @staticmethod
    def _descriptors(value: object) -> list[bytes]:
        _require(isinstance(value, list), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _require(len(value) <= 64, Ctap2Error.LIMIT_EXCEEDED)
        ids = []
        for item in value:
            _require(isinstance(item, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
            _require(item.get("type") == "public-key"
                     and _bytes(item.get("id"))
                     and 1 <= len(item["id"]) <= 1023,
                     Ctap2Error.INVALID_PARAMETER)
            ids.append(item["id"])
        return ids

    @staticmethod
    def _pin_unsupported(params: dict, *keys: int) -> None:
        if any(key in params for key in keys):
            raise _CtapFailure(Ctap2Error.UNSUPPORTED_OPTION)

    @staticmethod
    def _client_hash(params: dict) -> bytes:
        if 2 not in params:
            raise _CtapFailure(Ctap2Error.MISSING_PARAMETER)
        _require(_bytes(params[2], 32), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        return params[2]

    def _approve(
        self, approval: Callable | None, action: str, rp_id: str,
        cancel_event: threading.Event | None,
    ) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
        if approval is None:
            raise _CtapFailure(Ctap2Error.OPERATION_DENIED)
        # The UI callback is responsible for blocking until the human acts or
        # cancel_event is signalled; the server emits keepalives while waiting.
        try:
            approved = approval(action=action, rp_id=rp_id, cancel_event=cancel_event)
        except TimeoutError:
            if cancel_event is not None and cancel_event.is_set():
                raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
            raise _CtapFailure(Ctap2Error.USER_ACTION_TIMEOUT)
        except Exception:
            if cancel_event is not None and cancel_event.is_set():
                raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
            log.error("user-presence callback failed; denying operation")
            raise _CtapFailure(Ctap2Error.OPERATION_DENIED)
        if cancel_event is not None and cancel_event.is_set():
            raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
        _require(approved is True, Ctap2Error.OPERATION_DENIED)

    def _make(self, params: dict, approval: Callable | None,
              cancel_event: threading.Event | None) -> dict:
        if any(key not in params for key in (1, 2, 3, 4)):
            raise _CtapFailure(Ctap2Error.MISSING_PARAMETER)
        digest = params[1]
        _require(_bytes(digest, 32), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        rp = params[2]
        user = params[3]
        _require(isinstance(rp, dict) and isinstance(user, dict),
                 Ctap2Error.CBOR_UNEXPECTED_TYPE)
        rp_id = self._rp(rp.get("id"))
        user_id = user.get("id")
        _require(_bytes(user_id) and len(user_id) <= 64,
                 Ctap2Error.CBOR_UNEXPECTED_TYPE)
        algorithms = params[4]
        _require(isinstance(algorithms, list), Ctap2Error.CBOR_UNEXPECTED_TYPE)
        _require(any(isinstance(item, dict) and item.get("type") == "public-key"
                     and type(item.get("alg")) is int and item["alg"] == -7
                     for item in algorithms), Ctap2Error.UNSUPPORTED_ALGORITHM)
        exclude = self._descriptors(params.get(5, []))
        self._extensions(params, 6)
        self._options(params, 7, make=True)
        self._pin_unsupported(params, 8, 9, 10)
        # Credential-existence probing must also require real user presence.
        self._approve(approval, "makeCredential", rp_id, cancel_event)
        for identifier in exclude:
            if self.store.lookup(rp_id, identifier) is not None:
                raise _CtapFailure(Ctap2Error.CREDENTIAL_EXCLUDED)
        if cancel_event is not None and cancel_event.is_set():
            raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
        credential = self.store.create(rp_id, user_id, cancel_event=cancel_event)
        cose = cbor.encode(_cose_es256(credential.private_key))
        attested = (
            self.aaguid + struct.pack(">H", len(credential.credential_id))
            + credential.credential_id + cose
        )
        auth_data = _auth_data(rp_id, _UP | _AT, 0) + attested
        return {1: "none", 2: auth_data, 3: {}}

    def _assert(self, params: dict, approval: Callable | None,
                cancel_event: threading.Event | None) -> dict:
        if 1 not in params or 2 not in params:
            raise _CtapFailure(Ctap2Error.MISSING_PARAMETER)
        rp_id = self._rp(params[1])
        client_hash = self._client_hash(params)
        allow = self._descriptors(params.get(3, []))
        self._extensions(params, 4)
        require_up = self._options(params, 5, make=False)
        self._pin_unsupported(params, 6, 7)
        _require(bool(allow), Ctap2Error.NO_CREDENTIALS)
        selected: Credential | None = None
        for identifier in allow:
            selected = self.store.lookup(rp_id, identifier)
            if selected is not None:
                break
        _require(selected is not None, Ctap2Error.NO_CREDENTIALS)
        # A silent UP=false probe only works for an already known RP and
        # credential ID in the caller's explicit allowList. It does NOT assert
        # user presence or verification. The subsequent Windows operation with
        # UP=true must still require a fresh physical Volume Up press.
        if require_up:
            self._approve(approval, "getAssertion", rp_id, cancel_event)
        if cancel_event is not None and cancel_event.is_set():
            raise _CtapFailure(Ctap2Error.KEEPALIVE_CANCEL)
        counter = self.store.next_counter(cancel_event=cancel_event)
        auth_data = _auth_data(rp_id, _UP if require_up else 0, counter)
        signature = selected.private_key.sign(auth_data + client_hash, ec.ECDSA(hashes.SHA256()))
        return {
            1: {"type": "public-key", "id": selected.credential_id},
            2: auth_data,
            3: signature,
        }

    def handle_cbor(
        self, request: bytes, approval: Callable | None = None,
        cancel_event: threading.Event | None = None,
    ) -> bytes:
        if not request:
            return bytes([Ctap2Error.INVALID_LENGTH])
        command = request[0]
        if command not in (Ctap2Command.GET_INFO, Ctap2Command.MAKE_CREDENTIAL,
                           Ctap2Command.GET_ASSERTION):
            return bytes([Ctap2Error.INVALID_COMMAND])
        try:
            params = cbor.decode(request[1:]) if request[1:] else {}
            _require(isinstance(params, dict), Ctap2Error.CBOR_UNEXPECTED_TYPE)
            if command == Ctap2Command.GET_INFO:
                _require(not params, Ctap2Error.INVALID_PARAMETER)
                return bytes([Ctap2Error.SUCCESS]) + cbor.encode(self.get_info())
            if not request[1:]:
                raise _CtapFailure(Ctap2Error.MISSING_PARAMETER)
            _require(all(type(key) is int for key in params), Ctap2Error.CBOR_UNEXPECTED_TYPE)
            with self._command_lock:
                effective_approval = approval if approval is not None else self.approval
                if command == Ctap2Command.MAKE_CREDENTIAL:
                    result = self._make(params, effective_approval, cancel_event)
                else:
                    result = self._assert(params, effective_approval, cancel_event)
            return bytes([Ctap2Error.SUCCESS]) + cbor.encode(result)
        except cbor.CborError:
            log.info("CTAP2 command 0x%02x failed: INVALID_CBOR", command)
            return bytes([Ctap2Error.INVALID_CBOR])
        except _CtapFailure as exc:
            log.info("CTAP2 command 0x%02x failed: %s (0x%02x)",
                     command, exc.status.name, int(exc.status))
            return bytes([exc.status])
        except CredentialOperationCancelled:
            return bytes([Ctap2Error.KEEPALIVE_CANCEL])
        except OverflowError:
            return bytes([Ctap2Error.KEY_STORE_FULL])
        except (OSError, ValueError):
            log.error("credential store or signing operation failed")
            return bytes([Ctap2Error.OTHER])
