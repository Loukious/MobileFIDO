"""Offline cryptographic and CTAP2 regression tests for Milestone 3A.

No gadget, network, browser, registration or real account is touched.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ctaphid import cbor
from ctaphid.constants import Ctap2Error
from ctaphid.credentials import CredentialStore
from ctaphid.dev_backend import DevCredentialBackend


RP = "localhost"
HASH = bytes(range(32))
USER = b"local-user"
APPROVE = lambda **kwargs: True
DENY = lambda **kwargs: False


def send(backend, code: int, params: dict | None = None, **kwargs):
    request = bytes([code]) + (cbor.encode(params) if params is not None else b"")
    response = backend.handle_cbor(request, **kwargs)
    if response[0] == 0:
        return response[0], cbor.decode(response[1:])
    assert len(response) == 1, response.hex()
    return response[0], None


def registration(params=None):
    base = {
        1: HASH, 2: {"id": RP, "name": "Local test"},
        3: {"id": USER, "name": "Development user"},
        4: [{"type": "public-key", "alg": -7}],
    }
    return {**base, **(params or {})}


def assertion(identifier, params=None):
    return {
        1: RP, 2: HASH, 3: [{"type": "public-key", "id": identifier}],
        **(params or {}),
    }


def unpack_attested(auth_data: bytes):
    assert auth_data[:32] == hashlib.sha256(RP.encode()).digest()
    assert auth_data[32] == 0x41
    count = struct.unpack(">I", auth_data[33:37])[0]
    aaguid = auth_data[37:53]
    length = struct.unpack(">H", auth_data[53:55])[0]
    identifier = auth_data[55:55 + length]
    cose = cbor.decode(auth_data[55 + length:])
    return count, aaguid, identifier, cose


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "authenticator" / "credentials.json"
        self.backend = DevCredentialBackend(self.path)

    def create(self, params=None, *, approval=APPROVE):
        status, result = send(
            self.backend, 1, registration() if params is None else params,
            approval=approval,
        )
        self.assertEqual(status, Ctap2Error.SUCCESS)
        return unpack_attested(result[2])[2], result

    def test_get_info_only_advertises_implemented_capabilities(self):
        status, info = send(self.backend, 4)
        self.assertEqual(status, 0)
        self.assertEqual(info[1], ["FIDO_2_0"])
        self.assertEqual(len(info[3]), 16)
        self.assertEqual(info[4], {
            "rk": False, "up": True, "uv": False, "clientPin": False,
        })
        self.assertEqual(info[10], [{"type": "public-key", "alg": -7}])
        self.assertNotIn(6, info)
        self.assertEqual(self.backend.handle_cbor(b"\x04\xa0")[0], 0)
        self.assertEqual(send(self.backend, 4, {1: "extra"})[0], Ctap2Error.INVALID_PARAMETER)

    def test_default_denies_and_does_not_create_any_keys(self):
        self.assertEqual(send(self.backend, 1, registration())[0], Ctap2Error.OPERATION_DENIED)
        self.assertEqual(send(self.backend, 1, registration(), approval=DENY)[0],
                         Ctap2Error.OPERATION_DENIED)
        self.assertFalse(self.path.exists())
        self.assertEqual(send(self.backend, 2, assertion(b"x"))[0], Ctap2Error.NO_CREDENTIALS)

    def test_instance_approval_only_when_explicitly_configured(self):
        backend = DevCredentialBackend(self.path, approval=APPROVE)
        status, result = send(backend, 1, registration())
        self.assertEqual(status, 0)
        self.assertEqual(result[1], "none")

    def test_make_credential_attested_auth_data_and_cose(self):
        seen = []

        def approval(**kwargs):
            seen.append(kwargs)
            return True

        identifier, result = self.create(approval=approval)
        self.assertEqual(result[1], "none")
        self.assertEqual(result[3], {})
        count, aaguid, credential_id, cose = unpack_attested(result[2])
        self.assertEqual(count, 0)
        self.assertEqual(aaguid, self.backend.aaguid)
        self.assertEqual(credential_id, identifier)
        self.assertEqual(len(identifier), 32)
        self.assertEqual(cose[1], 2)
        self.assertEqual(cose[3], -7)
        self.assertEqual(cose[-1], 1)
        self.assertEqual(len(cose[-2]), 32)
        self.assertEqual(len(cose[-3]), 32)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["action"], "makeCredential")
        self.assertEqual(seen[0]["rp_id"], RP)
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        private_text = self.path.read_text()
        self.assertNotIn("BEGIN PRIVATE KEY", private_text)  # base64 encoded JSON
        self.assertEqual(len(self.backend.store._read()["credentials"]), 1)

    def test_assertion_signature_and_persisted_monotonic_counter(self):
        identifier, registration_result = self.create()
        _, _, _, cose = unpack_attested(registration_result[2])
        pubkey = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        for counter in (1, 2, 3):
            if counter == 3:
                self.backend = DevCredentialBackend(self.path, approval=APPROVE)
            status, result = send(self.backend, 2, assertion(identifier),
                                  approval=APPROVE)
            self.assertEqual(status, 0)
            self.assertEqual(result[1]["type"], "public-key")
            self.assertEqual(result[1]["id"], identifier)
            self.assertEqual(result[2][:32], hashlib.sha256(RP.encode()).digest())
            self.assertEqual(result[2][32], 1)
            self.assertEqual(struct.unpack(">I", result[2][33:37])[0], counter)
            self.assertEqual(len(result[2]), 37)
            pubkey.verify(result[3], result[2] + HASH, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(self.backend.store._read()["counter"], 3)

    def test_wrong_client_hash_fails_signature_verification(self):
        identifier, data = self.create()
        cose = unpack_attested(data[2])[3]
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"), ec.SECP256R1(),
        ).public_key()
        status, result = send(self.backend, 2, assertion(identifier), approval=APPROVE)
        self.assertEqual(status, 0)
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            public_key.verify(result[3], result[2] + bytes(32),
                              ec.ECDSA(hashes.SHA256()))

    def test_exclude_list_is_rp_scoped_and_requires_presence(self):
        identifier, _ = self.create()
        params = registration({5: [{"type": "public-key", "id": identifier}]})
        self.assertEqual(send(self.backend, 1, params)[0], Ctap2Error.OPERATION_DENIED)
        self.assertEqual(send(self.backend, 1, params, approval=APPROVE)[0],
                         Ctap2Error.CREDENTIAL_EXCLUDED)
        self.assertEqual(len(self.backend.store._read()["credentials"]), 1)
        # The same credential ID cannot assert for any different RP, even when
        # another explicit development RP is enabled.
        other = DevCredentialBackend(self.path, approval=APPROVE,
                                     allowed_rp_ids={RP, "test.local"})
        status, _ = send(other, 2, assertion(identifier, {1: "test.local"}))
        self.assertEqual(status, Ctap2Error.NO_CREDENTIALS)

    def test_allow_list_only_and_no_credential_leakage(self):
        identifier, _ = self.create()
        self.assertEqual(send(self.backend, 2, {1: RP, 2: HASH},
                              approval=APPROVE)[0], Ctap2Error.NO_CREDENTIALS)
        self.assertEqual(send(self.backend, 2, assertion(os.urandom(32)),
                              approval=APPROVE)[0], Ctap2Error.NO_CREDENTIALS)
        self.assertEqual(send(self.backend, 2, assertion(identifier),
                              approval=DENY)[0], Ctap2Error.OPERATION_DENIED)
        self.assertEqual(self.backend.store._read()["counter"], 0)
        status, result = send(self.backend, 2, assertion(identifier), approval=APPROVE)
        self.assertEqual(status, 0)
        self.assertNotIn(4, result)  # non-discoverable user details not exposed
        self.assertNotIn(5, result)  # no numberOfCredentials, no getNextAssertion
        self.assertEqual(send(self.backend, 8)[0], Ctap2Error.INVALID_COMMAND)

    def test_windows_silent_up_false_credential_probe(self):
        # Windows issues a check-only GetAssertion(up=False) to decide if the
        # USB key contains the allowListed credential before prompting for a
        # touch. It must be a VALID assertion with UP=0, not INVALID_OPTION.
        identifier, registration_result = self.create()
        cose = unpack_attested(registration_result[2])[3]
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        def no_presence(**kwargs):
            self.fail("up=False must not ask for a button press")

        status, probe = send(self.backend, 2, assertion(
            identifier, {5: {"up": False}}), approval=no_presence)
        self.assertEqual(status, Ctap2Error.SUCCESS)
        self.assertEqual(probe[1]["id"], identifier)
        self.assertEqual(probe[2][32], 0, "UP and UV must both be clear")
        public_key.verify(probe[3], probe[2] + HASH, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(self.backend.store._read()["counter"], 1)

        status, regular = send(self.backend, 2, assertion(identifier), approval=DENY)
        self.assertEqual(status, Ctap2Error.OPERATION_DENIED)
        self.assertEqual(self.backend.store._read()["counter"], 1)
        status, regular = send(self.backend, 2, assertion(identifier), approval=APPROVE)
        self.assertEqual(status, Ctap2Error.SUCCESS)
        self.assertEqual(regular[2][32], 1, "normal assertion must assert UP")
        self.assertEqual(struct.unpack(">I", regular[2][33:37])[0], 2)

    def test_multiple_credential_ids_and_persistence(self):
        first, _ = self.create()
        second, _ = self.create()
        self.assertNotEqual(first, second)
        backend = DevCredentialBackend(self.path, approval=APPROVE)
        status, result = send(backend, 2, assertion(first), approval=APPROVE)
        self.assertEqual(status, 0)
        self.assertEqual(result[1]["id"], first)
        status, result = send(
            backend, 2, assertion(first, {3: [
                {"type": "public-key", "id": b"nonexistent"},
                {"type": "public-key", "id": second},
                {"type": "public-key", "id": first},
            ]}), approval=APPROVE,
        )
        self.assertEqual(status, 0)
        self.assertEqual(result[1]["id"], second)

    def test_invalid_requests_fail_before_approval(self):
        fail_if_called = lambda **kwargs: self.fail("invalid request reached approval")
        cases = [
            (1, {}, Ctap2Error.MISSING_PARAMETER),
            (1, registration({1: b"short"}), Ctap2Error.CBOR_UNEXPECTED_TYPE),
            (1, registration({2: {"id": "remote.example"}}), Ctap2Error.OPERATION_DENIED),
            (1, registration({3: {"id": "invalid-user"}}), Ctap2Error.CBOR_UNEXPECTED_TYPE),
            (1, registration({4: [{"type": "public-key", "alg": -257}]}),
             Ctap2Error.UNSUPPORTED_ALGORITHM),
            (1, registration({7: {"rk": True}}), Ctap2Error.UNSUPPORTED_OPTION),
            (1, registration({7: {"uv": True}}), Ctap2Error.INVALID_OPTION),
            (1, registration({7: {"up": False}}), Ctap2Error.INVALID_OPTION),
            (1, registration({6: {"hmac-secret": True}}), Ctap2Error.UNSUPPORTED_EXTENSION),
            (1, registration({8: b"x"}), Ctap2Error.UNSUPPORTED_OPTION),
            (2, {1: RP}, Ctap2Error.MISSING_PARAMETER),
            (2, assertion(b"id", {2: b"short"}), Ctap2Error.CBOR_UNEXPECTED_TYPE),
            (2, assertion(b"id", {5: {"uv": True}}), Ctap2Error.INVALID_OPTION),
            (2, assertion(b"id", {4: {"largeBlobKey": True}}),
             Ctap2Error.UNSUPPORTED_EXTENSION),
            (2, assertion(b"id", {6: b"x"}), Ctap2Error.UNSUPPORTED_OPTION),
            (2, assertion(b"id", {3: []}), Ctap2Error.NO_CREDENTIALS),
        ]
        for command, params, expected in cases:
            with self.subTest(command=command, params=params):
                self.assertEqual(
                    send(self.backend, command, params, approval=fail_if_called)[0],
                    expected,
                )
        self.assertFalse(self.path.exists())
        self.assertEqual(self.backend.handle_cbor(b""), bytes([Ctap2Error.INVALID_LENGTH]))
        self.assertEqual(self.backend.handle_cbor(b"\x01\xff"), bytes([Ctap2Error.INVALID_CBOR]))
        self.assertEqual(send(self.backend, 1, [1, 2])[0], Ctap2Error.CBOR_UNEXPECTED_TYPE)
        self.assertEqual(send(self.backend, 7)[0], Ctap2Error.INVALID_COMMAND)

    def test_cancellation_blocks_creation_and_counter_change(self):
        cancelled = threading.Event()
        cancelled.set()
        self.assertEqual(send(self.backend, 1, registration(),
                              approval=APPROVE, cancel_event=cancelled)[0],
                         Ctap2Error.KEEPALIVE_CANCEL)
        self.assertFalse(self.path.exists())
        identifier, _ = self.create()
        self.assertEqual(send(self.backend, 2, assertion(identifier),
                              approval=APPROVE, cancel_event=cancelled)[0],
                         Ctap2Error.KEEPALIVE_CANCEL)
        self.assertEqual(self.backend.store._read()["counter"], 0)

    def test_cancellation_while_waiting_for_real_approval(self):
        entered = threading.Event()
        stopped = threading.Event()
        cancel = threading.Event()
        result = []

        def wait_for_approval(**kwargs):
            entered.set()
            kwargs["cancel_event"].wait(2)
            stopped.set()
            return True  # even a late approval must not override cancel

        thread = threading.Thread(
            target=lambda: result.append(send(
                self.backend, 1, registration(),
                approval=wait_for_approval, cancel_event=cancel,
            )[0]), daemon=True,
        )
        thread.start()
        self.assertTrue(entered.wait(1))
        cancel.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(stopped.is_set())
        self.assertEqual(result, [Ctap2Error.KEEPALIVE_CANCEL])
        self.assertFalse(self.path.exists())

    def test_cancellation_just_before_store_commit_does_not_write(self):
        cancel = threading.Event()
        original_save = self.backend.store._save

        def cancel_before_save(data, cancel_event=None):
            cancel.set()
            return original_save(data, cancel_event=cancel_event)

        with patch.object(self.backend.store, "_save", side_effect=cancel_before_save):
            status, _ = send(self.backend, 1, registration(),
                             approval=APPROVE, cancel_event=cancel)
        self.assertEqual(status, Ctap2Error.KEEPALIVE_CANCEL)
        self.assertFalse(self.path.exists())
        cancel.clear()
        identifier, _ = self.create()
        with patch.object(self.backend.store, "_save", side_effect=cancel_before_save):
            status, _ = send(self.backend, 2, assertion(identifier),
                             approval=APPROVE, cancel_event=cancel)
        self.assertEqual(status, Ctap2Error.KEEPALIVE_CANCEL)
        self.assertEqual(self.backend.store._read()["counter"], 0)

    def test_callback_timeout_and_failure_denied_without_key_creation(self):
        def timeout(**_kwargs):
            raise TimeoutError("approval timed out")

        def failure(**_kwargs):
            raise RuntimeError("approval input unavailable")

        self.assertEqual(send(self.backend, 1, registration(),
                              approval=timeout)[0], Ctap2Error.USER_ACTION_TIMEOUT)
        self.assertEqual(send(self.backend, 1, registration(),
                              approval=failure)[0], Ctap2Error.OPERATION_DENIED)
        self.assertFalse(self.path.exists())

    def test_denial_and_storage_integrity_across_restart(self):
        identifier, _ = self.create()
        self.assertEqual(
            send(self.backend, 2, assertion(identifier), approval=DENY)[0],
            Ctap2Error.OPERATION_DENIED,
        )
        self.assertEqual(self.backend.store._read()["counter"], 0)
        self.path.write_text("corrupted json")
        with self.assertRaises(ValueError):
            DevCredentialBackend(self.path)
        self.assertEqual(self.path.read_text(), "corrupted json")

    def test_store_mode_rejection(self):
        self.create()
        self.path.chmod(0o644)
        with self.assertRaises(PermissionError):
            DevCredentialBackend(self.path)
        self.path.chmod(0o600)
        alias = self.path.with_name("alias.json")
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            DevCredentialBackend(alias)

    def test_counter_exhaustion_never_wraps(self):
        identifier, _ = self.create()
        data = self.backend.store._read()
        data["counter"] = CredentialStore.MAX_COUNTER
        self.backend.store._save(data)
        self.assertEqual(send(self.backend, 2, assertion(identifier),
                              approval=APPROVE)[0], Ctap2Error.KEY_STORE_FULL)
        self.assertEqual(self.backend.store._read()["counter"], CredentialStore.MAX_COUNTER)


if __name__ == "__main__":
    unittest.main()
