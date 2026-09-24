"""Development-only, on-disk non-discoverable ES256 credentials.

Private keys are unencrypted PKCS#8 in a mode-0600 JSON file.  This store is
only suitable for the local CTAP prototype: rooted device users and backups
can copy its keys.  Production should use hardware-backed keys and a secure
monotonic counter.  A failed or corrupted load never silently recreates keys.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    rp_id: str
    user_id: bytes
    private_key: ec.EllipticCurvePrivateKey


class CredentialOperationCancelled(Exception):
    """The caller cancelled before a credential/counter commit."""


class CredentialStore:
    """One serialized store shared by every backend command on this process.

    All writes replace the file atomically and sync both file and directory.
    A lock covers lookup, counter allocation and save.  The store supports a
    single daemon process; no interprocess lock is implemented.  The counter
    allocation needs a durable write before releasing a signature.
    """

    MAX_CREDENTIALS = 64
    MAX_COUNTER = 0xFFFFFFFF

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._read()

    def _read(self) -> dict:
        with self._lock:
            if self.path.is_symlink():
                raise ValueError("refusing symlink credential store")
            try:
                details = self.path.stat()
            except FileNotFoundError:
                return {"version": 1, "counter": 0, "credentials": []}
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("credential store must be a regular file")
            if os.name == "posix" and details.st_mode & 0o077:
                raise PermissionError("credential store must be private (chmod 600)")
            raw = self.path.read_bytes()
            try:
                data = json.loads(raw)
                if (not isinstance(data, dict) or data["version"] != 1
                        or type(data["counter"]) is not int
                        or not 0 <= data["counter"] <= self.MAX_COUNTER
                        or not isinstance(data["credentials"], list)
                        or len(data["credentials"]) > self.MAX_CREDENTIALS):
                    raise ValueError("invalid credential store header")
                seen = set()
                for row in data["credentials"]:
                    cred = self._from_row(row)
                    if cred.credential_id in seen:
                        raise ValueError("duplicate credential identifier")
                    seen.add(cred.credential_id)
                return data
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("invalid credential store") from exc

    @staticmethod
    def _from_row(row: dict) -> Credential:
        if not isinstance(row, dict) or not isinstance(row["rp_id"], str):
            raise ValueError("invalid credential record")
        credential_id = _unb64(row["id"])
        user_id = _unb64(row["user_id"])
        private_key = serialization.load_pem_private_key(_unb64(row["key"]), password=None)
        if (len(credential_id) != 32 or len(user_id) > 64
                or not isinstance(private_key, ec.EllipticCurvePrivateKey)
                or not isinstance(private_key.curve, ec.SECP256R1)):
            raise ValueError("invalid credential record data")
        return Credential(credential_id, row["rp_id"], user_id, private_key)

    def _save(self, data: dict, cancel_event: threading.Event | None = None) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("refusing symlink credential store")
        # The unpredictable temporary name avoids collisions and never exposes
        # partial JSON under the final name.  O_EXCL also blocks symlink races.
        temporary = directory / (".credential-" + secrets.token_hex(16))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
            if cancel_event is not None and cancel_event.is_set():
                raise CredentialOperationCancelled()
            os.replace(temporary, self.path)
            if os.name == "posix":
                dirfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
        finally:
            if temporary.exists():
                temporary.unlink()

    def lookup(self, rp_id: str, credential_id: bytes) -> Credential | None:
        with self._lock:
            for row in self._read()["credentials"]:
                if row["rp_id"] == rp_id and _unb64(row["id"]) == credential_id:
                    return self._from_row(row)
            return None

    def create(
        self, rp_id: str, user_id: bytes,
        cancel_event: threading.Event | None = None,
    ) -> Credential:
        with self._lock:
            if cancel_event is not None and cancel_event.is_set():
                raise CredentialOperationCancelled()
            data = self._read()
            if len(data["credentials"]) >= self.MAX_CREDENTIALS:
                raise OverflowError("credential store full")
            ids = {_unb64(row["id"]) for row in data["credentials"]}
            identifier = secrets.token_bytes(32)
            while identifier in ids:
                identifier = secrets.token_bytes(32)
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            data["credentials"].append({
                "id": _b64(identifier), "rp_id": rp_id, "user_id": _b64(user_id),
                "key": _b64(pem),
            })
            self._save(data, cancel_event=cancel_event)
            return Credential(identifier, rp_id, user_id, key)

    def next_counter(self, cancel_event: threading.Event | None = None) -> int:
        """Persist a global monotonic signCount before signing an assertion."""
        with self._lock:
            if cancel_event is not None and cancel_event.is_set():
                raise CredentialOperationCancelled()
            data = self._read()
            if data["counter"] == self.MAX_COUNTER:
                raise OverflowError("signature counter exhausted")
            data["counter"] += 1
            self._save(data, cancel_event=cancel_event)
            return data["counter"]
