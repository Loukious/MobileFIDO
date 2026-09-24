#!/usr/bin/env python3
"""Development-only end-to-end WebAuthn relying-party verification on Windows.

Uses the Windows WebAuthn API rather than opening the security key as raw HID:
ordinary users can run this without elevation.  The local RP ID is localhost;
registration and authentication are verified by Yubico's Fido2Server.  The
phone MUST be unlocked and its physical Volume Up button pressed to approve
each operation.  Never use credentials created here for important accounts.

    python ctap3a_windows_test.py register
    python ctap3a_windows_test.py authenticate

The second command can run after USB reconnect and phone daemon restart.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from fido2.client import DefaultClientDataCollector
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData

RP = {"id": "localhost", "name": "Poco F7 FIDO2 Local Development Test"}
AAGUID = b"PocoF7-CTAP2-DEV"
STORE = Path(__file__).with_name("local-test-credential.json")


def client():
    if os.name != "nt":
        raise SystemExit("Run this script with Windows Python, not WSL/Kali Python")
    # fido2.client.windows imports Windows DLLs at module import time.
    from fido2.client.windows import WindowsClient

    if not WindowsClient.is_available():
        raise SystemExit("Windows WebAuthn API is not available")
    return WindowsClient(DefaultClientDataCollector("http://localhost"))


def register() -> None:
    if STORE.exists():
        raise SystemExit(f"{STORE} already exists: do not overwrite your test credential")
    # Request direct conveyance to preserve the AAGUID across WebAuthn clients.
    # The authenticator itself still returns fmt="none", so this development
    # identifier is self-asserted; it does not establish hardware provenance.
    rp = Fido2Server(RP, attestation="direct")
    creation, state = rp.register_begin(
        {"id": b"poco-f7-local-test", "name": "localtest", "displayName": "Poco F7 Local Test"},
        resident_key_requirement="discouraged",
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    print("Windows will display a security-key prompt. On the Poco F7 press its PHYSICAL Volume Up key once when requested.", flush=True)
    result = client().make_credential(creation.public_key)
    auth_data = rp.register_complete(state, result)
    credential = auth_data.credential_data
    if credential is None or credential.aaguid != AAGUID:
        raise SystemExit("Wrong authenticator selected; refused to save credential")
    if not auth_data.is_user_present() or auth_data.is_user_verified():
        raise SystemExit("Unexpected UP/UV flags; refused to save credential")
    STORE.write_text(json.dumps({
        "rp_id": RP["id"],
        "credential_data": base64.b64encode(bytes(credential)).decode("ascii"),
        "sign_count": auth_data.counter,
    }, indent=2) + "\n", encoding="utf-8")
    print("PASS registration verified by independent Fido2Server; development AAGUID matched")
    print("PASS UP asserted and UV not claimed")
    print("Saved public credential data only:", STORE)


def authenticate() -> None:
    stored = json.loads(STORE.read_text(encoding="utf-8"))
    if stored["rp_id"] != RP["id"]:
        raise SystemExit("Stored credential RP ID does not match test RP")
    credential = AttestedCredentialData(base64.b64decode(stored["credential_data"]))
    if credential.aaguid != AAGUID:
        raise SystemExit("Stored credential is not from the Poco F7 development authenticator")
    rp = Fido2Server(RP, attestation="direct")
    options, state = rp.authenticate_begin([credential], user_verification="discouraged")
    print("Authenticate using the same phone key. Press PHYSICAL Volume Up after the phone requests presence.", flush=True)
    selection = client().get_assertion(options.public_key)
    assertion = selection.get_response(0)
    verified = rp.authenticate_complete(state, [credential], assertion)
    if verified.credential_id != credential.credential_id:
        raise SystemExit("Authentication returned the wrong credential")
    auth_data = assertion.response.authenticator_data
    if auth_data.is_user_verified():
        raise SystemExit("Unexpected UV flag in development authenticator assertion")
    if auth_data.counter <= stored.get("sign_count", 0):
        raise SystemExit("Signature counter did not increase; refused to update credential")
    stored["sign_count"] = auth_data.counter
    STORE.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")
    print("PASS independent Fido2Server verified the assertion signature and challenge")
    print("PASS signature counter increased to", auth_data.counter)
    print("PASS re-used the original credential", credential.credential_id.hex()[:16] + "…")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("register", "authenticate"))
    args = parser.parse_args()
    if args.action == "register":
        register()
    else:
        authenticate()
