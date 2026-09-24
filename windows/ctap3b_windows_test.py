#!/usr/bin/env python3
"""Local-only Windows WebAuthn test for Android Keystore + biometric mode.

M3B deliberately has a distinct AAGUID and public-credential save file from
M3A, so an unencrypted development key can never be mistaken for a Keystore
key. This test REQUIRES real UV in both registration and authentication.

After the FIRST ordinary phone unlock following a reboot, the already enabled
Android helper starts its foreground listener automatically; it does not need
its Activity opened once to 'prime' background notifications. Allow request
notifications and keep the phone nearby:

    python windows/ctap3b_windows_test.py register
    python windows/ctap3b_windows_test.py authenticate

When a request arrives, tap its Android notification to open the helper;
the fingerprint prompt should appear without a separate Continue step.
Windows may request two biometrics during authentication: the up=false
credential preflight and the real up=true assertion each require their own
per-operation Android Keystore signature. Tapping a notification alone never
authorizes either operation.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
from pathlib import Path

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData

from ctap3a_windows_test import client


RP = {"id": "localhost", "name": "Poco F7 Biometric Keystore Local Test"}
AAGUID = b"PocoF7-BIO-DEV01"
STORE = Path(__file__).with_name("local-test-keystore-credential.json")
ADB = Path(os.environ.get("POCO_FIDO_ADB", r"D:\platform-tools\adb.exe"))


def check_phone_helper_ready() -> None:
    """Fail early if the Android helper's IPC socket is no longer present.

    A user-started background service can retain the root-only IPC listener
    while the consent Activity is stopped. Its socket must still exist: an
    absent socket can make Windows report the misleading 'security key doesn't
    look familiar' message. Socket presence alone does not prove an Android
    notification permission is granted or authenticate the socket's peer; the
    native CTAPHID responder performs the latter check using SO_PEERCRED.
    """
    if os.name != "nt":
        return  # The native Windows client() below rejects non-Windows hosts.
    if not ADB.is_file():
        raise SystemExit(f"Cannot check Poco F7 helper: adb missing at {ADB}. "
                         "Set POCO_FIDO_ADB to the full Windows adb.exe path.")

    def query(*args: str) -> str:
        try:
            response = subprocess.run(
                [str(ADB), "shell", *args], capture_output=True,
                text=True, timeout=12, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemExit("Poco F7 ADB unavailable; check USB and ADB connection") from exc
        if response.returncode:
            raise SystemExit("Poco F7 ADB shell failed; check the connected phone")
        return response.stdout

    if "@ctaphid-m3b-v1" not in query("cat", "/proc/net/unix"):
        raise SystemExit(
            "Android CTAP helper socket is stopped. Unlock the phone normally "
            "once after boot, verify PocoKey DEV's root-only listener starts, "
            "and enable request notifications. Open the app if Android has "
            "force-stopped/restricted it. Do not delete the registered credential."
        )
    print("PASS: Poco F7 helper IPC socket present; foreground Activity not required", flush=True)


def register() -> None:
    if STORE.exists():
        raise SystemExit(f"Refusing to overwrite {STORE}; authenticate or move the old file")
    rp = Fido2Server(RP, attestation="direct")
    creation, state = rp.register_begin(
        {"id": b"poco-f7-biometric-test", "name": "biotest", "displayName": "Poco F7 Biometric"},
        user_verification="required",
        resident_key_requirement="discouraged",
        authenticator_attachment="cross-platform",
    )
    print("Tap the Poco F7 request notification, then approve the fingerprint prompt.", flush=True)
    result = client().make_credential(creation.public_key)
    data = rp.register_complete(state, result)
    credential = data.credential_data
    if credential is None or credential.aaguid != AAGUID:
        raise SystemExit("Wrong or unrecognized development Keystore authenticator; not saving")
    if not data.is_user_present() or not data.is_user_verified():
        raise SystemExit("Authenticator did not actually assert UP + UV; not saving")
    STORE.write_text(json.dumps({
        "rp_id": RP["id"],
        "credential_data": base64.b64encode(bytes(credential)).decode("ascii"),
        "sign_count": data.counter,
    }, indent=2) + "\n", encoding="utf-8")
    print("PASS: independent Fido2Server accepted registration with UP=1 UV=1")
    print("PASS: distinct Keystore development AAGUID matches; saved public credential only")


def authenticate() -> None:
    saved = json.loads(STORE.read_text(encoding="utf-8"))
    if saved["rp_id"] != RP["id"]:
        raise SystemExit("Saved RP ID mismatch")
    credential = AttestedCredentialData(base64.b64decode(saved["credential_data"]))
    if credential.aaguid != AAGUID:
        raise SystemExit("Saved AAGUID mismatch")
    rp = Fido2Server(RP, attestation="direct")
    options, state = rp.authenticate_begin([credential], user_verification="required")
    print("Tap each phone request notification and approve each fingerprint prompt; "
          "Windows may run an up=false preflight first.", flush=True)
    result = client().get_assertion(options.public_key).get_response(0)
    matched = rp.authenticate_complete(state, [credential], result)
    if matched.credential_id != credential.credential_id:
        raise SystemExit("Wrong credential returned")
    auth_data = result.response.authenticator_data
    if not auth_data.is_user_present() or not auth_data.is_user_verified():
        raise SystemExit("Expected both UP and UV in actual assertion")
    if auth_data.counter <= saved["sign_count"]:
        raise SystemExit("Sign counter did not increase")
    saved["sign_count"] = auth_data.counter
    STORE.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    print("PASS: independent RP verified ES256 assertion, user presence and UV")
    print("PASS: monotonically increasing sign counter", auth_data.counter)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("register", "authenticate"))
    parser.add_argument("--ready", action="store_true",
                        help="skip interactive confirmation that helper service/notifications are ready")
    args = parser.parse_args()
    if not args.ready:
        input("Unlock Poco F7 normally once after reboot, allow PocoKey DEV "
              "request notifications, and keep the phone nearby. "
              "Tap each request notification and scan your fingerprint "
              "(no Continue button). Press Enter to begin: ")
    check_phone_helper_ready()
    (register if args.action == "register" else authenticate)()
