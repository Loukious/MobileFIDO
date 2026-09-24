#!/usr/bin/env python3
"""Deterministically package standalone Android ARM64 CTAPHID KernelSU ZIP.

No adb, privilege escalation, phone mutation or APK signing. The input APK must
already be signed by the pinned MobileFIDO release certificate and pass Android
SDK `apksigner verify`. Does NOT bundle Kali, NetHunter, Python, native CPython
extensions, app credential stores or JKS.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "native-tools"
MOD = ROOT / "ksu-native-module"
BINARY = ROOT / "native-ctaphid/target/aarch64-linux-android/release/pocof7-native-ctaphid"
APK = Path(os.environ.get(
    "MOBILEFIDO_RELEASE_APK",
    ROOT / "android-helper/app/build/manual/MobileFIDO-5.1.1-release.apk",
)).expanduser().resolve()
ZIP = TOOLS / "dist/MobileFIDO-Android-FIDO2-KSU-Next.zip"
SIGNER_SHA = "c645b6e1b8b9436041588abd773bb5b4f872d0f3ecc078a64ae0c34c63eb45da"
STAMP = (2020, 1, 1, 0, 0, 0)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_file(path: Path, limit: int = 32 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"missing, symlinked or oversized module source: {path}")
    return path.read_bytes()


def apksigner_path() -> Path:
    explicit = os.environ.get("MOBILEFIDO_APKSIGNER")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    build_tools = os.environ.get("ANDROID_BUILD_TOOLS")
    if build_tools:
        candidates.append(Path(build_tools) / "apksigner")
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if sdk:
        candidates.append(Path(sdk) / "build-tools/35.0.0/apksigner")
    on_path = shutil.which("apksigner")
    if on_path:
        candidates.append(Path(on_path))
    # Local development fallback used by this workspace; callers can override
    # it with MOBILEFIDO_APKSIGNER on any other machine/SDK version.
    candidates.append(Path("/tmp/mobilefido-toolchain/android-sdk/build-tools/35.0.0/apksigner"))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise ValueError("Android apksigner unavailable; set MOBILEFIDO_APKSIGNER or ANDROID_BUILD_TOOLS")


def verify_apk_signer(path: Path) -> str:
    signer = apksigner_path()
    env = dict(os.environ)
    java_home = env.get("JAVA_HOME")
    if not java_home and Path("/tmp/mobilefido-toolchain/jdk/bin/java").is_file():
        java_home = "/tmp/mobilefido-toolchain/jdk"
        env["JAVA_HOME"] = java_home
    if java_home:
        env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
    result = subprocess.run(
        [str(signer), "verify", "--verbose", "--print-certs", str(path)],
        capture_output=True, text=True, env=env, check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"apksigner rejected release APK: {result.stderr.strip() or result.stdout.strip()}")
    output = result.stdout
    count = re.search(r"^Number of signers: (\d+)$", output, re.M)
    certs = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$",
                       output, re.M)
    modern = ("Verified using v3 scheme (APK Signature Scheme v3): true" in output or
              "Verified using v3.1 scheme (APK Signature Scheme v3.1): true" in output)
    if not count or count.group(1) != "1" or len(certs) != 1 or not modern:
        raise ValueError("release APK must have exactly one verified v3/v3.1 signer")
    return certs[0].lower()


def collect() -> dict[str, bytes]:
    entries = {}
    for name, source in (
        ("module.prop", TOOLS / "module.prop"),
        ("customize.sh", TOOLS / "customize.sh"),
    ):
        entries[name] = input_file(source)
    entries["skip_mount"] = b""
    for source in sorted(MOD.rglob("*")):
        if source.is_dir():
            if source.is_symlink():
                raise ValueError(f"symlink folder: {source}")
            continue
        name = source.relative_to(MOD).as_posix()
        if (name in ("module.prop", "customize.sh", "skip_mount") or
                name.startswith(("system/", "payload/", "bin/")) or
                any(part.startswith(".") for part in name.split("/")) or
                source.suffix in (".jks", ".pem", ".key", ".so", ".pyc")):
            if name == "module.prop":
                if input_file(source).splitlines()[0] != b"id=pocof7_ctap_native":
                    raise ValueError("runtime and package module IDs differ")
                continue
            raise ValueError(f"unsafe module source: {name}")
        if name in entries:
            raise ValueError(f"duplicate module entry: {name}")
        entries[name] = input_file(source)
    for script in ("service.sh", "action.sh", "uninstall.sh", "lib/common.sh",
                   "lib/usb.sh", "lib/daemon.sh"):
        if script not in entries:
            raise ValueError(f"missing critical module script: {script}")

    binary = input_file(BINARY)
    if (len(binary) < 4096 or binary[:4] != b"\x7fELF" or binary[4] != 2 or
            binary[5] != 1 or struct.unpack_from("<H", binary, 18)[0] != 183):
        raise ValueError("not an ELF64 little-endian AArch64 native binary")
    if b"/system/bin/linker64" not in binary:
        raise ValueError("binary not linked for Android's bionic linker")
    entries["bin/pocof7-native-ctaphid"] = binary

    apk = input_file(APK)
    apk_sha = sha(apk)
    if verify_apk_signer(APK) != SIGNER_SHA:
        raise ValueError("bundled APK is not signed by the pinned MobileFIDO release identity")
    entries["payload/helper.apk"] = apk

    provenance = {
        "format": 1,
        "moduleId": "pocof7_ctap_native",
        "backend": "Android ARM64 native Rust; bionic API >=31",
        "noKaliNetHunterPythonRuntime": True,
        "binarySha256": sha(binary),
        "appPackage": "org.pocof7.ctap3b",
        "appSha256": apk_sha,
        "appSignerSha256": SIGNER_SHA,
        "appSignerVerification": "Android SDK apksigner verify --print-certs",
        "files": {name: sha(data) for name, data in sorted(entries.items())},
    }
    entries["provenance.json"] = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()
    entries["sha256sums.txt"] = "".join(
        f"{sha(data)}  {name}\n" for name, data in sorted(entries.items())
    ).encode("ascii")
    return entries


def build(path: Path = ZIP) -> tuple[Path, str]:
    entries = collect()  # Validate ALL input before opening output.
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ctap-native-", suffix=".zip", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as file:
            with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9) as archive:
                for name, data in sorted(entries.items()):
                    info = zipfile.ZipInfo(name, STAMP)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = ((0o100755 if name.endswith(".sh") or name.startswith("bin/")
                                           else 0o100644) << 16)
                    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED,
                                     compresslevel=9)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path, sha(path.read_bytes())


if __name__ == "__main__":
    try:
        output, digest = build(Path(sys.argv[1]) if len(sys.argv) > 1 else ZIP)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        sys.exit(f"Standalone module build REFUSED: {exc}")
    print(f"ZIP: {output}\nSHA256: {digest}\nAPP SHA256: {sha(APK.read_bytes())}\nAPP SIGNER SHA256: {SIGNER_SHA}")
