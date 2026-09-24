#!/usr/bin/env python3
"""Deterministic, host-only KernelSU Next CTAP3B module ZIP builder.

Default ZIP merges ksu-tools/{module.prop,customize.sh}, the worker-owned
ksu-module/ scripts, source ctaphid/*.py, and the exact installed signed APK.
Never runs adb/su/pm or chroot and never vendors Android app private data,
Keystore, JKS, Python native modules or caches. The final SHA256 is printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
)

ROOT = Path(__file__).resolve().parent.parent
TOOLS = Path(__file__).resolve().parent
PINNED_APK_SHA256 = "b25cc48500549d42e2efc14e48cd48b6d398db14df2aba7ccfc94f295a8fa23c"
PINNED_SIGNER_SHA256 = "3f133472fa0066963cc16ae19a6250e275e7f0f8265589dc5a0b05f746d20da2"
# Frozen copy of the original same-signed helper that matches the disabled
# legacy module. The actively developed native module uses the NEW APK from
# android-helper/app/build/manual; rebuilding it must not break legacy tests.
DEFAULT_APK = TOOLS / "approved-legacy-helper.apk"
DEFAULT_OUT = TOOLS / "dist/PocoF7-CTAP3B-KSU-Next.zip"
MODULE_SCRIPTS = ("service.sh", "action.sh", "uninstall.sh")
TIMESTAMP = (2020, 1, 1, 0, 0, 0)  # ZIP requires a DOS-compatible timestamp.
MAX_SOURCE_BYTES = 16 * 1024 * 1024
SAFE_NAME = re.compile(r"^[a-zA-Z0-9._/+\-]+$")
SECRET_EXTENSIONS = {".jks", ".keystore", ".pem", ".key", ".p12", ".pfx",
                     ".pyc", ".pyo", ".so"}
RESERVED = {"customize.sh", "sha256sums.txt",
            "provenance.json", "payload/"}


class BuildError(RuntimeError):
    pass


def _file(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"not a regular, non-symlink file: {path}")
    if path.stat().st_size > limit:
        raise BuildError(f"oversized source: {path}")
    return path.read_bytes()


def _add(inputs: dict[str, bytes], target: str, data: bytes) -> None:
    if (not SAFE_NAME.fullmatch(target) or target.startswith("/") or
            any(part in ("", ".", "..") for part in target.split("/")) or
            target in inputs):
        raise BuildError(f"unsafe/duplicate module entry: {target!r}")
    inputs[target] = data


def _apk_signer_sha256(apk: bytes) -> str:
    from io import BytesIO
    try:
        with zipfile.ZipFile(BytesIO(apk)) as package:
            if "AndroidManifest.xml" not in package.namelist():
                raise BuildError("signed APK has no Android manifest")
            entries = [name for name in package.namelist()
                       if re.fullmatch(r"META-INF/[^/]+\.RSA", name, re.I)]
            if len(entries) != 1:
                raise BuildError("APK must contain exactly one known v1 signer certificate")
            certs = load_der_pkcs7_certificates(package.read(entries[0]))
            if len(certs) != 1:
                raise BuildError("APK must carry exactly one v1 signer")
            signer = certs[0].fingerprint(hashes.SHA256()).hex()
            # The v2/v3 signing block is separate from ZIP entries.
            if b"APK Sig Block 42" not in apk:
                raise BuildError("APK missing its v2/v3 signing block")
            return signer
    except (zipfile.BadZipFile, ValueError) as exc:
        raise BuildError("invalid signed APK") from exc


def collect_inputs(repo: Path = ROOT, module_src: Path | None = None,
                   apk_path: Path | None = None,
                   *, expected_apk_sha256: str = PINNED_APK_SHA256,
                   expected_signer_sha256: str = PINNED_SIGNER_SHA256) -> dict[str, bytes]:
    repo = repo.resolve()
    module_src = module_src if module_src is not None else repo / "ksu-module"
    apk_path = apk_path if apk_path is not None else DEFAULT_APK
    if not module_src.is_dir() or module_src.is_symlink():
        raise BuildError(f"module source folder unavailable: {module_src}")
    entries: dict[str, bytes] = {}
    _add(entries, "module.prop", _file(TOOLS / "module.prop"))
    _add(entries, "customize.sh", _file(TOOLS / "customize.sh"))
    _add(entries, "skip_mount", b"")
    for script in MODULE_SCRIPTS:
        if not (module_src / script).is_file():
            raise BuildError(f"required KernelSU module script missing: {script}")
    for path in sorted(module_src.rglob("*")):
        if path.is_dir():
            if path.is_symlink():
                raise BuildError(f"symlinked module directory forbidden: {path}")
            continue
        rel = path.relative_to(module_src).as_posix()
        if rel == "module.prop":
            # Worker1 keeps a development module.prop alongside scripts.
            # The released metadata is generated from ksu-tools; accepting
            # a different ID would break hardcoded runtime module paths.
            source = _file(path).decode("utf-8")
            matched = re.search(r"(?m)^id=([^\r\n]+)$", source)
            if matched is None or matched.group(1) != "pocof7_ctap3b":
                raise BuildError("worker module.prop ID mismatches packaged module")
            continue
        if rel == "skip_mount":
            if _file(path):
                raise BuildError("worker skip_mount must be empty")
            continue
        if (rel in RESERVED or rel.startswith(("payload/", "system/",
                                               "META-INF/"))):
            raise BuildError(f"reserved module path: {rel}")
        if (path.suffix.lower() in SECRET_EXTENSIONS or
                any(part.startswith(".") or part == "__pycache__"
                    for part in path.relative_to(module_src).parts)):
            raise BuildError(f"refusing hidden/secret module input: {rel}")
        _add(entries, rel, _file(path))
    pyfiles = sorted((repo / "ctaphid").glob("*.py"))
    if "android_backend.py" not in [path.name for path in pyfiles]:
        raise BuildError("CTAP Android backend source missing")
    for path in pyfiles:
        _add(entries, "payload/ctaphid/" + path.name, _file(path))
    for script in ("ctaphid_start.sh", "ctaphid_stop.sh"):
        _add(entries, "payload/legacy/" + script, _file(repo / script))
    apk = _file(apk_path)
    digest = hashlib.sha256(apk).hexdigest()
    if digest != expected_apk_sha256.lower():
        raise BuildError(f"APK differs from installed approved build: {digest}")
    signer = _apk_signer_sha256(apk)
    if signer != expected_signer_sha256.lower():
        raise BuildError(f"APK signing identity differs: {signer}")
    _add(entries, "payload/helper.apk", apk)

    files_sha = {name: hashlib.sha256(content).hexdigest()
                 for name, content in sorted(entries.items())}
    provenance = {
        "format": 1, "id": "pocof7_ctap3b",
        "apkPackage": "org.pocof7.ctap3b",
        "apkSha256": digest, "apkSignerCertSha256": signer,
        "runtime": "Kali aarch64 /usr/bin/python3 + preinstalled cryptography",
        "files": files_sha,
    }
    _add(entries, "provenance.json",
         (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode())
    sha_lines = "".join(
        hashlib.sha256(content).hexdigest() + "  " + name + "\n"
        for name, content in sorted(entries.items())
    )
    _add(entries, "sha256sums.txt", sha_lines.encode("ascii"))
    return entries


def build(repo: Path = ROOT, module_src: Path | None = None,
          apk_path: Path | None = None, output: Path = DEFAULT_OUT,
          **kwargs: str) -> tuple[Path, str]:
    entries = collect_inputs(repo, module_src, apk_path, **kwargs)
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Open output only after all preflight checks: failure never clobbers an
    # existing known-good installer ZIP.
    descriptor, temporary = tempfile.mkstemp(
        prefix=".ctap3b-", suffix=".zip", dir=output.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9, strict_timestamps=True) as archive:
                for name, data in sorted(entries.items()):
                    info = zipfile.ZipInfo(name, TIMESTAMP)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = ((0o100755 if name.endswith(".sh")
                                            else 0o100644) << 16)
                    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED,
                                     compresslevel=9)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return output, hashlib.sha256(output.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--module-src", type=Path, default=None)
    parser.add_argument("--apk", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    try:
        path, checksum = build(args.repo, args.module_src, args.apk, args.out)
    except (BuildError, OSError) as exc:
        parser.exit(1, f"Build refused: {exc}\n")
    print(f"ZIP: {path}\nSHA256: {checksum}\nAPK SHA256: {PINNED_APK_SHA256}\n"
          f"APK signer SHA256: {PINNED_SIGNER_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
