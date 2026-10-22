#!/usr/bin/env python3
"""Verify and stage the fixed Linux release artifacts for clean-host bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from typing import NoReturn


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
REQUIRED_ARTIFACTS = {
    "artifacts/helicoid-server": ("helicoid-server", 0o755),
    "artifacts/hs-server": ("hs-server", 0o755),
    "artifacts/hs-server.service": ("hs-server.service", 0o644),
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def read_regular_at(directory_fd: int, name: str, maximum: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            fail(f"{name} is not a bounded regular file")
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > maximum:
            fail(f"{name} exceeds its size bound")
        return bytes(content)
    finally:
        os.close(fd)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def release_version(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value
    ):
        return False
    return all(int(part) <= 2**32 - 1 for part in value.split("."))


def verify_signature(manifest: bytes, signature: bytes, key_hex: str) -> None:
    if len(key_hex) != 64:
        fail("verification key must be exactly 32 bytes of hex")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as error:
        raise SystemExit("verification key is not valid hex") from error
    if len(key) != 32:
        fail("verification key must be exactly 32 bytes")
    if len(signature) != 64:
        fail("manifest.sig must be exactly 64 bytes")

    with tempfile.TemporaryDirectory(prefix="helicoid-bootstrap-key-", dir="/var/tmp") as directory:
        key_path = os.path.join(directory, "release-key.der")
        manifest_path = os.path.join(directory, "manifest.json")
        signature_path = os.path.join(directory, "manifest.sig")
        for path, content in (
            (key_path, PUBLIC_KEY_DER_PREFIX + key),
            (manifest_path, manifest),
            (signature_path, signature),
        ):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(fd)
        try:
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    key_path,
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    manifest_path,
                    "-sigfile",
                    signature_path,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            fail("release manifest signature verification failed")


def validate_manifest(manifest_bytes: bytes) -> dict[str, dict[str, object]]:
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=unique_object
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise SystemExit(f"signed manifest is not valid JSON: {error}") from error

    if not isinstance(manifest, dict):
        fail("signed manifest is not a JSON object")
    format_version = manifest.get("format_version")
    if isinstance(format_version, bool) or not isinstance(format_version, int) or format_version != 1:
        fail("signed package has an unsupported manifest format")
    if manifest.get("product") != "hs-server" or manifest.get("platform") != "linux-x86_64":
        fail("signed package is not the Linux x86_64 server release")
    if not release_version(manifest.get("version")) or not release_version(
        manifest.get("min_installer_version")
    ):
        fail("signed package has a malformed release or installer version")
    schema = manifest.get("min_schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or not 1 <= schema <= 2**63 - 1:
        fail("signed package has an invalid schema version")

    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or len(entries) != len(REQUIRED_ARTIFACTS):
        fail("signed package does not contain the exact bootstrap artifact set")
    found: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
            fail("signed package contains a malformed artifact entry")
        path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if not isinstance(path, str) or path not in REQUIRED_ARTIFACTS or path in found:
            fail("signed package contains an unexpected or duplicate artifact path")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail("signed package contains an invalid artifact digest")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_BYTES:
            fail("signed package contains an invalid artifact size")
        found[path] = entry
    if set(found) != set(REQUIRED_ARTIFACTS):
        fail("signed package is missing a required bootstrap artifact")
    return found


def verify_and_stage(package_path: str, output_path: str, entries: dict[str, dict[str, object]]) -> None:
    root_fd = os.open(package_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        artifacts_fd = os.open(
            "artifacts",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            output_fd = os.open(output_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                output_info = os.fstat(output_fd)
                if not stat.S_ISDIR(output_info.st_mode) or output_info.st_uid != 0 or output_info.st_mode & 0o077:
                    fail("bootstrap staging directory is not private and root-owned")
                for relative_path, (destination, mode) in REQUIRED_ARTIFACTS.items():
                    name = relative_path.split("/", 1)[1]
                    source_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=artifacts_fd,
                    )
                    try:
                        info = os.fstat(source_fd)
                        expected = entries[relative_path]
                        if not stat.S_ISREG(info.st_mode) or info.st_size != expected["size_bytes"]:
                            fail(f"artifact is not a regular file with its signed size: {relative_path}")
                        destination_fd = os.open(
                            destination,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            mode,
                            dir_fd=output_fd,
                        )
                        digest = hashlib.sha256()
                        total = 0
                        header = bytearray()
                        try:
                            with os.fdopen(destination_fd, "wb", closefd=False) as output:
                                while True:
                                    block = os.read(source_fd, 1024 * 1024)
                                    if not block:
                                        break
                                    total += len(block)
                                    if total > expected["size_bytes"]:
                                        fail(f"artifact grew beyond its signed size: {relative_path}")
                                    if len(header) < 24:
                                        header.extend(block[: 24 - len(header)])
                                    digest.update(block)
                                    output.write(block)
                                os.fchmod(output.fileno(), mode)
                                output.flush()
                                os.fsync(output.fileno())
                        finally:
                            os.close(destination_fd)
                        if total != expected["size_bytes"] or digest.hexdigest() != expected["sha256"]:
                            fail(f"artifact hash or size does not match the signed manifest: {relative_path}")
                        if destination in {"hs-server", "helicoid-server"} and (
                            len(header) != 24
                            or header[:4] != b"\x7fELF"
                            or header[4] != 2
                            or header[5] != 1
                            or header[6] != 1
                            or struct.unpack_from("<H", header, 18)[0] != 62
                            or struct.unpack_from("<I", header, 20)[0] != 1
                        ):
                            fail(f"artifact is not a Linux x86_64 ELF executable: {relative_path}")
                    finally:
                        os.close(source_fd)
            finally:
                os.close(output_fd)
        finally:
            os.close(artifacts_fd)
    finally:
        os.close(root_fd)


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: bootstrap-linux-package.py PACKAGE_DIR VERIFY_KEY_HEX ROOT_STAGING_DIR")
    if os.geteuid() != 0:
        fail("clean-host bootstrap verification must run as root")
    package_path, key_hex, output_path = sys.argv[1:]
    root_fd = os.open(package_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        manifest = read_regular_at(root_fd, "manifest.json", MAX_MANIFEST_BYTES)
        signature = read_regular_at(root_fd, "manifest.sig", 64)
    finally:
        os.close(root_fd)
    verify_signature(manifest, signature, key_hex)
    entries = validate_manifest(manifest)
    verify_and_stage(package_path, output_path, entries)


if __name__ == "__main__":
    main()
