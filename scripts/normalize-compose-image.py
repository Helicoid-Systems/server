#!/usr/bin/env python3
"""Normalize a single-platform Buildx Docker archive for signed packaging."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_MEMBER_PATH_BYTES = 512


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def safe_member_name(name: str, *, directory: bool = False) -> bool:
    if directory and name.endswith("/"):
        name = name[:-1]
    if not name or name.endswith("/") or "//" in name:
        return False
    try:
        encoded_name = name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    if len(encoded_name) > MAX_MEMBER_PATH_BYTES:
        return False
    if "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and bool(path.parts)
        and path.as_posix() == name
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def read_bounded(archive: tarfile.TarFile, member: tarfile.TarInfo, bound: int) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > bound:
        fail(f"Docker image member is not a bounded regular file: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read Docker image member: {member.name}")
    with stream:
        data = stream.read(bound + 1)
    if len(data) != member.size:
        fail(f"Docker image member has an inconsistent size: {member.name}")
    return data


def write_text_exclusive(path: Path, value: str) -> None:
    encoded = value.encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o644)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


def normalize(raw_path: Path, stage_dir: Path, template_path: Path, expected_build_ref: str) -> None:
    raw_metadata = raw_path.lstat()
    if not stat.S_ISREG(raw_metadata.st_mode) or raw_metadata.st_size > MAX_ARCHIVE_BYTES:
        fail("Buildx image archive is not a bounded regular file")
    if not re.fullmatch(r"localhost/helicoid-server:build-[0-9a-f]{64}", expected_build_ref):
        fail("temporary image reference is invalid")

    with tarfile.open(raw_path, mode="r:") as archive:
        members: list[tarfile.TarInfo] = []
        members_by_name: dict[str, tarfile.TarInfo] = {}
        canonical_names: set[str] = set()
        total_bytes = 0
        for member in archive:
            if len(members) >= MAX_ARCHIVE_MEMBERS:
                fail("Docker image archive member count is outside the bound")
            if not safe_member_name(member.name, directory=member.isdir()):
                fail("Docker image archive contains an unsafe member path")
            canonical_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
            if canonical_name in canonical_names:
                fail("Docker image archive contains an unsafe or duplicate member path")
            if member.isfile():
                if member.size < 0:
                    fail("Docker image archive contains a negative member size")
                total_bytes += member.size
            elif not member.isdir():
                fail("Docker image archive contains a link or special file")
            if total_bytes > MAX_ARCHIVE_BYTES:
                fail("Docker image archive exceeds the signed artifact size bound")
            members.append(member)
            members_by_name[member.name] = member
            canonical_names.add(canonical_name)

        if not members:
            fail("Docker image archive member count is outside the bound")
        manifest_member = members_by_name.get("manifest.json")
        if manifest_member is None:
            fail("Docker image archive is missing manifest.json")
        manifest_bytes = read_bounded(archive, manifest_member, MAX_MANIFEST_BYTES)
        try:
            image_manifest = json.loads(manifest_bytes, object_pairs_hook=unique_json_object)
        except (ValueError, UnicodeDecodeError):
            fail("Docker image manifest is invalid JSON")
        if not isinstance(image_manifest, list) or len(image_manifest) != 1:
            fail("Docker image archive must contain exactly one image")

        image = image_manifest[0]
        if not isinstance(image, dict) or image.get("RepoTags") != [expected_build_ref]:
            fail("Docker image archive tag does not match the requested build")
        config_name = image.get("Config")
        layer_names = image.get("Layers")
        if not isinstance(config_name, str) or not safe_member_name(config_name):
            fail("Docker image config path is invalid")
        if (
            not isinstance(layer_names, list)
            or not layer_names
            or len(layer_names) > MAX_ARCHIVE_MEMBERS
            or any(not isinstance(name, str) or not safe_member_name(name) for name in layer_names)
            or len(set(layer_names)) != len(layer_names)
            or config_name in layer_names
        ):
            fail("Docker image layer list is invalid")
        config_member = members_by_name.get(config_name)
        if config_member is None:
            fail("Docker image config is missing")
        config_bytes = read_bounded(archive, config_member, MAX_CONFIG_BYTES)
        digest = hashlib.sha256(config_bytes).hexdigest()
        if config_name != f"{digest}.json":
            fail("Docker image config filename does not match its SHA-256 digest")

        try:
            image_config = json.loads(config_bytes, object_pairs_hook=unique_json_object)
        except (ValueError, UnicodeDecodeError):
            fail("Docker image config is invalid JSON")
        if not isinstance(image_config, dict) or image_config.get("architecture") != "amd64" or image_config.get("os") != "linux":
            fail("Docker image config is not Linux x86_64")
        rootfs = image_config.get("rootfs")
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
        if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
            fail("Docker image root filesystem metadata is invalid")
        if (
            not isinstance(diff_ids, list)
            or len(diff_ids) != len(layer_names)
            or any(
                not isinstance(diff_id, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id)
                for diff_id in diff_ids
            )
        ):
            fail("Docker image config and manifest layer counts differ")
        for layer_name in layer_names:
            if not isinstance(layer_name, str) or not safe_member_name(layer_name):
                fail("Docker image layer path is invalid")
            layer_member = members_by_name.get(layer_name)
            if layer_member is None or not layer_member.isfile():
                fail("Docker image layer is missing")

        image_ref = f"localhost/helicoid-server:sha256-{digest}"
        image["RepoTags"] = [image_ref]
        normalized_manifest = (json.dumps(image_manifest, separators=(",", ":")) + "\n").encode("utf-8")
        normalized_manifest_path = stage_dir / "image.manifest.json"
        with normalized_manifest_path.open("xb") as output:
            output.write(normalized_manifest)
            output.flush()
            os.fsync(output.fileno())

        temp_image = stage_dir / ".server-image.tar"
        with temp_image.open("xb") as output_stream, tarfile.open(
            fileobj=output_stream, mode="w", format=tarfile.USTAR_FORMAT
        ) as normalized:
            for member in members:
                if member.name == "repositories":
                    # manifest.json RepoTags is authoritative for modern engines.
                    continue
                info = tarfile.TarInfo(member.name)
                info.mode = member.mode & 0o777
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                if member.name == "manifest.json":
                    payload = normalized_manifest
                    info.size = len(payload)
                    normalized.addfile(info, io.BytesIO(payload))
                elif member.isdir():
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    normalized.addfile(info)
                else:
                    info.size = member.size
                    stream = archive.extractfile(member)
                    if stream is None:
                        fail(f"cannot read Docker image member: {member.name}")
                    with stream:
                        normalized.addfile(info, stream)
            output_stream.flush()
            os.fsync(output_stream.fileno())

    final_image = stage_dir / "server-image.tar"
    os.replace(temp_image, final_image)
    final_size = final_image.stat().st_size
    if final_size > MAX_ARCHIVE_BYTES:
        fail("normalized Compose image exceeds the signed artifact size bound")

    template = template_path.read_text(encoding="utf-8")
    marker = "__HELICOID_IMAGE_REF__"
    if template.count(marker) != 1:
        fail("release Compose template must contain exactly one image reference marker")
    compose = template.replace(marker, image_ref)
    if marker in compose:
        fail("release Compose template rendering failed")
    compose_path = stage_dir / "compose.yaml"
    with compose_path.open("xb") as output:
        output.write(compose.encode("utf-8"))
        output.flush()
        os.fsync(output.fileno())

    write_text_exclusive(stage_dir / "image-ref", image_ref + "\n")
    write_text_exclusive(stage_dir / "image-id", f"sha256:{digest}\n")
    normalized_manifest_path.unlink()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: normalize-compose-image.py RAW_TAR STAGE_DIR COMPOSE_TEMPLATE BUILD_REF")
    normalize(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
