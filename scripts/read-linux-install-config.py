#!/usr/bin/env python3
"""Validate a root-reviewed Linux installer JSON config and emit NUL fields."""

from __future__ import annotations

import json
import os
import stat
import sys


MAX_CONFIG_BYTES = 64 * 1024


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_object(value: object, keys: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name} must contain exactly: {', '.join(sorted(keys))}")
    return value


def text_field(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{name} must be a {'possibly empty ' if allow_empty else ''}string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def read_config(path: str) -> list[str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CONFIG_BYTES:
            raise ValueError("configuration must be a regular file no larger than 64 KiB")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            document = json.load(stream, object_pairs_hook=reject_duplicate_keys)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    root = exact_object(
        document,
        {"schema_version", "package_dir", "verify_key", "deployment_kind", "network", "storage"},
        "configuration",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("schema_version must be 1")

    package_dir = text_field(root["package_dir"], "package_dir")
    if not os.path.isabs(package_dir):
        raise ValueError("package_dir must be absolute")
    verify_key = text_field(root["verify_key"], "verify_key")
    if len(verify_key) != 64 or any(char not in "0123456789abcdefABCDEF" for char in verify_key):
        raise ValueError("verify_key must contain exactly 64 hexadecimal characters")
    deployment_kind = text_field(root["deployment_kind"], "deployment_kind")
    if deployment_kind not in {"linux_systemd", "linux_compose"}:
        raise ValueError("deployment_kind must be linux_systemd or linux_compose")

    network = exact_object(
        root["network"],
        {"scope", "bind_address", "client_hostname", "authority_port"},
        "network",
    )
    scope = text_field(network["scope"], "network.scope")
    bind_address = text_field(network["bind_address"], "network.bind_address", allow_empty=True)
    client_hostname = text_field(
        network["client_hostname"], "network.client_hostname", allow_empty=True
    )
    port = network["authority_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("network.authority_port must be an integer from 1 to 65535")
    if scope in {"lan", "private_dns"}:
        if not bind_address or port < 1024 or port == 8787:
            raise ValueError("LAN/private DNS requires an address and a port from 1024 to 65535 other than 8787")
        if scope == "private_dns" and not client_hostname:
            raise ValueError("private_dns requires a Manager client hostname")
    elif scope == "loopback_development":
        if bind_address or client_hostname or port != 8787:
            raise ValueError("loopback_development requires empty address/hostname and port 8787")
    else:
        raise ValueError("network.scope must be lan, private_dns, or loopback_development")

    storage = exact_object(
        root["storage"], {"data_directory", "backup_directory"}, "storage"
    )
    data_directory = text_field(storage["data_directory"], "storage.data_directory")
    backup_directory = text_field(storage["backup_directory"], "storage.backup_directory")
    if not os.path.isabs(data_directory) or not os.path.isabs(backup_directory):
        raise ValueError("storage directories must be absolute")

    return [
        package_dir,
        verify_key,
        deployment_kind,
        scope,
        bind_address,
        client_hostname,
        str(port),
        data_directory,
        backup_directory,
    ]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: read-linux-install-config.py CONFIG.json", file=sys.stderr)
        return 2
    try:
        values = read_config(sys.argv[1])
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        print(f"invalid installer configuration: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(b"\0".join(value.encode("utf-8") for value in values) + b"\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
