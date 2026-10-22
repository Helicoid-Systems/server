#!/usr/bin/env python3
"""Write a public Qt Manager profile from the installed v2 network config."""

import ipaddress
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path


def endpoint_from_configuration(configuration: object) -> str:
    if not isinstance(configuration, dict):
        raise ValueError("stored deployment configuration is not an object")

    network = configuration.get("network")
    if not isinstance(network, dict):
        raise ValueError("stored network configuration is missing")

    scope = network.get("scope")
    if scope == "loopback_development":
        if network.get("authority_port") != 8787 or network.get("bind_address") is not None:
            raise ValueError("stored loopback configuration is invalid")
        return "http://127.0.0.1:8787"

    if scope not in ("lan", "private_dns"):
        raise ValueError("stored network scope cannot be exported as a Manager profile")
    private_dns = scope == "private_dns"

    bind_address = network.get("bind_address")
    if not isinstance(bind_address, str):
        raise ValueError("stored LAN/private DNS bind address is missing")
    address = ipaddress.ip_address(bind_address)
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ValueError("stored LAN/private DNS bind address is not a usable private address")
    if address.version == 4:
        allowed_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if not any(address in network_range for network_range in allowed_networks):
            raise ValueError("stored LAN/private DNS IPv4 address is outside RFC1918 ranges")
    elif address not in ipaddress.ip_network("fc00::/7"):
        raise ValueError("stored LAN/private DNS IPv6 address is outside the unique-local range")

    port = network.get("authority_port")
    if type(port) is not int or not 1024 <= port <= 65535 or port == 8787:
        raise ValueError("stored LAN/private DNS authority port is invalid")
    client_hostname = network.get("client_hostname")
    if private_dns and not isinstance(client_hostname, str):
        raise ValueError("stored private DNS Manager hostname is missing")
    if client_hostname is not None:
        if not isinstance(client_hostname, str) or not valid_client_hostname(client_hostname):
            raise ValueError("stored Manager client hostname is invalid")
        host = client_hostname.lower()
    else:
        host = f"[{address.compressed}]" if address.version == 6 else str(address)
    return f"https://{host}:{port}"


def valid_client_hostname(hostname: str) -> bool:
    lowercase = hostname.lower()
    if (
        not hostname
        or len(hostname) > 253
        or lowercase == "localhost"
        or lowercase.endswith(".localhost")
        or not any("a" <= character.lower() <= "z" for character in hostname)
    ):
        return False
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return False
    for label in hostname.split("."):
        if not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum():
            return False
        if not all(character.isascii() and (character.isalnum() or character == "-") for character in label):
            return False
    return True


def write_profile(output_path: str, endpoint: str) -> None:
    target = Path(output_path).expanduser().absolute()
    if not target.parent.is_dir():
        raise ValueError("profile destination directory does not exist")

    document = {
        "schema_version": 1,
        "profiles": [
            {
                "profile_id": str(uuid.uuid4()),
                "display_name": "Helicoid server",
                "endpoint": endpoint,
            }
        ],
    }
    temporary_path = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".helicoid-manager-profile-", dir=target.parent
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, target)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: export-manager-profile.py OUTPUT_PATH\n")
        return 2

    try:
        configuration_json = sys.stdin.buffer.read(65537)
        if len(configuration_json) > 65536:
            raise ValueError("stored configuration exceeds 64 KiB")
        configuration = json.loads(configuration_json)
        endpoint = endpoint_from_configuration(configuration)
        write_profile(sys.argv[1], endpoint)
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write(f"cannot export Manager profile: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
