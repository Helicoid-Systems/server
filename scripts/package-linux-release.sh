#!/usr/bin/env bash

set -euo pipefail

usage() {
	cat <<EOF
Usage: ${0##*/} ARTIFACT_DIR VERSION SIGNING_KEY OUTPUT_DIR

Create a signed Linux x86_64 server package from build-linux-artifact-dir.sh output.
The Ed25519 signing key must be a private PEM file readable only by its owner.
OUTPUT_DIR must not already exist; its parent directory must exist.
EOF
}

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

if [[ "$#" -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
	usage
	exit 0
fi
if [[ "$#" -ne 4 ]]; then
	usage >&2
	exit 2
fi

artifact_input=$1
version=$2
key_input=$3
output_input=$4
[[ -n "$artifact_input" && -n "$version" && -n "$key_input" && -n "$output_input" ]] || die "all arguments are required"
[[ "$(uname -s)" == "Linux" ]] || die "run package assembly on Linux"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "version must be strict major.minor.patch"
(( ${#version} <= 32 )) || die "version components must fit unsigned 32-bit integers"
IFS=. read -r version_major version_minor version_patch <<< "$version"
for component in "$version_major" "$version_minor" "$version_patch"; do
	(( ${#component} <= 10 && 10#$component <= 4294967295 )) || \
		die "version components must fit unsigned 32-bit integers"
done
[[ ! -L "$artifact_input" && -d "$artifact_input" ]] || die "artifact directory must be a real directory, not a symlink"
[[ ! -L "$key_input" && -f "$key_input" ]] || die "signing key must be a regular non-symlink file"
[[ ! -e "$output_input" && ! -L "$output_input" ]] || die "output directory already exists"

artifact_dir=$(realpath -e -- "$artifact_input") || die "cannot resolve artifact directory"
key_path=$(realpath -e -- "$key_input") || die "cannot resolve signing key"
output_dir=$(realpath -m -- "$output_input") || die "cannot resolve output directory"
output_parent=$(dirname -- "$output_dir")
[[ -d "$artifact_dir/artifacts" && ! -L "$artifact_dir/artifacts" ]] || die "artifact directory must contain a real artifacts/ directory"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || die "output directory already exists"
[[ -d "$output_parent" && ! -L "$output_parent" ]] || die "output parent must be an existing non-symlink directory"
parent_mode=$(stat -c '%a' -- "$output_parent") || die "cannot inspect output parent permissions"
[[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] || die "cannot parse output parent permissions"
if (( (8#$parent_mode & 0022) != 0 && (8#$parent_mode & 01000) == 0 )); then
	die "output parent must not be group- or world-writable unless it is sticky"
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v realpath >/dev/null 2>&1 || die "realpath is required"

key_mode=$(stat -c '%a' -- "$key_path") || die "cannot inspect signing key permissions"
[[ "$key_mode" =~ ^[0-7]{3,4}$ ]] || die "cannot parse signing key permissions"
(( (8#$key_mode & 077) == 0 )) || die "signing key must not be readable or writable by group or others"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
stage_dir=$(mktemp -d "$output_parent/.helicoid-linux-package.XXXXXXXX") || die "cannot create private package staging directory"

cleanup() {
	if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
		rm -rf -- "$stage_dir"
	fi
}
trap cleanup EXIT
trap 'exit 128' HUP INT TERM

mkdir -m 0755 "$stage_dir/artifacts"
python3 - "$artifact_dir/artifacts" "$stage_dir/artifacts" "$version" "$repo_root/src/db.rs" "$repo_root/src/installer/manifest.rs" "$stage_dir/manifest.json" <<'PY'
import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

source_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
version = sys.argv[3]
database_source = Path(sys.argv[4])
installer_source = Path(sys.argv[5])
manifest_path = Path(sys.argv[6])

def source_constant(path: Path, name: str) -> int | str:
    contents = path.read_text(encoding="utf-8")
    matches = re.findall(rf"^(?:pub )?const {re.escape(name)}: (?:i64|&str) = (.+);$", contents, re.MULTILINE)
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {name} constant in {path}")
    value = matches[0].strip()
    if name == "SCHEMA_VERSION":
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise SystemExit("SCHEMA_VERSION must be a positive integer literal")
        return int(value)
    if not re.fullmatch(r'"[0-9]+\.[0-9]+\.[0-9]+"', value):
        raise SystemExit("INSTALLER_VERSION must be a major.minor.patch string literal")
    return value[1:-1]

def validate_path(relative: str) -> None:
    raw = relative.encode("utf-8", "strict")
    segments = relative.split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if len(raw) > 256 or not relative.isascii() or not relative.startswith("artifacts/") or len(segments) > 16:
        raise SystemExit(f"artifact path is outside the package bounds: {relative!r}")
    for segment in segments:
        if (
            not segment
            or segment in {".", ".."}
            or len(segment.encode("ascii", "strict")) > 64
            or segment.endswith((".", " "))
            or not re.fullmatch(r"[a-z0-9._-]+", segment)
            or segment.split(".", 1)[0] in reserved
        ):
            raise SystemExit(f"artifact path is not portable: {relative!r}")

files: list[Path] = []
for directory, child_dirs, child_files in os.walk(source_root, topdown=True, followlinks=False):
    current = Path(directory)
    for name in list(child_dirs):
        child = current / name
        if child.is_symlink():
            raise SystemExit(f"symlink in artifact directory: {child}")
        if not child.is_dir():
            raise SystemExit(f"non-directory in artifact directory: {child}")
    for name in child_files:
        child = current / name
        metadata = child.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"non-regular file in artifact directory: {child}")
        files.append(child)

if not files or len(files) > 256:
    raise SystemExit("artifact package must contain between 1 and 256 regular files")

required = {"hs-server", "helicoid-server", "hs-server.service"}
present = {path.relative_to(source_root).as_posix() for path in files}
missing = required - present
if missing:
    raise SystemExit(f"artifact package is missing required files: {', '.join(sorted(missing))}")

entries = []
for source in sorted(files, key=lambda item: item.relative_to(source_root).as_posix()):
    relative_to_artifacts = source.relative_to(source_root).as_posix()
    package_path = f"artifacts/{relative_to_artifacts}"
    validate_path(package_path)
    destination = output_root / relative_to_artifacts
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
            raise SystemExit(f"artifact is not a bounded regular file: {package_path}")
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(source_fd), "rb") as source_stream, destination.open("xb") as destination_stream:
            while True:
                chunk = source_stream.read(64 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > 512 * 1024 * 1024:
                    raise SystemExit(f"artifact exceeds the package size bound: {package_path}")
                digest.update(chunk)
                destination_stream.write(chunk)
            destination_stream.flush()
            output_mode = 0o755 if relative_to_artifacts in {"hs-server", "helicoid-server"} else 0o644
            os.fchmod(destination_stream.fileno(), output_mode)
            os.fsync(destination_stream.fileno())
        after = os.fstat(source_fd)
        if copied != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise SystemExit(f"artifact changed while packaging: {package_path}")
    finally:
        os.close(source_fd)

    if relative_to_artifacts in {"hs-server", "helicoid-server"}:
        with destination.open("rb") as artifact_stream:
            elf_header = artifact_stream.read(24)
        if (
            len(elf_header) != 24
            or elf_header[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<H", elf_header, 16)[0] not in {2, 3}
            or struct.unpack_from("<H", elf_header, 18)[0] != 62
            or struct.unpack_from("<I", elf_header, 20)[0] != 1
        ):
            raise SystemExit(f"artifact is not a Linux x86_64 ELF executable: {package_path}")

    entries.append({"path": package_path, "sha256": digest.hexdigest(), "size_bytes": copied})

manifest = {
    "format_version": 1,
    "product": "hs-server",
    "version": version,
    "platform": "linux-x86_64",
    "min_schema_version": source_constant(database_source, "SCHEMA_VERSION"),
    "min_installer_version": source_constant(installer_source, "INSTALLER_VERSION"),
    "artifacts": entries,
}
encoded = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")
if len(encoded) > 1024 * 1024:
    raise SystemExit("generated manifest exceeds the installer parsing bound")
with open(manifest_path, "xb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
PY

openssl pkeyutl -sign -rawin -inkey "$key_path" -in "$stage_dir/manifest.json" -out "$stage_dir/manifest.sig" || die "manifest signing failed"
[[ "$(stat -c '%s' -- "$stage_dir/manifest.sig")" == 64 ]] || die "Ed25519 signature must be exactly 64 bytes"
openssl pkey -in "$key_path" -pubout -out "$stage_dir/.verify-key.pem" >/dev/null 2>&1 || die "signing key is not a supported Ed25519 PEM key"
openssl pkeyutl -verify -pubin -inkey "$stage_dir/.verify-key.pem" -rawin -in "$stage_dir/manifest.json" -sigfile "$stage_dir/manifest.sig" >/dev/null 2>&1 || die "generated signature did not verify"
openssl pkey -in "$key_path" -pubout -outform DER -out "$stage_dir/.verify-key.der" >/dev/null 2>&1 || die "cannot derive the Ed25519 public key"
verification_key_hex=$(python3 - "$stage_dir/.verify-key.der" <<'PY'
import sys
from pathlib import Path

encoded = Path(sys.argv[1]).read_bytes()
prefix = bytes.fromhex("302a300506032b6570032100")
if len(encoded) != 44 or encoded[:12] != prefix:
    raise SystemExit("derived public key is not canonical Ed25519 SubjectPublicKeyInfo")
print(encoded[12:].hex())
PY
) || die "cannot encode the Ed25519 verification key"
[[ "$verification_key_hex" =~ ^[[:xdigit:]]{64}$ ]] || die "derived verification key is not 32 bytes"
rm -f -- "$stage_dir/.verify-key.pem" "$stage_dir/.verify-key.der"
chmod 0644 "$stage_dir/manifest.json" "$stage_dir/manifest.sig"
chmod 0755 "$stage_dir" "$stage_dir/artifacts"
find "$stage_dir/artifacts" -type d -exec chmod 0755 {} +

mv -T -- "$stage_dir" "$output_dir" || die "cannot publish the signed package"
stage_dir=
printf 'Signed Linux x86_64 package published at %s\n' "$output_dir"
printf 'Public verification key (distribute separately): %s\n' "$verification_key_hex"
