#!/usr/bin/env bash

set -euo pipefail

usage() {
	printf 'Usage: %s OUTPUT_DIR\n' "${0##*/}"
	printf '%s\n' \
		"Builds unsigned Linux x86_64 installer artifacts with pinned Rust and Go toolchains plus Docker Buildx." \
		"OUTPUT_DIR must not already exist. The release process must create and sign manifest.json."
}

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

if [[ "$#" -ne 1 ]]; then
	usage >&2
	exit 2
fi

output_input=$1
[[ -n "$output_input" ]] || die "output directory is required"
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || die "build on Linux x86_64"

rust_version=$(rustc --version 2>/dev/null) || die "rustc 1.99.0 is required"
[[ "$rust_version" == "rustc 1.99.0 "* ]] || die "expected rustc 1.99.0; found: $rust_version"
go_version=$(go version 2>/dev/null) || die "Go 1.27.1 is required"
read -r go_name go_word go_release go_target <<< "$go_version"
[[ "$go_name" == "go" && "$go_word" == "version" && "$go_release" == "go1.27.1" && "$go_target" == "linux/amd64" ]] ||
	die "expected Go 1.27.1 on linux/amd64; found: $go_version"
command -v docker >/dev/null 2>&1 || die "Docker CLI is required to package the Compose image"
docker buildx version >/dev/null 2>&1 || die "Docker Buildx is required to package the Compose image"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
unit_source="$repo_root/deploy/systemd/hs-server.service"
[[ -f "$unit_source" && ! -L "$unit_source" ]] || die "the systemd unit template is missing or is a symlink"

[[ ! -e "$output_input" && ! -L "$output_input" ]] || die "output directory already exists"
output_dir=$(realpath -m -- "$output_input") || die "cannot resolve output directory"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || die "output directory already exists"
output_parent=$(dirname -- "$output_dir")
[[ -d "$output_parent" && ! -L "$output_parent" ]] || die "output parent must be an existing non-symlink directory"

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/helicoid-linux-build.XXXXXXXX") || die "cannot create private build directory"
stage_dir=$(mktemp -d "$output_parent/.helicoid-linux-artifacts.XXXXXXXX") || {
	rm -rf -- "$build_dir"
	die "cannot create staging directory beside output"
}

cleanup() {
	if [[ -n "${build_dir:-}" && -d "$build_dir" ]]; then
		rm -rf -- "$build_dir"
	fi
	if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
		rm -rf -- "$stage_dir"
	fi
}
trap cleanup EXIT
trap 'exit 128' HUP INT TERM

mkdir -m 0755 "$stage_dir/artifacts"
(
	cd -- "$repo_root"
	CARGO_TARGET_DIR="$build_dir/cargo-target" cargo build --locked --release --bin hs-server
)
install -m 0755 "$build_dir/cargo-target/release/hs-server" "$stage_dir/artifacts/hs-server"

(
	cd -- "$repo_root/tui"
	GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' -o "$stage_dir/artifacts/helicoid-server" .
)
install -m 0644 "$unit_source" "$stage_dir/artifacts/hs-server.service"

server_description=$(file -b -- "$stage_dir/artifacts/hs-server") || die "cannot inspect hs-server output"
tui_description=$(file -b -- "$stage_dir/artifacts/helicoid-server") || die "cannot inspect helicoid-server output"
[[ "$server_description" == *ELF* && "$server_description" == *x86-64* ]] || die "hs-server output is not ELF x86_64"
[[ "$tui_description" == *ELF* && "$tui_description" == *x86-64* ]] || die "helicoid-server output is not ELF x86_64"

"$script_dir/build-linux-compose-artifacts.sh" "$stage_dir"

mv -T -- "$stage_dir" "$output_dir" || die "cannot publish the artifact directory"
stage_dir=
printf 'Unsigned Linux x86_64 artifacts staged at %s\n' "$output_dir"
