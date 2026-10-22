#!/usr/bin/env bash

set -euo pipefail

usage() {
	printf 'Usage: %s ARTIFACT_DIR\n' "$(basename "$0")"
	printf '%s\n' \
		"Builds an offline-loadable Linux x86_64 Compose image from staged server binaries." \
		"ARTIFACT_DIR must contain artifacts/hs-server and artifacts/helicoid-server." \
		"The output is added at ARTIFACT_DIR/artifacts/compose and is ready for package signing."
}

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

if [[ "$#" -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
	usage
	exit 0
fi
if [[ "$#" -ne 1 ]]; then
	usage >&2
	exit 2
fi

artifact_input=$1
[[ -n "$artifact_input" ]] || die "artifact directory is required"
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || die "run Compose image assembly on Linux x86_64"
[[ ! -L "$artifact_input" && -d "$artifact_input" ]] || die "artifact directory must be a real directory, not a symlink"

artifact_dir=$(realpath -e -- "$artifact_input") || die "cannot resolve artifact directory"
artifact_root="$artifact_dir/artifacts"
[[ -d "$artifact_root" && ! -L "$artifact_root" ]] || die "artifact directory must contain a real artifacts/ directory"
artifact_owner=$(stat -c '%u' -- "$artifact_root") || die "cannot inspect artifact directory ownership"
artifact_mode=$(stat -c '%a' -- "$artifact_root") || die "cannot inspect artifact directory permissions"
[[ "$artifact_owner" == "$(id -u)" ]] || die "artifact directory must be owned by the current user"
[[ "$artifact_mode" =~ ^[0-7]{3,4}$ ]] || die "cannot parse artifact directory permissions"
(( (8#$artifact_mode & 0022) == 0 )) || die "artifact directory must not be group- or world-writable"
for name in hs-server helicoid-server; do
	[[ -f "$artifact_root/$name" && ! -L "$artifact_root/$name" ]] || die "required regular artifact is missing: artifacts/$name"
done
for name in hs-server helicoid-server; do
	artifact_size=$(stat -c '%s' -- "$artifact_root/$name") || die "cannot inspect artifact size: artifacts/$name"
	[[ "$artifact_size" =~ ^[1-9][0-9]*$ ]] || die "artifact is empty or has an invalid size: artifacts/$name"
	(( artifact_size <= 512 * 1024 * 1024 )) || die "artifact exceeds the signed package size bound: artifacts/$name"
done
[[ ! -e "$artifact_root/compose" && ! -L "$artifact_root/compose" ]] || die "artifacts/compose already exists"

command -v docker >/dev/null 2>&1 || die "Docker CLI is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v realpath >/dev/null 2>&1 || die "realpath is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
docker buildx version >/dev/null 2>&1 || die "Docker Buildx is required"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
normalizer="$script_dir/normalize-compose-image.py"
dockerfile_source="$repo_root/deploy/compose/Dockerfile.release"
compose_template="$repo_root/deploy/compose/release-compose.yaml"
env_example_source="$repo_root/deploy/compose/.env.example"
tls_readme_source="$repo_root/deploy/compose/tls/README.md"
for source in "$normalizer" "$dockerfile_source" "$compose_template" "$env_example_source" "$tls_readme_source"; do
	[[ -f "$source" && ! -L "$source" ]] || die "required Compose release source is missing or a symlink: $source"
done

context_dir=$(mktemp -d "${TMPDIR:-/tmp}/helicoid-compose-context.XXXXXXXX") || die "cannot create private Docker build context"
stage_dir=$(mktemp -d "$artifact_root/.compose.XXXXXXXX") || {
	rm -rf -- "$context_dir"
	die "cannot create private Compose artifact staging directory"
}

cleanup() {
	if [[ -n "${context_dir:-}" && -d "$context_dir" ]]; then
		rm -rf -- "$context_dir"
	fi
	if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
		rm -rf -- "$stage_dir"
	fi
}
trap cleanup EXIT
trap 'exit 128' HUP INT TERM

install -m 0755 "$artifact_root/hs-server" "$context_dir/hs-server"
install -m 0755 "$artifact_root/helicoid-server" "$context_dir/helicoid-server"
install -m 0644 "$dockerfile_source" "$context_dir/Dockerfile"
mkdir -m 0755 "$stage_dir/tls"
install -m 0644 "$env_example_source" "$stage_dir/.env.example"
install -m 0644 "$tls_readme_source" "$stage_dir/tls/readme.md"

build_nonce=$(openssl rand -hex 32) || die "cannot create a temporary Docker build tag"
build_ref="localhost/helicoid-server:build-$build_nonce"
raw_image="$stage_dir/raw-server-image.tar"
docker buildx build \
	--file "$context_dir/Dockerfile" \
	--platform linux/amd64 \
	--provenance=false \
	--output "type=docker,dest=$raw_image" \
	--tag "$build_ref" \
	"$context_dir" || die "Docker Buildx could not export the offline-loadable image archive"

python3 "$normalizer" "$raw_image" "$stage_dir" "$compose_template" "$build_ref" || die "Docker image archive validation or normalization failed"
rm -f -- "$raw_image"
chmod 0644 "$stage_dir"/.env.example "$stage_dir"/compose.yaml "$stage_dir"/image-ref "$stage_dir"/image-id "$stage_dir"/server-image.tar "$stage_dir"/tls/readme.md
chmod 0755 "$stage_dir" "$stage_dir"/tls
mv -T -- "$stage_dir" "$artifact_root/compose" || die "cannot publish the Compose artifact set"
stage_dir=
printf 'Compose image artifacts added at %s/compose\n' "$artifact_root"
