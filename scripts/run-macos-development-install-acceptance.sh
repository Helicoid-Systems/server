#!/usr/bin/env bash
#
# Disposable macOS real-host acceptance for the development-only installer.
#
# NEVER run this on a machine that matters. It creates a fixed `_helicoid`
# account/group, product directories, a LaunchDaemon, and root-owned installer
# state, then attempts cleanup. MANUAL ONLY pending authoritative
# absence/identity cleanup hardening; push-triggered acceptance is disabled.
# It requires passwordless sudo and a disposable GitHub Actions macOS runner
# (or a throwaway VM). It must be run as the normal runner user, not root.
#
# Usage:
#   run-macos-development-install-acceptance.sh install
#   run-macos-development-install-acceptance.sh rollback
#
# `install` proves a successful end-to-end install and then cleans it up.
# `rollback` makes /Library/LaunchDaemons immutable after review so the launchd
# phase fails deterministically, then proves the journaled reverse rollback
# removed every resource created by the failed install.
#
# The script does not commit, push, or execute any test on a developer machine.

set -euo pipefail

mode=${1:-}
case "$mode" in
	install|rollback) ;;
	*)
		printf 'Usage: %s install|rollback\n' "${0##*/}" >&2
		exit 2
		;;
esac

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "this acceptance runs only on macOS"
[[ "$(id -u)" -ne 0 ]] || die "run as the normal runner user, not root; the script elevates only fixed commands"
sudo -n true >/dev/null 2>&1 || die "passwordless sudo is required on the disposable runner"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

runner_temp=${RUNNER_TEMP:-$(mktemp -d "${TMPDIR:-/tmp}/helicoid-acceptance.XXXXXXXX")}
work=$(mktemp -d "$runner_temp/helicoid-acceptance.XXXXXXXX") || die "cannot create acceptance work directory"
clean_state_confirmed="$work/clean-state-confirmed"
external_clean_state_marker="$runner_temp/helicoid-acceptance-clean-state-confirmed"
immutable_set="$work/immutable-set"
key_path=$work/dev-signing-key.pem
key_hex=
package_dir=$work/package
bin=$repo_root/target/release/hs-server
label=com.helicoid.server
plist=/Library/LaunchDaemons/com.helicoid.server.plist
product_root="/Library/Application Support/Helicoid"
state_dir="/Library/Application Support/Helicoid-Installer"
lock_file="/Library/Application Support/Helicoid-Installer.lock"
# The macOS plan never creates this configured backup directory. Acceptance
# refuses to start if it pre-exists and never deletes it during cleanup.
backup_path="/Library/Application Support/Helicoid-Backups"
tls_source=/etc/helicoid/tls

cleanup() {
	set +e
	local cleanup_failed=0
	if [[ -e "$immutable_set" ]]; then
		sudo -n /usr/bin/chflags nouchg /Library/LaunchDaemons >/dev/null 2>&1
		rm -f -- "$immutable_set"
	fi
	if [[ -f "$clean_state_confirmed" ]]; then
		if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then
			sudo -n /bin/launchctl bootout "system/$label" >/dev/null 2>&1
			for _ in {1..20}; do
				sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1 || break
				sleep 0.5
			done
		fi
		sudo -n rm -f -- "$plist"
		sudo -n rm -rf -- "$product_root"
		sudo -n rm -rf -- "$state_dir"
		sudo -n rm -f -- "$lock_file"
		sudo -n rm -rf -- /etc/helicoid

		# The service identity is retained until every non-identity resource
		# is proven gone. Deleting it early would orphan files or hide a
		# launchd stop failure.
		local non_identity_leftover=0
		for path in "$plist" "$product_root" "$state_dir" "$lock_file" "$backup_path" /etc/helicoid; do
			if [ -e "$path" ] || [ -L "$path" ]; then
				non_identity_leftover=1
			fi
		done
		if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then
			non_identity_leftover=1
		fi
		if [ "$non_identity_leftover" -eq 0 ]; then
			if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
				sudo -n /usr/bin/dscl . -delete /Users/_helicoid
			fi
			if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
				printf 'Error: _helicoid user remains; preserving the group until the user is removed\n' >&2
				cleanup_failed=1
			else
				if /usr/bin/dscl . -read /Groups/_helicoid >/dev/null 2>&1; then
					sudo -n /usr/bin/dscl . -delete /Groups/_helicoid
				fi
				if /usr/bin/dscl . -read /Groups/_helicoid >/dev/null 2>&1; then
					printf 'Error: _helicoid group remains after deletion\n' >&2
					cleanup_failed=1
				fi
			fi
			sudo -n /usr/bin/dscacheutil -flushcache >/dev/null 2>&1
		else
			printf 'Error: preserving _helicoid identity because non-identity cleanup is incomplete\n' >&2
			cleanup_failed=1
		fi

		local leftover=0
		for path in "$plist" "$product_root" "$state_dir" "$lock_file" "$backup_path" /etc/helicoid; do
			if [ -e "$path" ] || [ -L "$path" ]; then
				leftover=1
			fi
		done
		if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then
			leftover=1
		fi
		if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
			leftover=1
		fi
		if /usr/bin/dscl . -read /Groups/_helicoid >/dev/null 2>&1; then
			leftover=1
		fi
		if [ "$leftover" -ne 0 ]; then
			cleanup_failed=1
		else
			rm -f -- "$external_clean_state_marker"
		fi
	else
		rm -f -- "${external_clean_state_marker:-}"
	fi
	if [ -n "${work:-}" ] && [ -d "$work" ]; then
		rm -rf -- "$work"
	fi
	return "$cleanup_failed"
}
trap 'rc=$?; set +e; cleanup; crc=$?; if [ "$rc" -eq 0 ] && [ "$crc" -ne 0 ]; then exit 1; fi; exit "$rc"' EXIT
trap 'exit 128' HUP INT TERM

phase() {
	printf '\n== %s ==\n' "$1"
}

phase "assert disposable clean state"
for path in "$product_root" "$state_dir" "$lock_file" "$plist" "$backup_path" /etc/helicoid; do
	if [ -e "$path" ] || [ -L "$path" ]; then
		die "refusing to adopt preexisting path: $path"
	fi
done
if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
	die "refusing to adopt preexisting account _helicoid"
fi
if /usr/bin/dscl . -read /Groups/_helicoid >/dev/null 2>&1; then
	die "refusing to adopt preexisting group _helicoid"
fi
if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then
	die "refusing to adopt preexisting launchd job $label"
fi
touch "$clean_state_confirmed"
touch "$external_clean_state_marker"

phase "select OpenSSL 3 with Ed25519 support"
if ! command -v openssl >/dev/null 2>&1 || ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
	command -v brew >/dev/null 2>&1 || die "Homebrew is required to install OpenSSL 3"
	brew install openssl@3
fi
openssl_prefix=$(brew --prefix openssl@3 2>/dev/null || true)
if [ -n "$openssl_prefix" ] && [ -x "$openssl_prefix/bin/openssl" ]; then
	export HELICOID_OPENSSL=$openssl_prefix/bin/openssl
else
	export HELICOID_OPENSSL=$(command -v openssl)
fi
"$HELICOID_OPENSSL" version
"$HELICOID_OPENSSL" pkeyutl -help 2>&1 | grep -q -- '-rawin' || die "OpenSSL 3 pkeyutl -rawin support is required"

phase "obtain the CI-pinned Ed25519 development key"
if [ -n "${HELICOID_MACOS_DEV_TRUST_KEY:-}" ] && [ -n "${HELICOID_MACOS_DEV_SIGNING_KEY:-}" ]; then
	key_hex=$HELICOID_MACOS_DEV_TRUST_KEY
	key_path=$HELICOID_MACOS_DEV_SIGNING_KEY
	[[ -f "$key_path" && ! -L "$key_path" ]] || die "HELICOID_MACOS_DEV_SIGNING_KEY is not a regular file"
else
	umask 077
	"$HELICOID_OPENSSL" genpkey -algorithm ED25519 -out "$key_path" >/dev/null 2>&1 || die "cannot generate Ed25519 signing key"
	chmod 0600 "$key_path"
fi
key_der=$work/dev-signing-key-pub.der
"$HELICOID_OPENSSL" pkey -in "$key_path" -pubout -outform DER -out "$key_der" >/dev/null 2>&1 || die "cannot derive the Ed25519 public key"
[ "$(wc -c < "$key_der" | tr -d ' ')" = 44 ] || die "Ed25519 public key DER must be 44 bytes"
derived_hex=$(python3 - "$key_der" <<'PY'
import sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
if len(raw) != 44 or raw[:12] != bytes.fromhex("302a300506032b6570032100"):
    raise SystemExit("unexpected Ed25519 SubjectPublicKeyInfo")
print(raw[-32:].hex())
PY
) || die "cannot extract the Ed25519 public key"
[[ "$derived_hex" =~ ^[0-9a-f]{64}$ ]] || die "derived public key hex is malformed"
if [ -n "$key_hex" ]; then
	[ "$key_hex" = "$derived_hex" ] || die "HELICOID_MACOS_DEV_TRUST_KEY does not match the signing key"
else
	key_hex=$derived_hex
fi

phase "build the development-trust binary"
HELICOID_MACOS_DEV_TRUST_KEY=$key_hex cargo build --locked --release --features macos-dev-install
[ -x "$bin" ] || die "release binary was not built"
# Apple Silicon requires a code signature to execute. This is an ad-hoc
# development signature, not notarization or a release security review.
/usr/bin/codesign --force --sign - "$bin" >/dev/null 2>&1 || die "cannot ad-hoc sign the development binary"
/usr/bin/codesign --verify --strict "$bin" >/dev/null 2>&1 || die "ad-hoc signature did not verify"

case "$(uname -m)" in
	arm64) platform=macos-arm64 ;;
	x86_64) platform=macos-x86_64 ;;
	*) die "unsupported architecture" ;;
esac

phase "package and sign the exact hs-server artifact"
"$repo_root/scripts/package-macos-development.sh" "$bin" 0.1.0 "$platform" "$key_path" "$package_dir" > "$work/package.out"
packaged_hex=$(sed -n 's/^verification_key_hex=//p' "$work/package.out")
[ "$packaged_hex" = "$key_hex" ] || die "package verification key does not match the build-pinned key"
chmod 0700 "$package_dir"

phase "stage operator TLS material at the fixed source path"
sudo -n install -d -m 0700 -o root -g wheel /etc/helicoid /etc/helicoid/tls
"$HELICOID_OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$work/tls-key.pem" -out "$work/tls-cert.pem" -days 2 \
	-subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" \
	-addext "basicConstraints=critical,CA:FALSE" \
	-addext "keyUsage=critical,digitalSignature" \
	-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 \
	|| die "cannot generate disposable TLS material"
sudo -n install -m 0600 -o root -g wheel "$work/tls-cert.pem" "$tls_source/fullchain.pem"
sudo -n install -m 0600 -o root -g wheel "$work/tls-key.pem" "$tls_source/private-key.pem"

phase "write reviewed v2 configuration"
export HELICOID_ACCEPTANCE_WORK=$work
export HELICOID_ACCEPTANCE_PACKAGE=$package_dir
export HELICOID_ACCEPTANCE_KEY_HEX=$key_hex
export HELICOID_ACCEPTANCE_REPO_ROOT=$repo_root
export HELICOID_ACCEPTANCE_BACKUP=$backup_path
python3 - <<'PY'
import json
import os
from pathlib import Path

work = Path(os.environ["HELICOID_ACCEPTANCE_WORK"])
configuration = {
    "deployment_kind": "macos_launchd",
    "network": {"scope": "loopback_development", "authority_port": 8920},
    "storage": {
        "data_directory": "/Library/Application Support/Helicoid/Data",
        "backup_directory": os.environ["HELICOID_ACCEPTANCE_BACKUP"],
        "preserve_data_on_remove": True,
    },
}
(work / "configuration.json").write_text(json.dumps(configuration), encoding="utf-8")
(work / "preflight-input.json").write_text(
    json.dumps({"contract_version": 2, "configuration": configuration}),
    encoding="utf-8",
)
(work / "status-input.json").write_text(
    json.dumps({"contract_version": 2, "configuration": configuration}),
    encoding="utf-8",
)
PY

phase "capabilities must advertise only the development install path"
installer_cmd=(sudo -n env RUST_LOG=off "$bin" installer)
"${installer_cmd[@]}" capabilities-v2 > "$work/capabilities.json"
python3 - "$work/capabilities.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
expected = ["preflight", "plan", "install", "cancel", "inspect"]
assert value["supported_actions"] == expected, value["supported_actions"]
assert value["cancellation"] is True
assert value["durable_operation_journal"] is True
assert value["online_update"] is False
assert value["backup_and_restore"] is False
assert value["reasons_unavailable"]["macos_launchd"].startswith("macOS install is enabled only by the development-only")
PY

phase "preflight and plan as root"
"${installer_cmd[@]}" preflight-v2 < "$work/preflight-input.json" > "$work/preflight.json"
python3 - "$work/preflight.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["ok"] is True, value
assert value["host_checks"]["ok"] is True
assert value["host_checks"]["checks"]["privileges"]["is_root"] is True
PY
python3 - "$work/preflight.json" "$work/plan-input.json" "$package_dir" <<'PY'
import json
import os
import sys
preflight = json.load(open(sys.argv[1], encoding="utf-8"))
configuration = preflight["configuration"]
plan_input = {
    "contract_version": 2,
    "configuration": configuration,
    "preflight": preflight,
    "package_dir": os.environ["HELICOID_ACCEPTANCE_PACKAGE"],
}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(plan_input))
PY
"${installer_cmd[@]}" plan-v2 --package-dir "$package_dir" --verify-key "$key_hex" \
	< "$work/plan-input.json" > "$work/plan.json"
python3 - "$work/plan.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["ok"] is True, value.get("error")
assert value["plan"]["product"] == "hs-server"
assert value["package_evidence"]["target"].startswith("macos-")
assert value["identity_evidence"]["decision"] == "account_absent_group_absent"
assert len(value["reviewed_plan_digest"]) == 64
PY
python3 - "$work/plan.json" "$work/apply-input.json" "$work/status-input.json" <<'PY'
import json
import os
import sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
configuration = plan["configuration"]
preflight = json.load(open(os.path.join(os.path.dirname(sys.argv[1]), "preflight.json"), encoding="utf-8"))
apply_input = {
    "contract_version": 2,
    "configuration": configuration,
    "preflight": preflight,
    "plan": plan["plan"],
    "reviewed_plan_digest": plan["reviewed_plan_digest"],
    "confirm": True,
    "package_dir": os.environ["HELICOID_ACCEPTANCE_PACKAGE"],
    "verify_key": os.environ["HELICOID_ACCEPTANCE_KEY_HEX"],
}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(apply_input))
PY

phase "refuse an arbitrary trust key before any effect"
umask 077
foreign_key=$work/foreign-signing-key.pem
foreign_der=$work/foreign-pub.der
"$HELICOID_OPENSSL" genpkey -algorithm ED25519 -out "$foreign_key" >/dev/null 2>&1
"$HELICOID_OPENSSL" pkey -in "$foreign_key" -pubout -outform DER -out "$foreign_der" >/dev/null 2>&1
foreign_hex=$(python3 - "$foreign_der" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).read_bytes()[-32:].hex())
PY
)
python3 - "$work/apply-input.json" "$work/foreign-apply-input.json" "$foreign_hex" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["verify_key"] = sys.argv[3]
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(value))
PY
if sudo -n env RUST_LOG=off HELICOID_MACOS_DEV_TRUST_KEY="$foreign_hex" "$bin" installer apply-v2 \
	< "$work/foreign-apply-input.json" > "$work/foreign-apply.json" 2> "$work/foreign-apply.err"; then
	die "apply accepted an arbitrary trust key"
fi
grep -q 'build-pinned development release key' "$work/foreign-apply.err" \
	|| die "foreign-key refusal did not cite the build-pinned key"
for path in "$product_root" "$state_dir" "$lock_file" "$plist"; do
	if [ -e "$path" ] || [ -L "$path" ]; then
		die "foreign-key refusal mutated $path"
	fi
done
if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
	die "foreign-key refusal created the service account"
fi

if [ "$mode" = rollback ]; then
	phase "force a deterministic post-effect launchd failure"
	touch "$immutable_set"
	sudo -n /usr/bin/chflags uchg /Library/LaunchDaemons
	if sudo -n sh -c ': > /Library/LaunchDaemons/.helicoid-immutable-probe' 2>/dev/null; then
		sudo -n rm -f /Library/LaunchDaemons/.helicoid-immutable-probe
		die "immutable flag did not block writes; rollback acceptance is inconclusive"
	fi
fi

phase "apply the reviewed install"
"${installer_cmd[@]}" apply-v2 < "$work/apply-input.json" > "$work/apply-result.json"

# The macOS plan does not create the configured backup directory. It was
# verified absent at startup; if it appeared, fail without deleting it.
if [ -e "$backup_path" ] || [ -L "$backup_path" ]; then
	die "configured backup directory was created unexpectedly; refusing to delete it"
fi

if [ "$mode" = install ]; then
	python3 - "$work/apply-result.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["state"] == "completed", value
assert value["service_installed"] is True
assert value["result"]["code"] == "installed"
assert value["bootstrap_ready"] is False
assert value["server_ready_for_enrollment"] is False
PY

	phase "verify launchd startup, identity, TLS, and pinned health"
	sudo -n /bin/launchctl print "system/$label" > "$work/launchd.txt"
	grep -q 'state = running' "$work/launchd.txt" || die "launchd did not report a running service"
	/usr/bin/codesign --verify --strict "$product_root/bin/hs-server" >/dev/null 2>&1 \
		|| die "installed executable lost its code signature"
	pid=$(sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' "$work/launchd.txt" | head -1)
	[ -n "$pid" ] || die "launchd did not report a service PID"
	[ "$(ps -o user= -p "$pid" | tr -d '[:space:]')" = "_helicoid" ] || die "service did not run as _helicoid"
	id _helicoid >/dev/null
	sudo -n /usr/bin/dscl . -read /Users/_helicoid >/dev/null
	sudo -n /usr/bin/dscl . -read /Groups/_helicoid >/dev/null
	curl --noproxy '*' --connect-timeout 5 --max-time 10 --cacert "$work/tls-cert.pem" \
		-fsS https://127.0.0.1:8920/health > "$work/health.json" \
		|| die "pinned TLS /health request failed"
	python3 - "$work/health.json" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

value = json.load(open(sys.argv[1], encoding="utf-8"))
repo = Path(os.environ["HELICOID_ACCEPTANCE_REPO_ROOT"])
wire_source = (repo / "src" / "models.rs").read_text(encoding="utf-8")
storage_source = (repo / "src" / "db.rs").read_text(encoding="utf-8")
wire_match = re.search(
    r"^pub const WIRE_CONTRACT_V1_VERSION: i64 = ([0-9]+);$",
    wire_source,
    re.MULTILINE,
)
storage_match = re.search(
    r"^pub const SCHEMA_VERSION: i64 = ([0-9]+);$",
    storage_source,
    re.MULTILINE,
)
assert wire_match, "WIRE_CONTRACT_V1_VERSION not found"
assert storage_match, "SCHEMA_VERSION not found"
assert value["schema_version"] == int(wire_match.group(1)), value
assert value["storage_schema_version"] == int(storage_match.group(1)), value
assert value["security_state_ok"] is True, value
assert value["recovery_quarantined"] is False, value
assert value["authority_state"] == "active", value
assert value["authority_generation"] > 0, value
assert isinstance(value["bootstrap_completed"], bool), value
assert isinstance(value["accepting_authorized_operations"], bool), value
if value["status"] == "ok":
    assert value["bootstrap_completed"] is True, value
    assert value["accepting_authorized_operations"] is True, value
else:
    assert value["status"] == "degraded", value
    assert value["accepting_authorized_operations"] is False, value
    assert value["bootstrap_completed"] is False, value
PY
	sudo -n cat "$product_root/Configuration/install-receipt.json" > "$work/receipt.json"
	python3 - "$work/receipt.json" "$work/apply-result.json" "$work/plan.json" <<'PY'
import hashlib
import json
import os
import sys
receipt = json.load(open(sys.argv[1], encoding="utf-8"))
status = json.load(open(sys.argv[2], encoding="utf-8"))
plan = json.load(open(sys.argv[3], encoding="utf-8"))
assert receipt["product"] == "hs-server"
assert receipt["service_account"] == "_helicoid"
assert receipt["service_group"] == "_helicoid"
assert receipt["launchd_label"] == "com.helicoid.server"
assert receipt["operation_id"] == status["operation_id"]
assert receipt["unique_id"] > 0
assert receipt["primary_group_id"] > 0
assert receipt["package_manifest_sha256"] == plan["package_evidence"]["manifest_sha256"]
assert receipt["artifact_sha256"] == plan["package_evidence"]["artifact_sha256"]
assert receipt["reviewed_plan_digest"] == plan["reviewed_plan_digest"]
assert receipt["tls_certificate_sha256"] == plan["tls_evidence"]["certificate_sha256"]
assert receipt["tls_private_key_sha256"] == plan["tls_evidence"]["private_key_sha256"]
assert receipt["verifying_key_sha256"] == hashlib.sha256(
    bytes.fromhex(os.environ["HELICOID_ACCEPTANCE_KEY_HEX"])
).hexdigest()
for field in (
    "package_manifest_sha256",
    "verifying_key_sha256",
    "artifact_sha256",
    "tls_certificate_sha256",
    "tls_private_key_sha256",
    "reviewed_plan_digest",
):
    assert len(receipt[field]) == 64, (field, receipt[field])
PY
	sudo -n stat -f '%u:%g:%Lp' "$product_root/Configuration/install-receipt.json" | grep -qx '0:0:644' \
		|| die "install receipt is not root-owned 0644"
	service_uid=$(python3 - "$work/receipt.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["unique_id"])
PY
)
	sudo -n stat -f '%u:%Lp' "$product_root/TLS/fullchain.pem" | grep -qx "$service_uid:600" \
		|| die "installed TLS certificate is not service-owned 0600"
	sudo -n stat -f '%u:%Lp' "$product_root/TLS/private-key.pem" | grep -qx "$service_uid:600" \
		|| die "installed TLS key is not service-owned 0600"
	"${installer_cmd[@]}" status-v2 < "$work/status-input.json" > "$work/status.json"
	python3 - "$work/status.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["state"] == "completed", value
assert value["service_installed"] is True
assert value["result"]["code"] == "installed"
PY
	printf 'install acceptance passed: launchd, identity, provenance receipt, TLS, health, and status verified\n'
else
	phase "verify reverse rollback removed every test-created resource"
	python3 - "$work/apply-result.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["state"] == "attention_required", value
assert value["result"]["code"] == "rolled_back", value["result"]
assert value["service_installed"] is False
# A fully rolled-back operation removes its journal, so the post-rollback
# status deliberately reports no phase map. Resource absence is checked below.
PY
	sudo -n /usr/bin/chflags nouchg /Library/LaunchDaemons
	rm -f -- "$immutable_set"
	for path in "$product_root" "$plist"; do
		if [ -e "$path" ] || [ -L "$path" ]; then
			die "rollback left $path behind"
		fi
	done
	if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then
		die "rollback left the launchd job loaded"
	fi
	if /usr/bin/dscl . -read /Users/_helicoid >/dev/null 2>&1; then
		die "rollback left the service account behind"
	fi
	if /usr/bin/dscl . -read /Groups/_helicoid >/dev/null 2>&1; then
		die "rollback left the service group behind"
	fi
	"${installer_cmd[@]}" status-v2 < "$work/status-input.json" > "$work/status.json"
	python3 - "$work/status.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["state"] == "attention_required", value
assert value["service_installed"] is False
assert value["result"]["code"] == "rolled_back", value["result"]
PY
	printf 'rollback acceptance passed: failed launchd phase rolled back files, receipt, TLS, and identity\n'
fi

printf '\nacceptance mode %s passed\n' "$mode"
