#!/usr/bin/env bash

set -euo pipefail
umask 077

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
	printf '%s\n' \
		"Usage: install-linux.sh [--package-dir DIR] [--verify-key HEX] | --non-interactive --config FILE [--confirm] | --non-interactive [--resume] --request FILE [--confirm]" \
		"Plans a signed Linux x86_64 systemd or Docker Compose install, applies a reviewed plan, or resumes its journaled operation."
}

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

installer_log() {
	local level=$1
	local message=$2

	if command -v gum >/dev/null 2>&1 && gum log --level "$level" "$message" >&2; then
		return 0
	fi
	printf '%s: %s\n' "$level" "$message" >&2
}

installer_script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || die "cannot locate the Linux installer scripts"

package_dir=
verify_key=
config_file=
request_file=
non_interactive=0
confirm_apply=0
resume_operation=0
bootstrap_temporary_directory=
network_scope=lan
network_bind_address=
network_client_hostname=
network_authority_port=8920
while (($# > 0)); do
	case "$1" in
	--package-dir)
		(($# >= 2)) || die "--package-dir requires a value"
		package_dir=$2
		shift 2
		;;
	--verify-key)
		(($# >= 2)) || die "--verify-key requires a value"
		verify_key=$2
		shift 2
		;;
	--config)
		(($# >= 2)) || die "--config requires a value"
		config_file=$2
		shift 2
		;;
	--request)
		(($# >= 2)) || die "--request requires a value"
		request_file=$2
		shift 2
		;;
	--non-interactive)
		non_interactive=1
		shift
		;;
	--confirm)
		confirm_apply=1
		shift
		;;
	--resume)
		resume_operation=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "unknown argument: $1"
		;;
	esac
done

if ((non_interactive)); then
	if [[ -n "$config_file" ]]; then
		[[ -z "$request_file" ]] || die "use either --config or --request, not both"
		((resume_operation == 0)) || die "--config cannot be used with --resume; resume the reviewed request"
		[[ -z "$package_dir" && -z "$verify_key" ]] || die "--config supplies the package directory and verification key"
	elif [[ -n "$request_file" ]]; then
		[[ -z "$package_dir" && -z "$verify_key" ]] || die "use the reviewed request instead of package arguments in non-interactive mode"
	else
		die "--request or --config is required in non-interactive mode"
	fi
elif ((confirm_apply || resume_operation)) || [[ -n "$request_file" ]]; then
	die "--confirm, --resume, and --request are only valid with --non-interactive"
elif [[ -n "$config_file" ]]; then
	die "--config is only valid with --non-interactive"
else
	if [[ -z "$package_dir" ]]; then
		if command -v gum >/dev/null 2>&1; then
			package_dir=$(gum file --directory --header "Select the extracted signed package directory" .) || exit 1
		else
			printf '%s' "Path to extracted signed package: "
			IFS= read -r package_dir || exit 1
		fi
	fi
	if [[ -z "$verify_key" ]]; then
		if command -v gum >/dev/null 2>&1; then
			verify_key=$(gum input --prompt "Trusted release public key (hex): " --placeholder "64 hex characters") || exit 1
		else
			printf '%s' "Trusted release public key (hex): "
			IFS= read -r verify_key || exit 1
		fi
	fi
fi

[[ "$EUID" -eq 0 ]] || die "run this installer as root; the current backend applies host changes directly"
if ((!non_interactive)); then
	[[ -n "$package_dir" ]] || die "package directory is required"
	[[ -n "$verify_key" ]] || die "release verification key is required"
	[[ -d "$package_dir" ]] || die "package directory does not exist"
fi

trusted_root_executable() {
	local candidate=$1
	local current=$candidate
	local owner mode mode_value

	[[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]] || return 1
	while :; do
		[[ ! -L "$current" ]] || return 1
		if [[ "$current" == "$candidate" ]]; then
			[[ -f "$current" ]] || return 1
		else
			[[ -d "$current" ]] || return 1
		fi
		owner=$(stat -c '%u' -- "$current") || return 1
		mode=$(stat -c '%a' -- "$current") || return 1
		[[ "$owner" == 0 ]] || return 1
		mode_value=$((8#$mode))
		(( (mode_value & 0022) == 0 )) || return 1
		[[ "$current" != / ]] || break
		current=${current%/*}
		[[ -n "$current" ]] || current=/
	done
	return 0
}

trusted_root_review() {
	local candidate=$1
	local owner mode mode_value current

	[[ "$candidate" == /* && -f "$candidate" && ! -L "$candidate" ]] || return 1
	owner=$(stat -c '%u' -- "$candidate") || return 1
	mode=$(stat -c '%a' -- "$candidate") || return 1
	[[ "$owner" == 0 ]] || return 1
	mode_value=$((8#$mode))
	(( mode_value == 0600 )) || return 1
	current=${candidate%/*}
	while :; do
		[[ -d "$current" && ! -L "$current" ]] || return 1
		owner=$(stat -c '%u' -- "$current") || return 1
		mode=$(stat -c '%a' -- "$current") || return 1
		[[ "$owner" == 0 ]] || return 1
		mode_value=$((8#$mode))
		if (( (mode_value & 0022) != 0 && (mode_value & 01000) == 0 )); then
			return 1
		fi
		[[ "$current" != / ]] || break
		current=${current%/*}
		[[ -n "$current" ]] || current=/
	done
	return 0
}

trusted_root_directory() {
	local candidate=$1
	local current=$candidate
	local owner mode mode_value

	[[ -d "$candidate" && ! -L "$candidate" ]] || return 1
	while :; do
		[[ -d "$current" && ! -L "$current" ]] || return 1
		owner=$(stat -c '%u' -- "$current") || return 1
		mode=$(stat -c '%a' -- "$current") || return 1
		[[ "$owner" == 0 ]] || return 1
		mode_value=$((8#$mode))
		(( (mode_value & 0022) == 0 )) || return 1
		[[ "$current" != / ]] || break
		current=${current%/*}
		[[ -n "$current" ]] || current=/
	done
	return 0
}

if ((non_interactive)) && [[ -n "$config_file" ]]; then
	[[ "$config_file" == /* ]] || die "configuration path must be absolute"
	trusted_root_review "$config_file" || die "configuration must be a root-owned 0600 file under trusted root-managed directories"
	config_values_file=$(mktemp /var/tmp/helicoid-config-fields.XXXXXXXX) || die "cannot create a private configuration staging file"
	if ! chmod 600 "$config_values_file"; then
		rm -f -- "$config_values_file"
		die "cannot protect the configuration staging file"
	fi
	if ! python3 "$installer_script_directory/read-linux-install-config.py" "$config_file" >"$config_values_file"; then
		rm -f -- "$config_values_file"
		die "installer configuration is invalid"
	fi
	mapfile -d '' -t config_values < "$config_values_file"
	rm -f -- "$config_values_file"
	[[ "${#config_values[@]}" -eq 9 ]] || die "installer configuration returned an invalid field count"
	package_dir=${config_values[0]}
	verify_key=${config_values[1]}
	deployment_kind=${config_values[2]}
	network_scope=${config_values[3]}
	network_bind_address=${config_values[4]}
	network_client_hostname=${config_values[5]}
	network_authority_port=${config_values[6]}
	data_directory=${config_values[7]}
	backup_directory=${config_values[8]}
	package_dir=$(realpath -e -- "$package_dir") || die "configured package directory does not exist"
	[[ -d "$package_dir" ]] || die "configured package path is not a directory"
fi

cleanup_bootstrap_directory() {
	if [[ -n "$bootstrap_temporary_directory" ]]; then
		rm -rf -- "$bootstrap_temporary_directory"
		bootstrap_temporary_directory=
	fi
}

trap cleanup_bootstrap_directory EXIT

bootstrap_release_binaries() {
	local source_package=$1
	local public_key=$2
	local installer_directory=/opt/helicoid/bin
	local bootstrap_directory
	local staged_directory
	local script_directory

	command -v python3 >/dev/null 2>&1 || die "python3 is required to bootstrap a clean host"
	command -v openssl >/dev/null 2>&1 || die "openssl is required to verify the signed release package"
	script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || die "cannot locate the Linux installer scripts"
	bootstrap_directory=$(mktemp -d /var/tmp/helicoid-bootstrap.XXXXXXXX) || die "cannot create a private bootstrap directory"
	bootstrap_temporary_directory=$bootstrap_directory
	chmod 700 "$bootstrap_directory" || die "cannot protect the private bootstrap directory"
	staged_directory=$bootstrap_directory/artifacts
	mkdir -m 700 -- "$staged_directory" || die "cannot create the private artifact staging directory"

	if ! python3 "$script_directory/bootstrap-linux-package.py" \
		"$source_package" "$public_key" "$staged_directory"; then
		die "signed package bootstrap verification failed; no binaries were installed"
	fi

	if [[ -e "$installer_directory/helicoid-server" || -L "$installer_directory/helicoid-server" ||
		-e "$installer_directory/hs-server" || -L "$installer_directory/hs-server" ]]; then
		die "bootstrap destination already contains a binary; inspect the existing installation before continuing"
	fi
	trusted_root_directory /opt || die "the /opt directory is not protected and root-owned"
	if [[ -e /opt/helicoid || -L /opt/helicoid ]]; then
		trusted_root_directory /opt/helicoid || die "the existing /opt/helicoid directory is not protected and root-owned"
	fi
	if [[ -e "$installer_directory" || -L "$installer_directory" ]]; then
		trusted_root_directory "$installer_directory" || die "the existing installer directory is not protected and root-owned"
	fi
	install -d -o root -g root -m 0755 /opt/helicoid "$installer_directory" || {
		die "cannot create the protected bootstrap directory"
	}
	if ! trusted_root_directory "$installer_directory"; then
		die "bootstrap destination is not a protected root-owned directory"
	fi
	install -o root -g root -m 0755 "$staged_directory/helicoid-server" "$installer_directory/helicoid-server" || {
		rm -f -- "$installer_directory/helicoid-server"
		die "cannot install the signed management bootstrap binary"
	}
	install -o root -g root -m 0755 "$staged_directory/hs-server" "$installer_directory/hs-server" || {
		rm -f -- "$installer_directory/helicoid-server" "$installer_directory/hs-server"
		die "cannot install the signed lifecycle backend"
	}
	chmod 0755 "$installer_directory/helicoid-server" "$installer_directory/hs-server" || {
		rm -f -- "$installer_directory/helicoid-server" "$installer_directory/hs-server"
		die "cannot protect the installed bootstrap binaries"
	}
	cleanup_bootstrap_directory
	printf '%s\n' "Verified the manifest signature and fixed artifact digests; staged installer binaries in $installer_directory."
}

server_cli=
for candidate in \
	/opt/helicoid/bin/helicoid-server \
	/usr/local/bin/helicoid-server \
	/usr/bin/helicoid-server; do
	if trusted_root_executable "$candidate"; then
		server_cli=$candidate
		break
	fi
done

if [[ -z "$server_cli" ]]; then
	if ((non_interactive)) && [[ -n "$request_file" ]]; then
		die "no root-owned helicoid-server binary is installed; first-time setup must use --config with a signed package or the interactive signed-package flow"
	fi
	[[ -n "$package_dir" && -n "$verify_key" ]] || die "signed package directory and release verification key are required to bootstrap the installer"
	bootstrap_release_binaries "$package_dir" "$verify_key"
	server_cli=/opt/helicoid/bin/helicoid-server
	trusted_root_executable "$server_cli" || die "the bootstrapped management binary is not a protected root-owned executable"
fi

temporary_dir=
preserve_review=0
cleanup_review() {
	if [[ -n "$temporary_dir" ]] && ((preserve_review == 0)); then
		rm -rf -- "$temporary_dir"
	fi
}
trap 'cleanup_review; cleanup_bootstrap_directory' EXIT

if ((non_interactive)) && [[ -n "$request_file" ]]; then
	review_file=$(realpath -e -- "$request_file") || die "review request does not exist"
	trusted_root_review "$review_file" || die "review request must be a root-owned 0600 file under trusted root-managed directories"
else
	temporary_dir=$(mktemp -d "/var/tmp/helicoid-installer.XXXXXXXX") || die "cannot create private review directory"
	chmod 700 "$temporary_dir" || die "cannot protect review directory"
	review_file=$temporary_dir/reviewed-plan.json
fi

if ((!non_interactive)) || [[ -n "$config_file" ]]; then
	if ((!non_interactive)); then
		deployment_kind=linux_systemd
		if command -v gum >/dev/null 2>&1; then
			deployment_choice=$(gum choose --header "Choose the Linux deployment" "Native systemd" "Docker Compose") || exit 1
			case "$deployment_choice" in
			"Native systemd") deployment_kind=linux_systemd ;;
			"Docker Compose") deployment_kind=linux_compose ;;
			*) die "gum returned an unknown deployment kind" ;;
			esac
		else
			printf '%s' "Deployment kind [linux_systemd/linux_compose] (default linux_systemd): "
			IFS= read -r deployment_kind || exit 1
			deployment_kind=${deployment_kind:-linux_systemd}
		fi
	default_data_directory=/var/lib/helicoid/data
	default_backup_directory=/var/lib/helicoid/backups
	if command -v gum >/dev/null 2>&1; then
		network_scope_choice=$(gum choose --header "Choose the server network scope" "LAN" "Private DNS" "Loopback development") || exit 1
		case "$network_scope_choice" in
		"LAN") network_scope=lan ;;
		"Private DNS") network_scope=private_dns ;;
		"Loopback development") network_scope=loopback_development ;;
		*) die "gum returned an unknown network scope choice" ;;
		esac
		if [[ "$network_scope" == lan || "$network_scope" == private_dns ]]; then
			network_bind_address=$(gum input --prompt "Private LAN IP assigned to this host: " --placeholder "192.168.1.10") || exit 1
			if [[ "$network_scope" == private_dns ]]; then
				network_client_hostname=$(gum input --prompt "Required private DNS hostname: " --placeholder "server.school.lan") || exit 1
			else
				network_client_hostname=$(gum input --prompt "Manager DNS hostname (optional): " --placeholder "server.school.lan") || exit 1
			fi
		elif [[ "$network_scope" != loopback_development ]]; then
			die "network scope must be lan, private_dns, or loopback_development"
		fi
		if [[ "$deployment_kind" == linux_compose && "$network_scope" == loopback_development ]]; then
			printf '%s\n' \
				"Compose loopback mode still uses TLS inside the container. Provide a root-owned certificate chain and matching private key at:" \
				"  /etc/ssl/helicoid/fullchain.pem" \
				"  /etc/ssl/helicoid/private-key.pem" \
				"The certificate must cover localhost; the installer checks its SAN before copying it into the container."
		fi
		data_directory=$(gum input --prompt "Server data directory: " --placeholder "$default_data_directory") || exit 1
		backup_directory=$(gum input --prompt "Server backup directory: " --placeholder "$default_backup_directory") || exit 1
	else
		printf '%s' "Network scope [lan/private_dns/loopback_development] (default lan): "
		IFS= read -r network_scope || exit 1
		network_scope=${network_scope:-lan}
		if [[ "$network_scope" == lan || "$network_scope" == private_dns ]]; then
			printf '%s' "Private LAN IP assigned to this host: "
			IFS= read -r network_bind_address || exit 1
			if [[ "$network_scope" == private_dns ]]; then
				printf '%s' "Required private DNS hostname used by Managers: "
			else
				printf '%s' "Manager DNS hostname (optional, press Enter to use the IP): "
			fi
			IFS= read -r network_client_hostname || exit 1
		elif [[ "$network_scope" != loopback_development ]]; then
			die "network scope must be lan, private_dns, or loopback_development"
		fi
		printf 'Server data directory [%s]: ' "$default_data_directory"
		IFS= read -r data_directory || exit 1
		printf 'Server backup directory [%s]: ' "$default_backup_directory"
		IFS= read -r backup_directory || exit 1
	fi
	data_directory=${data_directory:-$default_data_directory}
	backup_directory=${backup_directory:-$default_backup_directory}
	fi
	[[ "$deployment_kind" == linux_systemd || "$deployment_kind" == linux_compose ]] ||
		die "deployment kind must be linux_systemd or linux_compose"
	if [[ "$deployment_kind" == linux_systemd ]] &&
		{ ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; }; then
		die "native systemd deployment requires a running systemd host; choose Docker Compose if that is the intended host"
	fi
	if [[ "$deployment_kind" == linux_compose ]] && ! command -v docker >/dev/null 2>&1; then
		die "Docker Engine and its Compose plugin are required for Docker Compose deployment"
	fi
	plan_args=(installer plan --package-dir "$package_dir" --verify-key "$verify_key" --output "$review_file" --deployment-kind "$deployment_kind")
	plan_args+=(--scope "$network_scope")
	if [[ "$network_scope" == lan || "$network_scope" == private_dns ]]; then
		[[ -n "$network_bind_address" ]] || die "a private LAN/private DNS bind address is required"
		if [[ "$network_scope" == private_dns ]]; then
			[[ -n "$network_client_hostname" ]] || die "a Manager DNS hostname is required for private_dns scope"
		fi
		plan_args+=(--port "$network_authority_port")
		printf '%s\n' \
			"Private-network TLS is enabled on port $network_authority_port. Provide a root-owned certificate chain and matching private key at:" \
			"  /etc/ssl/helicoid/fullchain.pem" \
			"  /etc/ssl/helicoid/private-key.pem" \
			"Keep /etc/ssl/helicoid root-owned mode 0700 and both files root-owned mode 0600." \
			"The installer leaves DNS, firewall, proxy, certificate renewal, and client trust setup to the operator."
		if [[ -n "$network_client_hostname" ]]; then
			printf 'Create private DNS for %s pointing to %s and include that name in the certificate DNS SAN; preflight checks the name.\n' "$network_client_hostname" "$network_bind_address"
			plan_args+=(--client-hostname "$network_client_hostname")
		else
			printf 'Include the bind IP %s in the certificate IP SAN; preflight checks the name.\n' "$network_bind_address"
		fi
		printf '%s\n' "Manager clients must trust the certificate's issuing CA; preflight does not check client trust."
		printf 'Firewall guidance: permit TCP %s only from trusted Manager client networks; no UDP listener is required.\n' "$network_authority_port"
		if [[ "$network_scope" == private_dns ]]; then
			printf 'If using a proxy, forward HTTPS for %s to %s:%s with certificate validation and the hostname preserved.\n' "$network_client_hostname" "$network_bind_address" "$network_authority_port"
		fi
		plan_args+=(--bind-address "$network_bind_address")
		if [[ -n "$network_client_hostname" ]]; then
			if [[ "$network_scope" == private_dns ]]; then
				configured_network_summary="Private DNS TLS authority: $network_client_hostname:$network_authority_port ($network_bind_address)"
			else
				configured_network_summary="LAN TLS authority: $network_client_hostname:$network_authority_port ($network_bind_address)"
			fi
		else
			configured_network_summary="LAN TLS authority: $network_bind_address:$network_authority_port"
		fi
	else
		network_authority_port=8787
		plan_args+=(--port 8787)
		configured_network_summary="Loopback development listener only"
	fi
	plan_args+=(--data-dir "$data_directory" --backup-dir "$backup_directory")
	if ((!non_interactive)) && command -v gum >/dev/null 2>&1; then
		if ! gum spin --title "Checking host and verifying the signed package" -- "$server_cli" "${plan_args[@]}"; then
			die "preflight or signed package verification failed"
		fi
	else
		printf '%s\n' "Checking host and verifying the signed package..."
		"$server_cli" "${plan_args[@]}" || die "preflight or signed package verification failed"
	fi
fi

if ((non_interactive)); then
	deployment_kind=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["configuration"]["deployment_kind"])' "$review_file") ||
		die "cannot read the reviewed deployment kind"
	[[ "$deployment_kind" == linux_systemd || "$deployment_kind" == linux_compose ]] ||
		die "review request has an unsupported deployment kind"
	if [[ "$deployment_kind" == linux_systemd ]] &&
		{ ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; }; then
		die "native systemd deployment requires a running systemd host"
	fi
	if [[ "$deployment_kind" == linux_compose ]] && ! command -v docker >/dev/null 2>&1; then
		die "Docker Engine and its Compose plugin are required for Docker Compose deployment"
	fi
fi

printf '\n%s\n' "Review the exact deployment request below. It includes the host observations, owned resources, and review digest:"
cat -- "$review_file"
printf '\n'

if ((!non_interactive)) && command -v gum >/dev/null 2>&1; then
	{
		printf 'Deployment,%s\n' "$deployment_kind"
		printf 'Network scope,%s\n' "$configured_network_summary"
		printf 'Data directory,%s\n' "$data_directory"
		printf 'Backup directory,%s\n' "$backup_directory"
	} | gum table --separator ',' --columns 'Setting,Reviewed value' --print
fi

if ((non_interactive && confirm_apply == 0)); then
	if ((resume_operation)); then
		printf '%s\n' \
			"No host changes were applied. Review the supplied plan and rerun with --confirm to resume it:" \
			"  $review_file" \
			"The review file remains unchanged."
	else
		if [[ -n "$config_file" ]]; then
			preserve_review=1
			printf '%s\n' \
				"No service was installed or started. Review the generated plan and rerun with --confirm to apply it:" \
				"  $review_file"
			printf '  '
			printf '%q ' sudo "$installer_script_directory/install-linux.sh" --non-interactive --request "$review_file" --confirm
			printf '\n%s\n' \
				"The protected bootstrap binaries and reviewed request are retained."
		else
			printf '%s\n' \
				"No host changes were applied. Review the supplied plan and rerun with --confirm to apply it:" \
				"  $review_file" \
				"The review file remains unchanged."
		fi
	fi
	exit 0
elif ((non_interactive && confirm_apply)); then
	:
elif command -v gum >/dev/null 2>&1; then
	confirmation_prompt="Apply this $deployment_kind plan? The installer will make the listed host changes."
	if ((resume_operation)); then
		confirmation_prompt="Resume this $deployment_kind operation using the existing journal and reviewed request?"
	fi
	if ! gum confirm "$confirmation_prompt"; then
		preserve_review=1
		printf '%s\n' "No host changes were applied. The review file remains at $review_file"
		exit 0
	fi
else
	confirmation_prompt="Type APPLY to make the reviewed host changes: "
	if ((resume_operation)); then
		confirmation_prompt="Type APPLY to resume the journaled operation: "
	fi
	printf '%s' "$confirmation_prompt"
	IFS= read -r confirmation || exit 1
	[[ "$confirmation" == "APPLY" ]] || {
		preserve_review=1
		printf '%s\n' "No host changes were applied. The review file remains at $review_file"
		exit 0
	}
fi

installer_action=apply
if ((resume_operation)); then
	installer_action=resume
fi

if ((resume_operation)); then
	installer_log info "Resuming the journaled installation operation."
else
	installer_log info "Applying the reviewed installation plan."
fi

if ! "$server_cli" installer "$installer_action" --request "$review_file" --confirm; then
	preserve_review=1
	installer_log error "The installer operation needs attention; keep its review request for recovery."
	printf '%s\n' \
		"Installation needs attention. Keep this review file and the verified package directory available:" \
		"  $review_file" \
		"Resume the same journaled operation with the command below:" >&2
	if ((resume_operation)); then
		printf '  %s installer resume --request %q --confirm\n' "$server_cli" "$review_file" >&2
	else
		printf '  %q --non-interactive --resume --request %q --confirm\n' "$0" "$review_file" >&2
	fi
	exit 1
fi

installer_log info "The reviewed installer operation completed."

compose_args=()
if [[ "$deployment_kind" == linux_compose ]]; then
	status_json=$("$server_cli" status --json) || die "cannot inspect the completed Compose operation"
	install_operation_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("operation_id") or "")' <<< "$status_json") ||
		die "cannot read the Compose operation identity"
	[[ "$install_operation_id" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] ||
		die "the Compose operation returned an invalid identity"
	install_operation_id=${install_operation_id,,}
	compose_project="helicoid-${install_operation_id//-/}"
	compose_args=(compose --project-name "$compose_project" --project-directory /opt/helicoid/compose
		--env-file /opt/helicoid/compose/.env -f /opt/helicoid/compose/compose.yaml)
fi

read_bootstrap_health() {
	if [[ "$deployment_kind" == linux_compose ]]; then
		docker "${compose_args[@]}" exec -T server helicoid-server doctor --json 2>/dev/null || true
	else
		"$server_cli" doctor --json 2>/dev/null || true
	fi
}

bootstrap_state=unknown
bootstrap_health_json=$(read_bootstrap_health)
if grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*true[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_health_json"; then
	bootstrap_state=recorded
elif grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*false[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_health_json"; then
	bootstrap_state=pending
fi

bootstrap_requested=0
bootstrap_user=${SUDO_USER:-}
bootstrap_uid=
if [[ "$bootstrap_state" == pending ]] && ((!non_interactive)) && [[ -t 0 && -t 1 && -n "$bootstrap_user" && "$bootstrap_user" != root ]] && command -v getent >/dev/null 2>&1; then
	bootstrap_account=$(getent passwd "$bootstrap_user" || true)
	IFS=: read -r _ _ bootstrap_uid _ <<< "$bootstrap_account"
	if [[ "$bootstrap_account" == "$bootstrap_user:"* && "$bootstrap_uid" =~ ^[0-9]+$ ]] && ((bootstrap_uid > 0)); then
		if command -v gum >/dev/null 2>&1; then
			if gum confirm "Prepare first-administrator MFA bootstrap for $bootstrap_user now?"; then
				bootstrap_requested=1
			fi
		else
			printf 'Prepare first-administrator MFA bootstrap for %s now? [y/N] ' "$bootstrap_user"
			IFS= read -r bootstrap_answer || bootstrap_answer=
			if [[ "${bootstrap_answer,,}" == y || "${bootstrap_answer,,}" == yes ]]; then
				bootstrap_requested=1
			fi
		fi
	fi
fi

if ((bootstrap_requested)); then
	hs_server_cli=/opt/helicoid/bin/hs-server
	if [[ "$deployment_kind" == linux_systemd ]] && ! command -v runuser >/dev/null 2>&1; then
		printf '%s\n' "Warning: runuser is unavailable; first-administrator bootstrap remains pending." >&2
	elif ! trusted_root_executable "$hs_server_cli"; then
		printf '%s\n' "Warning: the installed hs-server binary is not a trusted root-owned executable; bootstrap remains pending." >&2
	elif [[ "$deployment_kind" == linux_systemd ]] && ! systemctl is-active --quiet hs-server.service; then
		printf '%s\n' "Warning: the installed service is not active; bootstrap remains pending." >&2
	else
		printf '\n%s\n' "Creating a single-use bootstrap token through the installed server."
		bootstrap_database=$($server_cli installer database-path) || bootstrap_database=
		if [[ -z "$bootstrap_database" ]]; then
			printf '%s\n' "Warning: could not read the reviewed data directory; bootstrap remains pending." >&2
		elif [[ "$deployment_kind" == linux_compose ]] &&
			docker "${compose_args[@]}" exec server hs-server --data "$bootstrap_database" init; then
			printf '\n%s\n' "Starting the MFA-protected first-administrator flow as $bootstrap_user."
			if docker "${compose_args[@]}" exec server helicoid-server bootstrap; then
				bootstrap_state=ready
			else
				printf '%s\n' \
					"Warning: the first-administrator flow did not finish; the installation remains in place." \
					"If it printed an enrollment ID, retry inside the Compose service with: helicoid-server mfa confirm ENROLLMENT_ID" \
					"Inspect the in-container doctor output before creating another token." >&2
				bootstrap_after_json=$(read_bootstrap_health)
				if grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*true[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
					bootstrap_state=bootstrap_created_unverified
				elif grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*false[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
					bootstrap_state=pending
				else
					bootstrap_state=unknown
				fi
			fi
		elif [[ "$deployment_kind" == linux_systemd ]] && runuser --user hs-server -- "$hs_server_cli" --data "$bootstrap_database" init; then
			printf '\n%s\n' "Starting the MFA-protected first-administrator flow as $bootstrap_user."
			if runuser --login --user "$bootstrap_user" -- "$server_cli" bootstrap; then
				bootstrap_state=ready
			else
				printf '%s\n' \
					"Warning: the first-administrator flow did not finish; the installation remains in place." \
					"If it printed an enrollment ID, retry with: $server_cli mfa confirm ENROLLMENT_ID" \
					"If no enrollment was created, inspect the doctor output before creating another token." >&2
				bootstrap_after_json=$(read_bootstrap_health)
				if grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*true[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
					bootstrap_state=bootstrap_created_unverified
				elif grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*false[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
					bootstrap_state=pending
				else
					bootstrap_state=unknown
				fi
			fi
		else
			printf '%s\n' "Warning: token creation failed; the installation remains in place." >&2
			bootstrap_after_json=$(read_bootstrap_health)
			if grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*true[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
				bootstrap_state=recorded
			elif grep -Eq '^[[:space:]]*"bootstrap_completed"[[:space:]]*:[[:space:]]*false[[:space:]]*,?[[:space:]]*$' <<< "$bootstrap_after_json"; then
				bootstrap_state=pending
			else
				bootstrap_state=unknown
			fi
		fi
	fi
fi

if [[ "$bootstrap_state" == ready ]]; then
	printf '\n%s\n' \
		"Installed: yes." \
		"Ready for Enrollment: yes; first-administrator MFA and independent recovery storage were confirmed." \
		"${configured_network_summary:-Network scope is recorded in the reviewed request.}" \
		"Public Integration Pending: yes; external reachability and client trust have not been verified." \
		"Deployment Verified: no."
elif [[ "$bootstrap_state" == pending ]]; then
	manual_bootstrap_database=$("$server_cli" installer database-path 2>/dev/null || true)
	manual_bootstrap_database=${manual_bootstrap_database:-/var/lib/helicoid/data/hs-server.db}
	if [[ "$deployment_kind" == linux_compose ]]; then
		manual_bootstrap_compose_prefix=$(printf 'docker compose --project-name %q --project-directory /opt/helicoid/compose --env-file /opt/helicoid/compose/.env -f /opt/helicoid/compose/compose.yaml' "$compose_project")
		manual_bootstrap_command=$(printf '  %s exec server hs-server --data %q init' "$manual_bootstrap_compose_prefix" "$manual_bootstrap_database")
		manual_bootstrap_tui_command=$(printf '  %s exec server helicoid-server bootstrap' "$manual_bootstrap_compose_prefix")
	else
		manual_bootstrap_command=$(printf '  sudo -u hs-server /opt/helicoid/bin/hs-server --data %q init' "$manual_bootstrap_database")
		manual_bootstrap_tui_command="  $server_cli bootstrap"
	fi
	printf '\n%s\n' \
		"Installed: yes." \
		"Ready for Enrollment: no; first-administrator bootstrap is pending." \
		"${configured_network_summary:-Network scope is recorded in the reviewed request.}" \
		"Public Integration Pending: yes; external reachability and client trust have not been verified." \
		"Deployment Verified: no." \
		"To create a one-time token, run as an administrator:" \
		"$manual_bootstrap_command" \
		"Then run the interactive MFA bootstrap:" \
		"$manual_bootstrap_tui_command"
elif [[ "$bootstrap_state" == bootstrap_created_unverified ]]; then
	printf '\n%s\n' \
		"Installed: yes." \
		"Ready for Enrollment: unverified; the first-administrator bootstrap record exists, but this run could not confirm MFA activation." \
		"If an enrollment ID was printed, retry with: $server_cli mfa confirm ENROLLMENT_ID" \
		"Do not create another bootstrap token; inspect $server_cli doctor --json if the enrollment ID was not retained." \
		"${configured_network_summary:-Network scope is recorded in the reviewed request.}" \
		"Public Integration Pending: yes; external reachability and client trust have not been verified." \
		"Deployment Verified: no."
elif [[ "$bootstrap_state" == recorded ]]; then
	printf '\n%s\n' \
		"Installed: yes." \
		"An existing bootstrap record was detected; this installer did not revalidate MFA readiness." \
		"${configured_network_summary:-Network scope is recorded in the reviewed request.}" \
		"Public Integration Pending: yes; external reachability and client trust have not been verified." \
		"Deployment Verified: no."
else
	printf '\n%s\n' \
		"Installed: yes." \
		"${configured_network_summary:-Network scope is recorded in the reviewed request.}" \
		"The administrator bootstrap state could not be verified; run $server_cli doctor --json before continuing." \
		"Public Integration Pending: yes." \
		"Deployment Verified: no."
fi

if status_json=$("$server_cli" status --json); then
	printf '\n%s\n' "Current durable operation status:" "$status_json"
else
	printf '%s\n' "Warning: installation completed, but the durable status could not be read." >&2
fi
if [[ "$deployment_kind" == linux_compose ]]; then
	printf '\n%s\n' "For later local administration, run the TUI inside the protected Compose service:"
	printf '  docker'
	printf ' %q' "${compose_args[@]}"
	printf ' exec server helicoid-server\n'
fi

if ((!non_interactive)) && [[ -t 0 && -t 1 ]]; then
	operator_user=${SUDO_USER:-}
	operator_account=
	operator_uid=
	operator_home=
	if [[ -n "$operator_user" && "$operator_user" != root ]] && command -v getent >/dev/null 2>&1; then
		operator_account=$(getent passwd "$operator_user" || true)
		IFS=: read -r _ _ operator_uid _ _ operator_home _ <<< "$operator_account"
		if [[ "$operator_account" != "$operator_user:"* || ! "$operator_uid" =~ ^[0-9]+$ ||
			"$operator_home" != /* || ! -d "$operator_home" ]]; then
			operator_user=
		elif ((operator_uid == 0)); then
			operator_user=
		fi
	else
		operator_user=
	fi

	if [[ -n "$operator_user" ]] &&
		{ [[ "$deployment_kind" == linux_compose ]] || command -v runuser >/dev/null 2>&1; }; then
		profile_writer=$installer_script_directory/export-manager-profile.py
		default_profile_path=$operator_home/Helicoid-server-profile.json
		export_profile=0
		if command -v gum >/dev/null 2>&1; then
			if gum confirm "Export a public Manager connection profile for $operator_user?"; then
				export_profile=1
			fi
		else
			printf 'Export a public Manager connection profile for %s? [Y/n] ' "$operator_user"
			IFS= read -r export_answer || export_answer=n
			if [[ -z "$export_answer" || "${export_answer,,}" == y || "${export_answer,,}" == yes ]]; then
				export_profile=1
			fi
		fi

		if ((export_profile)); then
			if command -v gum >/dev/null 2>&1; then
				profile_path=$(gum input --prompt "Profile output path: " --value "$default_profile_path" --char-limit 4096) || profile_path=
			else
				printf 'Profile output path [%s] (empty uses default): ' "$default_profile_path"
				IFS= read -r profile_path || profile_path=
				profile_path=${profile_path:-$default_profile_path}
			fi
			if [[ -n "$profile_path" ]]; then
				if ! runuser --user "$operator_user" -- test -r "$profile_writer"; then
					printf '%s\n' "Warning: the profile exporter is not readable by $operator_user; profile export was skipped." >&2
				elif ! "$server_cli" installer configuration-v2 --state-dir /opt/helicoid/.installer |
					runuser --login --user "$operator_user" -- python3 "$profile_writer" "$profile_path"; then
					printf '%s\n' "Warning: the Manager profile could not be exported. Existing files are never overwritten." >&2
				else
					printf 'Exported a public connection profile to %q. Import it with File > Import Profiles, then verify the deployment identity through your trusted organization channel.\n' "$profile_path"
				fi
			fi
		fi

		installed_tui=/opt/helicoid/bin/helicoid-server
		if trusted_root_executable "$installed_tui"; then
			launch_tui=0
			if command -v gum >/dev/null 2>&1; then
				if gum confirm "Open the Helicoid server TUI as $operator_user now?"; then
					launch_tui=1
				fi
			else
				printf 'Open the Helicoid server TUI as %s now? [y/N] ' "$operator_user"
				IFS= read -r launch_answer || launch_answer=n
				if [[ "${launch_answer,,}" == y || "${launch_answer,,}" == yes ]]; then
					launch_tui=1
				fi
			fi
			if ((launch_tui)); then
				if [[ "$deployment_kind" == linux_compose ]]; then
					if ! docker "${compose_args[@]}" exec server helicoid-server; then
						printf '%s\n' "Warning: the in-container server TUI exited unsuccessfully; the installed deployment remains in place." >&2
					fi
				elif ! runuser --login --user "$operator_user" -- "$installed_tui"; then
					printf '%s\n' "Warning: the server TUI exited unsuccessfully; the installed deployment remains in place." >&2
				fi
			fi
		else
			printf '%s\n' "Server TUI is not available at the protected install path; run doctor --json for deployment status." >&2
		fi
	else
		if [[ -z "$operator_user" ]]; then
			printf '%s\n' "No non-root invoking operator was identified. Import a profile created by Manager File > Add Server, or run /opt/helicoid/bin/helicoid-server as an unprivileged operator." >&2
		else
			printf '%s\n' "Warning: runuser is unavailable; profile export and TUI launch were skipped." >&2
		fi
	fi
fi
