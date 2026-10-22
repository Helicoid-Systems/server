# Helicoid Server TUI

This Go module builds the `helicoid-server` terminal application. It uses
Bubble Tea v2, Bubbles v2, Lip Gloss v2, and Charm Log v2. The module requires
Go 1.26 or newer at build time; release bundles are expected to ship the built
binary so the target server does not need a Go toolchain.

The Linux systemd resource plan expects `artifacts/helicoid-server` in the
signed package and installs it at `/opt/helicoid/bin/helicoid-server` beside
`hs-server`. The Linux Compose plan installs the signed offline image archive
and runs the same TUI binary inside that image. The installer verifies the
package manifest and artifact hashes before copying or loading artifacts; no
Go toolchain is needed on the target.
[`../scripts/build-linux-artifact-dir.sh`](../scripts/build-linux-artifact-dir.sh)
stages these files with Rust 1.99.0 and Go 1.27.1, then builds a
signed-package-ready Compose image archive from those same binaries with Docker
Buildx. To assemble an installable package, pass its output to
[`../scripts/package-linux-release.sh`](../scripts/package-linux-release.sh)
with a release version, owner-only Ed25519 PEM signing key, and new output
directory. The packager signs the manifest and verifies its signature before
publishing, then prints the raw public verification key. Distribute that key
separately through a trusted channel; the package cannot establish its own
trust anchor.

```sh
go build -o helicoid-server .
./helicoid-server
./helicoid-server status --json
./helicoid-server doctor --json
./helicoid-server logs recent
./helicoid-server audit recent
sudo ./helicoid-server installer install
./helicoid-server installer plan --package-dir ./release \
  --verify-key TRUSTED_KEY_HEX --output /tmp/review.json \
  --scope lan --bind-address 192.168.1.10 --port 8920 \
  --client-hostname server.school.lan \
  --data-dir /var/lib/helicoid/data/school-a \
  --backup-dir /var/backups/helicoid/school-a
./helicoid-server installer apply --request /tmp/review.json --confirm
./helicoid-server installer resume --request /tmp/review.json --confirm
sudo ./helicoid-server installer remove --confirm \
  --data-dir /var/lib/helicoid/data/school-a \
  --backup-dir /var/backups/helicoid/school-a
sudo ./helicoid-server installer database-path
```

For an explicitly private-DNS deployment, use `--scope private_dns` and supply
`--client-hostname`; planning rejects a missing hostname and prints the manual
DNS, trust, firewall, proxy, and certificate-renewal responsibilities.

The TUI reads installer state through the Rust `hs-server installer` v2
commands, first discovering the durable deployment configuration so status
and removal keep custom storage paths bound to the install record.
`helicoid-server doctor --json` uses those same saved paths for preflight
instead of silently checking the default directories. The TUI checks `/health`
at the fixed loopback address
`http://127.0.0.1:8787/health`. `HELICOID_SERVER_BACKEND` may select an
alternate local `hs-server` executable for packaging and development. Backend
requests are JSON on stdin, use a bounded response size and timeout, and never
invoke a shell.

The Diagnostics and support screen can export a local redacted support bundle
with `helicoid-server support export --output NEW_FILE` (or press `e` and enter
a new file path in the TUI). The schema-v2 JSON is capped at 64 KiB, created
with mode `0600`, and published without replacing an existing file. It contains
only allowlisted health flags, installer state enums and phase count, known
capabilities, runtime architecture, diagnostic pass/fail counts, and the
sanitized event metadata described below. It omits
hostnames, addresses, deployment IDs, paths, account/manager identities,
credentials, file names/content, database content, raw errors, and command
output. The systemd collector reads the local journal; the Compose collector
reads the journaled running container. Either can include at most 100
allowlisted event codes, severities, and UTC timestamps from the last 15
minutes. Raw messages and fields are always omitted. On Compose, the root-owned
host control service verifies the journaled project, container identity, and
signed image, filters messages on the host, and sends only sanitized event
metadata through its UID-checked socket; the container receives no Docker-daemon
socket. Press `l` in Diagnostics or run
`helicoid-server logs recent` to view the same sanitized event list. Compose
severity is `unspecified` because Docker's merged logs do not preserve
systemd's priority field. Security administrators can read retained audit
metadata with `helicoid-server audit recent [LIMIT]` or by pressing `A` in
Diagnostics. This opens a fresh MFA-backed session, fetches one bounded page
of 1–100 events, validates the metadata before display, and revokes the
temporary session after the read. Continue to older records with
`helicoid-server audit page BEFORE_UNIX BEFORE_ID [LIMIT]`, using the cursor
printed at the end of a page. Press `T` in Diagnostics or run
`helicoid-server audit retention` to review and optionally change the 1–3650 day
policy. A change requires a typed confirmation. Shortening it removes older
events from the active audit table; database free pages and backups may retain
prior bytes. The support bundle omits audit records and is not uploaded.

On the Docker Compose image, local administrative commands verify that the
root-owned server executable running `serve-dual` owns the expected loopback
socket before using it. The shell installer runs bootstrap and offers to open
the TUI through the exact `docker compose exec` command for the reviewed
operation. Lifecycle status, resume, and removal remain host-side operations
because they need the host installer journal and Docker daemon adapter. On a
native systemd install, the TUI verifies the
root-owned unit, service user, executable, and loopback listener.
The `installer database-path` helper prints the database path from that same
durable record; the shell installer uses it when creating the first bootstrap
token so custom data directories remain usable.

The implemented screens include an installer overview, read-only local
diagnostics, a Services and storage status view bound to the saved deployment
configuration and backend capabilities, first-administrator bootstrap, account
and manager administration, scoped access grants, operator MFA policy, factor
recovery, reviewed authority cutover actions, and explicitly confirmed removal
of journaled service resources. The
Services and storage view is read-only; service repair and storage recovery are
not advertised unless the lifecycle backend reports them as supported. From Installation, press `i`
to start the root-only guided installer. It checks the local host, verifies the
signed package, prints the exact reviewed resource plan, and requires the phrase
`install helicoid server` before apply. The root-owned `hs-server` lifecycle
backend must already be installed at a supported path. If apply is interrupted
or needs attention, the 0600 reviewed request remains in `/var/tmp` and the
screen prints the resume command. Press `R` in Installation to select that
request and resume the journaled operation; an interrupted removal can also be
retried there.

Recovery Cutover exposes the server-local `cutover status|drain|approve|cancel`
commands from the TUI. Press `l` to inspect state, `d` to drain the predecessor,
`a` to approve a restored deployment after independent fencing review, or `x`
to cancel a still-cancellable drain. Mutations retain their security-admin,
fresh-authentication, and exact-confirmation requirements. The screen states
the proof boundary: local review records operator attestation but cannot
coordinate two hosts, reconcile peer trust, or independently establish that an
unreachable predecessor was fenced.

Updates and rollback reports the backend's signed update, rollback, and
lifecycle backup/restore capabilities with the specific unavailable reason.
The current Linux backend supports signed package review for installation but
does not advertise in-place updates or binary rollback. Database snapshots and
restore-to-new-file remain separate from service update rollback.

The first-time installer defaults to LAN scope. Supply an RFC1918 IPv4 or
unique-local IPv6 address assigned to this host and, optionally, the DNS
hostname Manager clients will use. `private_dns` scope requires that hostname;
the reviewed plan reports that DNS, firewall, proxy, CA trust, and certificate
renewal remain operator-managed. It prints the matching DNS and TLS SAN
instructions and advises allowing TCP only from trusted Manager client
networks; it does not change those integrations. It then requires a matching
root-owned certificate chain/key at
`/etc/ssl/helicoid/fullchain.pem` and
`/etc/ssl/helicoid/private-key.pem`. Make the directory root-owned mode `0700`
and both files root-owned mode `0600`. The certificate SAN must cover the DNS
name or IP used by Manager clients, and those clients must trust its issuing CA.
Preflight validates the address, TLS pair, authority port, and that the leaf
certificate SAN covers the configured DNS name or bind IP. It does not verify
the issuing CA or client trust. The systemd adapter passes the private key
through per-service credentials. Compose stages the key as a mode-0400 file
owned by its unprivileged service account. Key contents are not placed in
process arguments.
The installer leaves DNS, firewall, proxy, and client trust configuration to
the operator. Use `--scope loopback_development` for an explicit local-only
installation. The Overview reports readiness from local runtime checks: the
systemd probes the loopback health and deployment-identity routes, and Compose
checks health plus a read-only readiness probe inside the verified journaled
container. Public integration remains pending, and deployment verification is
not recorded by the installer. These checks do not validate external
reachability, client trust, proxy behavior, or an authorized endpoint's media
and teardown path.

From Accounts, press `b` before bootstrap has completed.
Bootstrap verifies the protected systemd service or Compose server process and
loopback listener before sending credentials. It uses the
local v2 API, creates a private per-user Ed25519 manager identity scoped to the
deployment, enrolls mandatory TOTP MFA, and requires the operator to confirm
recovery codes were stored away from the server. The
`helicoid-server bootstrap` command provides the same flow outside the TUI;
`helicoid-server mfa confirm ENROLLMENT_ID` retries a pending enrollment.
Persistent v2 credential operations are rejected by the backend when the
database platform cannot verify its private-storage boundary.
The bootstrap token, password, TOTP code, TOTP secret, and recovery codes are
never placed in command arguments or application logs. The one-time secret
output requires a terminal.
After bootstrap, press `l` in Accounts or run `helicoid-server accounts list`
to perform challenge-based sign-in with the enrolled manager key and TOTP,
read the authorized account list, and revoke the short-lived session without
persisting its bearer token. Press `m` in Accounts or run
`helicoid-server managers list` to inspect management devices; approve a
pending device with `helicoid-server managers approve [MANAGER_ID]` or revoke a
device with `helicoid-server managers revoke [MANAGER_ID]`. Both changes ask
for an exact ID confirmation and a fresh MFA session, and the signed-in device
cannot revoke itself. Account, access, computer, and manager reads use the v2
API; manager approval and revocation use the current v2 fresh-MFA contract.
Revocation also invalidates that manager device's active server sessions.
Press `c` in Computers
or run `helicoid-server computers list` for the scoped, read-only computer
inventory; it includes IDs and group labels for group membership operations.
Run `helicoid-server computers enrollment-list` (or press `u` in Computers)
to inspect the bounded enrollment metadata inventory without observe access;
it omits endpoint public identities and pixels. The group membership workflow
also prints this inventory before asking for a computer ID. In
Computers, press `g` to list groups, `n` to create, `e` to rename, `m` to change
membership, and `d` to delete. These operations are also available as
`helicoid-server groups list|create|rename|member|delete`. They require
`manage_enrollment` and an approved key-bearing manager session. Mutations use
current revisions and operation-specific confirmation. Group membership only
labels inventory; it never creates or changes computer access assignments.
Run `helicoid-server enrollment invitations|invite|approve|revoke|revoke-invitation`
to create one-time endpoint setup codes, list or revoke unused codes, approve
proof-backed pending endpoints, and revoke enrolled endpoints. The TUI signs
in with a fresh MFA-backed session for each workflow. Invitation codes are
shown once, expire after 15 minutes, and are not written to logs or persistent
client state. Approval and revocation confirm the exact endpoint ID and use
the current enrollment epoch; revocation increments the epoch. Endpoint
capture admission and pixels remain unavailable.
In Accounts, press `n` to create an account with mandatory MFA,
`e` to change capabilities, or `s` to enable or disable an account. Provisioning
shows the new account's one-time TOTP secret and recovery codes only in the
interactive terminal, requires independent recovery storage before activation,
and never puts the initial password in arguments. Capability and lifecycle
updates use the account revision returned by the server and exact confirmation.
Press `i` to list access assignments, `g` to grant `operate`, `observe`, or
`install_maintain` to all or selected computers, and `p` to review or change the
operator MFA policy. Press `x` to revoke an assignment by ID. Grants,
revocations, and policy changes require fresh MFA and exact confirmation.
`observe` grants record authority only; this server build does not deliver
screen pixels. Press `f` in Accounts or run `helicoid-server mfa recover` to
re-enroll an account's TOTP factor using its password and one unused recovery
code. This flow creates no session and does not reset the password. Screen
observation and control remain unavailable from this TUI. In Files and requests,
press `f` or run `helicoid-server files jobs` to list jobs owned by the signed-in
account; the deployment advertises file jobs only when its authenticated v2
routes are mounted. Delivery job commands check that feature before
authentication and revoke their short-lived session after the operation.
The server exposes request and recipient-bound file-job commands on authenticated
v2 TLS routes and the loopback API.
Press `v` or run `helicoid-server files storage` to view deployment-wide logical
payload quota usage. It counts active delivery jobs and uploading or retained
Received request files; it does not report database pages, backups, or disk
free space. Press `r` to list owned requests, `n` to create a draft, `p` to publish a reviewed draft, `s` to
review submission metadata, `w` to save one received file, `x` to remove
retained submission content, or `d` to close an open request. The CLI equivalents
are `files requests list`, `create`, `publish [REQUEST_ID]`,
`close [REQUEST_ID]`, `submissions [REQUEST_ID]`, `download [REQUEST_ID]`, and
`delete-submission [REQUEST_ID]`. Creation limits targets to enrolled computers
in the signed-in account's visible inventory, validates file limits and
extensions, and saves a draft only after exact confirmation. Publishing and
closure show the revision-bound request details and require the exact request
ID. Submission review shows bounded file metadata and hashes for the request.
Download requires a received submission and file, confirms the exact file ID,
streams bounded chunks into a private temporary file, checks size and SHA-256,
and publishes it without overwriting an existing destination. Content removal
requires the exact submission ID, releases the files from the active quota, and
keeps submission and file metadata, including deletion time and manager account
ID. It is logical deletion: SQLite free pages
and prior database backups may still retain the bytes. Automated retention
policy remains unavailable; request commands do not grant arbitrary delivery
authority.
Press `c` or run `helicoid-server files cancel [JOB_ID]` to review and cancel an
owned uploading or queued job. Cancellation requires the exact job ID and the
server rejects it once endpoint delivery has been leased. The list shows the
server's delivery expiry in UTC; queued delivery expires within 24 hours after
upload verification and releases its stored payload.
The TUI removal screen requires the exact phrase `remove helicoid server` and
preserves data and backups by default. Run it with `sudo` so its backend uses
the root-owned product binary. The CLI offers optional data purge only with
both `--delete-data` and `--confirm-delete-data`. Endpoint capture admission,
computer screen observation and control, quotas, updates, and network setup
remain unavailable. The TUI can launch one-shot encrypted database backup,
verification, and restore-to-new-file commands in a protected terminal on
Unix, including from the Compose image when the command runs inside that
container and uses its mounted storage paths. On a completed Linux systemd or
Compose install with systemd 250 or newer, it can also enable a daily encrypted
database backup schedule. Compose uses a root-owned host timer that validates
the journaled project and signed image before sending the encrypted credential
to its running container over stdin. The in-container TUI reaches the host
through a dedicated systemd AF_UNIX socket that permits only fixed enable and
disable requests and verifies the peer UID/GID; it has no Docker socket mount.
Press `D` to stop and disable that timer;
its credential and existing archives are kept, and a backup already running
may finish. Peer trust migration and two-host cutover orchestration remain
unavailable; the server-local drain and review commands are described below.
The Rust `hs-server backup create|verify|restore|prune` commands provide
passphrase-encrypted SQLite snapshots on Unix. `hs-server backup list
--directory DIR` and the TUI's `l` key show private `.hsb` archive names,
encrypted sizes, and modification times without opening archive contents.
Restore writes a new private
database file, rotates the deployment and grant-signing identities, revokes
restored sessions and Manager approvals, disables restored accounts, and
quarantines endpoint enrollment before publication. The encrypted archive
contains the source database state; restore does not carry its old signer or
deployment identity into the recovered database. Start the recovered server
with `hs-server init`, then complete a fresh v2 Manager-key and MFA bootstrap.
Review the result with `helicoid-server recovery status`. A restored authority
begins in `awaiting_cutover`; after a fresh Manager/MFA bootstrap, use
`helicoid-server cutover approve` to record the predecessor-fencing procedure
and evidence reference for the exact old and replacement authority IDs. An
authorized security administrator can then run
`helicoid-server recovery release-quarantine` to acknowledge missing
post-backup history and release setup for new authority. Restored accounts
stay disabled, prior Managers stay revoked, and endpoints require fresh
enrollment. The predecessor can run `helicoid-server cutover drain` before
backup; cancellation is available only while that same predecessor is still
draining. These records are operator attestations: they do not prove a remote
host is powered off or update peer trust. Offline Managers/endpoints remain
unreconciled and must not be treated as migrated. TLS keys and host
configuration are outside the database backup. In the interactive Backup
and Restore page, `i` shows the reviewed quarantine summary and `Q` starts the
same explicit release prompts after bootstrap; `q` remains the quit key. Enabling the systemd
schedule stores its passphrase as an encrypted systemd credential using
host-local keys, with TPM binding when available; keep the passphrase
separately so archives remain recoverable after host loss. The schedule does
not prune archives automatically. In the TUI backup screen, press `P` to
retain a chosen number of the newest scheduled archives; the command requires
typing `prune backups` and removes only files matching the scheduled archive
name format. The local drain/review flow does not orchestrate a two-host
cutover or verify peer adoption. The Compose schedule
requires access to the local Docker daemon from the host's root-owned backup
service; the credential is not put in command arguments or container
environment variables.
The server has a loopback
development API and authenticated v2 TLS routes for request drafts, explicit
publication/closure, signed-user-bound endpoint uploads, and scoped manager
metadata/content retrieval, plus recipient-bound file-job history and
cancellation. General file-job routes are available through authenticated v2
TLS and loopback routers. The lifecycle backend reports
unsupported operations explicitly. If an install is interrupted, resume it
with the same reviewed request and package directory; the backend verifies the
journal, package, preflight, and plan digest again. Successful installation or
health checks do not mean the deployment is verified.

The Network and certificates screen reads local interface addresses and, on
Linux, resolver nameservers when opened or refreshed with `d`; it also shows
the saved Manager hostname when configured. For a saved LAN or private DNS endpoint, the same
refresh performs a bounded DNS lookup and a TLS handshake using the TUI
process's system trust store and the configured hostname. It sends no credentials and
only connects to resolved private addresses, with a cap of eight attempted
addresses. It reports those addresses, negotiated TLS version, and the verified
leaf certificate fingerprint. These observations come from the TUI process's
network namespace. When the TUI runs in the Compose container, they describe
the container's interfaces and resolver, not the host's. The endpoint probe
also originates in that namespace. It does not inspect firewall rules or public routing.
The screen also shows the certificate-chain SHA-256 and SAN-verification result
from the last local installer preflight only when that preflight's saved
network configuration still matches; it does not reread certificate files.
Backends that omit the SAN result are reported as unverified. Private DNS
records and certificate lifecycle remain operator-managed.

The root-level Linux entry point is `../scripts/install-linux.sh`. It uses Gum
when available and otherwise prompts in a plain terminal. It requires root,
an extracted signed Linux package, and the trusted release verification key.
On a clean host, it first checks the manifest signature and the hashes and
ELF architecture of the three fixed package artifacts with OpenSSL and Python,
then stages only `helicoid-server` and `hs-server` under the protected product
directory. The Rust lifecycle backend performs its full package verification
again before installation planning or apply. Existing helper binaries must
already be root-owned and protected. The installer supports reviewed Linux
systemd and Docker Compose configurations. After a reviewed interactive
systemd install, it can create the one-time bootstrap token as the `hs-server`
service account and launch the MFA bootstrap as the invoking unprivileged sudo
user. For Compose, it creates the token and starts bootstrap inside the
unprivileged container.
Non-interactive installs leave bootstrap pending and print the two commands to
continue it manually. `hs-server init` rotates any earlier unused token, and
refuses to issue another once bootstrap has completed. LAN TLS is configured
by default when a private host address and certificate pair are supplied;
public integration and deployment verification remain pending. The
clean-host bootstrap is source implemented but has not yet been exercised
against a signed release artifact.

After a successful interactive install launched through `sudo`, the shell
installer offers to write a schema-v1 public Manager connection profile as the
invoking operator, with mode `0600` and no-overwrite behavior. Its endpoint
uses the configured Manager DNS hostname when present or the private bind
address otherwise. It contains only the endpoint and profile metadata;
importing it does not establish the trusted deployment identity. The installer
then offers to launch the installed server TUI. Systemd launches it as that
same unprivileged operator; Compose launches it inside the unprivileged
container so the local-only API remains private. Non-interactive runs make
neither offer.

Interactive runs can prompt for the offline package directory and trusted
public key. For configuration-driven automation, create a root-owned 0600 JSON
file with schema version 1. It contains the extracted package directory, the
public verification key received through a trusted channel, deployment kind,
network settings, and storage paths. The parser rejects unknown or duplicate
fields, symbolic links, control characters, invalid ports, and non-absolute
paths. It never evaluates configuration text as shell code.

```json
{
  "schema_version": 1,
  "package_dir": "/srv/releases/helicoid",
  "verify_key": "REPLACE_WITH_64_HEX_CHARACTERS_FROM_A_TRUSTED_CHANNEL",
  "deployment_kind": "linux_systemd",
  "network": {
    "scope": "lan",
    "bind_address": "192.168.1.10",
    "client_hostname": "server.school.lan",
    "authority_port": 8920
  },
  "storage": {
    "data_directory": "/var/lib/helicoid/data/school-a",
    "backup_directory": "/var/backups/helicoid/school-a"
  }
}
```

Run without `--confirm` to verify the package and host, write the exact
reviewed request under `/var/tmp`, and print its path. Inspect that request,
then pass it back with `--confirm` to apply. Supplying `--confirm` with the
configuration performs those steps in one automation run after the signed
package, host, TLS, and reviewed-plan checks pass.

```sh
sudo install -d -o root -g root -m 0700 /etc/helicoid
sudo install -o root -g root -m 0600 install.json /etc/helicoid/install.json
sudo ../scripts/install-linux.sh --non-interactive \
  --config /etc/helicoid/install.json
sudo ../scripts/install-linux.sh --non-interactive \
  --request /var/tmp/helicoid-installer.OPAQUE/reviewed-plan.json --confirm
```

Replace `OPAQUE` with the review directory printed by the first run. The
configuration mode is limited to the local Linux host; it does not connect to
or configure a remote SSH server.

For an already generated request, pass that exact root-owned 0600 file to the
shell installer:

The interactive installer asks for `linux_systemd` or `linux_compose`. The
automation `installer plan` command accepts the same choice with
`--deployment-kind`. Compose preflight also prints the Docker runtime and
lifecycle capability details. The backend journals signed image loading,
project files, TLS staging, container start and removal. Compose updates and
host cutover orchestration remain unavailable; server-local drain/review plus
manual encrypted database backup and restore-to-new-file commands are
available inside the container.
Scheduled backups use a host systemd timer and require systemd 250 or newer.

```sh
sudo helicoid-server installer plan --package-dir ./release \
  --verify-key TRUSTED_KEY_HEX --output /var/tmp/helicoid-reviewed.json \
  --scope lan --bind-address 192.168.1.10 --client-hostname server.school.lan --port 8920
sudo ../scripts/install-linux.sh --non-interactive \
  --request /var/tmp/helicoid-reviewed.json --confirm
```

Without `--confirm`, the script prints the supplied plan and makes no changes.
For an interrupted operation, pass the same request with `--resume`; this uses
the existing journal instead of creating a new plan:

```sh
sudo ../scripts/install-linux.sh --non-interactive --resume \
  --request /var/tmp/helicoid-reviewed.json --confirm
```
