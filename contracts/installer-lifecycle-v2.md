# Installer lifecycle contract v2

Owner: `modules/server`. Status: Linux systemd and Docker Compose support
loopback development, a certificate-backed private LAN listener, and a
certificate-backed private-DNS listener. macOS supports read-only loopback
launchd preflight and plan review plus a prepared service entry that fails
closed. Other deployment modes and operations remain capability-gated.

A macOS build reports the `macos_launchd` deployment kind, the
`loopback_development` network scope, and only the `preflight` and `plan`
actions. It does not advertise `install`, `resume`, `cancel`, `inspect`, or
`remove`. The macOS plan is a read-only review artifact: it verifies the signed
package and fixed paths, but no apply/install, account creation, launchd plist
writing or loading, readiness, backup, or removal implementation exists.

This local JSON contract is shared by installers, the SSH TUI, and desktop
hosting adapters. It does not itself create an HTTP route. The installed
LAN/private-DNS listeners use TLS and the v2-only network router. V1 installer request and response types remain
available for existing callers. V2 adds explicit deployment configuration,
capability discovery, a configuration-bound review digest, a durable
operation ID, phase status, cancellation availability, and structured results.

## Capability discovery

`hs-server installer capabilities-v2` prints the v2 capability document and
does not read stdin or change the host. A Linux build reports
`linux_systemd` and `linux_compose`, `loopback_development`, `lan`, and
`private_dns`, plus the
`preflight`, `plan`, `install`, `resume`, `inspect`, and `remove` actions.
Compose preflight requires an available Docker Engine and Compose plugin, and
the reviewed plan binds their reported versions. `remove-v2` is backed by the
durable operation record; it removes only resources listed in the ownership journal.
V2 removal accepts only `/opt/helicoid/.installer` and refuses symlinked
installer state paths.
Loopback development binds to `127.0.0.1:8787`. LAN and private DNS modes keep
that local listener and add a TLS v2-only listener on the configured private
address (default port `8920`). Private DNS additionally requires a Manager
hostname and a certificate whose SAN covers that hostname. Plans print that
private DNS records, firewall rules, proxy routing, client CA trust, and
certificate renewal are operator-managed. Install plans create no firewall
rules. Public
routing, cancellation, online update, and deployment restore/cutover remain
unavailable. The Rust CLI provides encrypted database backup, verify, and
restore-to-new-file operations on Unix. A completed native systemd install
with systemd 250 or newer can enable a daily encrypted database backup
schedule; setup stores the backup passphrase as a systemd encrypted credential
using host-local keys, with TPM binding when available, and requires the
operator to save that passphrase separately. The TUI can disable the timer
while keeping its credential and archives. Compose uses a root-owned host
systemd service that checks the journaled project and signed container image,
then sends the credential to the running container on stdin. Automated
retention and deployment cutover are unavailable.
Compose plans use the signed offline image archive and journal project files,
TLS files, containers, network, and data volume under the install operation
identity. Removal uses a separate durable journal and keeps the shared
content-tagged image. Compose resume rechecks the reviewed runtime and may
restart only the operation-labeled service. These paths are source implemented;
a Docker image build and installed Linux recovery/removal cycle remain
unverified. Systemd and Compose installs accept custom data paths under
`/var/lib/helicoid/data` and backup paths under `/var/lib/helicoid/backups` or
`/var/backups/helicoid`.
`configuration-v2 --state-dir DIR` returns the durable operation configuration
or JSON `null` when the state directory has no v2 operation record. It is a
read-only query used by management clients to preserve configured storage paths
for status and removal.

The selected WebRTC public edge is a separate organization-owned deployment.
Legacy RustDesk ports 21115–21117 are not reserved, opened, or installed by the
current plan. Port 80/443 ownership and existing proxy configuration remain
outside this installer. Old journaled Helicoid firewall rules are still
recognized by exact port, protocol, and product comment during removal.

## Configuration and reviewed plan

The v2 configuration is part of the review digest:

```json
{
  "deployment_kind": "linux_systemd",
  "network": { "scope": "loopback_development", "authority_port": 8787 },
  "storage": {
    "data_directory": "/var/lib/helicoid/data",
    "backup_directory": "/var/lib/helicoid/backups",
    "preserve_data_on_remove": true
  }
}
```

For Linux LAN and private DNS modes, `network` also carries `bind_address` (an
RFC1918 IPv4 or unique-local IPv6 literal assigned to the host) and may carry
`client_hostname`, an ASCII DNS hostname used by Manager clients
(not an IP literal, all-numeric name, or `localhost`). The
listener binds only to `bind_address`; the hostname is used for the exported
Manager endpoint and manual DNS/TLS-SAN instructions. Private DNS requires
`client_hostname`; LAN may omit it and use the bind IP. Preflight checks that
the leaf certificate SAN covers the selected client hostname, or the bind IP
when no hostname is configured. This name check does not verify the issuer or
client trust, and the installer does not configure DNS. Loopback mode permits
neither field.

Example LAN network configuration:

```json
{
  "scope": "lan",
  "authority_port": 8920,
  "bind_address": "192.168.1.10",
  "client_hostname": "server.school.lan"
}
```

Example private-DNS network configuration (the hostname is required and must
resolve only within the deployment's private network):

```json
{
  "scope": "private_dns",
  "authority_port": 8920,
  "bind_address": "192.168.1.10",
  "client_hostname": "server.school.lan"
}
```

The data path must be normalized and stay at or below
`/var/lib/helicoid/data`. The backup path must stay at or below
`/var/lib/helicoid/backups` or `/var/backups/helicoid`. Paths with traversal,
control characters, symlink components, or overlapping data and backup trees
are refused. V2 renders the systemd unit from the reviewed data path; service-
owned data and backup directories use mode `0700`, while executable and
configuration directories remain root-owned. The legacy unit artifact is
still signature-verified as part of the package, but the V2 plan excludes it
and installs the configuration-bound unit. A fresh install refuses an
existing selected data or backup root because the plan creates it with service
ownership and private permissions; existing storage trees are never silently
adopted.

Unsupported deployment kinds, network scopes, ports, and storage paths are
refused before system changes. A v2 plan returns both the existing resource
`review_digest` and `reviewed_plan_digest`. The latter is SHA-256 over the v2
version, configuration, host preflight observation, canonical resource
digest, and digest of the validated public TLS certificate chain in LAN or
private-DNS mode.
It prevents applying a stale or edited review; it is not a signature
or authorization token. Apply still re-verifies the signed package and
reconstructs and compares the full canonical product resource plan before
executing any phase.

`preflight-v2` wraps the frozen v1 host observation in the v2 configuration.
It inspects the current local host; remote SSH preflight is not implemented in
this server process, so the command must run on the target Linux host. The
review digest binds that exact host observation along with the v2 configuration
and canonical resource digest. Its `tls_subject_name_verified` result is true
only when LAN or private-DNS preflight verified the leaf certificate SAN; it defaults false
when omitted by an older v2 backend. Apply repeats preflight and refuses changed
host state and revalidates the TLS certificate. In LAN and private-DNS modes, the bind address
must be a private address assigned to the host, TCP port 8920 is used by
default, and a matching certificate/key pair must be installed at
`/etc/ssl/helicoid/fullchain.pem` and `/etc/ssl/helicoid/private-key.pem` with
a root-owned mode-`0700` directory and root-owned mode-`0600` files. systemd
loads these as per-service credentials; Compose stages the key for its
unprivileged service account. Key contents are not included in process
arguments. For `linux_compose`, `docker_compose_runtime` reports Docker Engine
and Compose plugin availability and versions. Preflight, plan, apply, resume,
status, and removal recheck the deployment kind and Docker ownership labels;
unavailable or mismatched runtime prerequisites fail closed.
`preflight.ok` reports host prerequisites only. `plan-v2` separately verifies
the signed package and refuses a Compose plan unless the manifest includes all
required signed Compose artifacts, including its offline image archive.
The installer does not change firewall, DNS, proxy, or client trust
configuration. Resume instead
requires the existing v2 operation record and journal, and re-verifies the
package, canonical plan, TLS certificate name, and certificate-chain digest.

## macOS read-only plan and prepared service entry

macOS accepts only `macos_launchd`, `loopback_development`, an unprivileged
authority port, the Manager-owned data path
`/Library/Application Support/Helicoid/Data`, and a caller-selected normalized
backup directory outside the product, data, plist, and LaunchDaemons paths.
Backup overlap is refused component-wise under case-insensitive comparison,
matching the default macOS filesystem. The reviewed paths are fixed:

- executable: `/Library/Application Support/Helicoid/bin/hs-server`
- configuration: `/Library/Application Support/Helicoid/Configuration/service.json`
- TLS directory: `/Library/Application Support/Helicoid/TLS`
- launchd label and plist: `com.helicoid.server` and
  `/Library/LaunchDaemons/com.helicoid.server.plist`

Every reviewed path ancestor must be a real root-owned directory without unsafe
write access or an ALLOW ACL. Symlink ancestors are refused with a diagnostic;
the adapter does not resolve them. On a default macOS host `/tmp` and `/var` are
commonly symlinks to `/private/tmp` and `/private/var`, and those targets are
also group/world-writable. Use another reviewed, root-owned directory rather
than weakening the symlink or write-permission checks.

`plan-v2` runs only on the target Mac. It re-runs the read-only macOS
preflight, refuses a submitted preflight that no longer matches the stable
observed host facts, and rejects inconsistent `preflight.ok` /
`host_checks.ok` values. It derives the frozen `macos-arm64` or
`macos-x86_64` package target from the observed architecture. It then observes
the fixed `_helicoid` service account and group. A fresh-install review plan is
allowed only when both the account and group are absent. An absent account with
an existing `_helicoid` group is not a fresh identity and is refused. Every
existing account is refused unless an independent Helicoid-owned receipt can be
verified. No receipt verifier exists in this build, so every existing account is
refused. Unavailable Directory Services facts fail closed. Only after the
identity observation permits a fresh review does the command verify the exact
signed macOS package shape against the caller-supplied key.

The macOS plan contains the fixed directories, the verified executable, the
launchd unit, the loopback listener, the current schema migration, and explicit
`not_implemented` entries for apply/install, `_helicoid` account creation,
configuration/plist writing/loading, TLS material installation, readiness,
updates, backup, restore, and removal. It never claims the service is installed
or ready. `reviewed_plan_digest` binds the contract version, deployment
configuration, stable preflight projection, canonical plan digest, exact
signature-verified manifest bytes, caller-supplied verifying-key fingerprint,
frozen target, artifact path/hash/size, and the service-account/group decision.
`package_evidence` and `identity_evidence` expose those audit facts; the key is
caller-supplied and must be distributed and verified out of band. macOS
`apply-v2`, `resume-v2`, `status-v2`, `cancel-v2`, `remove-v2`, and the legacy
mutation commands remain unavailable.

`hs-server macos-service` is a separate prepared fixed launchd entry, not an
installer. It reads no options and uses only the fixed root-owned configuration
and fixed product paths. It requires equal nonzero real/effective IDs resolving
to `_helicoid`, a product-owned identity decision, owner-private data/TLS
material, a TLS leaf covering literal `127.0.0.1`, and a literal loopback bind.
The product-ownership seam has no accepting decision in this build, so startup
fails closed before configuration bytes, TLS material, the database, or the
listener are touched. This command does not create an account, write or load a
plist, install TLS/trust material, or establish readiness.

## Durable operations

V2 apply writes `operation-v2.json` under the state directory before invoking
the resource-changing phase journal. It contains a UUID operation ID, the
review digest, configuration, action, and creation timestamp. The existing
`journal.json` remains the write-ahead record for phases and product-owned
resources. `status-v2` reads both records without changing the host. A missing
operation sidecar in a legacy v1 install is reported as an absent ID; it is not
invented during a read.

Install, resume, and removal mutations acquire the same exclusive Linux
`flock` at `/run/lock/helicoid-installer.lock` before reading or changing
durable operation state. The lock file must remain a private root-owned regular
file in a protected root-owned `/run/lock` directory. A competing mutation is
refused while the current operation holds the lock; process exit releases it
automatically, so an interrupted operation can still be resumed from its
journal. The legacy v1 apply and remove entry points use the same lock.

The status response includes:

- deployment configuration and durable operation ID when available;
- reviewed-plan digest, current phase, and phase-to-state map;
- `cancellation_available` and `resume_available`;
- service-installed, bootstrap-ready, and server-ready-for-enrollment states;
- stable result code, summary, errors, and warnings.

Cancellation currently reports `false`. A failed or interrupted phase can be
resumed only with the same verified package, preflight, resource plan, and v2
review digest. A journal alone does not mean the service is healthy. For a
completed systemd install, the CLI probes only literal-loopback `127.0.0.1:8787`
and requires bounded, correctly framed `/health` and `/v2/deployment` JSON
responses. `bootstrap_ready` means the service advertises MFA and manager
enrollment, bootstrap is incomplete, and a valid deployment identity is
available. `server_ready_for_enrollment` means bootstrap is complete and
authorized operations are accepted. For Compose, status verifies the journaled
container identity and signed image, then reads that exact container's health
state and runs the hidden read-only `installer-readiness` probe inside it.
The probe distinguishes a service ready for initial bootstrap from a service
whose bootstrap is complete. The packaged healthcheck must also report healthy
before Compose status sets `server_ready_for_enrollment`. Any missing or
invalid probe leaves the corresponding readiness false.
These checks do not verify public reachability, client trust, endpoint
enrollment, or media/control. `Deployment Verified` is never inferred from
installation or a health probe. Removal records a configuration and
journal-bound digest before host changes, retains the ownership journal when
cleanup reports errors, and can be retried against that same journal. The
default configuration preserves data and backups; deleting them requires an explicit
`preserve_data_on_remove: false` value in the confirmed request. A completed
removal result remains available through `status-v2` after the install journal
is removed. That removal preference may be changed in the confirmed removal
request without changing the reviewed install paths; removal retries remain
bound to the first reviewed removal request.

## Commands

Commands exchange bounded JSON on stdin/stdout. The verifying key is public
material and may be passed as a CLI option; bootstrap, account, manager, and
recovery secrets are not accepted by this contract.

```text
hs-server installer capabilities-v2
hs-server installer preflight-v2
hs-server installer plan-v2 --package-dir DIR --verify-key HEX
hs-server installer apply-v2 --state-dir DIR
hs-server installer resume-v2 --state-dir DIR
hs-server installer status-v2 --state-dir DIR
hs-server installer configuration-v2 --state-dir DIR
hs-server installer remove-v2 --state-dir DIR
```

The v2 request schemas are Rust-owned in
`src/installer/lifecycle_v2.rs`. Do not hand-construct a plan or infer support
from a command's existence; discover capabilities and honor explicit refusal.
On macOS, only `capabilities-v2`, `preflight-v2`, and `plan-v2` are available;
every mutation command fails closed.
