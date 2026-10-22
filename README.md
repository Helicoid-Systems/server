# Helicoid Systems — coordination server foundation

Current conditional-MFA prerequisite: [CI38932191897](https://github.com/Helicoid-Systems/server/actions/runs/38932191897)
passes302 Linux and310 Windows tests plus format/strict Clippy, release and both
PowerShell fixtures at `89a35c4fd920d576fb724e8a620222463b4c011b`. Coordinator309
Mac tests and real Rust HTTPS native-client interoperability (7 Swift/6 C#) pass.
[Unsigned Windows server download](https://github.com/Helicoid-Systems/server/actions/runs/38932191897/artifacts/12059988937)
is digest/PE/launcher verified. Mandatory administrator MFA and conditional
operator MFA remain enforced; installed/public hosting and complete release
checkpoints remain Not Verified. See BUILD-REPORT for exact limits.

The coordinator's309 macOS tests include independent regressions proving that
future MFA assurance, legacy login and historical password-only sessions cannot
bypass mandatory MFA or approved manager-key proof. Operator MFA is optional by
default; administrator and already-enrolled factors remain mandatory. Schema3
requires explicit migration; no production database was migrated. The initial
Windows fixture failure and14 October billing interruption are historical; the
corrected fixture reaches the mandatory-MFA denial for the correct Unicode
password and credentials denial for a wrong password, without minting a session.

`hs-server` is an independently buildable Rust service owned by `modules/server`.
It provides the first durable slice of the Helicoid Systems coordination plane:
local accounts, single-use bootstrap, manager enrollment distinct from operator
auth, per-computer access scopes, bounded inventory reads, and explicit
security-state-unavailable behavior.

| Identity | Value |
| --- | --- |
| Product | **Helicoid** (Helicoid Systems) |
| Organization | Helicoid-Systems |
| Apps | **Helicoid Manager** (operator console), **Helicoid Computer** (managed endpoint) |

Repository: https://github.com/Helicoid-Systems/server. Durable release identifiers remain pending.

Earlier accepted prerequisite evidence: bounded MFA factor recovery, product/release/target-bound package verification and literal-loopback HTTPS passed complete [CI38441619920](https://github.com/Helicoid-Systems/server/actions/runs/38441619920) at exact code `c30c9e2b96ce6b7bf0b41f4ef59f67b8ec79149d`: **270 Linux / 278 Windows tests**, formatting, strict Clippy, release and both PowerShell launchers. Five new regressions prove cancellation preserves the established factor, confirmation installs the replacement, real device-key login works, private-store restart retains those boundaries, and storage failure after transaction writes rolls back while blocking new authority. The coordinator independently passes **277 Mac tests**, reproduces both baseline defects and verifies the exact production fix with the same regressions. [Download the development server bundle](https://github.com/Helicoid-Systems/server/actions/runs/38441619920/artifacts/11837145033); its digest, actual PE x64 executable and companion scripts are independently inspected. All26 package tests and prior TLS/private-store guards stay green. Metadata verification supports four trusted targets; installation commands remain Linux-only and Windows/macOS service setup remains unavailable. Public authentication/media/control, installed acceptance, delegation, authority recovery/cutover and signing remain gated. Configurable operator MFA is verified in the current prerequisite above. Owned-child kill/reap is not installed service-stop acceptance.

Existing SQLite store files accept only currentUser/SYSTEM/Administrators ownership together with the strict held DACL/shape/link and protected-parent boundary. New objects, recovery/key reads and product directories remain current-user owned; foreign and TrustedInstaller store owners remain refused. The launcher chooses a missing path and lets the server create its protected folder. The private-store prerequisite checkpoint did not establish public authentication, network-facing v2 acceptance, installed services, recovery cutover, or signing. The current worktree contains additional v2 TLS, deployment-authority, cutover, and Linux installer source described below; those source paths do not establish deployed hosting or worker/admission acceptance. Historical failures and bounded acceptance evidence are in [BUILD-REPORT.md](BUILD-REPORT.md).

## What this foundation is

| Area | Status in this build |
| --- | --- |
| Local account bootstrap + login | Implemented (Argon2id passwords) |
| Opaque bearer sessions | Implemented (SHA-256 at rest, never logged) |
| Manager enrollment | Implemented as **loopback development identity fixtures** |
| D20 deny-before-approval | Implemented (pending manager cannot bind/login) |
| Per-computer access scopes | Implemented (explicit IDs or scope-all) |
| Bounded inventory reads | Implemented (hard cap 100) |
| Schema init / migration | Storage schema 20; explicit init or migration with consistent backup; never migrates on open |
| Flat computer groups | Revision-checked v2 group APIs; membership labels stay separate from per-computer access grants |
| Security State Unavailable | Durable latch; restart never resets it; no auto-recovery |
| Required read/commit failures | Latch + `503 security_state_unavailable` (not bare 500) |
| v2 administrator MFA | TOTP enrollment, Ed25519 device proof and atomic challenge completion are available on v2 routes. Operator MFA is configurable (optional default). v2 completion returns challenge-proven `manager_public_key`. Native private-store tests pass on Unix and Windows; public deployment acceptance remains gated |
| v2 recovery credentials | Bounded, single-use factor recovery only; cannot issue normal sessions. Cancel of a pending recovery never deactivates an established active factor; confirmation installs the verified replacement secret |
| Configurable operator MFA | **Implemented on v2 routes**: deployment policy `optional` (default) / `required`; administrator MFA stays mandatory; active factors stay mandatory under `optional`. Scoped delegation remains unavailable |
| Security audit metadata | Bounded schema-v20 event store, 30-day configurable retention, MFA-protected event/retention APIs, and same-transaction records for bootstrap, self-service MFA enrollment/activation, endpoint enrollment, access, account, Manager, group, observation-grant, interaction-reservation, file-delivery, file-request, content-deletion, recovery, cutover, and MFA-policy changes. Denied-attempt coverage, remaining action paths, and end-to-end audit acceptance remain pending |
| Recipient-bound file jobs | Authenticated v2 routes are available on loopback and TLS network listeners; each target is bound to a fresh signed endpoint session and bounded storage lease. Runtime and release acceptance remain pending |
| Authority recovery and cutover | Storage schema 20 persists Active/Draining/Awaiting Cutover state. Drain requires no active interactions, observation grants, or file jobs; it revokes endpoint sessions and pauses normal authorization. A fresh-MFA security-admin review of predecessor-fencing evidence is required before recovery quarantine release. Evidence is operator-attested; peer trust adoption, old-host runtime fencing proof, and two-host acceptance remain unavailable |
| Remote control / screen observation | One-use grants and bounded signaling relay are source-present. Qt Manager and Windows Computer sources now wire certificate attestation, native peer negotiation, proof redemption, primary-display capture, frame display, and fresh-grant renewal. Native observation capabilities remain disabled; the Windows DLL is absent and no installed pixel/denial/teardown evidence exists (B02/B03/RD03 acceptance pending) |
| Bind policy | Plain HTTP is literal-loopback only. HTTPS defaults to loopback; nonloopback binds require `--allow-network` |
| HTTPS transport | `serve-tls` or `serve-dual`, maintained rustls TLS1.2/1.3 and private held-descriptor reads on Unix and Windows; network binds use v2 routes only |
| Login throttle | v1 development map remains bounded/in-memory; v2 challenge throttles are durable and capacity-capped |
| Linux installer candidate | Signed-manifest verification, ownership-bounded journal and native adapter hardening; installed Linux acceptance still required |
| Installer package targets | Typed trusted target (`linux-x86_64`, `windows-x86_64`, `macos-arm64`, `macos-x86_64`), exact `hs-server` product binding, strict release `major.minor.patch`, nonempty bounded artifact list, and portable artifact paths in [contracts/installer-package-targets-v1.md](contracts/installer-package-targets-v1.md); verification only — Windows/macOS installation remains unavailable |
| Windows/macOS host installation | Unavailable in this server build |
| Windows persistent v2 MFA | **Verified prerequisite**: real native bootstrap/MFA/reopen, strict current-user directories/material, trusted SQLite file owners and private child inheritance. Installed service identity and security review remain Not Verified |

Legacy v1 Manager `public_identity` values are **not** cryptographic production identities.
They are development fixtures for local/loopback integration until B03 freezes
signed endpoint/manager identity formats. Do not invent grant formats.

MFA-enrolled accounts refuse legacy password-only login through the service,
HTTP route and CLI. The final session transaction rechecks the shared MFA
requirement (administrator OR operator policy `required` OR any persisted MFA
material), account state, the verified password hash and manager approval —
so required-policy operators and administrators cannot bypass MFA via v1.
Legacy login remains an explicitly loopback-only development path for
non-administrator accounts without an MFA requirement. A v1 display label
never binds a key-bearing manager; cryptographic device binding requires a
v2 Ed25519 challenge proof. The Windows private store requires a protected current-user product directory, trusted child inheritance and verified trusted SQLite file ownership before explicit migration;
native refusal tests retain both the original database bytes and no-output checks.

The [v2 development contract](contracts/http-v2.md) describes deployment-bound
Ed25519 challenges, administrator enrollment, transaction boundaries and recovery
limits. Literal-loopback HTTPS transport is implemented on Unix and Windows as a
loopback prerequisite. `serve-tls --allow-network --bind <address>` now enables
an explicit HTTPS network listener with the v2-only router; it omits the v1
development API. Certificate trust distribution, public routing, firewall
integration, installed services, and deployment verification remain pending.
The v1 HTTP wire contract remains version 1; health separately reports storage
schema 15. Earlier TLS acceptance at `1d99669` passed **242 Mac, 235 Linux and
243 Windows tests** in CI 38259032769 and coordinator checks. That result, and
the `f01019f`/`ccaf29a` artifacts which refused Windows TLS, are historical
evidence. Current complete acceptance is recorded above and in
BUILD-REPORT.md.

Platform-split of `tests/installer_adapter.rs` (29 total): **19 portable**
(listener/parser/systemctl decode, read bounds, injected query faults) run on
every OS including Windows; **10 Unix-only** `cfg(unix)` real-filesystem
regressions cover the descriptor-relative atomic writer (`write_file_atomic`).
There is no Windows native service installer and no Windows atomic writer —
host installation on Windows/macOS remains unavailable.

Historical native private-store/MFA/CLI and loopback HTTPS acceptance at `1d99669`:

| Platform | Verified total | Notes |
| --- | --- | --- |
| macOS | **242** | Coordinator full tests, formatting, strict Clippy and build |
| Linux | **235** | Native full tests, formatting and strict Clippy |
| Windows Server 2025 CI | **243** | Native full tests including24 TLS tests, strict Clippy, release and actual PowerShell5.1/7 launchers; installed Windows11 runtime and service-stop remain Not Verified |

`hs-server --data /private-product-directory/hs-server.db serve-tls --tls-cert /private-product-directory/server.crt --tls-key /private-product-directory/server.key` requires operator-supplied certificate/key files. Each file is bounded at64KiB, owner-only, regular, singly linked and read through its verified held descriptor. It refuses malformed/mismatched material before opening data. Public binds refuse before reading material or creating data on every platform. Bootstrap remains local-only or inside verified SSH tunnels. These checks do not establish installation or enrollment readiness.

In-memory (nonpersistent) auth v2 tests run on **every** platform including
Windows and exercise real TOTP/Ed25519/recovery crypto. They are **not** a
production confidentiality claim and **not** a persistent-MFA support claim.

## Build and test

```sh
cd modules/server
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
```

Independent GitHub Actions workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
runs the three Linux checks for this crate as its own repository root, plus a
native `windows-latest` job (`cargo test --locked`, `cargo build --locked --release`)
that uploads a disposable development download bundle (`hs-server.exe`,
`scripts/start-development.cmd`, `scripts/start-development.ps1`, `scripts/windows-tester.md`).

## Operate (development)

```sh
# 1. Create schema and print a single-use bootstrap token (shown once, stored hashed).
hs-server --data ./hs-server.db init

# 2. Create the first administrator. Prefer stdin for the password.
printf '%s' 'your-long-password' | hs-server --data ./hs-server.db bootstrap \
  --token '<token-from-init>' --username admin --password-stdin \
  --manager-public-identity dev-manager-key --manager-friendly-name 'Lab manager'

# 3. Serve the HTTP API (loopback only — non-loopback binds are refused).
hs-server --data ./hs-server.db serve --bind 127.0.0.1:8787
```

On Unix, create and verify encrypted SQLite snapshots with a passphrase read
from a no-echo terminal prompt (two matching lines for creation, one for
verification; piped input follows the same rule):

```sh
hs-server --data /var/lib/helicoid/data/hs-server.db backup create \
  --output /var/backups/helicoid/server-2026-10-22.hsb --passphrase-stdin
hs-server backup verify --input /var/backups/helicoid/server-2026-10-22.hsb \
  --passphrase-stdin
hs-server backup restore --input /var/backups/helicoid/server-2026-10-22.hsb \
  --output /var/lib/helicoid/recovery/restored.db --passphrase-stdin
```

The format uses Argon2id and AES-256-GCM with authenticated 1 MiB records. The
passphrase must contain at least 16 bytes. Output is owner-private and created
without replacing an existing path. Verification decrypts to a private
temporary database, checks SQLite integrity and foreign keys, and requires the
current schema version. Restore performs those checks before publishing a new
private database file and refuses to replace an existing path. It revokes
restored manager and endpoint sessions, consumes pending authentication and
MFA challenges, invalidates unused bootstrap/enrollment invitations, and fails
active interaction claims while advancing their per-computer revisions. It
also rotates the deployment identity, disables and marks restored accounts as
quarantined, revokes restored Manager approvals, and moves endpoints to
quarantined enrollment with a new epoch.
These commands cover the SQLite database only; the encrypted archive includes
database-resident state, including the deployment grant-signing seed. Restore
rotates that seed and requires a fresh v2 bootstrap with a new Manager device
proof and MFA confirmation. The security administrator must then review
`helicoid-server recovery status` and explicitly release the loopback recovery
quarantine; restored accounts and endpoints remain individually blocked.
Restore does not back up TLS keys, packages, proxy settings, external signing
keys, or other host configuration. It publishes a separate database file; it
does not switch a running service or perform two-host cutover.

For a managed network, configure a trusted certificate and private key, then
explicitly enable the HTTPS listener. The address may be a specific LAN
interface or a wildcard when the operator intends to bind all interfaces:

```sh
hs-server --data ./hs-server.db serve-tls \
  --bind 192.168.1.10:8920 \
  --tls-cert /etc/helicoid/tls/fullchain.pem \
  --tls-key /etc/helicoid/tls/private-key.pem \
  --allow-network
```

Nonloopback binds are refused without `--allow-network`. The listener is TLS
only and mounts the v2 router; `/v1/*` development routes are not present.
This enables endpoint invitation redemption and v2 Manager API access, but
does not configure DNS, a public reverse proxy, firewall rules, or an installed
deployment.

`hs-server healthcheck --address 127.0.0.1:8787` performs a bounded request to
the literal-loopback `/health` route without opening the database. It exits
successfully only when bootstrap is complete and the durable authorization
state accepts work; network addresses and oversized or malformed responses
fail closed. Docker Compose uses this command as its container healthcheck.

To keep the server TUI and local recovery surfaces available while remote
Managers use TLS, run both listeners from one process:

```sh
hs-server --data /var/lib/helicoid/data/server.db serve-dual \
  --local-bind 127.0.0.1:8787 \
  --network-bind 0.0.0.0:8920 \
  --tls-cert /etc/helicoid/tls/fullchain.pem \
  --tls-key /etc/helicoid/tls/private-key.pem \
  --allow-network
```

The local API is literal-loopback HTTP for the local CLI/TUI. The separate
network listener requires real TLS and exposes v2 routes; bootstrap and factor
recovery stay local. The listeners must use different ports. This command does
not configure a firewall, certificate trust, DNS, or a proxy.

`hs-server check-login --username admin --password-stdin` runs the real
credential path without starting HTTP. Mandatory administrator MFA refuses
password-only sessions, so a correct password exits nonzero with the safe
MFA-required denial (password verified first), and a wrong password exits
nonzero with `invalid credentials` — never a session. On accounts without an
MFA requirement, success prints `login ok` and the ephemeral session is
discarded immediately.

Never log or print `password`, `token`, `bootstrap_token`, or `Authorization`.

## Windows 11 x64 development download

CI artifact `hs-server-windows-x64-dev` (from the `windows-latest` job) contains:

| File | Purpose |
| --- | --- |
| `hs-server.exe` | Release build of this server |
| [`scripts/start-development.cmd`](scripts/start-development.cmd) | Double-click launcher that retains errors |
| [`scripts/start-development.ps1`](scripts/start-development.ps1) | Disposable literal-loopback fixture launcher |
| [`scripts/windows-tester.md`](scripts/windows-tester.md) | Tester instructions and manual CLI steps |

`start-development.ps1` selects a fresh unique disposable database path
(refuses any existing path or DB) and lets `hs-server init` create the private
store directory (current-user owned, protected DACL; the launcher never
creates that folder with `New-Item` and never re-ACLs one), prompts for a
password of at least 12 characters (hidden), passes that password to
`hs-server` only via stdin, captures the init bootstrap token in memory only,
approves exactly `dev-manager-key` at bootstrap, and serves on
`http://127.0.0.1:8787` in the foreground until Ctrl+C.

It does **not** install a service, elevate, bypass execution policy, open
firewall ports, bind non-loopback, auto-create access scopes, or delete the
disposable directory. PowerShell cannot guarantee managed-string zeroization;
see `windows-tester.md` for the honest residual-risk table.

Connect **Helicoid Manager** in development-server mode:

```powershell
.\Helicoid.Manager.exe --development-server --development-manager-identity dev-manager-key
# or: .\Helicoid.Manager.exe --development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key
```

Fixture values: address `http://127.0.0.1:8787`, manager identity `dev-manager-key`
(loopback development fixture, not a production cryptographic identity),
username `admin` (password is whatever you entered at the prompt).

### Windows private-store candidate and accepted legacy baseline

This candidate verifies held-handle owner/DACL boundaries before opening or
creating persistent credentials. Existing objects are never silently re-ACL'd;
unknown principals, unsafe namespace rights, aliases/reparse points and public
SQLite sidecars are refused. Native Windows CI acceptance of private-store and loopback TLS prerequisites is recorded above. The v2-only network listener is implemented; installed hosting, public routing, and deployment verification remain pending.

The accepted downloaded baseline `3a20aa0` opens a **legacy loopback development** store
(`StoreCapability::PersistentUnverified`):

- **Available:** v1 `init` / `bootstrap` / `check-login` / `serve` on literal
  loopback (the PowerShell fixture path above).
- **Denied:** NEW persisted v2 MFA credentials (`bootstrap-v2`, factor
  recovery, MFA enrollment confirm) — refused before the transaction and
  before any secret is printed. Recovery-file private creation is also denied.
- **Refused at open:** a database that already contains persisted MFA rows
  (`account_mfa`, `recovery_codes`, `mfa_enrollments`). There is no implicit
  migration and no exposure of existing v2 authority through legacy paths.
- **Privacy boundary:** the on-disk store is **not** claimed private on
  Windows (no native-verified owner/SYSTEM/administrators DACL). Treat the
  disposable development directory as readable by other local principals
  that can traverse to it. Do not place production credentials there.
- **Production hosting on Windows is unavailable.** Do not install as a
  service, do not expose beyond loopback, and do not claim MFA or
  confidential-storage support. Enabling Windows persistent v2 later
  requires an exact allowlist DACL verification on the held HANDLE plus
  native prove-success tests — never a SID blacklist.

In-memory nonpersistent stores still exercise real TOTP/Ed25519/recovery
crypto on Windows. That is a **narrower** proof than persistent MFA support.

## API contract

Native clients integrate from **[contracts/http-v1.md](contracts/http-v1.md)**.
Its version-1 wire shape remains unchanged. The v2 manager routes add
device-bound sessions, bootstrap, account lifecycle, access, MFA recovery, and
MFA policy operations in [contracts/http-v2.md](contracts/http-v2.md).

## Linux server TUI

The `tui/` Go module builds the current `helicoid-server` terminal client. It
provides `status --json`, `doctor --json`, an installation overview,
read-only local diagnostics, and confirmed removal backed by the Rust
lifecycle-v2 commands and the loopback `/health` endpoint. Its `installer plan`
command writes a private,
reviewable plan request, `installer apply --confirm` sends that request
through the Rust journaled systemd installer, and `installer resume --confirm`
continues the same journal with its original request. `installer remove
--confirm` removes journaled service resources and preserves data/backups by
default; data purge requires both `--delete-data` and `--confirm-delete-data`.
`installer plan` accepts `--data-dir` and `--backup-dir` within the reviewed
Helicoid-owned roots. `installer remove` reads those paths from the durable
installation record so removal remains bound to the install. The interactive
shell installer prompts for both directories and bootstraps the database at
the reviewed data path. The
[`scripts/build-linux-artifact-dir.sh`](scripts/build-linux-artifact-dir.sh)
stages the Linux x86_64 server, TUI, and systemd unit using the pinned Rust
1.99.0 and Go 1.27.1 toolchains. The release packager
[`scripts/package-linux-release.sh`](scripts/package-linux-release.sh) copies
those artifacts into a bounded package, derives the compatibility floors from
the source constants, hashes the copied files, and signs `manifest.json` with
an owner-only Ed25519 PEM key. The packager prints the raw public verification
key for distribution through a separate trusted channel; a key shipped beside
its package does not establish trust.
The optional Gum entry point is
[`scripts/install-linux.sh`](scripts/install-linux.sh); it also has a plain
terminal fallback. Build instructions and the exact feature ceiling are in
[`tui/README.md`](tui/README.md). The local TUI now includes account and
manager administration, scoped access grants, enrollment and group workflows,
and file-request draft, review, publication, closure, and verified download
controls through authenticated v2 request routes, including authorized removal
of retained submission content with metadata preserved. Recipient-bound file-job
routes are mounted on both the TLS and loopback routers, and `/health` advertises
`file_jobs=true`; the Qt Manager can preflight recipients, create jobs, and upload
bounded chunks, while the TUI lists and cancels owned jobs. Endpoint clients and
the Manager source still need platform builds and D29/V48 runtime acceptance.

The TUI also exports a bounded schema-v2 support bundle from allowlisted local
health, lifecycle, and recent service-event metadata. It is created private and
without overwriting. Up to 100 allowlisted event codes, severities, and UTC
timestamps may be included; raw messages and journal fields are discarded.
Paths, identities, credentials, and database content are excluded. Audit-event
export remains unavailable.

The TUI Network screen also reports bounded local interface addresses and Linux
resolver nameservers; it does not configure LAN/TLS or probe remote reachability.
The Rust CLI now creates, verifies, and restores encrypted SQLite snapshots.
After a native Linux systemd or Compose install, the TUI can enable or disable a
daily encrypted database backup schedule using a passphrase stored as a systemd
encrypted credential. Compose runs a root-owned host service that validates the
installed container and streams the credential to it over stdin. The Compose
TUI sends enable/disable requests through a dedicated AF_UNIX socket; the host
checks UID/GID and accepts no command or path from the container. The container
does not receive the Docker socket. The passphrase must also be saved
independently to recover archives after host loss. Automated retention,
host-wide recovery and restore cutover,
update, and remote SSH administration screens remain unavailable, so this is
still not the complete server administration TUI in the product plan. The
shell installer supports Linux systemd and Docker Compose, requires a prebuilt
signed package and trusted public verification key, and supports interactive
Gum/plain-terminal setup plus an explicit non-interactive plan/apply mode using
a pre-reviewed request file.
The interactive path can bootstrap a
clean host by verifying the signed manifest and fixed artifact hashes with
OpenSSL and Python before staging the two installer executables under
`/opt/helicoid/bin`; the Rust backend repeats full package verification before
planning or applying host changes. The signed plan also installs the verified
`helicoid-server` artifact there for later administration. Non-interactive
plan/apply still requires a preinstalled root-owned TUI and lifecycle backend.
The host-changing backend runs as root and supports local systemd and Docker
Compose deployments. An interactive sudo install can optionally create a single-use
bootstrap token as the `hs-server` service account and run the existing MFA
bootstrap as the invoking unprivileged user. Non-interactive installs leave
bootstrap pending. LAN/public networking and deployment verification remain
unavailable. The clean-host bootstrap source has not been exercised against a
signed release artifact or host.

## Security notes for this foundation

- Passwords: Argon2id via the maintained `argon2` crate (PHC strings).
- Session tokens: 32-byte OS RNG values; only SHA-256 digests are stored.
- Owner fields (capabilities, scopes) come from the session, never from request bodies.
- Administration capability does not imply inventory, observe, or operate rights.
- Single-use bootstrap tokens are hashed at rest and consumed transactionally;
  issuing a replacement invalidates earlier unused tokens, and issuance stops
  after the first administrator is created.
- Bootstrap tokens are opaque URL-safe base64 and may begin with `-`; both
  `bootstrap` and `bootstrap-v2` accept `--token VALUE` unchanged (Clap
  `allow_hyphen_values` on that option only). Invalid tokens still fail closed.
- Durable Security State Unavailable latch: hydrated at service start with
  exact integer `0`/`1` (invalid values fail closed); required storage **and**
  lock-poison/internal failures latch and deny new authority; memory latch stays
  authoritative if the durable note cannot be written; **never auto-recovers**.
- Health is fail-closed: `accepting_authorized_operations` is true only after
  bootstrap completes and trust state is healthy. Missing deployment row latches.
- Plain HTTP non-loopback binds are refused. Nonloopback HTTPS binds require
  `--allow-network` and serve only the network v2 routes. Bootstrap and MFA
  recovery stay on literal-loopback APIs or the local CLI.
- Login throttle map is bounded (dev budget 1024 keys, idle prune 15m); unknown
  keys fail closed when saturated. This is not production credential/MFA policy.
- Request types that carry secrets do not implement `Debug`.
- No certificate bypass or invented signed grants in-process.

## Out of scope here

Broader plan work (complete file jobs, scheduled retention, production MFA
policy, recovery/cutover, remote desktop, native apps, production installers)
remains required and unfinished. Owner-scoped file requests and aggregate
logical payload quota reporting use authenticated v2 routes on TLS; retention,
physical storage accounting, and installed network acceptance remain unfinished.
See
`BUILD-REPORT.md` for tested versus unproven boundaries.

On Windows, double-click `start-development.cmd` or run the PowerShell script
from an existing terminal. The CMD launcher keeps errors visible after the
child process stops and preserves the configured execution policy.


Historical HTTPS prerequisite code `ccaf29a` passed **238 Mac, 231 Linux and189 native Windows tests**, formatting/Clippy/build and the actual Windows PowerShell development fixture. [Native CI38143445740](https://github.com/Helicoid-Systems/server/actions/runs/38143445740) provides the [Windows x64 development server](https://github.com/Helicoid-Systems/server/actions/runs/38143445740/artifacts/11703299972). That revision refused Windows HTTPS hosting. The current tree supports literal-loopback `serve-tls` by default and explicitly enabled nonloopback TLS with v2-only routes on Unix and Windows; installed services, public routing, and production recovery remain unverified. Current native Linux/Windows TLS checks and coordinator artifact inspection are recorded above and in BUILD-REPORT.md.
