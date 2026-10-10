# Helicoid Systems — coordination server foundation

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

## What this foundation is

| Area | Status in this build |
| --- | --- |
| Local account bootstrap + login | Implemented (Argon2id passwords) |
| Opaque bearer sessions | Implemented (SHA-256 at rest, never logged) |
| Manager enrollment | Implemented as **loopback development identity fixtures** |
| D20 deny-before-approval | Implemented (pending manager cannot bind/login) |
| Per-computer access scopes | Implemented (explicit IDs or scope-all) |
| Bounded inventory reads | Implemented (hard cap 100) |
| Schema init | Explicit; refuses unrelated nonempty DBs; no auto-migration |
| Security State Unavailable | Durable latch; restart never resets it; no auto-recovery |
| Required read/commit failures | Latch + `503 security_state_unavailable` (not bare 500) |
| MFA / file jobs / security recovery | Explicitly unavailable (`501`), not fake success |
| Remote control / screen observation | Not present (B02/B03/RD03 proofs pending) |
| Bind policy | **Literal loopback only** (`127.0.0.1` / `::1`); other binds refused |
| Login throttle | Bounded in-memory map (1024 keys); fails closed when saturated |

Manager `public_identity` values are **not** cryptographic production identities.
They are development fixtures for local/loopback integration until B03 freezes
signed endpoint/manager identity formats. Do not invent grant formats.

## Build and test

```sh
export CARGO_HOME=/tmp/hs-toolchain/cargo
export RUSTUP_HOME=/tmp/hs-toolchain/rustup
export PATH=/tmp/hs-toolchain/cargo/bin:$PATH
export CARGO_TARGET_DIR=/tmp/hs-build/server-target

cd modules/server
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
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

`hs-server check-login --username admin --password-stdin` verifies credentials
without starting HTTP and immediately discards the ephemeral session.

Never log or print `password`, `token`, `bootstrap_token`, or `Authorization`.

## Windows 11 x64 development download

CI artifact `hs-server-windows-x64-dev` (from the `windows-latest` job) contains:

| File | Purpose |
| --- | --- |
| `hs-server.exe` | Release build of this server |
| [`scripts/start-development.cmd`](scripts/start-development.cmd) | Double-click launcher that retains errors |
| [`scripts/start-development.ps1`](scripts/start-development.ps1) | Disposable literal-loopback fixture launcher |
| [`scripts/windows-tester.md`](scripts/windows-tester.md) | Tester instructions and manual CLI steps |

`start-development.ps1` creates a fresh unique disposable database directory
(refuses any existing DB), prompts for a password of at least 12 characters
(hidden), passes that password to `hs-server` only via stdin, captures the init
bootstrap token in memory only, approves exactly `dev-manager-key` at bootstrap,
and serves on `http://127.0.0.1:8787` in the foreground until Ctrl+C.

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

## API contract

Native clients integrate from **[contracts/http-v1.md](contracts/http-v1.md)**.
HTTP wire shape is unchanged from that version-1 file.

## Security notes for this foundation

- Passwords: Argon2id via the maintained `argon2` crate (PHC strings).
- Session tokens: 32-byte OS RNG values; only SHA-256 digests are stored.
- Owner fields (capabilities, scopes) come from the session, never from request bodies.
- Administration capability does not imply inventory, observe, or operate rights.
- Single-use bootstrap token is hashed at rest and consumed transactionally.
- Durable Security State Unavailable latch: hydrated at service start with
  exact integer `0`/`1` (invalid values fail closed); required storage **and**
  lock-poison/internal failures latch and deny new authority; memory latch stays
  authoritative if the durable note cannot be written; **never auto-recovers**.
- Health is fail-closed: `accepting_authorized_operations` is true only after
  bootstrap completes and trust state is healthy. Missing deployment row latches.
- Non-loopback socket binds are refused before listen (CLI + `require_loopback_bind`).
- Login throttle map is bounded (dev budget 1024 keys, idle prune 15m); unknown
  keys fail closed when saturated. This is not production credential/MFA policy.
- Request types that carry secrets do not implement `Debug`.
- No TLS terminator, certificate bypass, or invented signed grants in-process.

## Out of scope here

Broader plan work (file jobs, MFA factors, recovery/cutover, remote desktop,
native apps, production installers) remains required and unfinished. See
`BUILD-REPORT.md` for tested versus unproven boundaries.

On Windows, double-click `start-development.cmd` or run the PowerShell script
from an existing terminal. The CMD launcher keeps errors visible after the
child process stops and preserves the configured execution policy.
