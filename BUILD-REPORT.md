# BUILD-REPORT — Helicoid `hs-server` foundation

Owned path: `modules/server/**` only.
Product: **Helicoid** (Helicoid Systems). Organization: **Helicoid-Systems**.
Apps: **Helicoid Manager** / **Helicoid Computer**.
Build date: 10 October 2026 (review-fix pass).
Toolchain: rustc 1.99.0 / cargo 1.99.0 (`/tmp/hs-toolchain`).
Dedicated target dir: `/tmp/hs-build/server-target`.

## Outcome

**VERIFIED** for the development foundation and all five coordinator review
findings (unit + integration tests + clippy/fmt + CLI refusal + loopback health).
**NOT VERIFIED:** production identity/cryptographic manager keys, LAN authority,
remote desktop, MFA, file jobs, recovery/cutover, real multi-process soak.

## Fresh proof commands (this turn)

```
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

| Command | Result |
| --- | --- |
| `cargo fmt -- --check` | **clean** |
| `cargo test --locked` | **39 passed, 0 failed** (10 lib + 12 http_api + 17 review_findings) |
| `cargo clippy --all-targets -- -D warnings` | **clean** |

### Named tests (final guard/health pass)

| Finding | Tests |
| --- | --- |
| Latch hydration exact 0/1 | `hydrate_fails_closed_on_invalid_security_state_ok_integer`, `invalid_security_state_ok_integer_fails_closed`, `security_state_ok_one_hydrates_ok` |
| Missing deployment row latches | `missing_deployment_row_latches_and_denies_authority`, `hydrate_fails_closed_when_deployment_row_missing` |
| Health bootstrap semantics | `health_unbootstracked_is_not_accepting`, `health_accepts_only_after_bootstrap`, `health_reports_real_bootstrap_completed_when_latched` |
| Guard lock/Internal uncertainty | `internal_storage_uncertainty_fails_closed`, `required_read_failure_latches_and_denies_without_deadlock` |
| Unique tempdirs | `tempfile` dev-dependency (UUID-backed dirs); no `process::id` + `remove_file` helpers |

### Named tests (review findings)

| Finding | Tests |
| --- | --- |
| 1 Durable latch | `security_latch_survives_file_reopen`, `security_latch_survives_service_recreation_same_db`, `hydrate_fails_closed_when_deployment_row_missing`, `hydrate_fails_closed_when_trust_table_unreadable` |
| 2 Required-read guard | `required_read_failure_latches_and_denies_without_deadlock`, `health_fails_closed_when_durable_record_unreadable` |
| 3 Loopback-only bind | `refuses_non_loopback_bind_addresses`, `cli_serve_refuses_wildcard_bind`, `health_on_loopback_socket_still_works` |
| 4 Bounded throttle | `invalid_username_length_rejected_before_hash_work`, `login_throttle_locks_out_and_expires`, `login_throttle_bounded_fails_closed_when_saturated`, `throttle_prunes_expired_idle_entries` |
| 5 CI / no secret Debug | `.github/workflows/ci.yml`; `BootstrapRequest`/`LoginRequest` and CLI `Debug` removed |

Prior foundation tests (schema init, single-use bootstrap, deny-before-approval,
scoped inventory, unique claims, explicit 501 surfaces) still pass.

These include a real loopback TCP health probe and a real `hs-server` CLI
process refusal for `0.0.0.0` / `[::]`. They are **not** OS-installed platform
proof.

## Review fixes implemented

### 1. Durable Security State latch

- `Service::new` hydrates `deployment.security_state_ok` as **exact integer 0/1**
  (`2` or any non-`1` value → `Unavailable`; avoids SQLite nonzero-as-true).
- Missing row, unreadable table, or storage error → `SecurityState::Unavailable`.
- Restart / service recreation never resets a latched deployment (file reopen tested).
- Memory latch is authoritative if persisting the durable note fails.
- **Policy: never auto-recover.** Recovery is an explicit future E07/V47 procedure.

### 2. Centralized required persistence guard

- `with_conn` uses an IIFE so **lock acquisition errors** also flow through
  `finish_storage` (not an early return past the guard).
- `finish_storage` maps `AppError::Storage` **and** lock-poison/`Internal`
  uncertainty → latch + `503 security_state_unavailable`.
- Guard runs only after the Db mutex is released (no deadlock).
- Health latches on a **missing deployment row** (memory cannot stay `Ok`).
- Health reports real `bootstrap_completed` when the durable row is readable.

### 3. Loopback-only bind

- `require_loopback_bind` refuses non-loopback before listen.
- CLI `serve --bind 0.0.0.0` and `serve --bind [::]` exit non-zero (tested).
- Real `127.0.0.1` socket `/health` returns 200 (tested).
- **Wire contract shape unchanged**; health semantics documented in
  `contracts/http-v1.md` (accepting only after bootstrap).

### 4. Bounded login throttle

- Map keyed by `normalize_login_key` = `trim` + ASCII lowercase (matches DB
  `COLLATE NOCASE` for the ASCII username charset we accept).
- `LOGIN_THROTTLE_MAX_KEYS = 1024`; idle entries pruned after 15 minutes.
- Unknown keys fail closed (`429`) when saturated; existing lockout fairness kept
  (5 failures → 60s lock, success clears the key).
- Username/password length rejected **before** Argon2 work.
- Not production credential/MFA policy (still E07).

### 5. CI and hygiene

- Independent GitHub Actions: `modules/server/.github/workflows/ci.yml` runs
  `cargo fmt -- --check`, `cargo test --locked`, `cargo clippy --all-targets -- -D warnings`
  as this crate’s repository root.
- Secrets-bearing `Debug` removed from `BootstrapRequest`, `LoginRequest`, and CLI.
- Sensitive values never appear in logs or this report.

## Product decisions (confirmed by user)

- Product name **Helicoid** (Helicoid Systems); organization **Helicoid-Systems**.
- **D18:** dynamic All / fixed explicit monitoring scope.
- **D21:** file-request close retains files; replacement needs confirmation.
- Those workflows remain unimplemented in this foundation (no room/class/lesson objects).

## Explicit non-goals (unchanged)

MFA, file jobs, security recovery, authority cutover, remote control/pixels,
production LAN, TLS in-process, signed production manager identity. Manager
`public_identity` remains a **loopback development fixture**.

## API contract

`contracts/http-v1.md` remains the owned v1 wire contract. **No response shape
changes** required for these fixes. Added operational note: non-loopback binds
are refused at start (CLI), not a JSON field.

## Next actions (outside this owner)

1. B03/E07 production identities, MFA, delegation ceilings, replay fencing.
2. S01 native clients on `contracts/http-v1.md`.
3. File jobs / recovery / cutover per `docs/spec/build-map.md`.

---

# BUILD-REPORT — Windows 11 x64 development-server download

Date: 10 October 2026.
Owned paths this pass: `modules/server/.github/workflows/**`,
`modules/server/scripts/**`, `modules/server/README.md`, `modules/server/BUILD-REPORT.md`.
No Rust `src`/`tests`/`contracts`/`Cargo.lock` changes. No git/push/deletes.
Server not started on this Mac.

## Outcome

**VERIFIED (this Mac, content-level):** workflow YAML structure, script/tester
artifact paths, fixture contract text (fresh unique disposable DB, literal
loopback, no service/elevation/ExecutionPolicy bypass/firewall, password on
stdin not argv, token in memory / env not argv, fixed `dev-manager-key`, no
auto scope creation, no auto-delete of test directory).
**NOT VERIFIED (this Mac):** Windows PowerShell execution of
`start-development.ps1`, native `windows-latest` Rust build/test of this crate,
artifact download by a Windows 11 tester. **CI Windows must establish the
Windows Rust build after coordinator publishes. Do not treat that gate as
passed from Mac.**

## Fresh proof commands (this turn)

| Command | Result |
| --- | --- |
| `ls modules/server/scripts modules/server/.github/workflows` | `start-development.ps1`, `windows-tester.md`, `ci.yml` present |
| `ruby -ryaml -e "...YAML.load_file(...ci.yml)..."` | **clean parse**; jobs `verify,windows`; Linux verify steps preserved (Checkout/Toolchain/Cache/Format/Test/Clippy); windows steps Test/Build release/Stage/Upload |
| `git status --short` in `modules/server` | only `.github/workflows/ci.yml`, `README.md`, `BUILD-REPORT.md` modified + `scripts/` added; no Rust/src/tests/contracts/lock changes |
| `command -v pwsh` / `powershell` | **not installed on this Mac** — script not executed here |
| Server binary start | **not run** (explicitly out of scope on this Mac) |
| Python structural scan of `start-development.ps1` | brace/paren balance 0; required markers present (`Read-Host -AsSecureString`, `--password-stdin`, `HS_BOOTSTRAP_TOKEN`, `dev-manager-key`, `127.0.0.1:8787`, `ZeroFreeBSTR`, `serve --bind`); no `Write-Host` of password/token variables |

## Deliverables

| Path | Role |
| --- | --- |
| `.github/workflows/ci.yml` | Linux `verify` job unchanged (`fmt` / `test --locked` / `clippy`); new `windows` job: `cargo test --locked`, `cargo build --locked --release`, upload `hs-server-windows-x64-dev` |
| `scripts/start-development.ps1` | Disposable fixture launcher (Windows PowerShell 5.1+) |
| `scripts/windows-tester.md` | Tester instructions + exact manual CLI steps |
| `README.md` | Windows download section; app names set to **Helicoid Manager** / **Helicoid Computer** |
| `BUILD-REPORT.md` | This report |

CI artifact `hs-server-windows-x64-dev` stages: `hs-server.exe`,
`start-development.ps1`, `windows-tester.md`.

## Runtime fixture contract (encoded in script + docs)

| Requirement | Implementation |
| --- | --- |
| Fresh unique disposable DB directory | `helicoid-hs-server-<timestamp>-<guid8>` under temp or `-ParentDirectory`; **refuses** existing directory and any existing DB file |
| Literal loopback | `serve --bind 127.0.0.1:8787` only; server itself refuses non-loopback |
| No service / elevation / ExecutionPolicy bypass / firewall / network exposure | Script never does these; docs tell testers not to use `-ExecutionPolicy Bypass` |
| Password >= 12, prompted securely | `Read-Host -AsSecureString`; length checked before bootstrap |
| Password via stdin not argv | `--password-stdin` + pipeline; `--password` flag never used |
| Init token in memory only | Captured from `init` stdout; not printed; passed as `HS_BOOTSTRAP_TOKEN` for bootstrap only (not argv, not a file) |
| Bootstrap approves fixed `dev-manager-key` | `--manager-public-identity dev-manager-key` (same value Manager sends at login) |
| Foreground serve, Ctrl+C stops | Direct `& hs-server.exe serve` (no service) |
| User-visible address / identity / username | Printed before serve; password/token/bearer **never** logged |
| No auto-create scopes/authority | No HTTP admin calls after bootstrap; docs state inventory stays empty |
| Never delete test directory | Script leaves the disposable directory in place |

## Script syntax / tool availability / limitations (recorded)

| Item | Status |
| --- | --- |
| Target dialect | Windows PowerShell **5.1** (`#Requires -Version 5.1`); also intended for PowerShell 7+ |
| `$PSScriptRoot`, `Read-Host -AsSecureString`, `Marshal.SecureStringToBSTR` / `ZeroFreeBSTR` | Used; available in 5.1 |
| `ProcessStartInfo.ArgumentList` | **Not used** (not in .NET Framework / PS 5.1) |
| UTF-8 stdin for `--password-stdin` | `$OutputEncoding` set to UTF-8 no BOM for the bootstrap call (PS 5.1 native pipe encoding quirk) |
| Managed-string zeroization | **Not possible.** Variables cleared and `[GC]::Collect()` requested as best effort only. Report and tester doc say this explicitly — no zeroization claim |
| Local `pwsh` / `powershell` on build Mac | **Absent.** Script not syntax-executed here |
| Windows CI Rust build/test | **Pending coordinator publish.** `windows-latest` job is the proof gate |

## Manager launch flags (verified against source)

Actual Windows Helicoid Manager switches (`DevelopmentLaunchOptions.cs`):

- `--development-server` (optional `=http://127.0.0.1:8787`)
- `--development-manager-identity dev-manager-key`

Handoff prose mentioned `--development-server-address` / `--manager-public-identity`
(those names are the macOS manager surface). Tester docs use the **Windows**
switches above so sign-in actually works. Identity value remains `dev-manager-key`.

## Explicit non-goals (this pass)

Production installer/authority/remote-engine claims, LAN exposure, service
install, scope auto-grant, secret zeroization claims, starting the server on
this Mac, asserting Windows CI green from Mac.

Coordinator review changed bootstrap to a child-only environment and explicit UTF-8 stdin, preserving the calling PowerShell environment/encoding and applying a 15-second deadline. Windows CI parses the actual launcher with Windows PowerShell, calls its real init/bootstrap helpers, authenticates the Unicode password, checks caller environment preservation and refuses reused bootstrap. Results remain pending until that native job completes.

## Windows user handoff correction

The user confirmed both Windows apps launch. Their server-test video showed
Explorer opening the PowerShell source in an editor and a subsequent
PowerShell window closing before an error could be read. No sign-in success
is inferred from that video. The bundle now includes `start-development.cmd`,
which invokes the same script without elevation or policy override and pauses
after its child exits, preserving visible error diagnostics. The launcher
keeps the exact foreground loopback behavior and does not install a service.
Actual double-click behavior on the user's PC still needs their test.
