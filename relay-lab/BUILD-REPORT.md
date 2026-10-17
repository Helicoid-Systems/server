# BUILD-REPORT — R01 relay lab

Date: 2026-10-17
Owner: `modules/server` isolated relay-lab only
Model: EU xiaomi-token-plan-ams / mimo-v2.6-pro high (NeedQuality)

## 1. Pin verification

| Item | Expected | Observed |
|---|---|---|
| coturn commit | `23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b` | `23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b` |
| libevent tarball sha256 | `92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb` | match (`shasum -a 256 -c`) |
| coturn source checkout size | ≤ 100 MiB | 11 MiB (`du -sh coturn-src`) |
| host free space | ≥ 8 GiB | 8.6 GiB (`df -h /tmp`) |

OpenSSL: system existing (`/opt/homebrew/opt/openssl` on this macOS host).
No global/homebrew/apt install performed by this session.

## 2. Build artifacts (local macOS lab host)

| Binary | sha256 |
|---|---|
| `turnserver-stock` | `4344215c5857af7b6b87873e8749142d0e701f8c77d2bf105967f388232a41ed` |
| `turnserver-patched` | `b1dd53dd48061521e769949634136822fb6b4c9fd791e7ebbad37469cbcda313` |
| `turnserver-clockfault` | `20bcd86611aebc8af4a29df67df4ef4f07f9193032acb75624169cb3045c0c9b` |

Compile warnings in touched files (`ns_turn_defs.h`, `ns_turn_server.c`,
`userdb.c`, `ns_turn_session.h`, `ns_ioalib_engine_impl.c`): **none**
(`make` rebuilt; `rg 'warning:|error:'` on those paths empty).

`turnserver-clockfault` compile line includes `-DTURN_TEST_CLOCK_FAULT`
(verified in `relay-lab/build/coturn-make-clockfault.log`).

## 3. Patch

File: `relay-lab/patches/0001-auth-lifetime-cap.patch` (428 lines, 5 files)

| File | Change |
|---|---|
| `src/ns_turn_defs.h` | `turn_monotonic_ms` fail-closed sentinel; `TURN_TEST_CLOCK_FAULT` test seam; **no `time(NULL)` fallback** |
| `src/server/ns_turn_session.h` | `auth_deadline_mono_ms` field + sentinel semantics |
| `src/server/ns_turn_server.c` | freeze deadline once; `auth_remaining_{secs,ms}` fail-closed; Allocate/Refresh capped to remaining; timer to the bound; non-reentrant destroy |
| `src/apps/relay/userdb.c` | REST remaining checked narrowing (no int wrap to unlimited; `ts==ctime` denied) |
| `src/apps/relay/ns_ioalib_engine_impl.c` | sub-second timer arming (`secs==0 && ms>0`) |

License headers preserved (BSD-3-Clause SPDX retained).

## 4. Protocol harness

- Real loopback TLS/TCP control + UDP relay data. CA-pinned TLS
  (`ssl.CERT_REQUIRED`, `check_hostname=True`, generated CA).
  **Zero `CERT_NONE` / insecure fallback** (removed).
- Strict STUN transaction-id / method / class checks and authenticated
  success MESSAGE-INTEGRITY verification.
- No secrets in console, argv, fixtures, or reports.

## 5. Measured results

Current acceptance candidate is **R02 v4** (`6afd46f965e8c522b4ad0dd9722db52060349f81981ec0c6b1a9c05dda177727`).
It remains a **candidate** pending native Linux CI runtime. Independent coordinator checks now pass
delete/reallocation isolation, server caps, four wall-clock phases, actual
60second cutoff, accelerated isolation and native clock-fault denial.
The ordered patch matches the built source; launcher11 and causal9 checks pass. Do not treat §5.1–§5.2 as current
acceptance; they are historical R01 evidence retained because the failed
rows are still useful.

### 5.1 Historical R01 stock baseline (defect reproduced — red)

| Scenario | Result | Evidence |
|---|---|---|
| `refresh_after_expiry` | **FAIL** (unbounded) | `unbounded_after_expiry=true` |
| `last_fraction_refresh` | **FAIL** | `pre_forward=true`, `in_last_fraction=true`, `refresh_ok=true`, `refresh_lifetime=600`, `regrant_full_lifetime=true`, `refresh_relative_s=6.983` (window 7), `last_success_rel_s≈6.98` |
| `silent_client_expires` | **FAIL** | `refresh_ok=true` after expiry |
| `late_allocate_rejected` | PASS | new Allocate after REST ts expiry → 401 |
| `matching_cleanup` | PASS | process reaped, ports free |

Source: `relay-lab/run/final6-stock-accelerated.json`, `final6-stock-lastfraction.json`

### 5.2 Historical R01 patched binary `b1dd53dd…` (native gate Failed)

Frozen R01 patched binary `b1dd53dd48061521e769949634136822fb6b4c9fd791e7ebbad37469cbcda313`
is **timing-dependent**. Useful failed evidence retained below. A later
wall-phase sample that PASSED on the same binary does **not** erase the
real failure. Native patch gate for this binary is **FAILED**.
`allocation_isolation` also fails (`del_forward_after=true`).

| Scenario | Result | Measured bound |
|---|---|---|
| accelerated `last_fraction_refresh` | PASS (one phase) | `pre_forward=true`, `in_last_fraction=true`, `refresh_err=401`, `regrant=false`, `post_forward=false` |
| lastfraction `last_fraction_refresh` | **FAILED (real cutoff)** | in-window attempt `0.291429s` remaining; `refresh_ok=true`; `extends_past_deadline=true`; **5** post-bound arrivals |
| boundary60 `last_fraction_refresh` | PASS (one phase) | `refresh_err=401`, `in_last_fraction=true` in that run |
| `refresh_after_expiry` | PASS | `unbounded_after_expiry=false` |
| `silent_client_expires` | PASS | no successful Refresh past expiry when pre_ok |
| `late_allocate_rejected` | PASS | 401 |
| `allocation_isolation` | **FAIL** | `del_forward_after=true` after delete |
| `wrong_auth_rejected` | PASS | fresh username + paired good-cred + 401 |
| `matching_cleanup` | PASS | reaped, ports free |

Source: `final6-patched-accelerated.json`, `final6-patched-lastfraction.json`,
`final6-patched-boundary60.json`, `native-lab-1792243403-90349/run`.

**Measured tolerance (not a hard bound claim):** under a 15s / 7s / 60s REST
window the first failed peer-forward / Refresh denial landed at
6.668s / 6.546s / 59.787s on the monotonic clock, i.e. within one poll
interval (0.15s) of the authorization deadline. REST timestamps are integer
seconds; async key-lookup delay and fractional wall rounding are real
limits — see §7.

### 5.3 Clock-fault injection (test-only seam)

Binary: `turnserver-clockfault` (`-DTURN_TEST_CLOCK_FAULT`)

| Scenario | Result | Detail |
|---|---|---|
| `clockfault_allocate_denied` | **PASS** | valid REST ts, `allocate_ok=false`, `error=401`, `fail_closed=true`, `granted_unlimited=false` |
| `clockfault_refresh_denied` | **PASS** | `refresh_ok=false`, `error=437`, `fail_closed=true` |
| `matching_cleanup` | **PASS** | reaped, ports free |

Source: `clockfault-patched.json`. Recorded as **fault injection**, not OS
fault acceptance. No host clock mutation. Python arithmetic mirrors are
**not** native proof and are not used as acceptance evidence.

## 6. CI package

`.github/workflows/relay-lab.yml` — one isolated Linux job on `ubuntu-latest`:

1. Record runner/tool versions (uname, cc, make, git, python3, openssl, dpkg).
2. `apt-get install` build deps on the disposable runner only.
3. `fetch-coturn.sh` (pin + sha256) → `build-lab.sh` (strict apply/check) →
   stock baseline build → `run-lab.sh`.
4. Upload metadata-only JSON + version file as artifact.

Coordinator owns push/dispatch and exact artifact inspection.
**Linux runtime is NotVerified until that workflow runs.**

## 7. Limits / NotVerified (honest)

| Gate | Status |
|---|---|
| Stock defect reproduced on real sockets | **VERIFIED** (historical R01 host evidence; still useful) |
| R01 patched bound holds, incl. fresh-window last-fraction | **FAILED** — timing-dependent; see §5.2 |
| R01 real 60s boundary trial with `pre_forward=true` | **one-phase sample only** — not a hard bound |
| R02 v4 candidate delete-realloc + server-cap | **Verified locally by coordinator**; native Linux runtime pending |
| Clock-fault denial on real native binary | **VERIFIED** (fault injection) |
| No `time(NULL)` fallback in `turn_monotonic_ms` | **VERIFIED** (source + patch) |
| No `CERT_NONE` in harness | **VERIFIED** |
| Linux CI runtime on disposable runner | **NOT VERIFIED** (workflow authored only) |
| Independent coordinator reproduction of R02 v4 | **VERIFIED** for the bounded local native scenarios; full renewable authority remains Not Verified |
| Full renewable authority lease issuance | **NOT VERIFIED** (out of scope) |
| Public route / engine relay adoption | **NOT VERIFIED** (out of scope) |
| Hard 60s bound (config-declared) | **NOT VERIFIED** — only measured, see §5.2 |
| Source fractional REST ts / async lookup delay | **NOT VERIFIED as eliminated** — integer-second REST timestamps and async `get_user_key` delay remain; measured denial is post-those effects |
| Historical reentrant-timeout crash | recorded as historical failure (non-reentrant destroy now present); not silently discarded |

## 8. Commands / exits

### 8.1 Historical R01 (this report’s original turn; not current acceptance)

```
python3 -m py_compile harness/run_expiry_lab.py harness/turn_protocol.py   # 0
make bin/turnserver                                                        # 0 (patched)
make bin/turnserver CPPFLAGS=-DTURN_TEST_CLOCK_FAULT                       # 0 (clockfault)
run_expiry_lab.py --mode clockfault   ...                                  # 0 PASS
run_expiry_lab.py --mode accelerated  --turnserver-bin stock   ...         # 1 (defect)
run_expiry_lab.py --mode accelerated  --turnserver-bin patched ...         # 0 PASS
run_expiry_lab.py --mode lastfraction --turnserver-bin stock   ...         # 1 (defect)
run_expiry_lab.py --mode lastfraction --turnserver-bin patched ...         # 0 PASS
run_expiry_lab.py --mode boundary60   --turnserver-bin patched ...         # 0 PASS
```

JSON evidence lives under `/tmp/hs-finish-20261013/relay-lab/run/final6-*.json`
and `clockfault-patched.json` (scratch, not git).

### 8.2 R02 v4 correction build (2026-10-17)

Coordinator rejected prior green on reallocation + server-cap. Bounded fixes
in editable source only (`relay-lab-r02-cutoff/coturn-src`); frozen 0001 +
oracle/protocol/test files byte-identical.

| Artifact | sha256 |
|---|---|
| `turnserver-patched` | `6afd46f965e8c522b4ad0dd9722db52060349f81981ec0c6b1a9c05dda177727` |
| `turnserver-clockfault` | `6eabc4bcdd22bab9737bc15d25d8ec76162a536147953d070cbed0879277a15d` |
| `patches/0002-precise-auth-cutoff.patch` | `493857d6976d92f1b9f3b1d3100c865ee33df3cd0bcff7958a23e9c9337dc04a` |
| `patches/0001-auth-lifetime-cap.patch` (frozen) | `6a6fd685ca39b2eee85ac26d68465bdfd99a637a36272d4e32cdd2b8f8751990` |

Build dir: `/tmp/hs-finish-20261013/relay-lab-r02-cutoff/bin-r02-v4-20261017-172554`
(source `relay-lab-r02-cutoff/coturn-src`, stock+0001+0002). Old binaries and
receipts preserved. Ordered 0002 apply verified on a fresh copy of the
immutable 0001-only baseline (`patch-verify-20GryA`); resulting `ns_turn_server.c`
and `userdb.c` match the built tree.

### 8.3 Agent-run checks on R02 v4 (candidate only — not independent coordinator)

| Check | Result |
|---|---|
| Portable `test_delete_realloc_regression.py` (sibling oracle import) | see §8.4 / acceptance this turn |
| Coordinator-script delete-realloc (agent-run) | present in agent receipts — **not** independent coordinator reproduction |
| Coordinator-script server-cap auth=6/30 (agent-run) | present in agent receipts — **not** independent coordinator reproduction |
| Frozen lastfraction 7s / 60s (agent-run) | present in agent receipts |
| Clockfault allocate/refresh deny | PASS (native seam) |
| Stock accelerated (defect) | FAIL as expected (red proof) |
| `bash -n` scripts, `py_compile` harness | PASS |
| actionlint `relay-lab.yml` | PASS |
| Frozen 0001 + harness hashes | unchanged |

An intermediate Python arithmetic mirror is excluded from this package and
acceptance. The workflow retains actual native clock-fault checks.

Production renewable60s authority, public443, Windows/Intel, normal media/input
and release remain **NotVerified**.
