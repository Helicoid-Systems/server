> **R02 v5 status overlay (2026-10-17) — current summary.**
> This file is **historical R01 narrative**. Current acceptance candidate is
> R02 v4 binary `6afd46f965e8c522b4ad0dd9722db52060349f81981ec0c6b1a9c05dda177727`.
> It remains a **candidate** pending native Linux CI runtime. Independent coordinator checks now pass
> native delete/reallocation, server caps, fractional timing, the60second
> cutoff and clock-fault cases. Historical R01 green claims below are
> retained as evidence and labeled historical; the R01 patched binary
> `b1dd53dd…` native gate **FAILED** (timing-dependent lastfraction + isolation).
> No public, production, or renewable60 guarantee. See `README.md` /
> `BUILD-REPORT.md` for the current summary.

# Server R01 relay lab — final fault + package report

> **SUPERSEDED / NOT ACCEPTED (oracle v3/v5, 2026-10-17).**
> This historical report claimed patched lastfraction/boundary60 **VERIFIED**.
> Corrected oracle evidence supersedes those green claims: the frozen patched
> binary `b1dd53dd…` has a real lastfraction failure in
> `native-lab-1792243403-90349/run` (attempt `0.291429s` before timestamp;
> **5 post-bound arrivals**; in-window Refresh extended past deadline), plus
> `allocation_isolation` deletion failure (`del_forward_after=true`). Wrapper
> exits nonzero. Coordinator later PASSED a different wall phase on the same
> binary (`coordinator-relay-oracle-native-final-bcrovsbd/receipt.json`,
> `0.293633s` remaining, 0 post-bound) — timing-dependent; that does **not**
> erase the failure. **Native patch gate = Failed.** Stock red proof and
> clockfault compile-time seam remain narrower evidence only. Hard60 from
> issuance and renewable authority are **NotVerified**. Do not treat this file
> as current acceptance. See `README.md` / `BUILD-REPORT.md` oracle status.

Date: 2026-10-17
Owner: `/Users/barni/Documents/Github/main/modules/server` ONLY
Briefs: `coordinator-server-relay-final-fault-and-package-20261017.md`,
`coordinator-server-relay-expiry-lab-20261016.md`,
`coordinator-server-real-boundary-measurement-20261017.md`,
`coordinator-relay-monotonic-fault-review-20261017.md`,
`coordinator-server-path-correction-20261017.md`
Model: EU xiaomi-token-plan-ams / mimo-v2.6-pro high, NeedQuality mandatory
Boundary: isolated `relay-lab/` + one `.github/workflows/relay-lab.yml` + README/BUILD-REPORT.
No normal server auth/installer/contracts/schema edits. No prod/VM/DNS/SSH/global installs. No commit/push/deploy.

---

## 0. Executive outcome (historical R01 — see R02 v5 overlay)

The table below is the **historical** R01 executive claim set. Current
status is in the R02 v5 overlay and `BUILD-REPORT.md` §7: R01 patched
binary native gate **FAILED**; R02 v4 is a **candidate** pending
independent coordinator reproduction and native Linux runtime.

| Gate | Historical R01 verdict | Current note |
|---|---|---|
| Stock coturn REST/allocation **does not** bound existing allocation after auth stops | **VERIFIED** (defect reproduced) | still useful evidence |
| Smallest lifecycle patch freezes monotonic authorization deadline; Refresh cannot re-grant | **VERIFIED** (as claimed) | superseded for `b1dd53dd…` — timing-dependent |
| Fresh-window last-fraction Refresh denied (not vacuous) | **VERIFIED** (as claimed) | contradicted by real lastfraction failure |
| Real 60s boundary trial with `pre_forward=true` | **VERIFIED** (as claimed) | one-phase sample only |
| Forbidden wall-clock fallback removed; clock fault **denies** authority | **VERIFIED** (fault injection) | still useful evidence |
| Reproducible pinned fetch/build/run + isolated Linux CI workflow authored | **VERIFIED** (authored) | still useful evidence |
| Linux CI **runtime** | **NOT VERIFIED** (coordinator owns dispatch) | still NOT VERIFIED |
| Full renewable authority lease / public route adoption | **NOT VERIFIED** (out of scope) | no public/production/renewable60 guarantee |
| Hard 60s bound | **NOT VERIFIED** — measured only, see §5 | still NOT VERIFIED |

A correct failed gate is recorded as failed. No vacuous pass accepted.

---

## 1. Work preserved

All prior WIP/fixtures/evidence/artwork preserved. Coordinator snapshots and
original failure logs untouched (READONLY). Historical reentrant-timeout C crash
retained as a historical failure record (non-reentrant `destroy_allocation_at_auth_bound`
now present). Scratch bulk (`coturn-src`, builds, binaries, logs) stays in
`/tmp/hs-finish-20261013/relay-lab` (11 MiB source, 45 MiB lab root). Host free ≥ 8 GiB (8.6 GiB).

---

## 2. Concrete security repair: no wall-clock fallback

### 2.1 Defect

`src/ns_turn_defs.h` `turn_monotonic_ms()` silently fell back to
`((int64_t)time(NULL)) * 1000` when `CLOCK_MONOTONIC` was absent or
`clock_gettime` failed. Wall rollback could extend authorization. Failure was
conflated with deadline `0` (unlimited).

### 2.2 Fix (in `relay-lab/patches/0001-auth-lifetime-cap.patch`)

| File | Repair |
|---|---|
| `src/ns_turn_defs.h` | `TURN_MONOTONIC_MS_FAIL` / `TURN_AUTH_DEADLINE_FAIL` sentinels (`INT64_MIN`). **No `time(NULL)` fallback.** Checked `timespec`→ms conversion rejects overflow. Missing `CLOCK_MONOTONIC` is a fault. `TURN_TEST_CLOCK_FAULT` is a **compile-time** test seam only. |
| `src/server/ns_turn_server.c` | `auth_remaining_secs/ms` fail-closed on NULL session, negative/FAIL deadline, clock failure. Freeze at credential lookup: clock fault / overflow → `TURN_AUTH_DEADLINE_FAIL`, never `0`. Allocate/Refresh deny with 401 when remaining is invalid; lifetime capped to remaining; sub-second timer arms to the bound. |
| `src/server/ns_turn_session.h` | documents `0 = none`, `FAIL = deny`, positive = absolute deadline. |
| `src/apps/relay/userdb.c` | REST remaining checked narrowing: `ts==ctime` → `TURN_KEY_LOOKUP_EXPIRED` (not unlimited `0`); `remaining > INT_MAX` clamped (no signed wrap to negative → unlimited). |
| `src/apps/relay/ns_ioalib_engine_impl.c` | `secs==0 && ms>0` timers valid (sub-second bound). |

Existing armed timers are never extended on clock failure (Refresh is denied
before `refresh_relay_connection`).

### 2.3 Proof commands

```
# no wall fallback in patch
rg "return \(\(int64_t\)time\(NULL\)\)" relay-lab/patches/0001-auth-lifetime-cap.patch
# → no match (exit 1)  VERIFIED

# patch applies cleanly to stock
git -C coturn-stock-20261017 apply --check relay-lab/patches/0001-auth-lifetime-cap.patch
# → exit 0  VERIFIED

# touched-file compile warnings
make bin/turnserver  # then rg 'warning:|error:' on touched paths → empty
```

---

## 3. Clock-fault denial through real native binary

Fault injection, **not** OS fault acceptance. No host clock mutation. No
runtime/exported bypass (define is compile-time).

Binary: `turnserver-clockfault`
sha256 `20bcd86611aebc8af4a29df67df4ef4f07f9193032acb75624169cb3045c0c9b`
Compile line includes `-DTURN_TEST_CLOCK_FAULT` (see
`relay-lab/build/coturn-make-clockfault.log`).

Actual TURN requests over real TLS/TCP (CA-pinned):

| Scenario | Observed | Verdict |
|---|---|---|
| Allocate with **valid** REST timestamp | `allocate_ok=false`, `error=401`, `fail_closed=true`, `granted_unlimited=false` | **PASS** |
| Refresh | `refresh_ok=false`, `error=437`, `fail_closed=true` | **PASS** |
| cleanup | process reaped, UDP+TLS ports free | **PASS** |

Evidence: `/tmp/hs-finish-20261013/relay-lab/run/clockfault-patched.json`
Command: `run_expiry_lab.py --mode clockfault --turnserver-bin .../turnserver-clockfault` → exit 0.

---

## 4. Protocol harness (fresh-window, secure)

- Real loopback TLS/TCP + UDP relay. Generated CA; `ssl.CERT_REQUIRED`;
  `check_hostname=True`. **No `CERT_NONE`** (helper removed; only a comment
  mentions it). `ca_cert` required or the harness refuses.
- Strict transaction-id / method / class and authenticated success
  MESSAGE-INTEGRITY checks retained.
- `last_fraction_refresh` uses a **fresh allocation/credential window**:
  `pre_forward=true` required, attempt recorded on the monotonic clock,
  `in_last_fraction` must be true or the gate is FAIL/NotVerified (not green).
- Metadata-only output; secrets in 0600 scratch only.

---

## 5. Measured results (fail-closed binary `b1dd53dd…`)

### 5.1 Stock red — defect reproduced

| Scenario | Status | Key measured fields |
|---|---|---|
| `refresh_after_expiry` | FAIL | `unbounded_after_expiry=true` |
| `last_fraction_refresh` | FAIL | `pre_forward=true`, `in_last_fraction=true`, `refresh_ok=true`, `refresh_lifetime=600`, `regrant_full_lifetime=true`, `refresh_relative_s=6.983` (window 7) |
| `silent_client_expires` | FAIL | Refresh still succeeds past expiry |
| `late_allocate_rejected` | PASS | new Allocate → 401 (REST ts check) |
| `matching_cleanup` | PASS | reaped, ports free |

`mandatory_all_pass=false`, `defect_reproduced=true`
Files: `final6-stock-accelerated.json`, `final6-stock-lastfraction.json`
Binary sha256 `4344215c5857af7b6b87873e8749142d0e701f8c77d2bf105967f388232a41ed`

### 5.2 Historical patched sample — later contradicted (not current proof)

> Historical claim of green lastfraction/boundary60 on `b1dd53dd…`.
> Superseded: real lastfraction failure and isolation failure on the same
> binary. Rows retained as sample evidence only.

| Mode | `last_fraction_refresh` measured |
|---|---|
| accelerated (window 7s) | `pre_forward=true`, `in_last_fraction=true`, `refresh_err=401`, `refresh_relative_s=6.667`, `first_failure_rel_s=6.668`, `regrant=false`, `post_forward=false` |
| lastfraction (window 7s) | `refresh_relative_s=6.546`, `first_failure_rel_s=6.546`, `regrant=false` |
| **boundary60 (window 60s)** | `pre_forward=true`, `in_last_fraction=true`, `refresh_err=401`, `refresh_relative_s=59.786`, `first_failure_rel_s=59.787`, `regrant=false`, `post_forward=false` |

All mandatory scenarios PASS (`refresh_after_expiry`, `silent_client_expires`,
`late_allocate_rejected`, `allocation_isolation`, `wrong_auth_rejected`,
`matching_cleanup`).
Files: `final6-patched-{accelerated,lastfraction,boundary60}.json`
Binary sha256 `b1dd53dd48061521e769949634136822fb6b4c9fd791e7ebbad37469cbcda313`

**Measured limits (honest):** first denial fell at 6.668s / 6.546s / 59.787s on
a 15s / 7s / 60s REST window — within one 0.15s poll of the deadline. REST
timestamps are integer seconds and `get_user_key` is an async lookup; those
delays are real and are **not** claimed eliminated. This is a measured bound,
not a hard 60s guarantee.

### 5.3 Historical (do not treat as current proof)

Earlier `final3-patched-boundary60.json` last-fraction was **vacuous**
(`pre_forward=false`, `refresh_relative_s=73.0`, after the long Refresh loop).
Superseded by §5.2. Original stock 600s/unbounded receipts preserved.

---

## 6. Reproducible package

Committed under `modules/server` (untracked until coordinator commits):

```
relay-lab/
  .gitignore
  README.md
  BUILD-REPORT.md
  FINAL-REPORT-20261017.md              # this report (also at briefed /tmp path)
  patches/0001-auth-lifetime-cap.patch  # 428 lines, 5 files, BSD-3-Clause headers retained
  harness/run_expiry_lab.py
  harness/turn_protocol.py
  scripts/fetch-coturn.sh               # pin commit + libevent sha256
  scripts/build-lab.sh                  # strict apply/check + 3 binaries
  scripts/run-lab.sh                    # stock/patched/clockfault matrix
.github/workflows/relay-lab.yml         # one isolated ubuntu-latest job
```

Pins:
- coturn `23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b` (tag object `000296e7fdb41ed99ca325fcbd19d64404990980`)
- libevent 2.1.12-stable sha256 `92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb`
- OpenSSL: existing system (no install)

Checks this turn:
- `bash -n` on all three scripts → 0
- `python3 -m py_compile` harness → 0
- `git diff --check` → 0
- `git apply --check` patch vs stock → 0
- insecure TLS patterns (`ssl.CERT_NONE`, `check_hostname=False`) → none
- wall-clock fallback in patch → none
- `actionlint` → **NOT INSTALLED** (NotVerified); workflow YAML structurally parsed

Bulk source/binaries/private configs/logs are scratch-only (`.gitignore` covers
`coturn-src`, `bin/`, `run/`, `__pycache__`, `*.pem/key/crt`, configs).

---

## 7. Commands and exits (this turn)

| Command | Exit | Outcome |
|---|---|---|
| `make bin/turnserver` (patched) | 0 | warnings in touched files: none |
| `make bin/turnserver CPPFLAGS=-DTURN_TEST_CLOCK_FAULT` | 0 | clockfault binary |
| `run_expiry_lab.py --mode clockfault --turnserver-bin turnserver-clockfault` | 0 | PASS fail-closed |
| `run_expiry_lab.py --mode accelerated --turnserver-bin turnserver-stock` | 1 | defect reproduced |
| `run_expiry_lab.py --mode accelerated --turnserver-bin turnserver-patched` | 0 | PASS |
| `run_expiry_lab.py --mode lastfraction --turnserver-bin turnserver-stock` | 1 | defect reproduced |
| `run_expiry_lab.py --mode lastfraction --turnserver-bin turnserver-patched` | 0 | PASS |
| `run_expiry_lab.py --mode boundary60 --turnserver-bin turnserver-patched` | 0 | PASS (real 60s) |
| `bash -n scripts/*.sh` | 0 | OK |
| `git -C coturn-src diff --check` | 0 | OK |
| `git -C coturn-stock apply --check patch` | 0 | OK |

---

## 8. NotVerified gates (do not claim)

1. **Linux CI runtime** — workflow authored; coordinator owns push/dispatch and artifact inspection. Local runtime is macOS only.
2. **`actionlint`** — not installed on this host.
3. **Hard 60-second bound** — measured 59.787s first-failure under a 60s REST window; fractional REST timestamp and async lookup delay remain.
4. **Full renewable authority lease issuance** — not implemented.
5. **Authenticated carrier / engine relay integration / public route adoption** — unverified.
6. **OS-level CLOCK_MONOTONIC fault acceptance** — only compile-time fault injection tested.
7. **Normal server auth/installer/contracts/schema** — untouched (correctly out of scope).

---

## 9. Stop condition

Bounded package complete. Coordinator owns CI publication and exact artifact
inspection. No commit/push/deploy performed by this session.

Delivered at the briefed path `/tmp/hs-finish-20261013/server-relay-final-report-20261017.md`
and mirrored at `relay-lab/FINAL-REPORT-20261017.md`.
