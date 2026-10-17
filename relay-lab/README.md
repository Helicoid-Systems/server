# R01 relay lab — coturn allocation expiry prerequisite

Isolated lab for the R01 relay prerequisite: prove whether stock coturn REST
credentials and allocation lifetime cap actually bound **existing** allocation
lifetime after authorization stops, and (if not) add the smallest maintainable
lifecycle patch plus real protocol regression.

This lab does **not** implement full renewable authority lease issuance,
authenticated carrier, engine relay integration, or public route adoption.
Do not claim a hard 60-second bound from this lab alone.

## Oracle status (R02 v5 portability, 2026-10-17)

Current acceptance candidate is **R02 v4** patched binary
`6afd46f965e8c522b4ad0dd9722db52060349f81981ec0c6b1a9c05dda177727`.
It is a **candidate** pending native Linux CI runtime. Independent coordinator checks now pass
delete/reallocation isolation, server caps, four wall-clock phases, actual
60second cutoff, accelerated isolation and native clock-fault denial.
The ordered patch matches the built source; launcher11 and causal9 checks pass. Historical R01 results (including
failed evidence) are retained in `BUILD-REPORT.md` §5 and
`FINAL-REPORT-20261017.md` and are labeled historical — do not treat them
as current acceptance.

Root-cause fixes after coordinator rejection of binary
`6b93fcb68b9018ca2f425684523d25ad968400d76462a894f5c4c910bf68a65c`:

1. Refresh lifetime=0 now clears permission/channel maps (no stale
   CreatePermission on same-TLS reallocate).
2. Lifetime timer is `min(granted_lifetime_ms, auth_deadline_ms)`; integer
   auth cap uses safe ceil; server/client cap is never extended.
3. userdb samples monotonic **before** walltime with checked ceil/floor
   rounding and overflow-safe arithmetic.
4. Workflow builds stock+0001+0002 once; fixture/causal checks run early.
5. Portable delete-realloc harness imports its sibling frozen oracle and
   creates task temporary directories under a created `LAB_ROOT` or the
   tempfile default (no hardcoded coordinator paths).

| Gate | Status |
|---|---|
| Stock REST/allocation defect | **reproduced** (historical accelerated red) |
| Clockfault compile-time seam deny | **pass** (native fault-injection seam) |
| R01 patched lastfraction / isolation | **historical failure retained** — timing-dependent; see BUILD-REPORT §5.2 |
| R02 v4 delete-realloc / server-cap / lastfraction | **Verified locally by coordinator**; native Linux pending |
| Hard 60s from issuance / renewable authority / public route / production | **NotVerified** — no public, production, or renewable60 guarantee |

Python arithmetic mirrors are not native proof and are excluded from the
workflow. Native clockfault and fractional/cap tests remain.

`FINAL-REPORT-20261017.md` is historical R01 narrative with corrected
overlays; production renewable60s authority, public443, Windows/Intel,
media/input, release stay **NotVerified**.

## Scope boundary

| In scope | Out of scope |
|---|---|
| `relay-lab/` harness + patch | normal server auth / installer / contracts / schema |
| one isolated `.github/workflows/relay-lab.yml` | prod / VM / DNS / SSH / global installs |
| pinned coturn 4.18.0 source (scratch only) | commit / push / deploy |
| real TLS/TCP + UDP loopback protocol tests | public bind / unprotected listeners |

## Pin inventory

| Artifact | Pin | Notes |
|---|---|---|
| coturn | commit `23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b` (4.18.0) | tag object `000296e7fdb41ed99ca325fcbd19d64404990980` |
| libevent | 2.1.12-stable tarball | sha256 `92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb` |
| OpenSSL | system / distro existing | **no install**; lab records the version actually used |
| Python | 3.x stdlib only | harness has no third-party deps |

Bulk source, binaries, private configs, and logs stay in scratch
(`/tmp/hs-finish-20261013/relay-lab` or the CI `runner.temp`) and are **not**
vendored into git. Source checkout stays under 100 MiB.

## Layout

```
relay-lab/
  patches/0001-auth-lifetime-cap.patch   # license-attributed source diff
  harness/run_expiry_lab.py              # real-socket scenario runner
  harness/turn_protocol.py               # STUN/TURN codec + long-term auth
  scripts/fetch-coturn.sh                # pinned fetch + sha256 check
  scripts/build-lab.sh                   # strict apply/check + 3 binaries
  scripts/run-lab.sh                     # stock/patched/clockfault scenarios
  README.md
  BUILD-REPORT.md
```

## Binaries produced by `build-lab.sh`

| Binary | Meaning |
|---|---|
| `turnserver-stock` | unpatched baseline (defect reproduction) |
| `turnserver-patched` | lifecycle patch + fail-closed monotonic clock |
| `turnserver-clockfault` | test-only `TURN_TEST_CLOCK_FAULT` compile-time seam |

`turnserver-clockfault` is **fault injection**, not OS clock-fault acceptance.
No host clock mutation, no runtime bypass, no exported public hook.

## Security properties under test

1. Frozen absolute authorization deadline on `CLOCK_MONOTONIC` (ms).
2. Refresh / wall-clock rollback cannot re-grant the initial duration.
3. Last-fraction Refresh does not get a fresh full lifetime.
4. Allocation timer destroys the relay at the bound (sub-second capable).
5. Clock fault / missing `CLOCK_MONOTONIC` **denies** new/renewed authority
   (sentinel, never deadline-0 unlimited, never `time(NULL)` fallback).
6. REST remaining duration uses checked narrowing (no int wrap to “unlimited”).
7. TLS is CA-pinned (`CERT_REQUIRED` + hostname check). No `CERT_NONE`.

## How to run

```bash
# scratch root (defaults shown)
export LAB_ROOT=/tmp/hs-finish-20261013/relay-lab
./relay-lab/scripts/fetch-coturn.sh
./relay-lab/scripts/build-lab.sh
./relay-lab/scripts/run-lab.sh
```

Or a single scenario:

```bash
python3 relay-lab/harness/run_expiry_lab.py \
  --mode lastfraction \
  --turnserver-bin "$LAB_ROOT/bin/turnserver-patched" \
  --out /tmp/lastfraction.json
```

Modes: `accelerated` (15s auth), `boundary60` (real 60s), `lastfraction`
(fresh-window 0.3s-before-boundary Refresh), `clockfault` (fault injection).

## Secrets

REST shared secrets are generated per run into 0600 scratch files and passed
via config/env. Console/argv/fixtures/reports carry **metadata only**
(timestamps, lifetimes, ports, hashes) — never passwords or HMAC keys.

## License

Patch retains upstream SPDX / BSD-3-Clause headers from coturn. Upstream
license: BSD-3-Clause (coturn), BSD-3-Clause (libevent).
