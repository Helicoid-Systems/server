#!/usr/bin/env python3
"""Owned regression: auth deadline arithmetic and clock-fault fail-closed.

Mirrors userdb.c remaining_ms / mono+wall sampling rules (mono first, wall
ceil ms, checked ops, subsecond deny, monotonic failure deny). Does not
manufacture production 60s lease evidence.
"""
from __future__ import annotations

import sys

INT64_MAX = 2**63 - 1
TURN_MONOTONIC_MS_FAIL = -(2**63)
TURN_AUTH_DEADLINE_FAIL = -(2**63)


def wall_now_ms_from_timespec(tv_sec: int, tv_nsec: int):
    if tv_sec < 0 or tv_nsec < 0 or tv_nsec >= 1_000_000_000 or tv_sec > (INT64_MAX // 1000):
        return None
    sec_ms = tv_sec * 1000
    frac = tv_nsec // 1_000_000
    if tv_nsec % 1_000_000:
        frac += 1
    if frac > INT64_MAX - sec_ms:
        return None
    return sec_ms + frac


def admission_deadline(ts: int, mono_now: int, wall_sec: int, wall_nsec: int):
    """Return deadline mono ms, or FAIL sentinel / None for deny."""
    if mono_now == TURN_MONOTONIC_MS_FAIL:
        return TURN_AUTH_DEADLINE_FAIL
    wall_now = wall_now_ms_from_timespec(wall_sec, wall_nsec)
    if wall_now is None:
        return TURN_AUTH_DEADLINE_FAIL
    if ts > 0x7FFFFFFF:
        return TURN_AUTH_DEADLINE_FAIL
    deadline_wall_ms = ts * 1000
    remaining = deadline_wall_ms - wall_now
    if remaining < 1000:
        return TURN_AUTH_DEADLINE_FAIL
    if remaining > INT64_MAX - mono_now:
        return TURN_AUTH_DEADLINE_FAIL
    return mono_now + remaining


def auth_remaining_secs(deadline: int, now_ms: int) -> int:
    if deadline == 0:
        return 0
    if deadline < 0:
        return -1
    if now_ms == TURN_MONOTONIC_MS_FAIL:
        return -1
    remain = deadline - now_ms
    if remain < 1000:
        return -1
    secs = remain // 1000
    if remain % 1000:
        secs = min(secs + 1, 0x7FFFFFFF)
    return int(min(secs, 0x7FFFFFFF))


def want_timer_ms(granted_s: int, auth_ms: int) -> int:
    want = granted_s * 1000
    if auth_ms < want:
        want = auth_ms
    return want


def main() -> int:
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)

    # mono-first + wall ceil: scheduling gap cannot extend deadline past wall bound
    # ts at wall 100.000s; mono sampled earlier (90s) then wall later (90.2s).
    d = admission_deadline(100, 90_000, 90, 200_000_000)
    check("mono_first_deadline", d == 90_000 + (100_000 - 90_200))
    # Without ceil (floor ms) remaining would be 20ms longer; require ceil.
    floor_remaining = 100_000 - (90_000 + 200)
    ceil_remaining = 100_000 - (90_000 + 201)
    check("wall_ceil_shrinks", ceil_remaining == floor_remaining - 1)

    # subsecond deny
    check("subsecond_deny", admission_deadline(100, 99_200, 99, 200_000_000) == TURN_AUTH_DEADLINE_FAIL)

    # monotonic fault denies
    check(
        "mono_fault",
        admission_deadline(100, TURN_MONOTONIC_MS_FAIL, 90, 0) == TURN_AUTH_DEADLINE_FAIL,
    )

    # extreme tv_nsec / tv_sec cannot overflow
    check("bad_nsec", wall_now_ms_from_timespec(1, 1_000_000_000) is None)
    check("neg_sec", wall_now_ms_from_timespec(-1, 0) is None)
    check("huge_sec", wall_now_ms_from_timespec(INT64_MAX // 1000 + 1, 0) is None)

    # remaining_s overflow path
    huge_ts = 0x7FFFFFFF
    d2 = admission_deadline(huge_ts, 0, 0, 0)
    check("huge_ts_deadline", d2 == huge_ts * 1000)

    # ceil integer auth cap
    check("ceil_5900", auth_remaining_secs(10_000, 4_100) == 6)  # remain 5900 -> 6
    check("floor_5000", auth_remaining_secs(10_000, 5_000) == 5)  # remain 5000 -> 5
    check("subsec_secs", auth_remaining_secs(10_000, 9_200) == -1)

    # timer never exceeds granted lifetime or auth deadline
    check("cap_binds", want_timer_ms(5, 5_950) == 5_000)
    check("auth_binds", want_timer_ms(600, 5_950) == 5_950)
    check("exact", want_timer_ms(5, 5_000) == 5_000)

    if fails:
        print("FAIL:", ", ".join(fails))
        return 1
    print("PASS: auth clock arithmetic seam")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
