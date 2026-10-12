# Installer package targets — v1

Server-owned bounded contract for typed, target-bound installer package
verification. This document freezes platform strings and the portable artifact
path namespace. It does **not** enable Windows or macOS installation.

## Trusted target

Verification is bound to a trusted `InstallerTarget` supplied by the caller.

Provenance (clarified):

- The **verifier never infers** the target from the untrusted package
  `platform` field, and never from its own local OS.
- A trusted **server or native caller** selects the target. That selection may
  legitimately use **authenticated target-host or preflight platform facts**
  (for example, SSH preflight of a remote Linux host, or a native Windows/Mac
  wizard choosing its own platform). Those facts are trusted inputs to the
  caller, not values the verifier reads from the package.
- Remote/native setup is therefore not obstructed: the caller passes the
  chosen `InstallerTarget`; the verifier only checks the package matches it.

| `InstallerTarget` | Frozen `platform` string | OS | Arch |
| --- | --- | --- | --- |
| `LinuxX86_64` | `linux-x86_64` | linux | x86_64 |
| `WindowsX86_64` | `windows-x86_64` | windows | x86_64 |
| `MacosArm64` | `macos-arm64` | macos | arm64 |
| `MacosX86_64` | `macos-x86_64` | macos | x86_64 |

These four strings are frozen. Existing packages already use `linux-x86_64`
and `windows-x86_64`. Intel macOS is spelled `macos-x86_64` (not
`macos-x86-64`, `darwin-x86_64`, or `macos-intel`). Apple silicon is
`macos-arm64`.

Rules:

- Exact match between the package `platform` string and the trusted target's
  frozen string is required.
- Unknown platform strings refuse.
- A known string for a different target refuses (target mismatch).
- A known string with the same OS and a different architecture refuses
  (architecture mismatch).
- The default Linux entry point (`verify_manifest`) is bound to
  `LinuxX86_64` and still rejects Windows and macOS packages.

## Trust

Every supported target uses the **same** independently supplied Ed25519 trust
key:

- Signature over `manifest.json` is checked with strict Ed25519 verification
  (`verify_strict`), matching the server's device-proof path.
- Weak (small-order) verifying keys refuse.
- Weak/noncanonical signatures refuse.
- Valid signatures from the independent trust key continue to verify.
- Format version remains `1`. Artifact size/hash bounds, no-symlink and
  unknown-file guards are unchanged.

## Version and schema metadata floors

`min_installer_version` is strict `major.minor.patch` decimal: exactly three
components, digits only, no leading zeros, no overflow. Malformed values
refuse — they are **never** coerced to zero (that would look like “no floor”).

`min_schema_version` must be an integer in `[1, SCHEMA_VERSION]`. Non-positive
floors refuse. This is a package-metadata compatibility check only; it does
**not** introduce update, rollback, recovery, or security-floor semantics, and
does not change wire shapes.

## Portable artifact namespace

Declared artifact paths are package-relative, bounded, slash-separated,
lowercase ASCII. Host `Path::components` alone is not sufficient: a Windows
target package may be verified on macOS or Linux before transfer, so backslash
traversal, drive/UNC/ADS names and Windows aliases must be refused here.

Each path:

- is non-empty and at most 256 bytes;
- is relative (no leading `/`);
- is ASCII and uses only `/` as separator (no `\`);
- contains no `:`, NUL, or uppercase ASCII;
- starts with `artifacts/`;
- has at most 16 segments; each segment is at most 64 bytes;
- has no empty segment, `.` segment, or `..` segment;
- has no segment ending in `.` or space;
- has segments drawn from `a`–`z`, `0`–`9`, `.`, `_`, `-`;
- has no Windows reserved DOS basename (with or without extension):
  `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.

Declared artifacts also:

- have unique paths (no duplicates);
- do not collide as file vs directory prefix (no `artifacts/a` together with
  `artifacts/a/b`).

These path guards run **before** any affected artifact is opened. Existing
Linux fixture nested names (`artifacts/hs-server`, `artifacts/hs-server.service`,
`artifacts/sub/dir/file`) remain valid.

Unknown-file detection walks `artifacts/` recursively: every leaf must be a
declared path. Directories are descended only when they are a path prefix of a
declared artifact, and never through a symlink (symlinked parents of declared
artifacts are already refused by the artifact symlink-parent guard).

## Non-goals

- Windows/macOS installation, Service Management/SCM/systemd runtime
- Manifest `format_version` bump or automatic data migration
- CLI/wizard wire-shape changes
- Signing, release, security floors/rollback/recovery verification
