# Windows 11 x64 — `hs-server` development server tester instructions

Product: **Helicoid** (Helicoid Systems).  
Apps: **Helicoid Manager** (operator console), **Helicoid Computer** (managed endpoint).  
Server binary: `hs-server.exe` (from this download bundle).  
This is **literal-loopback disposable development only**. It is not a production
installer, not authority, and not a remote-engine claim.

## What you get in this bundle

| File | Purpose |
| --- | --- |
| `hs-server.exe` | Coordination server (local accounts, manager enrollment, scoped inventory) |
| `start-development.cmd` | Double-click launcher; retains errors without changing execution policy |
| `start-development.ps1` | Disposable fixture launcher (review it before running) |
| `windows-tester.md` | This document |

## Prerequisites

- Windows 11 x64
- Windows PowerShell 5.1 or PowerShell 7+ (`pwsh`)
- The Helicoid Manager Windows build (for the sign-in UI test)
- Permission to run a reviewed local script under **your** execution policy
  (this script does **not** bypass execution policy and does **not** elevate)

If your policy blocks script execution, use the **manual CLI steps** below
instead of weakening policy for this fixture.

## Safety contract

`start-development.ps1` and the manual steps below:

- create a **fresh unique disposable** database directory and refuse any existing DB
- bind **literal loopback only** (`127.0.0.1:8787`)
- do **not** install a Windows service
- do **not** require elevation
- do **not** change ExecutionPolicy
- do **not** open firewall ports or expose the network
- do **not** auto-create access scopes or authority after bootstrap
- do **not** delete the disposable database directory (delete it yourself later)
- do **not** log password, bootstrap token, or bearer tokens

## Quick start (script)

1. Download and unzip the bundle to a local folder.
2. Double-click `start-development.cmd`. It opens PowerShell, runs the fixture,
   and waits for a key after the server stops or an error occurs. It changes no
   execution policy and requests no administrator access.
3. Alternatively, open an existing PowerShell window in that folder and run:

```powershell
.\start-development.ps1
```

Optional parameters:

```powershell
.\start-development.ps1 -ServerExe 'C:\path\to\hs-server.exe'
.\start-development.ps1 -ParentDirectory 'C:\path\to\disposable-parent'
```

4. When prompted, enter a password of **at least 12 characters**. Input is
   hidden. The password is passed to the server only through stdin, never as a
   command-line argument.
5. The script prints connection details (address, manager identity, username)
   and starts the server in the **foreground**.
6. Stop the server with **Ctrl+C**. There is no service to uninstall.

### Launch Helicoid Manager

While the server is running, start the manager in development-server mode:

```powershell
.\Helicoid.Manager.exe --development-server --development-manager-identity dev-manager-key
```

Explicit loopback address form:

```powershell
.\Helicoid.Manager.exe --development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key
```

| Value | Meaning |
| --- | --- |
| `http://127.0.0.1:8787` | Literal loopback address of `hs-server` |
| `dev-manager-key` | Fixed development manager identity approved at bootstrap |
| `admin` | Fixed fixture username (password is the one you entered) |

Sign in with username `admin` and the password you chose. Inventory will be
**empty** until an administrator explicitly creates access scopes. This fixture
does not create those scopes for you.

## Manual CLI steps (no script)

Use these if you prefer not to run PowerShell scripts, or if policy blocks them.
Same safety rules apply. Do not put the password or bootstrap token on the
command line.

```powershell
# 1. Fresh disposable directory (never reuse an existing DB directory)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$unique = [guid]::NewGuid().ToString('N').Substring(0, 8)
$dbDir = Join-Path $env:TEMP "helicoid-hs-server-$stamp-$unique"
New-Item -ItemType Directory -Path $dbDir | Out-Null
$db = Join-Path $dbDir 'hs-server.db'

# 2. Init — prints a single-use bootstrap token ONCE (stdout).
#    Capture it in memory. Do not paste it into logs, chat, or screenshots.
.\hs-server.exe --data $db init
#    (token appears after the 'single-use bootstrap token' header)

# 3. Bootstrap — token via environment (not argv), password via stdin (not argv)
$env:HS_BOOTSTRAP_TOKEN = '<token-from-init>'
$secure = Read-Host -AsSecureString -Prompt 'Password (>= 12 characters)'
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
if ($pw.Length -lt 12) { throw 'Password must be at least 12 characters.' }

# UTF-8 without BOM so --password-stdin receives valid UTF-8
$prev = $OutputEncoding
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
try {
    $pw | .\hs-server.exe --data $db bootstrap `
        --username admin `
        --password-stdin `
        --manager-public-identity dev-manager-key `
        --manager-friendly-name 'Helicoid Windows development fixture'
}
finally {
    $OutputEncoding = $prev
    Remove-Item Env:HS_BOOTSTRAP_TOKEN -ErrorAction SilentlyContinue
}
$pw = $null   # drop reference only; managed strings are not zeroized

# 4. Serve foreground — Ctrl+C stops the server
.\hs-server.exe --data $db serve --bind 127.0.0.1:8787
```

Then launch Helicoid Manager as shown in the quick start.

## What the server CLI can and cannot do

| Command | Notes |
| --- | --- |
| `hs-server --data <db> init` | Creates schema in a new DB file; prints one bootstrap token |
| `hs-server --data <db> bootstrap` | Creates first admin; optional `--manager-public-identity` |
| `hs-server --data <db> serve --bind 127.0.0.1:8787` | Foreground HTTP; non-loopback binds are refused |
| `hs-server --data <db> check-login` | Verifies credentials without starting HTTP |

Useful flags for bootstrap:

| Flag | Purpose |
| --- | --- |
| `--password-stdin` | Read password from stdin (preferred; avoids argv) |
| `--token` / `HS_BOOTSTRAP_TOKEN` | Single-use bootstrap token (prefer env var over argv) |
| `--manager-public-identity` | Manager identity to approve at bootstrap only |
| `--username` | Administrator username |

Do **not** use `--password` or `--token` on shared machines: command lines are
visible to other processes.

## Secret-handling limitations (honest)

| Secret | How it is handled | Residual risk |
| --- | --- | --- |
| Account password | Prompted as `SecureString`; sent to `hs-server` on stdin only | .NET managed strings are **not** zeroized; references are dropped and GC is requested |
| Bootstrap token | Captured from `init` stdout in memory; passed to `bootstrap` via `HS_BOOTSTRAP_TOKEN` for that call only | Lives in process memory / that child environment until cleared; never written to disk or logs by these steps |
| Bearer session tokens | Held by Helicoid Manager / `hs-server` in memory; stored hashed on the server | Not printed by this fixture |

The script clears variables on a best-effort basis and requests a GC. It does
**not** claim secrets are zeroized. Process dumps, debuggers, or a compromised
same-user session can still read secrets while they are alive.

## Out of scope (this fixture)

- Production installers, services, TLS, LAN exposure
- Cryptographic manager or computer identities (`dev-manager-key` is a
  **loopback development fixture**, not a signed endpoint key)
- Remote control / screen observation / remote engine
- MFA, file jobs, security recovery, authority cutover
- Automatic access-scope creation (inventory stays empty until you create scopes)
- Automatic cleanup of the disposable database directory

## Cleanup

When finished:

1. Stop the server with Ctrl+C.
2. Delete the disposable directory printed by the script
   (under `%TEMP%\helicoid-hs-server-...` by default).
3. Close both Helicoid apps and delete their extracted folders and the extracted
   server folder. These builds install no service and need no administrator uninstall.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Double-clicking the `.ps1` opens an editor or its window closes | Use `start-development.cmd`, or run `./start-development.ps1` from an existing PowerShell window so errors stay visible. |
| Script will not run | Execution policy may block it. Inspect the script and use the manual CLI steps, or your org's approved way to run a local script. Do not use `-ExecutionPolicy Bypass` for this fixture. |
| `hs-server.exe not found` | Put `hs-server.exe` beside `start-development.ps1`, or pass `-ServerExe` |
| `Refusing existing database` | The directory/DB must be new. Choose a different `-ParentDirectory` or delete the leftover yourself after confirming it is disposable |
| Manager sign-in fails with pending/revoked manager | Use the same identity `dev-manager-key` that bootstrap approved |
| Inventory empty | Expected. Create access scopes explicitly as an administrator; this fixture does not |
| Port already in use | Another process holds `127.0.0.1:8787`. Stop it, or use the manual steps with a different loopback port and pass that address to Helicoid Manager |
| Non-loopback bind error | The server refuses anything except `127.0.0.1` / `::1`. That is intentional |
