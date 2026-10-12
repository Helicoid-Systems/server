#Requires -Version 5.1
<#
.SYNOPSIS
  Disposable literal-loopback hs-server development fixture for Helicoid.

.DESCRIPTION
  Selects a fresh missing database directory path under an existing parent,
  runs hs-server init + bootstrap with a fixed development manager identity
  (dev-manager-key), then serves on 127.0.0.1:8787 in the foreground until
  Ctrl+C.

  Credential-store directory creation is owned by hs-server init (exclusive
  held nofollow protected current-user-owner creation). This launcher never
  creates that folder with New-Item and never mutates an existing folder's
  owner or ACL.

  Scope and safety contract (this script does none of the following):
    - no Windows service install
    - no elevation / RunAsAdministrator
    - no ExecutionPolicy bypass or policy change
    - no firewall or network exposure
    - no non-loopback bind
    - no automatic scope / access / authority creation after bootstrap
    - no deletion of the disposable database directory
    - no logging of password, bootstrap token, or bearer tokens

  Secret handling (best effort, see also windows-tester.md):
    - password is prompted with Read-Host -AsSecureString (input hidden)
    - password reaches hs-server only via redirected stdin (--password-stdin),
      never on the process command line
    - init bootstrap token is captured from stdout in memory and passed to
      bootstrap via the HS_BOOTSTRAP_TOKEN environment variable for that call
      only (not argv, not a file, not written to the console)
    - references are cleared after use

  PowerShell limitation (not fixed here): .NET managed strings cannot be
  reliably zeroized. Clearing variables drops references only. This script does
  NOT claim secrets are zeroized.

.PARAMETER ServerExe
  Path to hs-server.exe. Defaults to hs-server.exe next to this script.

.PARAMETER ParentDirectory
  Parent folder for the disposable database directory. Defaults to the
  current user temp directory.
#>
[CmdletBinding()]
param(
    [string]$ServerExe,
    [string]$ParentDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fixed development fixture values. Bootstrap approves exactly this manager
# identity so Helicoid Manager can sign in with the same value.
$script:ManagerIdentity = 'dev-manager-key'
$script:FriendlyName = 'Helicoid Windows development fixture'
$script:Username = 'admin'
$script:BindAddress = '127.0.0.1:8787'
$script:MinPasswordLength = 12

function Get-PlainTextFromSecureString {
    param([Parameter(Mandatory = $true)][securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Resolve-ServerExePath {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "hs-server.exe not found at: $Explicit"
        }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $nextToScript = Join-Path $PSScriptRoot 'hs-server.exe'
    if (Test-Path -LiteralPath $nextToScript) {
        return (Resolve-Path -LiteralPath $nextToScript).Path
    }
    throw "hs-server.exe not found next to this script ($nextToScript). Pass -ServerExe or place hs-server.exe beside start-development.ps1."
}

function Select-DisposableDatabaseDirectoryPath {
    <#
    .SYNOPSIS
      Choose a fresh missing disposable credential-store directory path.

    .DESCRIPTION
      Chooses a unique missing path under an existing parent. Does NOT create
      the folder. hs-server init creates the final store directory through
      its exclusive held nofollow protected current-user-owner creation.
      Refuses any existing path and never repairs, deletes, or re-ACLs user
      files on collision.
    #>
    param([string]$Parent)
    if (-not $Parent) {
        $Parent = [System.IO.Path]::GetTempPath()
    }
    if (-not (Test-Path -LiteralPath $Parent)) {
        throw "Parent directory does not exist: $Parent"
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $unique = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $name = "helicoid-hs-server-$stamp-$unique"
    $dir = Join-Path $Parent $name
    if (Test-Path -LiteralPath $dir) {
        throw "Disposable directory already exists (refusing to reuse; not repaired): $dir"
    }
    # Path chosen only; folder stays absent until hs-server init creates it.
    return $dir
}

function Read-DevelopmentPassword {
    while ($true) {
        $secure = Read-Host -AsSecureString -Prompt 'Password (>= 12 characters; input is hidden and is not logged)'
        try {
            $plain = Get-PlainTextFromSecureString -Secure $secure
        }
        finally {
            $secure.Dispose()
        }
        if ([string]::IsNullOrEmpty($plain)) {
            Write-Host 'Password must not be empty.'
            continue
        }
        if ($plain.Length -lt $script:MinPasswordLength) {
            Write-Host ("Password must be at least {0} characters. Try again." -f $script:MinPasswordLength)
            continue
        }
        if ($plain.Length -gt 256) {
            Write-Host 'Password must be at most 256 characters. Try again.'
            continue
        }
        return $plain
    }
}

function Invoke-HsServerInit {
    param([string]$Exe, [string]$DbPath)
    # Capture stdout (contains the single-use token). Stderr is left on the
    # console for real errors and never includes the token.
    $output = & $Exe --data $DbPath init | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "hs-server init failed with exit code $exitCode (stdout was not shown because it may contain a one-time token)."
    }
    return $output
}

function Get-BootstrapTokenFromInitOutput {
    param([string]$InitOutput)
    $lines = $InitOutput -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'single-use bootstrap token') {
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                $candidate = $lines[$j].Trim()
                if ($candidate.Length -gt 0) {
                    # URL-safe base64 token from hs-server crypto (32 bytes => 43 chars).
                    if ($candidate -notmatch '^[A-Za-z0-9_-]{20,}$') {
                        throw 'init succeeded but the bootstrap token line was not in the expected format.'
                    }
                    return $candidate
                }
            }
            throw 'init succeeded but no bootstrap token line was found.'
        }
    }
    throw 'init succeeded but the bootstrap token header was not found in output.'
}

function Invoke-HsServerBootstrap {
    param(
        [string]$Exe,
        [string]$DbPath,
        [string]$Password
    )
    # Child-only environment and raw UTF-8 stdin; preserve the caller's
    # environment and encoding in Windows PowerShell 5.1 and PowerShell 7.
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Exe
    $info.Arguments = '--data "{0}" bootstrap --username "{1}" --password-stdin --manager-public-identity "{2}" --manager-friendly-name "{3}"' -f $DbPath, $script:Username, $script:ManagerIdentity, $script:FriendlyName
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['HS_BOOTSTRAP_TOKEN'] = $script:BootstrapToken
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $bytes = $null
    try {
        if (-not $process.Start()) { throw 'Could not start bootstrap.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $bytes = [Text.Encoding]::UTF8.GetBytes($Password + "`n")
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            throw 'Bootstrap exceeded its 15-second deadline.'
        }
        # Capture both streams without echoing possible secret material.
        $null = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "hs-server bootstrap failed with exit code $($process.ExitCode)."
        }
    }
    finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $info.EnvironmentVariables.Remove('HS_BOOTSTRAP_TOKEN')
        $process.Dispose()
    }
}

function Show-DevelopmentInstructions {
    param([string]$DbDirectory, [string]$DbPath)
    Write-Host ''
    Write-Host '================================================================'
    Write-Host ' Helicoid hs-server development fixture (literal loopback only)'
    Write-Host '================================================================'
    Write-Host ("  Address:           http://{0}" -f $script:BindAddress)
    Write-Host ("  Manager identity:  {0}" -f $script:ManagerIdentity)
    Write-Host ("  Username:          {0}" -f $script:Username)
    Write-Host ''
    Write-Host '  Password and bootstrap token are not printed or logged.'
    Write-Host '  PowerShell cannot guarantee managed-string zeroization;'
    Write-Host '  see windows-tester.md for exact limitations.'
    Write-Host ''
    Write-Host '  Helicoid Manager (development server mode):'
    Write-Host '    .\Helicoid.Manager.exe --development-server --development-manager-identity dev-manager-key'
    Write-Host '    or with an explicit loopback address:'
    Write-Host '    .\Helicoid.Manager.exe --development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key'
    Write-Host ''
    Write-Host '  Inventory is empty until an administrator explicitly creates'
    Write-Host '  access scopes. This script does not create scopes or authority.'
    Write-Host ''
    Write-Host '  Stop the server with Ctrl+C (foreground). No service is installed.'
    Write-Host ("  Disposable database (never deleted automatically):")
    Write-Host ("    {0}" -f $DbPath)
    Write-Host ("    directory: {0}" -f $DbDirectory)
    Write-Host '================================================================'
    Write-Host ''
}

# --- main -----------------------------------------------------------------

$serverExePath = Resolve-ServerExePath -Explicit $ServerExe
$dbDirectory = Select-DisposableDatabaseDirectoryPath -Parent $ParentDirectory
$dbPath = Join-Path $dbDirectory 'hs-server.db'
if (Test-Path -LiteralPath $dbPath) {
    throw "Refusing existing database file: $dbPath"
}

Write-Host ("Using hs-server: {0}" -f $serverExePath)
Write-Host ("Disposable database directory: {0}" -f $dbDirectory)
Write-Host 'Literal loopback bind only (127.0.0.1). No service, no firewall changes.'

$password = Read-DevelopmentPassword
$initOutput = $null
$script:BootstrapToken = $null

try {
    $initOutput = Invoke-HsServerInit -Exe $serverExePath -DbPath $dbPath
    $script:BootstrapToken = Get-BootstrapTokenFromInitOutput -InitOutput $initOutput
    # Drop the full init capture (contains the token) as soon as parsed.
    $initOutput = $null

    $null = Invoke-HsServerBootstrap -Exe $serverExePath -DbPath $dbPath -Password $password
    Write-Host 'Bootstrap complete. Starting HTTP server in the foreground.'
}
catch {
    # Never echo password or token. Drop references before rethrowing.
    $password = $null
    $initOutput = $null
    $script:BootstrapToken = $null
    throw
}

# Best-effort reference clearing only. Managed strings may persist until GC.
$password = $null
$initOutput = $null
$script:BootstrapToken = $null
Remove-Variable -Name password, initOutput -ErrorAction SilentlyContinue
[GC]::Collect()

Show-DevelopmentInstructions -DbDirectory $dbDirectory -DbPath $dbPath

# Foreground serve so Ctrl+C stops the server (Ctrl+C reaches this process tree).
& $serverExePath --data $dbPath serve --bind $script:BindAddress
exit $LASTEXITCODE
