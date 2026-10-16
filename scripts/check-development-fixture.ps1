#Requires -Version 5.1
# CI proof for the actual disposable launcher helpers; no interactive prompts.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'start-development.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Development launcher has syntax errors.' }
# Load only the function declarations, without executing the interactive main.
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $statement.Extent.Text
    }
}

# Non-credential fixture creation only (copied batch child). Isolated from
# credential-store path selection; no store data is written here. Credential
# store paths stay absent until hs-server init creates them privately.
function New-NonCredentialFixtureDirectory {
    param([string]$Parent)
    if (-not $Parent) {
        $Parent = [System.IO.Path]::GetTempPath()
    }
    if (-not (Test-Path -LiteralPath $Parent)) {
        throw "Parent directory does not exist: $Parent"
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $unique = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $name = "helicoid-batch-fixture-$stamp-$unique"
    $dir = Join-Path $Parent $name
    if (Test-Path -LiteralPath $dir) {
        throw "Fixture directory already exists (refusing to reuse): $dir"
    }
    New-Item -ItemType Directory -Path $dir | Out-Null
    return $dir
}

# Actual native Windows ACL proof (Get-Acl). Source AST parse does not prove ACL.
function Assert-PrivateStoreDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Store directory was not created by hs-server init: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentUserSid) {
        throw 'Could not resolve the current process user SID.'
    }
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $ownerSid -or $ownerSid.Value -ne $currentUserSid.Value) {
        throw "Store directory owner is not the current user; refusing: $Path"
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw "Store directory DACL is not protected; refusing: $Path"
    }
    $trustedSids = @(
        $currentUserSid.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($trustedSids -notcontains $ruleSid) {
            throw "Store directory has an untrusted allow SID ($ruleSid); refusing: $Path"
        }
    }
}

# Run the actual check-login CLI over private UTF-8 stdin. Streams are
# captured for bounded assertions and are never echoed (no secret output).
function Invoke-HsServerCheckLogin {
    param(
        [string]$Exe,
        [string]$DbPath,
        [string]$Password
    )
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Exe
    $info.Arguments = '--data "{0}" check-login --username admin --password-stdin' -f $DbPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $bytes = $null
    try {
        if (-not $process.Start()) { throw 'Could not start login check.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $bytes = [Text.Encoding]::UTF8.GetBytes($Password + "`n")
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            throw 'Login check exceeded its 15-second deadline.'
        }
        $outText = $stdout.GetAwaiter().GetResult()
        $errText = $stderr.GetAwaiter().GetResult()
        return @{
            ExitCode = $process.ExitCode
            Stdout = $outText
            Stderr = $errText
        }
    }
    finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $process.Dispose()
    }
}

# Safe denial markers from the actual CLI (AppError Display on stderr).
$script:MfaRequiredDenial = 'multi-factor authentication is required; password-only login is refused'
$script:InvalidCredentialsDenial = 'invalid credentials'

# Assert a captured check-login result without dumping secret or raw output.
function Assert-CheckLoginDenial {
    param(
        [hashtable]$Result,
        [string]$ExpectedDenial,
        [string]$ForbiddenDenial,
        [string]$Password,
        [string]$CaseName
    )
    if ($Result.ExitCode -eq 0) {
        throw "$CaseName : check-login must not exit 0 under mandatory MFA / failed credentials."
    }
    if ($Result.Stdout.Contains('login ok')) {
        throw "$CaseName : check-login must not print 'login ok'."
    }
    if (-not $Result.Stderr.Contains($ExpectedDenial)) {
        throw "$CaseName : expected safe denial was not present on stderr."
    }
    if ($Result.Stderr.Contains($ForbiddenDenial)) {
        throw "$CaseName : denial must be distinct from the other failure mode."
    }
    if ($Result.Stdout.Contains($Password) -or $Result.Stderr.Contains($Password)) {
        throw "$CaseName : captured output must not contain the password."
    }
    # Bounded diagnostic shape: the safe AppError line only.
    if ($Result.Stderr.Length -gt 256 -or $Result.Stdout.Length -gt 256) {
        throw "$CaseName : captured output exceeded the bounded diagnostic size."
    }
}

$script:Username = 'admin'
$script:ManagerIdentity = 'dev-manager-key'
$script:FriendlyName = 'CI development fixture'
$exe = (Resolve-Path 'target/release/hs-server.exe').Path
$directory = Select-DisposableDatabaseDirectoryPath
if (Test-Path -LiteralPath $directory) {
    throw 'Chosen store path must be initially absent.'
}
$database = Join-Path $directory 'hs-server.db'
$password = 'fixture-' + [guid]::NewGuid().ToString('N') + [char]0xE9 + [char]0x6F22
$output = Invoke-HsServerInit -Exe $exe -DbPath $database
# hs-server init must create the protected current-user store directory.
Assert-PrivateStoreDirectory -Path $directory
$script:BootstrapToken = Get-BootstrapTokenFromInitOutput -InitOutput $output
$output = $null
$priorEnvironment = [Environment]::GetEnvironmentVariable('HS_BOOTSTRAP_TOKEN')
Invoke-HsServerBootstrap -Exe $exe -DbPath $database -Password $password
if ([Environment]::GetEnvironmentVariable('HS_BOOTSTRAP_TOKEN') -cne $priorEnvironment) {
    throw 'Bootstrap modified the caller environment.'
}
# Correct Unicode password reaches password verification, then the
# mandatory administrator MFA gate: nonzero safe MFA-required denial.
# Wrong Unicode password stays a credentials failure, distinct from MFA.
# Neither path mints a session; stdout/stderr are captured, never dumped.
$correctLogin = Invoke-HsServerCheckLogin -Exe $exe -DbPath $database -Password $password
Assert-CheckLoginDenial -Result $correctLogin -ExpectedDenial $script:MfaRequiredDenial `
    -ForbiddenDenial $script:InvalidCredentialsDenial -Password $password `
    -CaseName 'correct Unicode password'
$correctLogin = $null

$wrongPassword = 'fixture-wrong-' + [guid]::NewGuid().ToString('N') + [char]0xE9 + [char]0x6F22
try {
    $wrongLogin = Invoke-HsServerCheckLogin -Exe $exe -DbPath $database -Password $wrongPassword
    Assert-CheckLoginDenial -Result $wrongLogin -ExpectedDenial $script:InvalidCredentialsDenial `
        -ForbiddenDenial $script:MfaRequiredDenial -Password $wrongPassword `
        -CaseName 'wrong Unicode password'
    $wrongLogin = $null
}
finally {
    $wrongPassword = $null
}
# The same real helper must refuse reused bootstrap, without leaking output.
$rejected = $false
try { Invoke-HsServerBootstrap -Exe $exe -DbPath $database -Password $password }
catch { $rejected = $true }
if (-not $rejected) { throw 'Repeated bootstrap was accepted.' }
$script:BootstrapToken = $null
$password = $null
Write-Host 'Windows PowerShell: launcher parse, absent store path, private store ACL, Unicode stdin bootstrap, mandatory MFA denial vs invalid-credentials, caller environment and single-use denial PASS.'
# Exercise the actual batch launcher against a failing local child. This proves
# exit propagation and retained diagnostics; interactive Explorer behavior is
# still a user-PC check. The copied child contains no credentials or server.
$batchDirectory = New-NonCredentialFixtureDirectory
$batch = Join-Path $batchDirectory 'start-development.cmd'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'start-development.cmd') -Destination $batch
[IO.File]::WriteAllText((Join-Path $batchDirectory 'start-development.ps1'),
    "Write-Output 'HELICOID_FIXTURE_CHILD_FAILURE'`r`nexit 7`r`n", [Text.Encoding]::ASCII)
$batchInfo = New-Object Diagnostics.ProcessStartInfo
$batchInfo.FileName = $env:ComSpec
$batchInfo.Arguments = '/d /c ""{0}""' -f $batch
$batchInfo.UseShellExecute = $false
$batchInfo.RedirectStandardInput = $true
$batchInfo.RedirectStandardOutput = $true
$batchInfo.RedirectStandardError = $true
$batchProcess = New-Object Diagnostics.Process
$batchProcess.StartInfo = $batchInfo
try {
    if (-not $batchProcess.Start()) { throw 'Could not start batch launcher proof.' }
    $batchOut = $batchProcess.StandardOutput.ReadToEndAsync()
    $batchErr = $batchProcess.StandardError.ReadToEndAsync()
    $batchProcess.StandardInput.WriteLine('x')
    $batchProcess.StandardInput.Close()
    if (-not $batchProcess.WaitForExit(15000)) {
        $batchProcess.Kill()
        throw 'Batch launcher proof exceeded its deadline.'
    }
    $visible = $batchOut.GetAwaiter().GetResult()
    $null = $batchErr.GetAwaiter().GetResult()
    if ($batchProcess.ExitCode -ne 7 -or
        -not $visible.Contains('HELICOID_FIXTURE_CHILD_FAILURE') -or
        -not $visible.Contains('exit 7') -or
        -not $visible.Contains('Press any key')) {
        throw 'Batch launcher lost child failure diagnostics or its exit code.'
    }
}
finally { $batchProcess.Dispose() }
Write-Host 'Windows CMD: real launcher child failure, retained diagnostics and exit-code propagation PASS.'
