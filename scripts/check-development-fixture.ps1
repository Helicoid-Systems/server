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
$script:Username = 'admin'
$script:ManagerIdentity = 'dev-manager-key'
$script:FriendlyName = 'CI development fixture'
$exe = (Resolve-Path 'target/release/hs-server.exe').Path
$directory = New-DisposableDatabaseDirectory
$database = Join-Path $directory 'hs-server.db'
$password = 'fixture-' + [guid]::NewGuid().ToString('N') + [char]0xE9 + [char]0x6F22
$output = Invoke-HsServerInit -Exe $exe -DbPath $database
$script:BootstrapToken = Get-BootstrapTokenFromInitOutput -InitOutput $output
$output = $null
$priorEnvironment = [Environment]::GetEnvironmentVariable('HS_BOOTSTRAP_TOKEN')
Invoke-HsServerBootstrap -Exe $exe -DbPath $database -Password $password
if ([Environment]::GetEnvironmentVariable('HS_BOOTSTRAP_TOKEN') -cne $priorEnvironment) {
    throw 'Bootstrap modified the caller environment.'
}
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = $exe
$info.Arguments = '--data "{0}" check-login --username admin --password-stdin' -f $database
$info.UseShellExecute = $false
$info.RedirectStandardInput = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$login = New-Object System.Diagnostics.Process
$login.StartInfo = $info
try {
    if (-not $login.Start()) { throw 'Could not start login check.' }
    $stdout = $login.StandardOutput.ReadToEndAsync()
    $stderr = $login.StandardError.ReadToEndAsync()
    $bytes = [Text.Encoding]::UTF8.GetBytes($password + "`n")
    $login.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $login.StandardInput.Close()
    [Array]::Clear($bytes, 0, $bytes.Length)
    if (-not $login.WaitForExit(15000)) { $login.Kill(); throw 'Login check timed out.' }
    $null = $stdout.GetAwaiter().GetResult()
    $null = $stderr.GetAwaiter().GetResult()
    if ($login.ExitCode -ne 0) { throw 'Unicode bootstrap password did not authenticate.' }
}
finally { $login.Dispose() }
# The same real helper must refuse reused bootstrap, without leaking output.
$rejected = $false
try { Invoke-HsServerBootstrap -Exe $exe -DbPath $database -Password $password }
catch { $rejected = $true }
if (-not $rejected) { throw 'Repeated bootstrap was accepted.' }
$script:BootstrapToken = $null
$password = $null
Write-Host 'Windows PowerShell: launcher parse, Unicode stdin bootstrap, caller environment and single-use denial PASS.'
