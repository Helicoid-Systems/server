#Requires -Version 5.1
# Read-only bounded native Windows ACL/ancestry diagnostic.
# Collects owner-class and ACE flag metadata for a disposable GUID temp
# directory and its path ancestors. This is NOT runtime acceptance of any
# store ACL policy. It never mutates ACLs, settings, or host state beyond
# one empty GUID directory under [IO.Path]::GetTempPath(), which is deleted
# non-recursively only when it has zero children.
# Output is intentionally bounded: component index, owner CLASS, ACE kind,
# mask, inherit and propagation flags only. No paths, account names, raw
# user SIDs, environment values, or file contents are printed.
$ErrorActionPreference = 'Stop'

$script:MaxComponents = 32
$script:MaxAcesPerComponent = 64

function New-KnownSid {
    param([System.Security.Principal.WellKnownSidType]$WellKnown)
    return New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
        $WellKnown, $null)
}

function Get-KnownSidCatalog {
    # Exact known SID constants only. Current process SID comes from
    # WindowsIdentity; remaining classes use verified well-known SID types
    # or the documented TrustedInstaller service SID. Unknown principals
    # are never emitted as identifiers; they classify as Other.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $current = $identity.User
    }
    finally {
        $identity.Dispose()
    }
    if ($null -eq $current) {
        throw 'WindowsIdentity current user SID is unavailable.'
    }
    # Verified exact NT SERVICE TrustedInstaller service SID constant.
    $trustedInstaller = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $catalog = New-Object 'System.Collections.Generic.List[object]'
    $catalog.Add(@{
        Class = 'CurrentUser'
        Sid = $current
    })
    $catalog.Add(@{
        Class = 'System'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid)
    })
    $catalog.Add(@{
        Class = 'Administrators'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
    })
    $catalog.Add(@{
        Class = 'TrustedInstaller'
        Sid = $trustedInstaller
    })
    $catalog.Add(@{
        Class = 'Users'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::BuiltinUsersSid)
    })
    $catalog.Add(@{
        Class = 'Everyone'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::WorldSid)
    })
    $catalog.Add(@{
        Class = 'AuthenticatedUsers'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid)
    })
    $catalog.Add(@{
        Class = 'CreatorOwner'
        Sid = New-KnownSid -WellKnown (
            [System.Security.Principal.WellKnownSidType]::CreatorOwnerSid)
    })
    return $catalog
}

function Get-OwnerClass {
    param(
        [System.Security.Principal.SecurityIdentifier]$Sid,
        [object[]]$Catalog
    )
    if ($null -eq $Sid) {
        return 'Other'
    }
    foreach ($entry in $Catalog) {
        if ($Sid.Equals($entry.Sid)) {
            return $entry.Class
        }
    }
    return 'Other'
}

function Format-InheritFlags {
    param([System.Security.AccessControl.InheritanceFlags]$Flags)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($Flags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        $parts.Add('CI')
    }
    if ($Flags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) {
        $parts.Add('OI')
    }
    if ($parts.Count -eq 0) {
        return 'none'
    }
    return ($parts -join '|')
}

function Format-PropagateFlags {
    param([System.Security.AccessControl.PropagationFlags]$Flags)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($Flags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
        $parts.Add('IO')
    }
    if ($Flags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
        $parts.Add('NP')
    }
    if ($parts.Count -eq 0) {
        return 'none'
    }
    return ($parts -join '|')
}

function Get-ComponentAcl {
    param([System.IO.DirectoryInfo]$Component)
    try {
        return Get-Acl -LiteralPath $Component.FullName
    }
    catch {
        throw 'GetAcl failed for an ancestor component; diagnostic aborted.'
    }
}

function Write-ComponentMetadata {
    param(
        [int]$Index,
        [System.IO.DirectoryInfo]$Component,
        [object[]]$Catalog
    )
    $acl = Get-ComponentAcl -Component $Component
    $ownerSid = $null
    try {
        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        throw 'GetOwner failed for an ancestor component; diagnostic aborted.'
    }
    $ownerClass = Get-OwnerClass -Sid $ownerSid -Catalog $Catalog
    $aces = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($aces.Count -gt $script:MaxAcesPerComponent) {
        throw ('Diagnostic bounds exceeded: component has more than {0} ACEs.' -f
            $script:MaxAcesPerComponent)
    }
    Write-Host ('component={0} ownerClass={1} aceCount={2}' -f
        $Index, $ownerClass, $aces.Count)
    for ($aceIndex = 0; $aceIndex -lt $aces.Count; $aceIndex++) {
        $ace = $aces[$aceIndex]
        if ($ace -isnot [System.Security.AccessControl.FileSystemAccessRule]) {
            throw 'Unexpected ACE presentation for filesystem ancestor; diagnostic aborted.'
        }
        $aceSid = $ace.IdentityReference
        $aceClass = Get-OwnerClass -Sid $aceSid -Catalog $Catalog
        $mask = [uint32]([int64]$ace.FileSystemRights -band 0xFFFFFFFFL)
        $inherit = Format-InheritFlags -Flags $ace.InheritanceFlags
        $propagate = Format-PropagateFlags -Flags $ace.PropagationFlags
        $kind = $ace.AccessControlType.ToString()
        Write-Host ('  ace={0} principalClass={1} kind={2} mask=0x{3:X8} inherit={4} propagate={5} inherited={6}' -f
            $aceIndex, $aceClass, $kind, $mask, $inherit, $propagate, $ace.IsInherited)
    }
}

Write-Host 'windows-store-ancestry diagnostic: read-only ACL metadata for a disposable GUID temp directory.'
Write-Host 'This diagnostic is not runtime acceptance of any store ACL policy.'

$createdPath = $null
$diagnosticOk = $false
$diagnosticStage = 'create-temp'
try {
    $guidName = [System.Guid]::NewGuid().ToString('N')
    $createdPath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(), $guidName)
    try {
        $null = [System.IO.Directory]::CreateDirectory($createdPath)
    }
    catch {
        throw 'Failed to create disposable GUID temp directory.'
    }

    $diagnosticStage = 'walk-components'
    $components = New-Object 'System.Collections.Generic.List[System.IO.DirectoryInfo]'
    $walk = New-Object System.IO.DirectoryInfo $createdPath
    while ($null -ne $walk) {
        if ($components.Count -ge $script:MaxComponents) {
            throw ('Diagnostic bounds exceeded: more than {0} path components.' -f
                $script:MaxComponents)
        }
        $components.Add($walk)
        $walk = $walk.Parent
    }
    if ($components.Count -eq 0) {
        throw 'Diagnostic produced zero path components.'
    }

    $diagnosticStage = 'sid-catalog'
    $catalog = Get-KnownSidCatalog
    for ($i = 0; $i -lt $components.Count; $i++) {
        $diagnosticStage = 'component-' + $i
        Write-ComponentMetadata -Index $i -Component $components[$i] -Catalog $catalog
    }

    Write-Host ('diagnostic bounds: components={0} maxComponents={1} maxAcesPerComponent={2} OK' -f
        $components.Count, $script:MaxComponents, $script:MaxAcesPerComponent)
    Write-Host 'diagnostic result: complete (metadata only; no policy change; not runtime acceptance).'
    $diagnosticOk = $true
}
catch {
    # No native exception text: it may include the runner's account/path.
    $errorType = [regex]::Replace($_.Exception.GetType().Name, '[^A-Za-z0-9_]', '')
    $errorType = $errorType.Substring(0, [Math]::Min(64, $errorType.Length))
    Write-Host ('diagnostic result: failed stage={0} errorType={1}' -f $diagnosticStage, $errorType)
    $diagnosticOk = $false
}
finally {
    if ($null -ne $createdPath -and [System.IO.Directory]::Exists($createdPath)) {
        try {
            # Inspect at most one entry; never materialize an unbounded listing.
            $hasEntry = @([System.IO.Directory]::EnumerateFileSystemEntries($createdPath) |
                Select-Object -First 1).Count -ne 0
            if (-not $hasEntry) {
                [System.IO.Directory]::Delete($createdPath, $false)
                Write-Host 'cleanup: non-recursive delete of empty GUID temp directory.'
            }
            else {
                Write-Host 'cleanup: GUID temp directory is not empty; skipped delete.'
                $diagnosticOk = $false
            }
        }
        catch {
            Write-Host 'cleanup: failed for owned GUID temp directory.'
            $diagnosticOk = $false
        }
    }
}

if (-not $diagnosticOk) {
    exit 1
}
exit 0
