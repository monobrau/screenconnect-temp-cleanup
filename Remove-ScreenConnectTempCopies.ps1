#Requires -Version 5.1
<#
.SYNOPSIS
    Scans temp folders for stale ScreenConnect copies, old installer files, and
    CVE-2026-84869 / Huntress staging leftovers.

.DESCRIPTION
    Finds leftover ScreenConnect temp folders and installer files (.msi/.exe).
    Scans temp paths, user profile download locations, SystemTemp, and service
    profile temps. Also cleans stale ConnectWise Automate (LTSvc) package cache
    for ScreenConnect when not in use. Also finds ConnectWise-signed .exe/.msi
    installers in user Downloads and Desktop folders (including MSP-branded names like
    RRC.RemoteSupport.Client.exe). Reports installed client versions against the
    CVE-2026-84869 patched build (26.6.5.9742) and looks for Huntress staging IOCs
    from the unauthorized file-transfer/execute campaign. Never deletes an installed
    or in-use ScreenConnect client (Program Files, service binary, or any path that
    belongs to a detected instance ID), including when that client is VULNERABLE.
    Dry-run by default.

.PARAMETER Delete
    Actually remove matched items. Without this switch, only reports findings.
    Never uninstalls or deletes an in-use / installed ScreenConnect client.

.PARAMETER MinAgeHours
    Skip temp folders modified within this many hours (unless -Force).

.PARAMETER MaxInstallerYear
    Remove installer files with LastWriteTime year less than or equal to this value.
    0 (default) means the current calendar year. Does not apply to ConnectWise-signed
    installers found in Downloads or Desktop.

.PARAMETER SkipAutomateCache
    Do not scan or clean C:\Windows\LTSvc\packages ScreenConnect Automate cache.

.PARAMETER SkipBrandedInstallerScan
    Do not scan Downloads/Desktop for ConnectWise-signed installer files.

.PARAMETER SkipCveScan
    Skip the CVE-2026-84869 client advisory and Huntress staging IOC pass.

.PARAMETER Force
    Skip the MinAgeHours folder age check.
#>
[CmdletBinding()]
param(
    [switch]$Delete,
    [int]$MinAgeHours = 24,
    [int]$MaxInstallerYear = 0,
    [switch]$SkipAutomateCache,
    [switch]$SkipBrandedInstallerScan,
    [switch]$SkipCveScan,
    [switch]$Force
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.7.1'

if ($MaxInstallerYear -le 0) {
    $MaxInstallerYear = [datetime]::Now.Year
}

$AutomatePackageNamePattern = 'connectwisecontrol|screenconnect|cwcontrol|connectwise.?control'
$ScreenConnectVersionFolderPattern = '^\d+\.\d+\.\d+\.\d+$'
$ConnectWiseSignerSubjectPattern = '(?i)connectwise|screenconnect'
$PatchedClientVersion = [version]'26.6.5.9742'
$KnownRogueInstanceIds = @('7a4d7d66502d4260')
$CveStagingExactNames = @(
    '1.vbs', '2.vbs', '3.vbs', '4.vbs',
    'map.txt', 'out.enc', 'out.tmp', 'runner.ps1',
    'windowsservicehost.vbs', 'windowsservicehost.bat',
    'pytorchfix.ps1', 'sys_cache.zip'
)
$CveStagingClusterNames = @('1.vbs', '2.vbs', '3.vbs', '4.vbs', 'map.txt', 'out.enc', 'out.tmp', 'runner.ps1', 'value.txt')
$CveMasqueradeNames = @('themes.exe', 'searchindex.exe', 'svcdrv64.sys', 'password.exe')
$script:ProtectedClientRoots = @()
$script:ProtectedActiveInstanceIds = @()

if ($env:OS -notlike '*Windows*' -and -not $IsWindows) {
    Write-Output "ERROR: This script supports Windows endpoints only."
    return
}

$InstanceIdPattern = '[a-f0-9]{16}'
$HashFolderPattern = "^$InstanceIdPattern$"
$ScreenConnectClientFolderPattern = '^ScreenConnect Client \([a-f0-9]{16}\)$'

function New-StringHashSet {
    New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
}

function New-StringList {
    New-Object 'System.Collections.Generic.List[string]'
}

function New-DirectoryInfoList {
    New-Object 'System.Collections.Generic.List[System.IO.DirectoryInfo]'
}

function Write-Result {
    param(
        [string]$Type,
        [string]$Status,
        [string]$Path,
        [string]$Detail = ''
    )

    $line = "[$Type] $Status : $Path"
    if ($Detail) {
        $line += " ($Detail)"
    }

    Write-Output $line
}

function Ensure-StringArray {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        return [string[]]@()
    }

    if ($InputObject -is [string]) {
        return [string[]]@($InputObject)
    }

    $values = @(
        foreach ($item in @($InputObject)) {
            if ($null -ne $item) {
                [string]$item
            }
        }
    )

    return [string[]]$values
}

function Get-ActiveScreenConnectInstanceId {
    $instanceIds = New-StringHashSet

    Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match "\(($InstanceIdPattern)\)") {
            [void]$instanceIds.Add($Matches[1])
        }
    }

    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $uninstallPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayNameProperty = $_.PSObject.Properties['DisplayName']
            $displayName = if ($null -ne $displayNameProperty) { $displayNameProperty.Value } else { $null }
            if ($null -eq $displayName) {
                return
            }

            if ($displayName -match "ScreenConnect Client \(($InstanceIdPattern)\)") {
                [void]$instanceIds.Add($Matches[1])
            }
        }
    }

    $list = New-StringList
    foreach ($id in $instanceIds) {
        [void]$list.Add($id)
    }

    return [string[]]($list.ToArray())
}

function Add-TempScanRoot {
    param(
        [System.Collections.Generic.HashSet[string]]$Roots,
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return
    }

    try {
        $resolved = [System.IO.Path]::GetFullPath($Candidate)
        if (Test-Path -LiteralPath $resolved) {
            [void]$Roots.Add($resolved)
        }
    }
    catch {
        Write-Warning "Temp path not accessible: $Candidate"
    }
}

function Get-UserProfileRelativeScanPaths {
    return @(
        'Downloads',
        'Desktop',
        'Documents',
        'AppData\Local\Temp',
        'AppData\Local\Microsoft\Windows\INetCache',
        'AppData\Local\Microsoft\Windows\Temporary Internet Files'
    )
}

function Get-BrandedInstallerScanRoots {
    $roots = New-StringHashSet
    $relativePaths = @('Downloads', 'Desktop')
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    $excludedProfiles = @('All Users', 'Default', 'Default User', 'DefaultAppPool')

    if (Test-Path -LiteralPath $usersRoot) {
        Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $excludedProfiles -and $_.Name -notlike 'Default*' } |
            ForEach-Object {
                foreach ($subpath in $relativePaths) {
                    Add-TempScanRoot -Roots $roots -Candidate (Join-Path $_.FullName $subpath)
                }
            }

        foreach ($subpath in $relativePaths) {
            Add-TempScanRoot -Roots $roots -Candidate (Join-Path $usersRoot (Join-Path 'Public' $subpath))
        }
    }

    $list = New-StringList
    foreach ($root in $roots) {
        [void]$list.Add($root)
    }

    return [string[]]($list.ToArray())
}

function Get-SystemScanPaths {
    $windir = $env:WINDIR
    if ([string]::IsNullOrWhiteSpace($windir)) {
        $windir = 'C:\Windows'
    }

    return @(
        (Join-Path $windir 'Temp'),
        (Join-Path $windir 'SystemTemp'),
        (Join-Path $windir 'System32\config\systemprofile\AppData\Local\Temp'),
        (Join-Path $windir 'ServiceProfiles\LocalService\AppData\Local\Temp'),
        (Join-Path $windir 'ServiceProfiles\NetworkService\AppData\Local\Temp')
    )
}

function Get-TempScanRoots {
    $roots = New-StringHashSet

    foreach ($candidate in @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'))) {
        Add-TempScanRoot -Roots $roots -Candidate $candidate
    }

    foreach ($candidate in (Get-SystemScanPaths)) {
        Add-TempScanRoot -Roots $roots -Candidate $candidate
    }

    $usersRoot = Join-Path $env:SystemDrive 'Users'
    $profileSubpaths = Get-UserProfileRelativeScanPaths
    $excludedProfiles = @('All Users', 'Default', 'Default User', 'DefaultAppPool')

    if (Test-Path -LiteralPath $usersRoot) {
        Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $excludedProfiles -and $_.Name -notlike 'Default*' } |
            ForEach-Object {
                foreach ($subpath in $profileSubpaths) {
                    Add-TempScanRoot -Roots $roots -Candidate (Join-Path $_.FullName $subpath)
                }
            }

        foreach ($subpath in @('Downloads', 'Desktop')) {
            Add-TempScanRoot -Roots $roots -Candidate (Join-Path $usersRoot (Join-Path 'Public' $subpath))
        }
    }

    $list = New-StringList
    foreach ($root in $roots) {
        [void]$list.Add($root)
    }

    return [string[]]($list.ToArray())
}

function Get-InstanceFolderCandidates {
    param([AllowNull()][object]$ScanRoots)

    $roots = Ensure-StringArray -InputObject $ScanRoots
    $candidates = New-DirectoryInfoList

    foreach ($root in $roots) {
        $screenConnectRoot = Join-Path $root 'ScreenConnect'
        if (Test-Path -LiteralPath $screenConnectRoot) {
            Get-ChildItem -LiteralPath $screenConnectRoot -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $HashFolderPattern } |
                ForEach-Object {
                    [void]$candidates.Add($_)
                }
        }

        Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ScreenConnectClientFolderPattern } |
            ForEach-Object {
                [void]$candidates.Add($_)
            }
    }

    return $candidates
}

function Get-FolderInstanceId {
    param([string]$FolderName)

    if ($FolderName -match "^$InstanceIdPattern$") {
        return $Matches[0]
    }

    if ($FolderName -match "ScreenConnect Client \(($InstanceIdPattern)\)") {
        return $Matches[1]
    }

    return $null
}

function Test-IsScreenConnectInstallerFile {
    param(
        [System.IO.FileInfo]$File
    )

    $extension = $File.Extension.ToLowerInvariant()
    if ($extension -notin @('.msi', '.exe')) {
        return $false
    }

    $name = $File.Name
    $parentPath = $File.DirectoryName

    if ($name -like '*ScreenConnect*' -or $name -like '*ConnectWise*Control*') {
        return $true
    }

    if ($name -ieq 'setup.msi' -and $parentPath -match '\\ScreenConnect\\') {
        return $true
    }

    if ($parentPath -match '\\ScreenConnect\\') {
        return $true
    }

    if ($parentPath -match '\\LTSvc\\packages\\') {
        return $true
    }

    return $false
}

$ConnectWiseSignatureCache = @{}

function Test-IsConnectWiseSignedInstaller {
    param(
        [System.IO.FileInfo]$File
    )

    $extension = $File.Extension.ToLowerInvariant()
    if ($extension -notin @('.msi', '.exe')) {
        return $false
    }

    $cacheKey = $File.FullName.ToLowerInvariant()
    if ($ConnectWiseSignatureCache.ContainsKey($cacheKey)) {
        return $ConnectWiseSignatureCache[$cacheKey]
    }

    $isMatch = $false
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName -ErrorAction Stop
        if ($signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate) {
            $isMatch = ($signature.SignerCertificate.Subject -match $ConnectWiseSignerSubjectPattern)
        }
    }
    catch {
        $isMatch = $false
    }

    $ConnectWiseSignatureCache[$cacheKey] = $isMatch
    return $isMatch
}

function Test-IsAutomatePackageName {
    param([string]$Name)

    return ($Name.ToLowerInvariant() -match $AutomatePackageNamePattern)
}

function Get-LtsvcAutomatePackageRoots {
    $packagesRoot = Join-Path $env:WINDIR 'LTSvc\packages'
    if (-not (Test-Path -LiteralPath $packagesRoot)) {
        return @()
    }

    $roots = New-StringList
    Get-ChildItem -LiteralPath $packagesRoot -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-IsAutomatePackageName -Name $_.Name } |
        ForEach-Object {
            [void]$roots.Add($_.FullName)
        }

    return [string[]]($roots.ToArray())
}

function Get-AutomatePackageInstallersByRoot {
    param([AllowNull()][object]$AutomateRoots)

    $map = @{}
    foreach ($root in (Ensure-StringArray -InputObject $AutomateRoots)) {
        $installers = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { Test-IsScreenConnectInstallerFile -File $_ })
        $map[$root.ToLowerInvariant()] = $installers
    }

    return $map
}

function Test-IsNewestAutomatePackageInstaller {
    param(
        [System.IO.FileInfo]$File,
        [AllowNull()][object]$RootInstallers
    )

    $installers = @($RootInstallers)
    if ($installers.Count -eq 0) {
        return $false
    }

    $newest = $installers | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return ($newest.FullName -ieq $File.FullName)
}

function Test-IsUnderActiveInstance {
    param(
        [string]$Path,
        [AllowNull()][object]$ActiveInstanceIds
    )

    foreach ($instanceId in (Ensure-StringArray -InputObject $ActiveInstanceIds)) {
        if ($Path -match ('\\{0}(\\|$)' -f [regex]::Escape($instanceId))) {
            return $true
        }

        if ($Path -match ('\\ScreenConnect Client \({0}\)(\\|$)' -f [regex]::Escape($instanceId))) {
            return $true
        }
    }

    return $false
}

function Get-ScreenConnectVersionTextFromPath {
    param([string]$Path)

    if ($Path -match '\\ScreenConnect\\(\d+\.\d+\.\d+\.\d+)\\') {
        return $Matches[1]
    }

    return $null
}

function Get-ScreenConnectRootFromPath {
    param([string]$Path)

    if ($Path -match '^(?<root>.*\\ScreenConnect)\\') {
        return $Matches['root']
    }

    return $null
}

function ConvertTo-ScreenConnectVersion {
    param([string]$VersionText)

    try {
        return [version]$VersionText
    }
    catch {
        return $null
    }
}

function Get-NewestVersionByScreenConnectRoot {
    param([AllowNull()][object]$ScanRoots)

    $map = @{}
    foreach ($root in (Ensure-StringArray -InputObject $ScanRoots)) {
        $scRoot = Join-Path $root 'ScreenConnect'
        if (-not (Test-Path -LiteralPath $scRoot -ErrorAction SilentlyContinue)) {
            continue
        }

        Get-ChildItem -LiteralPath $scRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ScreenConnectVersionFolderPattern } |
            ForEach-Object {
                $ver = ConvertTo-ScreenConnectVersion -VersionText $_.Name
                if ($null -eq $ver) {
                    return
                }

                $key = $scRoot.ToLowerInvariant()
                if (-not $map.ContainsKey($key) -or $ver -gt $map[$key].Version) {
                    $map[$key] = @{
                        Version     = $ver
                        VersionText = $_.Name
                        Path        = $_.FullName
                    }
                }
            }
    }

    return $map
}

function Add-ProtectedClientRoot {
    param(
        [System.Collections.Generic.HashSet[string]]$Roots,
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return
    }

    try {
        $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim().TrimEnd('\', '/'))
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            $resolved = [System.IO.Path]::GetDirectoryName($resolved)
        }

        if (-not [string]::IsNullOrWhiteSpace($resolved)) {
            [void]$Roots.Add($resolved)
        }
    }
    catch {
    }
}

function Get-ProtectedClientRoots {
    param([AllowNull()][object]$Clients)

    $roots = New-StringHashSet
    $bases = New-StringList
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        [void]$bases.Add($env:ProgramFiles)
    }

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        [void]$bases.Add($programFilesX86)
    }

    foreach ($base in $bases) {
        if (-not (Test-Path -LiteralPath $base)) {
            continue
        }

        Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ScreenConnectClientFolderPattern } |
            ForEach-Object {
                [void]$roots.Add($_.FullName)
            }
    }

    foreach ($client in @($Clients)) {
        if ($null -ne $client -and $client.PSObject.Properties['Path']) {
            Add-ProtectedClientRoot -Roots $roots -Candidate ([string]$client.Path)
        }
    }

    $list = New-StringList
    foreach ($root in $roots) {
        [void]$list.Add($root)
    }

    return [string[]]($list.ToArray())
}

function Test-IsInstalledClientPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $full = $Path
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
    }

    if ($full -match ('(?i)\\Program Files(?: \(x86\))?\\ScreenConnect Client \({0}\)' -f $InstanceIdPattern)) {
        return $true
    }

    foreach ($root in (Ensure-StringArray -InputObject $script:ProtectedClientRoots)) {
        if ($full.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
            $full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-IsNeverDeleteClientPath {
    param(
        [string]$Path,
        [AllowNull()][object]$ActiveInstanceIds
    )

    if (Test-IsInstalledClientPath -Path $Path) {
        return $true
    }

    return (Test-IsUnderActiveInstance -Path $Path -ActiveInstanceIds $ActiveInstanceIds)
}

function Test-VersionFolderHasActiveInstance {
    param(
        [System.IO.DirectoryInfo]$VersionDirectory,
        [AllowNull()][object]$ActiveInstanceIds
    )

    $activeIds = Ensure-StringArray -InputObject $ActiveInstanceIds
    if (Test-IsNeverDeleteClientPath -Path $VersionDirectory.FullName -ActiveInstanceIds $activeIds) {
        return $true
    }

    foreach ($child in @(Get-ChildItem -LiteralPath $VersionDirectory.FullName -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($activeIds -contains $child.Name) {
            return $true
        }
    }

    return $false
}

function Test-IsProtectedActiveInstancePath {
    param(
        [string]$Path,
        [AllowNull()][object]$ActiveInstanceIds,
        [datetime]$Cutoff,
        [AllowNull()][object]$NewestVersionByScRoot
    )

    # Age / superseded-version expiry must never un-protect an in-use client.
    # Cutoff and NewestVersionByScRoot are unused; kept so existing callers stay valid.
    $null = $Cutoff
    $null = $NewestVersionByScRoot
    return (Test-IsNeverDeleteClientPath -Path $Path -ActiveInstanceIds $ActiveInstanceIds)
}

function Get-ScreenConnectVersionFolderCandidates {
    param([AllowNull()][object]$ScanRoots)

    $candidates = New-DirectoryInfoList
    foreach ($root in (Ensure-StringArray -InputObject $ScanRoots)) {
        $scRoot = Join-Path $root 'ScreenConnect'
        if (-not (Test-Path -LiteralPath $scRoot -ErrorAction SilentlyContinue)) {
            continue
        }

        Get-ChildItem -LiteralPath $scRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ScreenConnectVersionFolderPattern } |
            ForEach-Object {
                [void]$candidates.Add($_)
            }
    }

    return $candidates
}

function Invoke-OldVersionFolderAction {
    param(
        [System.IO.DirectoryInfo]$VersionDirectory,
        [AllowNull()][object]$NewestVersionByScRoot,
        [datetime]$Cutoff,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    $path = $VersionDirectory.FullName
    $scRoot = Split-Path -Parent $path
    $scKey = $scRoot.ToLowerInvariant()

    if ($null -ne $NewestVersionByScRoot -and $NewestVersionByScRoot.ContainsKey($scKey) -and ($path -ieq $NewestVersionByScRoot[$scKey].Path)) {
        return
    }

    if (Test-VersionFolderHasActiveInstance -VersionDirectory $VersionDirectory -ActiveInstanceIds $script:ProtectedActiveInstanceIds) {
        Write-Result -Type 'Version-Folder' -Status 'SKIPPED (active)' -Path $path -Detail 'contains in-use instance - never deleted'
        $Stats.Value.SkippedFolders++
        return
    }

    if (Test-IsInstalledClientPath -Path $path) {
        Write-Result -Type 'Version-Folder' -Status 'SKIPPED (protected client)' -Path $path
        $Stats.Value.SkippedFolders++
        return
    }

    if ($RemovedPaths.Contains($path.ToLowerInvariant())) {
        return
    }

    # Superseded version folders are stale upgrade cache — MinAgeHours only applies to the newest version folder
    if (-not $Delete) {
        Write-Result -Type 'Version-Folder' -Status 'WOULD REMOVE' -Path $path -Detail 'superseded upgrade cache'
        $Stats.Value.WouldRemoveFolders++
        return
    }

    if ((Test-VersionFolderHasActiveInstance -VersionDirectory $VersionDirectory -ActiveInstanceIds $script:ProtectedActiveInstanceIds) -or (Test-IsInstalledClientPath -Path $path)) {
        Write-Result -Type 'Version-Folder' -Status 'SKIPPED (active)' -Path $path -Detail 'in-use or installed client - never deleted'
        $Stats.Value.SkippedFolders++
        return
    }

    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type 'Version-Folder' -Status 'REMOVED' -Path $path -Detail 'superseded upgrade cache'
        $Stats.Value.RemovedFolders++
        Remove-EmptyScreenConnectAncestors -StartPath $path
    }
    catch {
        Write-Result -Type 'Version-Folder' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedFolders++
    }
}

function Test-FolderTooNew {
    param(
        [System.IO.DirectoryInfo]$Directory,
        [datetime]$Cutoff
    )

    if ($Force) {
        return $false
    }

    return $Directory.LastWriteTime -gt $Cutoff
}

function Test-InstallerInProgress {
    param(
        [System.IO.FileInfo]$File,
        [AllowNull()][object]$ActiveInstanceIds,
        [datetime]$Cutoff
    )

    if ($Force) {
        return $false
    }

    $parentPath = $File.DirectoryName
    foreach ($instanceId in (Ensure-StringArray -InputObject $ActiveInstanceIds)) {
        if ($parentPath -match ('\\{0}(\\|$)' -f [regex]::Escape($instanceId)) -and $File.LastWriteTime -gt $Cutoff) {
            return $true
        }
    }

    return $false
}

function Remove-EmptyScreenConnectAncestors {
    param([string]$StartPath)

    $current = Split-Path -Parent $StartPath
    while ($current -and ($current -match '\\ScreenConnect(\\|$)')) {
        if (Test-IsNeverDeleteClientPath -Path $current -ActiveInstanceIds $script:ProtectedActiveInstanceIds) {
            break
        }

        $remaining = Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($remaining) {
            break
        }

        try {
            Remove-Item -LiteralPath $current -Force -ErrorAction Stop
            Write-Result -Type 'Folder' -Status 'REMOVED' -Path $current -Detail 'empty after cleanup'
            $current = Split-Path -Parent $current
        }
        catch {
            Write-Result -Type 'Folder' -Status 'FAILED' -Path $current -Detail $_.Exception.Message
            break
        }
    }
}

function Invoke-FolderAction {
    param(
        [System.IO.DirectoryInfo]$Directory,
        [AllowNull()][object]$ActiveInstanceIds,
        [datetime]$Cutoff,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths,
        [string]$ResultType = 'Folder',
        [AllowNull()][object]$NewestVersionByScRoot = $null
    )

    $activeIds = Ensure-StringArray -InputObject $ActiveInstanceIds
    $path = $Directory.FullName

    if (Test-IsNeverDeleteClientPath -Path $path -ActiveInstanceIds $activeIds) {
        Write-Result -Type $ResultType -Status 'SKIPPED (active)' -Path $path -Detail 'in-use or installed client - never deleted'
        $Stats.Value.SkippedFolders++
        return
    }

    if (Test-FolderTooNew -Directory $Directory -Cutoff $Cutoff) {
        Write-Result -Type $ResultType -Status 'SKIPPED (too new)' -Path $path -Detail ("modified {0:u}" -f $Directory.LastWriteTime)
        $Stats.Value.SkippedFolders++
        return
    }

    if (-not $Delete) {
        Write-Result -Type $ResultType -Status 'WOULD REMOVE' -Path $path
        $Stats.Value.WouldRemoveFolders++
        return
    }

    if (Test-IsNeverDeleteClientPath -Path $path -ActiveInstanceIds $activeIds) {
        Write-Result -Type $ResultType -Status 'SKIPPED (active)' -Path $path -Detail 'in-use or installed client - never deleted'
        $Stats.Value.SkippedFolders++
        return
    }

    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type $ResultType -Status 'REMOVED' -Path $path
        $Stats.Value.RemovedFolders++
        Remove-EmptyScreenConnectAncestors -StartPath $path
    }
    catch {
        Write-Result -Type $ResultType -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedFolders++
    }
}

function Invoke-InstallerAction {
    param(
        [System.IO.FileInfo]$File,
        [AllowNull()][object]$ActiveInstanceIds,
        [datetime]$Cutoff,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths,
        [string]$ResultType = 'Installer',
        [AllowNull()][object]$AutomateRootInstallers = $null,
        [AllowNull()][object]$NewestVersionByScRoot = $null,
        [switch]$SkipYearCutoff
    )

    $activeIds = Ensure-StringArray -InputObject $ActiveInstanceIds

    $path = $File.FullName
    $parentPath = $File.DirectoryName

    if ($RemovedPaths.Contains($path.ToLowerInvariant()) -or ($parentPath -and $RemovedPaths.Contains($parentPath.ToLowerInvariant()))) {
        return
    }

    if (Test-IsNeverDeleteClientPath -Path $path -ActiveInstanceIds $activeIds) {
        Write-Result -Type $ResultType -Status 'SKIPPED (active)' -Path $path -Detail 'in-use or installed client - never deleted'
        $Stats.Value.SkippedInstallers++
        return
    }

    if ($AutomateRootInstallers -and (Test-IsNewestAutomatePackageInstaller -File $File -RootInstallers $AutomateRootInstallers)) {
        Write-Result -Type $ResultType -Status 'SKIPPED (in use)' -Path $path -Detail 'newest Automate package cache copy'
        $Stats.Value.SkippedInstallers++
        return
    }

    $fileYear = $File.LastWriteTime.Year
    if (-not $SkipYearCutoff -and $fileYear -gt $MaxInstallerYear) {
        Write-Result -Type $ResultType -Status 'SKIPPED (year > cutoff)' -Path $path -Detail ("LastWriteTime year {0}, cutoff {1}" -f $fileYear, $MaxInstallerYear)
        $Stats.Value.SkippedInstallers++
        return
    }

    if (Test-InstallerInProgress -File $File -ActiveInstanceIds $activeIds -Cutoff $Cutoff) {
        Write-Result -Type $ResultType -Status 'SKIPPED (too new)' -Path $path -Detail 'active client reinstall in progress'
        $Stats.Value.SkippedInstallers++
        return
    }

    $detail = if ($SkipYearCutoff) {
        'ConnectWise-signed installer'
    }
    else {
        ("LastWriteTime {0:yyyy-MM-dd}" -f $File.LastWriteTime)
    }

    if (-not $Delete) {
        Write-Result -Type $ResultType -Status 'WOULD REMOVE' -Path $path -Detail $detail
        $Stats.Value.WouldRemoveInstallers++
        return
    }

    if (Test-IsNeverDeleteClientPath -Path $path -ActiveInstanceIds $activeIds) {
        Write-Result -Type $ResultType -Status 'SKIPPED (active)' -Path $path -Detail 'in-use or installed client - never deleted'
        $Stats.Value.SkippedInstallers++
        return
    }

    try {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type $ResultType -Status 'REMOVED' -Path $path -Detail $detail
        $Stats.Value.RemovedInstallers++
        Remove-EmptyScreenConnectAncestors -StartPath $path
    }
    catch {
        Write-Result -Type $ResultType -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedInstallers++
    }
}

function Get-ServiceImagePath {
    param([string]$ServiceName)

    try {
        $item = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $ServiceName) -ErrorAction Stop
        $raw = [string]$item.ImagePath
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }

        $trimmed = $raw.Trim()
        if ($trimmed -match '^"([^"]+)"') {
            return $Matches[1]
        }

        if ($trimmed -match '(?i)^((?:[a-z]:\\|\\\\)[^:]+\.exe)') {
            return $Matches[1]
        }

        return $trimmed.Trim('"')
    }
    catch {
        return $null
    }
}

function Get-FileVersionText {
    param([string]$Path)

    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        foreach ($candidate in @($info.FileVersion, $info.ProductVersion)) {
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and $candidate -match '\d+\.\d+') {
                return $candidate.Trim()
            }
        }
    }
    catch {
    }

    return $null
}

function Get-InstalledScreenConnectClients {
    $byId = @{}

    Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue | ForEach-Object {
        $id = $null
        if ($_.Name -match "\(($InstanceIdPattern)\)") {
            $id = $Matches[1]
        }

        if (-not $id) {
            return
        }

        $exe = Get-ServiceImagePath -ServiceName $_.Name
        $verText = $null
        $sigStatus = $null
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            $verText = Get-FileVersionText -Path $exe
            try {
                $sigStatus = [string](Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop).Status
            }
            catch {
                $sigStatus = 'Unknown'
            }
        }

        $byId[$id] = [pscustomobject]@{
            InstanceId     = $id
            ServiceName    = $_.Name
            ServiceStatus  = [string]$_.Status
            Path           = $exe
            VersionText    = $verText
            HasService     = $true
            HasUninstall   = $false
            SignatureValid = if ($null -eq $sigStatus) { $null } else { ($sigStatus -eq 'Valid') }
        }
    }

    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $uninstallPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayNameProperty = $_.PSObject.Properties['DisplayName']
            $displayName = if ($null -ne $displayNameProperty) { $displayNameProperty.Value } else { $null }
            if ($null -eq $displayName) {
                return
            }

            if ($displayName -notmatch "ScreenConnect Client \(($InstanceIdPattern)\)") {
                return
            }

            $id = $Matches[1]
            $displayVersionProperty = $_.PSObject.Properties['DisplayVersion']
            $displayVersion = if ($null -ne $displayVersionProperty) { [string]$displayVersionProperty.Value } else { $null }
            $installLocationProperty = $_.PSObject.Properties['InstallLocation']
            $installLocation = if ($null -ne $installLocationProperty) { [string]$installLocationProperty.Value } else { $null }

            if ($byId.ContainsKey($id)) {
                $byId[$id].HasUninstall = $true
                if (-not $byId[$id].VersionText -and $displayVersion) {
                    $byId[$id].VersionText = $displayVersion
                }

                if (-not $byId[$id].Path -and $installLocation) {
                    $byId[$id].Path = $installLocation
                }
            }
            else {
                $byId[$id] = [pscustomobject]@{
                    InstanceId     = $id
                    ServiceName    = $null
                    ServiceStatus  = $null
                    Path           = $installLocation
                    VersionText    = $displayVersion
                    HasService     = $false
                    HasUninstall   = $true
                    SignatureValid = $null
                }
            }
        }
    }

    return @($byId.Values | Sort-Object InstanceId)
}

function Write-ScreenConnectClientAdvisory {
    param([AllowNull()][object]$Clients)

    $list = @($Clients)
    Write-Output '=== ScreenConnect client advisory (CVE-2026-84869) ==='
    Write-Output "Patched client build: $PatchedClientVersion or later. This script does not uninstall Program Files clients."
    Write-Output 'Huntress/CISA: unauthorized TransferFiles + Run on clients before 26.6.5; reimage if 1.vbs-4.vbs ran from Process: Guest.'
    Write-Output ''

    if ($list.Count -eq 0) {
        Write-Output '[Client] NONE : No ScreenConnect client service or uninstall entry found.'
        Write-Output ''
        return
    }

    if ($list.Count -gt 1) {
        Write-Output ("WARNING: {0} ScreenConnect clients installed. Extra instances can be rogue access - confirm each ID is yours." -f $list.Count)
    }

    foreach ($client in $list) {
        $ver = ConvertTo-ScreenConnectVersion -VersionText $client.VersionText
        $status = 'UNKNOWN'
        $detailParts = New-StringList
        if ($client.VersionText) {
            [void]$detailParts.Add(('version {0}' -f $client.VersionText))
        }
        else {
            [void]$detailParts.Add('version unknown')
        }

        if ($null -ne $ver) {
            if ($ver -ge $PatchedClientVersion) {
                $status = 'PATCHED'
            }
            else {
                $status = 'VULNERABLE'
            }
        }

        if ($KnownRogueInstanceIds -contains $client.InstanceId) {
            $status = 'ROGUE-ID'
            [void]$detailParts.Add('Huntress IOC 7a4d7d66502d4260')
        }

        if ($client.HasService -and -not $client.HasUninstall) {
            [void]$detailParts.Add('uninstall key missing (hidden client)')
        }

        if ($client.HasService) {
            [void]$detailParts.Add(('service {0}' -f $client.ServiceStatus))
        }
        else {
            [void]$detailParts.Add('no service')
        }

        if ($client.SignatureValid -eq $false) {
            [void]$detailParts.Add('Authenticode not Valid')
        }

        $path = if ($client.Path) { $client.Path } else { ('ScreenConnect Client ({0})' -f $client.InstanceId) }
        Write-Result -Type 'Client' -Status $status -Path $path -Detail ($detailParts -join '; ')
    }

    Write-Output ''
}

function Get-CveStagingScanRoots {
    param([AllowNull()][object]$TempRoots)

    $roots = New-StringHashSet
    foreach ($root in (Ensure-StringArray -InputObject $TempRoots)) {
        if (Test-IsCveStagingLocation -Path $root) {
            [void]$roots.Add($root)
        }

        Add-TempScanRoot -Roots $roots -Candidate (Join-Path $root 'ScreenConnect')
    }

    $systemDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($systemDrive)) {
        $systemDrive = 'C:'
    }

    Add-TempScanRoot -Roots $roots -Candidate (Join-Path $systemDrive 'Users\Public\Libraries\Default\Lib')
    Add-TempScanRoot -Roots $roots -Candidate (Join-Path $systemDrive 'Users\Public\Libraries\Default\Lib\Lib1')

    $usersRoot = Join-Path $systemDrive 'Users'
    $excludedProfiles = @('All Users', 'Default', 'Default User', 'DefaultAppPool', 'Public')
    if (Test-Path -LiteralPath $usersRoot) {
        Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $excludedProfiles -and $_.Name -notlike 'Default*' } |
            ForEach-Object {
                Add-TempScanRoot -Roots $roots -Candidate (Join-Path $_.FullName 'AppData\Roaming')
                Add-TempScanRoot -Roots $roots -Candidate (Join-Path $_.FullName 'AppData\Local')
                Add-TempScanRoot -Roots $roots -Candidate (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Templates\Classic')
            }
    }

    $list = New-StringList
    foreach ($root in $roots) {
        [void]$list.Add($root)
    }

    return [string[]]($list.ToArray())
}

function Test-IsCveStagingClusterDirectory {
    param([string]$DirectoryPath)

    if ([string]::IsNullOrWhiteSpace($DirectoryPath) -or -not (Test-Path -LiteralPath $DirectoryPath)) {
        return $false
    }

    $names = @(
        Get-ChildItem -LiteralPath $DirectoryPath -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Name.ToLowerInvariant() }
    )

    foreach ($name in $CveStagingClusterNames) {
        if ($names -contains $name) {
            return $true
        }
    }

    return $false
}

function Test-IsCveStagingLocation {
    param([string]$Path)

    return ($Path -match '(?i)\\(Temp|SystemTemp|ScreenConnect|INetCache|Temporary Internet Files|Lib1|Templates\\Classic)(\\|$)')
}

function Test-IsCveStagingFile {
    param([System.IO.FileInfo]$File)

    $name = $File.Name.ToLowerInvariant()
    $parent = $File.DirectoryName
    $inStagingPath = Test-IsCveStagingLocation -Path $File.FullName

    if ($name -in @('windowsservicehost.vbs', 'windowsservicehost.bat')) {
        return $true
    }

    if (($name -in @('pytorchfix.ps1', 'sys_cache.zip')) -and $inStagingPath) {
        return $true
    }

    if ($CveStagingExactNames -contains $name -and $inStagingPath) {
        return $true
    }

    if ($name -eq 'value.txt' -and $inStagingPath -and (Test-IsCveStagingClusterDirectory -DirectoryPath $parent)) {
        return $true
    }

    if (($CveMasqueradeNames -contains $name) -and $inStagingPath) {
        return $true
    }

    return $false
}

function Test-IsTransferArtifactFile {
    param([System.IO.FileInfo]$File)

    if (Test-IsCveStagingFile -File $File) {
        return $false
    }

    $ext = $File.Extension.ToLowerInvariant()
    return ($ext -in @('.vbs', '.vbe', '.ps1', '.bat', '.cmd', '.js', '.jse', '.wsf', '.wsh', '.enc'))
}

function Invoke-CveStagingAction {
    param(
        [System.IO.FileInfo]$File,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    $path = $File.FullName
    if ($RemovedPaths.Contains($path.ToLowerInvariant())) {
        return
    }

    $parentPath = $File.DirectoryName
    if ($parentPath -and $RemovedPaths.Contains($parentPath.ToLowerInvariant())) {
        return
    }

    if (Test-IsInstalledClientPath -Path $path) {
        Write-Result -Type 'Cve-Staging' -Status 'SKIPPED (protected client)' -Path $path -Detail 'installed ScreenConnect client - never deleted'
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'Cve-Staging' -Status 'WOULD REMOVE' -Path $path -Detail 'Huntress/CVE-2026-84869 IOC'
        $Stats.Value.WouldRemoveStaging++
        return
    }

    if (Test-IsInstalledClientPath -Path $path) {
        Write-Result -Type 'Cve-Staging' -Status 'SKIPPED (protected client)' -Path $path -Detail 'installed ScreenConnect client - never deleted'
        return
    }

    try {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type 'Cve-Staging' -Status 'REMOVED' -Path $path -Detail 'Huntress/CVE-2026-84869 IOC'
        $Stats.Value.RemovedStaging++
    }
    catch {
        Write-Result -Type 'Cve-Staging' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedStaging++
    }
}

function Invoke-CveStagingFolderAction {
    param(
        [string]$Path,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    if ($RemovedPaths.Contains($Path.ToLowerInvariant())) {
        return
    }

    if (Test-IsInstalledClientPath -Path $Path) {
        Write-Result -Type 'Cve-Staging' -Status 'SKIPPED (protected client)' -Path $Path
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'Cve-Staging' -Status 'WOULD REMOVE' -Path $Path -Detail 'Huntress Lib1 staging folder'
        $Stats.Value.WouldRemoveStaging++
        return
    }

    if (Test-IsInstalledClientPath -Path $Path) {
        Write-Result -Type 'Cve-Staging' -Status 'SKIPPED (protected client)' -Path $Path
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($Path.ToLowerInvariant())
        Write-Result -Type 'Cve-Staging' -Status 'REMOVED' -Path $Path -Detail 'Huntress Lib1 staging folder'
        $Stats.Value.RemovedStaging++
    }
    catch {
        Write-Result -Type 'Cve-Staging' -Status 'FAILED' -Path $Path -Detail $_.Exception.Message
        $Stats.Value.FailedStaging++
    }
}

function Get-CveRunKeyFindings {
    $findings = New-Object System.Collections.ArrayList
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        try {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop | Out-Null
        }
        catch {
        }
    }

    $runPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($runPath in $runPaths) {
        $item = Get-ItemProperty -LiteralPath $runPath -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        $prop = $item.PSObject.Properties['WindowsServiceHost']
        if ($null -eq $prop) {
            continue
        }

        [void]$findings.Add([pscustomobject]@{
                HivePath = $runPath
                Value    = [string]$prop.Value
            })
    }

    try {
        Get-ChildItem -LiteralPath 'HKU:' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -notmatch '^S-1-5-21-' -or $_.PSChildName -match '_Classes$') {
                return
            }

            $runPath = "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            $item = Get-ItemProperty -LiteralPath $runPath -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                return
            }

            $prop = $item.PSObject.Properties['WindowsServiceHost']
            if ($null -eq $prop) {
                return
            }

            [void]$findings.Add([pscustomobject]@{
                    HivePath = $runPath
                    Value    = [string]$prop.Value
                })
        }
    }
    catch {
        Write-Warning ("HKU Run key scan failed: {0}" -f $_.Exception.Message)
    }

    return @($findings)
}

function Invoke-CveRunKeyAction {
    param(
        [object]$Finding,
        [ref]$Stats
    )

    $detail = if ($Finding.Value) { $Finding.Value } else { 'WindowsServiceHost' }
    if (-not $Delete) {
        Write-Result -Type 'Cve-RunKey' -Status 'WOULD REMOVE' -Path $Finding.HivePath -Detail $detail
        $Stats.Value.WouldRemoveRunKeys++
        return
    }

    try {
        Remove-ItemProperty -LiteralPath $Finding.HivePath -Name 'WindowsServiceHost' -Force -ErrorAction Stop
        Write-Result -Type 'Cve-RunKey' -Status 'REMOVED' -Path $Finding.HivePath -Detail $detail
        $Stats.Value.RemovedRunKeys++
    }
    catch {
        Write-Result -Type 'Cve-RunKey' -Status 'FAILED' -Path $Finding.HivePath -Detail $_.Exception.Message
        $Stats.Value.FailedRunKeys++
    }
}

function Invoke-CveStagingScan {
    param(
        [AllowNull()][object]$TempRoots,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    Write-Output '--- CVE-2026-84869 / Huntress staging ---'

    $systemDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($systemDrive)) {
        $systemDrive = 'C:'
    }

    $lib1 = Join-Path $systemDrive 'Users\Public\Libraries\Default\Lib\Lib1'
    Invoke-CveStagingFolderAction -Path $lib1 -Stats $Stats -RemovedPaths $RemovedPaths

    $cveRoots = Ensure-StringArray (Get-CveStagingScanRoots -TempRoots $TempRoots)
    $seenFiles = New-StringHashSet
    foreach ($root in $cveRoots) {
        $rootLeaf = [System.IO.Path]::GetFileName($root)
        # AppData\Roaming and AppData\Local are large — only walk known leaves + top-level IOC names there.
        $shallowAppData = ($rootLeaf -ieq 'Roaming' -or $rootLeaf -ieq 'Local')

        $files = New-Object System.Collections.ArrayList
        try {
            if ($shallowAppData) {
                foreach ($item in @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue)) {
                    [void]$files.Add($item)
                }

                $classic = Join-Path $root 'Microsoft\Windows\Templates\Classic'
                if (Test-Path -LiteralPath $classic) {
                    foreach ($item in @(Get-ChildItem -LiteralPath $classic -File -Force -Recurse -ErrorAction SilentlyContinue)) {
                        [void]$files.Add($item)
                    }
                }
            }
            else {
                foreach ($item in @(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue)) {
                    [void]$files.Add($item)
                }
            }
        }
        catch {
            Write-Warning ("CVE staging path not fully scanned: {0} ({1})" -f $root, $_.Exception.Message)
        }

        foreach ($file in $files) {
            if ($null -eq $file -or [string]::IsNullOrWhiteSpace($file.FullName)) {
                continue
            }

            if (-not $seenFiles.Add($file.FullName)) {
                continue
            }

            if (Test-IsCveStagingFile -File $file) {
                Invoke-CveStagingAction -File $file -Stats $Stats -RemovedPaths $RemovedPaths
            }
        }
    }

    $artifactSeen = New-StringHashSet
    foreach ($root in (Ensure-StringArray -InputObject $TempRoots)) {
        $scRoot = Join-Path $root 'ScreenConnect'
        if (-not (Test-Path -LiteralPath $scRoot)) {
            continue
        }

        try {
            Get-ChildItem -LiteralPath $scRoot -File -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($null -eq $_ -or [string]::IsNullOrWhiteSpace($_.FullName)) {
                    return
                }

                if (-not $artifactSeen.Add($_.FullName)) {
                    return
                }

                if (Test-IsCveStagingFile -File $_) {
                    return
                }

                if (Test-IsTransferArtifactFile -File $_) {
                    Write-Result -Type 'Transfer-Artifact' -Status 'REPORTED' -Path $_.FullName -Detail 'script/enc under ScreenConnect temp - investigate, not auto-deleted'
                    $Stats.Value.ReportedArtifacts++
                }
            }
        }
        catch {
            Write-Warning ("ScreenConnect temp not fully scanned: {0} ({1})" -f $scRoot, $_.Exception.Message)
        }
    }

    foreach ($finding in (Get-CveRunKeyFindings)) {
        Invoke-CveRunKeyAction -Finding $finding -Stats $Stats
    }

    if ($Stats.Value.WouldRemoveStaging -eq 0 -and $Stats.Value.RemovedStaging -eq 0 -and $Stats.Value.FailedStaging -eq 0 -and $Stats.Value.ReportedArtifacts -eq 0 -and $Stats.Value.WouldRemoveRunKeys -eq 0 -and $Stats.Value.RemovedRunKeys -eq 0 -and $Stats.Value.FailedRunKeys -eq 0) {
        Write-Output '[Cve-Staging] NONE : No Huntress IOC files or WindowsServiceHost Run keys found.'
    }

    Write-Output ''
}

$activeInstanceIds = Ensure-StringArray (Get-ActiveScreenConnectInstanceId)
$installedClients = @(Get-InstalledScreenConnectClients)
$script:ProtectedActiveInstanceIds = $activeInstanceIds
$script:ProtectedClientRoots = Get-ProtectedClientRoots -Clients $installedClients
$scanRoots = Ensure-StringArray (Get-TempScanRoots)
$automateRoots = if ($SkipAutomateCache) { @() } else { Ensure-StringArray (Get-LtsvcAutomatePackageRoots) }
$automateInstallersByRoot = if ($automateRoots.Length -gt 0) { Get-AutomatePackageInstallersByRoot -AutomateRoots $automateRoots } else { @{} }
$newestVersionByScRoot = Get-NewestVersionByScreenConnectRoot -ScanRoots $scanRoots
$folderCutoff = (Get-Date).AddHours(-1 * $MinAgeHours)
$mode = if ($Delete) { 'DELETE' } else { 'DRY-RUN' }

Write-Output "=== ScreenConnect Temp Cleanup v$ScriptVersion ==="
Write-Output "Mode: $mode"
Write-Output "Active instance ID(s): $(if ($activeInstanceIds -and $activeInstanceIds.Length -gt 0) { ($activeInstanceIds -join ', ') } else { '(none detected)' })"
Write-Output "Scan roots: $(($scanRoots -join '; '))"
Write-Output "Automate cache roots: $(if ($automateRoots.Length -gt 0) { ($automateRoots -join '; ') } else { '(none or skipped)' })"
Write-Output "Branded installer scan: $(if ($SkipBrandedInstallerScan) { 'skipped' } else { 'Downloads and Desktop (ConnectWise signature)' })"
Write-Output "CVE-2026-84869 / Huntress scan: $(if ($SkipCveScan) { 'skipped' } else { 'client advisory + staging IOCs' })"
Write-Output "Active/installed clients: never deleted (CVE status is report-only; -Force does not override)"
Write-Output "Protected client roots: $(if ($script:ProtectedClientRoots -and $script:ProtectedClientRoots.Length -gt 0) { ($script:ProtectedClientRoots -join '; ') } else { '(none discovered)' })"
Write-Output "Folder min age: $MinAgeHours hour(s)$(if ($Force) { ' (Force: age check disabled)' } else { '' })"
Write-Output "Installer year cutoff: <= $MaxInstallerYear"
Write-Output ''

if (-not $SkipCveScan) {
    Write-ScreenConnectClientAdvisory -Clients $installedClients
}

if (-not $activeInstanceIds -or $activeInstanceIds.Length -eq 0) {
    Write-Output 'WARNING: No active ScreenConnect client detected. Proceeding with temp-only cleanup.'
    Write-Output ''
}

$stats = @{
    WouldRemoveFolders    = 0
    RemovedFolders        = 0
    SkippedFolders        = 0
    FailedFolders         = 0
    WouldRemoveInstallers = 0
    RemovedInstallers     = 0
    SkippedInstallers     = 0
    FailedInstallers      = 0
    WouldRemoveStaging    = 0
    RemovedStaging        = 0
    FailedStaging         = 0
    ReportedArtifacts     = 0
    WouldRemoveRunKeys    = 0
    RemovedRunKeys        = 0
    FailedRunKeys         = 0
}

$automateStats = @{
    WouldRemoveFolders    = 0
    RemovedFolders        = 0
    SkippedFolders        = 0
    FailedFolders         = 0
    WouldRemoveInstallers = 0
    RemovedInstallers     = 0
    SkippedInstallers     = 0
    FailedInstallers      = 0
}

$removedPaths = New-StringHashSet
$seenInstallers = New-StringHashSet
$folderCandidates = Get-InstanceFolderCandidates -ScanRoots $scanRoots

$seenFolders = New-StringHashSet
foreach ($folder in $folderCandidates) {
    if (-not $seenFolders.Add($folder.FullName)) {
        continue
    }

    Invoke-FolderAction -Directory $folder -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths -NewestVersionByScRoot $newestVersionByScRoot
}

foreach ($root in $scanRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-IsScreenConnectInstallerFile -File $_ } |
        ForEach-Object {
            if (-not $seenInstallers.Add($_.FullName)) {
                return
            }

            Invoke-InstallerAction -File $_ -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths -NewestVersionByScRoot $newestVersionByScRoot
        }
}

if (-not $SkipBrandedInstallerScan) {
    $brandedScanRoots = Ensure-StringArray (Get-BrandedInstallerScanRoots)
    if ($brandedScanRoots.Length -gt 0) {
        Write-Output ''
        Write-Output '--- ConnectWise-signed installers (Downloads / Desktop) ---'

        foreach ($root in $brandedScanRoots) {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @('.exe', '.msi') } |
                Where-Object { -not (Test-IsScreenConnectInstallerFile -File $_) } |
                Where-Object { Test-IsConnectWiseSignedInstaller -File $_ } |
                ForEach-Object {
                    if (-not $seenInstallers.Add($_.FullName)) {
                        return
                    }

                    Invoke-InstallerAction -File $_ -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths -NewestVersionByScRoot $newestVersionByScRoot -ResultType 'Branded-Installer' -SkipYearCutoff
                }
        }
    }
}

$seenVersionFolders = New-StringHashSet
foreach ($versionFolder in (Get-ScreenConnectVersionFolderCandidates -ScanRoots $scanRoots)) {
    if (-not $seenVersionFolders.Add($versionFolder.FullName)) {
        continue
    }

    Invoke-OldVersionFolderAction -VersionDirectory $versionFolder -NewestVersionByScRoot $newestVersionByScRoot -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths
}

if ($automateRoots.Length -gt 0) {
    Write-Output ''
    Write-Output '--- ConnectWise Automate (LTSvc) package cache ---'

    $automateFolderCandidates = Get-InstanceFolderCandidates -ScanRoots $automateRoots
    $seenAutomateFolders = New-StringHashSet
    foreach ($folder in $automateFolderCandidates) {
        if (-not $seenAutomateFolders.Add($folder.FullName)) {
            continue
        }

        Invoke-FolderAction -Directory $folder -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$automateStats) -RemovedPaths $removedPaths -ResultType 'Automate-Folder'
    }

    $seenAutomateInstallers = New-StringHashSet
    foreach ($root in $automateRoots) {
        $rootKey = $root.ToLowerInvariant()
        $rootInstallers = $automateInstallersByRoot[$rootKey]

        Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { Test-IsScreenConnectInstallerFile -File $_ } |
            ForEach-Object {
                if (-not $seenAutomateInstallers.Add($_.FullName)) {
                    return
                }

                Invoke-InstallerAction -File $_ -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$automateStats) -RemovedPaths $removedPaths -ResultType 'Automate-Installer' -AutomateRootInstallers $rootInstallers
            }
    }
}

if (-not $SkipCveScan) {
    Write-Output ''
    Invoke-CveStagingScan -TempRoots $scanRoots -Stats ([ref]$stats) -RemovedPaths $removedPaths
}

Write-Output ''
Write-Output '=== Summary ==='
if ($Delete) {
    Write-Output ("Temp folders removed: {0}; skipped: {1}; failed: {2}" -f $stats.RemovedFolders, $stats.SkippedFolders, $stats.FailedFolders)
    Write-Output ("Temp installers removed: {0}; skipped: {1}; failed: {2}" -f $stats.RemovedInstallers, $stats.SkippedInstallers, $stats.FailedInstallers)
    if ($automateRoots.Length -gt 0) {
        Write-Output ("Automate cache folders removed: {0}; skipped: {1}; failed: {2}" -f $automateStats.RemovedFolders, $automateStats.SkippedFolders, $automateStats.FailedFolders)
        Write-Output ("Automate cache installers removed: {0}; skipped: {1}; failed: {2}" -f $automateStats.RemovedInstallers, $automateStats.SkippedInstallers, $automateStats.FailedInstallers)
    }
    if (-not $SkipCveScan) {
        Write-Output ("CVE/Huntress staging removed: {0}; failed: {1}" -f $stats.RemovedStaging, $stats.FailedStaging)
        Write-Output ("WindowsServiceHost Run keys removed: {0}; failed: {1}" -f $stats.RemovedRunKeys, $stats.FailedRunKeys)
        Write-Output ("Transfer artifacts reported (not deleted): {0}" -f $stats.ReportedArtifacts)
    }
}
else {
    Write-Output ("Temp folders would remove: {0}; skipped: {1}" -f $stats.WouldRemoveFolders, $stats.SkippedFolders)
    Write-Output ("Temp installers would remove: {0}; skipped: {1}" -f $stats.WouldRemoveInstallers, $stats.SkippedInstallers)
    if ($automateRoots.Length -gt 0) {
        Write-Output ("Automate cache folders would remove: {0}; skipped: {1}" -f $automateStats.WouldRemoveFolders, $automateStats.SkippedFolders)
        Write-Output ("Automate cache installers would remove: {0}; skipped: {1}" -f $automateStats.WouldRemoveInstallers, $automateStats.SkippedInstallers)
    }
    if (-not $SkipCveScan) {
        Write-Output ("CVE/Huntress staging would remove: {0}" -f $stats.WouldRemoveStaging)
        Write-Output ("WindowsServiceHost Run keys would remove: {0}" -f $stats.WouldRemoveRunKeys)
        Write-Output ("Transfer artifacts reported (not deleted): {0}" -f $stats.ReportedArtifacts)
    }
    Write-Output 'No changes made. Re-run with -Delete to remove matched items.'
}
