#Requires -Version 5.1
<#
.SYNOPSIS
    Scans temp folders for stale ScreenConnect copies and old installer files.

.DESCRIPTION
    Finds leftover ScreenConnect temp folders and installer files (.msi/.exe) dated
    2025 or older. Preserves the currently installed client. Dry-run by default.

.PARAMETER Delete
    Actually remove matched items. Without this switch, only reports findings.

.PARAMETER MinAgeHours
    Skip temp folders modified within this many hours (unless -Force).

.PARAMETER MaxInstallerYear
    Remove installer files with LastWriteTime year less than or equal to this value.

.PARAMETER Force
    Skip the MinAgeHours folder age check.
#>
[CmdletBinding()]
param(
    [switch]$Delete,
    [int]$MinAgeHours = 24,
    [int]$MaxInstallerYear = 2025,
    [switch]$Force
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.1.0'

$InstanceIdPattern = '[a-f0-9]{16}'
$HashFolderPattern = "^$InstanceIdPattern$"
$ScreenConnectClientFolderPattern = '^ScreenConnect Client \([a-f0-9]{16}\)$'

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
    $instanceIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

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

    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $instanceIds) {
        [void]$list.Add($id)
    }

    return [string[]]($list.ToArray())
}

function Get-TempScanRoots {
    $roots = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($candidate in @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'))) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        try {
            $resolved = [System.IO.Path]::GetFullPath($candidate)
            if (Test-Path -LiteralPath $resolved) {
                [void]$roots.Add($resolved)
            }
        }
        catch {
            Write-Output "WARNING: Temp path not accessible: $candidate"
        }
    }

    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $roots) {
        [void]$list.Add($root)
    }

    return [string[]]($list.ToArray())
}

function Get-InstanceFolderCandidates {
    param([AllowNull()][object]$ScanRoots)

    $roots = Ensure-StringArray -InputObject $ScanRoots
    $candidates = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()

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

    return $false
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
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    $activeIds = Ensure-StringArray -InputObject $ActiveInstanceIds
    $instanceId = Get-FolderInstanceId -FolderName $Directory.Name
    $path = $Directory.FullName

    if ($instanceId -and ($activeIds -contains $instanceId)) {
        Write-Result -Type 'Folder' -Status 'SKIPPED (active)' -Path $path
        $Stats.Value.SkippedFolders++
        return
    }

    if (Test-FolderTooNew -Directory $Directory -Cutoff $Cutoff) {
        Write-Result -Type 'Folder' -Status 'SKIPPED (too new)' -Path $path -Detail ("modified {0:u}" -f $Directory.LastWriteTime)
        $Stats.Value.SkippedFolders++
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'Folder' -Status 'WOULD REMOVE' -Path $path
        $Stats.Value.WouldRemoveFolders++
        return
    }

    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type 'Folder' -Status 'REMOVED' -Path $path
        $Stats.Value.RemovedFolders++
        Remove-EmptyScreenConnectAncestors -StartPath $path
    }
    catch {
        Write-Result -Type 'Folder' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedFolders++
    }
}

function Invoke-InstallerAction {
    param(
        [System.IO.FileInfo]$File,
        [AllowNull()][object]$ActiveInstanceIds,
        [datetime]$Cutoff,
        [ref]$Stats,
        [System.Collections.Generic.HashSet[string]]$RemovedPaths
    )

    $activeIds = Ensure-StringArray -InputObject $ActiveInstanceIds

    $path = $File.FullName
    $parentPath = $File.DirectoryName

    if ($RemovedPaths.Contains($path.ToLowerInvariant()) -or ($parentPath -and $RemovedPaths.Contains($parentPath.ToLowerInvariant()))) {
        return
    }

    if (Test-IsUnderActiveInstance -Path $path -ActiveInstanceIds $activeIds) {
        Write-Result -Type 'Installer' -Status 'SKIPPED (active)' -Path $path
        $Stats.Value.SkippedInstallers++
        return
    }

    $fileYear = $File.LastWriteTime.Year
    if ($fileYear -gt $MaxInstallerYear) {
        Write-Result -Type 'Installer' -Status 'SKIPPED (year > cutoff)' -Path $path -Detail ("LastWriteTime year {0}, cutoff {1}" -f $fileYear, $MaxInstallerYear)
        $Stats.Value.SkippedInstallers++
        return
    }

    if (Test-InstallerInProgress -File $File -ActiveInstanceIds $activeIds -Cutoff $Cutoff) {
        Write-Result -Type 'Installer' -Status 'SKIPPED (too new)' -Path $path -Detail 'active client reinstall in progress'
        $Stats.Value.SkippedInstallers++
        return
    }

    if (-not $Delete) {
        Write-Result -Type 'Installer' -Status 'WOULD REMOVE' -Path $path -Detail ("LastWriteTime {0:yyyy-MM-dd}" -f $File.LastWriteTime)
        $Stats.Value.WouldRemoveInstallers++
        return
    }

    try {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        [void]$RemovedPaths.Add($path.ToLowerInvariant())
        Write-Result -Type 'Installer' -Status 'REMOVED' -Path $path -Detail ("LastWriteTime {0:yyyy-MM-dd}" -f $File.LastWriteTime)
        $Stats.Value.RemovedInstallers++
        Remove-EmptyScreenConnectAncestors -StartPath $path
    }
    catch {
        Write-Result -Type 'Installer' -Status 'FAILED' -Path $path -Detail $_.Exception.Message
        $Stats.Value.FailedInstallers++
    }
}

$activeInstanceIds = Ensure-StringArray (Get-ActiveScreenConnectInstanceId)
$scanRoots = Ensure-StringArray (Get-TempScanRoots)
$folderCutoff = (Get-Date).AddHours(-1 * $MinAgeHours)
$mode = if ($Delete) { 'DELETE' } else { 'DRY-RUN' }

Write-Output "=== ScreenConnect Temp Cleanup v$ScriptVersion ==="
Write-Output "Mode: $mode"
Write-Output "Active instance ID(s): $(if ($activeInstanceIds -and $activeInstanceIds.Length -gt 0) { ($activeInstanceIds -join ', ') } else { '(none detected)' })"
Write-Output "Scan roots: $(($scanRoots -join '; '))"
Write-Output "Folder min age: $MinAgeHours hour(s)$(if ($Force) { ' (Force: age check disabled)' } else { '' })"
Write-Output "Installer year cutoff: <= $MaxInstallerYear"
Write-Output ''

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
}

$removedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$seenInstallers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$folderCandidates = Get-InstanceFolderCandidates -ScanRoots $scanRoots

$seenFolders = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($folder in $folderCandidates) {
    if (-not $seenFolders.Add($folder.FullName)) {
        continue
    }

    Invoke-FolderAction -Directory $folder -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths
}

foreach ($root in $scanRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-IsScreenConnectInstallerFile -File $_ } |
        ForEach-Object {
            if (-not $seenInstallers.Add($_.FullName)) {
                return
            }

            Invoke-InstallerAction -File $_ -ActiveInstanceIds $activeInstanceIds -Cutoff $folderCutoff -Stats ([ref]$stats) -RemovedPaths $removedPaths
        }
}

Write-Output ''
Write-Output '=== Summary ==='
if ($Delete) {
    Write-Output ("Folders removed: {0}; skipped: {1}; failed: {2}" -f $stats.RemovedFolders, $stats.SkippedFolders, $stats.FailedFolders)
    Write-Output ("Installers removed: {0}; skipped: {1}; failed: {2}" -f $stats.RemovedInstallers, $stats.SkippedInstallers, $stats.FailedInstallers)
}
else {
    Write-Output ("Folders would remove: {0}; skipped: {1}" -f $stats.WouldRemoveFolders, $stats.SkippedFolders)
    Write-Output ("Installers would remove: {0}; skipped: {1}" -f $stats.WouldRemoveInstallers, $stats.SkippedInstallers)
    Write-Output 'No changes made. Re-run with -Delete to remove matched items.'
}
