# ScreenConnect Temp Cleanup

PowerShell utility for removing leftover ScreenConnect temp folders and old installer files from Windows endpoints. Designed to run from the **ConnectWise Control (ScreenConnect) command console** by pulling the script directly from GitHub.

## What it does

- Scans session temp, `C:\Windows\Temp`, **`C:\Windows\SystemTemp`**, service profile temps, and **every user profile** for stale ScreenConnect folders and installers
- User profile paths include **Downloads**, **Desktop**, **Documents**, `%LOCALAPPDATA%\Temp`, and browser cache folders (`INetCache`, Temporary Internet Files), plus `C:\Users\Public\Downloads` and `Desktop`
- Cleans **ConnectWise Automate (LTSvc) package cache** under `C:\Windows\LTSvc\packages\connectwisecontrol\` (and similar ScreenConnect package folders)
- Removes ScreenConnect installer files (`.msi`, `.exe`) dated **2025 or older**
- Preserves the **currently installed** ScreenConnect client instance and the **newest** Automate package cache copy per folder
- **Dry-run by default** — reports findings without deleting until `-Delete` is used

## Safety

- Temp folders and Automate package cache — does not touch `Program Files`, `ProgramData`, or registry
- Skips folders/files belonging to the active ScreenConnect client service
- Skips the newest installer in each Automate package folder (Automate's in-use deployment copy)
- Skips temp folders modified within the last 24 hours (configurable)
- Skips installer files from 2026 onward

## Requirements

- **Windows endpoints only** (PowerShell 5.1+)
- Outbound HTTPS to `raw.githubusercontent.com`

Do **not** run these commands against **macOS or Linux** guests. On those systems, ScreenConnect interprets `#!ps` as the Unix `ps` process tool, not PowerShell, and you will see `ps: illegal argument`.

## ScreenConnect command console (Windows)

The SC command tab runs in `cmd` by default with a 10-second timeout. Use hashbang modifiers so PowerShell runs with enough time and output space.

Replace `monobrau/screenconnect-temp-cleanup` if you fork or rename the repository.

Use `ScriptBlock` invocation so `-Delete` binds correctly. Add a cache-buster query string so endpoints do not run a stale cached copy from GitHub CDN.

### Dry-run (recommended first)

```powershell
#!ps
#timeout=120000
#maxlength=100000
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = 'monobrau/screenconnect-temp-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-ScreenConnectTempCopies.ps1?v=1.4.0"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script))
```

### Delete matched items

```powershell
#!ps
#timeout=120000
#maxlength=100000
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = 'monobrau/screenconnect-temp-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-ScreenConnectTempCopies.ps1?v=1.4.0"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script)) -Delete
```

### Windows fallback (if `#!ps` fails)

Use this on **Windows only** when the hashbang is not routed to PowerShell:

```text
#!cmd
#timeout=120000
#maxlength=100000
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = 'https://raw.githubusercontent.com/monobrau/screenconnect-temp-cleanup/main/Remove-ScreenConnectTempCopies.ps1?v=1.3.0'; $script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content; & ([ScriptBlock]::Create($script)) -Delete }"
```

For dry-run, remove `-Delete` from the end of the `-Command` block.

Output should begin with `=== ScreenConnect Temp Cleanup v1.4.0 ===`. If you do not see a version number, the endpoint is still running an old cached script — bump the `?v=` value or retry.

## Local usage

```powershell
# Report only
.\Remove-ScreenConnectTempCopies.ps1

# Delete matched items
.\Remove-ScreenConnectTempCopies.ps1 -Delete

# Custom options
.\Remove-ScreenConnectTempCopies.ps1 -Delete -MinAgeHours 48 -MaxInstallerYear 2025
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Delete` | off | Remove matched folders and installer files |
| `-MinAgeHours` | `24` | Skip temp folders modified within this many hours |
| `-MaxInstallerYear` | `2025` | Remove installers with LastWriteTime year <= this value |
| `-SkipAutomateCache` | off | Skip `C:\Windows\LTSvc\packages` ScreenConnect Automate cache |
| `-Force` | off | Skip the folder age check |

## Example output

```text
=== ScreenConnect Temp Cleanup ===
Mode: DRY-RUN
Active instance ID(s): d519fd2fdcfe66e7
Scan roots: C:\Users\user\AppData\Local\Temp
Folder min age: 24 hour(s)
Installer year cutoff: <= 2025

[Folder] SKIPPED (active) : C:\Users\user\AppData\Local\Temp\ScreenConnect\d519fd2fdcfe66e7
[Folder] WOULD REMOVE : C:\Users\user\AppData\Local\Temp\ScreenConnect\abc123def4567890
[Installer] WOULD REMOVE : C:\Users\user\AppData\Local\Temp\ScreenConnect Client Setup.msi (LastWriteTime 2024-11-03)
[Installer] SKIPPED (year > cutoff) : C:\Users\user\AppData\Local\Temp\ScreenConnect-2026.msi (LastWriteTime year 2026, cutoff 2025)

=== Summary ===
Folders would remove: 1; skipped: 1
Installers would remove: 1; skipped: 1
No changes made. Re-run with -Delete to remove matched items.
```

## Troubleshooting

- **Command times out in SC:** Increase `#timeout=` (milliseconds). Large temp folders may need `#timeout=300000`.
- **`ps: illegal argument`:** The guest is **macOS** (or non-Windows). This script is Windows-only — run it on Windows endpoints.
- **Output truncated:** Increase `#maxlength=` or run locally and review full output.
- **TLS errors:** The SC one-liner sets TLS 1.2 explicitly; ensure the endpoint can reach GitHub.
- **No active client detected:** The script still runs but logs a warning. Review dry-run output before using `-Delete`.

## License

MIT — see [LICENSE](LICENSE).
