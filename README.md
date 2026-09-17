# ScreenConnect Temp Cleanup

PowerShell utility for removing leftover ScreenConnect temp folders, old installer files, and ConnectWise-signed branded installers from Windows endpoints. **v1.7.1** also reports installed client versions against **CVE-2026-84869** (unauthorized file transfer/execute on clients before `26.6.5.9742`) and cleans Huntress staging IOCs from that campaign.

**Run it from the ConnectWise Control (ScreenConnect) command console** — paste one of the blocks below into the Commands tab on a Windows guest.

**Windows endpoints only.** Do not run on macOS or Linux; ScreenConnect interprets `#!ps` as the Unix `ps` tool on those systems.

This is hygiene, not incident response. Huntress recommends **reimaging** any host where `1.vbs`–`4.vbs` ran from `Process: Guest`. The script never uninstalls `Program Files` clients.

Replace `monobrau/screenconnect-temp-cleanup` if you fork or rename the repository.

The command tab defaults to `cmd` with a 10-second timeout. The `#!ps` hashbang runs PowerShell; `#timeout` and `#maxlength` give the script enough time and output space. Use `ScriptBlock` invocation so `-Delete` binds correctly. Bump the `?v=` query string when you need to bypass GitHub CDN cache.

## Run from ScreenConnect (dry-run first)

Paste into the **Commands** tab. Reports findings only — nothing is deleted.

```powershell
#!ps
#timeout=120000
#maxlength=100000
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
$repo = 'monobrau/screenconnect-temp-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-ScreenConnectTempCopies.ps1?v=1.7.1"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script))
```

Expected first line: `=== ScreenConnect Temp Cleanup v1.7.1 ===` and `Mode: DRY-RUN`.

## Run from ScreenConnect (delete matched items)

Use after reviewing dry-run output on the same machine.

```powershell
#!ps
#timeout=120000
#maxlength=100000
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
$repo = 'monobrau/screenconnect-temp-cleanup'
$url = "https://raw.githubusercontent.com/$repo/main/Remove-ScreenConnectTempCopies.ps1?v=1.7.1"
$script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
& ([ScriptBlock]::Create($script)) -Delete
```

## ScreenConnect options

Append switches inside the `ScriptBlock` invocation. Examples:

```powershell
& ([ScriptBlock]::Create($script)) -Delete -MinAgeHours 48
& ([ScriptBlock]::Create($script)) -Delete -SkipBrandedInstallerScan
& ([ScriptBlock]::Create($script)) -Delete -SkipAutomateCache
& ([ScriptBlock]::Create($script)) -SkipCveScan
```

| Switch | Default | Description |
|--------|---------|-------------|
| `-Delete` | off | Remove matched folders, installer files, Huntress staging IOCs, and `WindowsServiceHost` Run values. Never uninstalls clients. |
| `-MinAgeHours` | `24` | Skip temp folders modified within this many hours |
| `-MaxInstallerYear` | current year | Remove name/path-matched installers with LastWriteTime year <= this value (`0` = current calendar year) |
| `-SkipAutomateCache` | off | Skip `C:\Windows\LTSvc\packages` ScreenConnect Automate cache |
| `-SkipBrandedInstallerScan` | off | Skip ConnectWise signature scan of Downloads/Desktop installers |
| `-SkipCveScan` | off | Skip the client-version advisory and Huntress staging IOC pass |
| `-Force` | off | Skip the folder age check |

## ScreenConnect fallback (`#!ps` not working)

**Windows only** — use when the hashbang is not routed to PowerShell. For dry-run, remove `-Delete` from the `-Command` block.

```text
#!cmd
#timeout=120000
#maxlength=100000
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}; $url = 'https://raw.githubusercontent.com/monobrau/screenconnect-temp-cleanup/main/Remove-ScreenConnectTempCopies.ps1?v=1.7.1'; $script = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content; & ([ScriptBlock]::Create($script)) -Delete }"
```

## What it does

- Scans session temp, `C:\Windows\Temp`, **`C:\Windows\SystemTemp`**, service profile temps, and **every user profile** for stale ScreenConnect folders and installers
- User profile paths include **Downloads**, **Desktop**, **Documents**, `%LOCALAPPDATA%\Temp`, and browser cache folders (`INetCache`, Temporary Internet Files), plus `C:\Users\Public\Downloads` and `Desktop`
- Cleans **ConnectWise Automate (LTSvc) package cache** under `C:\Windows\LTSvc\packages\connectwisecontrol\` (and similar ScreenConnect package folders)
- Removes ScreenConnect installer files (`.msi`, `.exe`) dated **this calendar year or older** (still skips the active/newest protected copies)
- Finds **ConnectWise-signed** `.exe`/`.msi` installers in user **Downloads** and **Desktop** folders even when the filename is MSP-branded (e.g. `RRC.RemoteSupport.Client.exe`) — identified by authenticode signature, not filename
- **Never deletes** an installed or in-use ScreenConnect client (`Program Files*\ScreenConnect Client (*)`, service ImagePath, uninstall InstallLocation, or any temp/cache path containing a detected instance ID). `VULNERABLE` / `ROGUE-ID` is report-only. `-Force` does not override this.
- Preserves the **newest** Automate package cache copy per folder
- Removes **superseded version folders** under `ScreenConnect\{version}\` only when they do **not** contain an in-use instance ID
- Reports each installed client as `PATCHED` / `VULNERABLE` / `ROGUE-ID` against CVE-2026-84869 (`26.6.5.9742`); flags extra instances and missing uninstall keys
- Removes Huntress staging IOCs (`1.vbs`–`4.vbs`, `map.txt`, `out.enc`, `runner.ps1`, `WindowsServiceHost.vbs`/`.bat`, `PyTorchFix.ps1`, `sys_cache.zip`, `Lib1`) from temp / ScreenConnect / Public Libraries paths, and the `WindowsServiceHost` Run key
- Reports other `.vbs`/`.ps1`/`.bat`/`.enc` files under ScreenConnect temp as `[Transfer-Artifact]` (not auto-deleted)
- **Dry-run by default** — reports findings without deleting until `-Delete` is used

## CVE-2026-84869 (September 2026)

ConnectWise [bulletin 2026-09-08](https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin): clients **before 26.6.5** can transfer and execute files during an active session without Host confirmation. Servers are not affected. CISA KEV: `CVE-2026-84869`. Huntress documented worm-like spread via `RunFiles`/`RanFiles` of `1.vbs`–`4.vbs` from `Process: Guest`.

This script **cannot patch the client**. After the ScreenConnect server is on 26.6.5, reinstall host clients / update access agents. Isolate and reimage if Huntress IOCs already ran.

## Safety

- **Hard rule:** the in-use / installed ScreenConnect client is never removed, even when the advisory says `VULNERABLE`. Every delete path re-checks Program Files client dirs, discovered install paths, and active instance IDs.
- Huntress staging cleanup will not delete files under those protected client install directories
- Temp folders, Automate package cache, Huntress staging files, and the `WindowsServiceHost` Run value only
- Skips the newest installer in each Automate package folder (Automate's in-use deployment copy)
- Skips temp folders modified within the last 24 hours (configurable)
- Skips name/path-matched installer files newer than the year cutoff (default: current year). ConnectWise-signed Downloads/Desktop installers are removed regardless of year
- Branded installer detection requires a **Valid** authenticode signature whose subject contains `ConnectWise` or `ScreenConnect` — unsigned or third-party-signed `.exe` files in Downloads are not touched
- Huntress-named scripts are only deleted under temp / ScreenConnect / `Lib1` / Templates paths (`WindowsServiceHost.*` is also matched under user AppData). A random `1.vbs` in Documents is left alone
- `value.txt` is only removed when it sits next to other staging names (`1.vbs`, `map.txt`, `out.enc`, …)

## Requirements

- **Windows endpoints only** (PowerShell 5.1+)
- Outbound HTTPS to `raw.githubusercontent.com`

## Local usage

For testing or running from an elevated PowerShell session on the machine:

```powershell
.\Remove-ScreenConnectTempCopies.ps1
.\Remove-ScreenConnectTempCopies.ps1 -Delete
.\Remove-ScreenConnectTempCopies.ps1 -Delete -MinAgeHours 48
.\Remove-ScreenConnectTempCopies.ps1 -SkipCveScan
```

## Example output

```text
=== ScreenConnect Temp Cleanup v1.7.1 ===
Mode: DRY-RUN
Active instance ID(s): d519fd2fdcfe66e7
CVE-2026-84869 / Huntress scan: client advisory + staging IOCs
Active/installed clients: never deleted (CVE status is report-only; -Force does not override)
Folder min age: 24 hour(s)
Installer year cutoff: <= 2026

=== ScreenConnect client advisory (CVE-2026-84869) ===
[Client] VULNERABLE : C:\Program Files (x86)\ScreenConnect Client (d519fd2fdcfe66e7)\ScreenConnect.ClientService.exe (version 23.9.10.8817; service Running)

[Folder] SKIPPED (active) : C:\Users\user\AppData\Local\Temp\ScreenConnect\d519fd2fdcfe66e7 (in-use or installed client - never deleted)
[Folder] WOULD REMOVE : C:\Users\user\AppData\Local\Temp\ScreenConnect\abc123def4567890
[Installer] WOULD REMOVE : C:\Users\user\AppData\Local\Temp\ScreenConnect Client Setup.msi (LastWriteTime 2024-11-03)

--- CVE-2026-84869 / Huntress staging ---
[Cve-Staging] WOULD REMOVE : C:\Users\user\AppData\Local\Temp\1.vbs (Huntress/CVE-2026-84869 IOC)
[Cve-RunKey] WOULD REMOVE : HKCU:\Software\Microsoft\Windows\CurrentVersion\Run (C:\Users\user\AppData\Roaming\WindowsServiceHost.vbs)

=== Summary ===
Temp folders would remove: 1; skipped: 1
Temp installers would remove: 1; skipped: 0
CVE/Huntress staging would remove: 1
WindowsServiceHost Run keys would remove: 1
No changes made. Re-run with -Delete to remove matched items.
```

## Troubleshooting (ScreenConnect)

- **Command times out:** Increase `#timeout=` (milliseconds). Large temp folders may need `#timeout=300000`.
- **`ps: illegal argument`:** The guest is **macOS** or **Linux**. This script is Windows-only.
- **Output truncated:** Increase `#maxlength=` or run locally and review full output.
- **TLS errors:** The one-liner sets TLS 1.2 as numeric `3072` (safe on PowerShell 2.0). Ensure the endpoint can reach GitHub.
- **No active client detected:** The script still runs but logs a warning. Review dry-run output before using `-Delete`.
- **`[Client] VULNERABLE`:** Update the ScreenConnect server to 26.6.5+ and push a new client. This script will not upgrade it.
- **`[Client] ROGUE-ID` / hidden uninstall key / extra instances:** Treat as compromise until proven otherwise. Huntress: reimage.
- **Stale script from GitHub:** Bump the `?v=1.7.1` cache-buster in the URL.

## License

MIT — see [LICENSE](LICENSE).
