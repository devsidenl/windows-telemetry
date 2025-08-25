# windows-telemetry
Disable all Microsoft Telemetry 

# Disable Microsoft Telemetry — GUI + Undo + Verify

A WPF-powered PowerShell tool to **reduce or disable Microsoft telemetry** on Windows, with a **WinUtil-style checkbox GUI**, **per-item Undo**, and **built-in Verify** checks so users can confirm what changed.

- **Apply** privacy policies for Windows, Office, and Microsoft Edge  
- **Disable** related services, ETW autologgers, and scheduled tasks (where present)  
- **Opt-out** common developer CLIs & tools (PowerShell 7+, .NET CLI, WinGet, etc.)  
- **Undo** any selected change safely (snapshotted state)  
- **Verify** results with clear ✅ / ⚠️ messages

---

## Quick Start

```powershell
# Recommended one-liner (replace with your own URL if self-hosting)
irm "https://devside.nl/win" | iex
```

- Auto-elevates to admin, switches to **STA** for WPF, and uses a **process-only ExecutionPolicy bypass**.  
- Presents a GUI with **Apply**, **Verify**, and **Undo** per checkbox group.  
- No hosts/DNS/firewall blocking.

---

## What It Changes

### Windows Privacy Policies
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
  - `AllowTelemetry = 0`
  - `DoNotShowFeedbackNotifications = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo`
  - `DisabledByGroupPolicy = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
  - `DisableWindowsConsumerFeatures = 1`
- `HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
  - `DisableTailoredExperiencesWithDiagnosticData = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows`
  - `CEIPEnable = 0`

### Windows Error Reporting (WER)
- Disables WER via both policy and local keys:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting` → `Disabled = 1`  
  - `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting` → `Disabled = 1`

### Services & ETW Autologgers
- Stops & disables services (if present): `DiagTrack`, `dmwappushservice`, `WerSvc`  
- ETW autologgers:
  - `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener` → `Start = 0`
  - `HKLM\...\Autologger\SQMLogger` (if present) → `Start = 0`

### Scheduled Tasks (Disabled if Present)
```
\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
\Microsoft\Windows\Application Experience\ProgramDataUpdater
\Microsoft\Windows\Application Experience\AitAgent
\Microsoft\Windows\Application Experience\StartupAppTask
\Microsoft\Windows\Customer Experience Improvement Program\Consolidator
\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask
\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver
\Microsoft\Windows\DiskFootprint\Diagnostics
\Microsoft\Windows\Autochk\Proxy
\Microsoft\Windows\Feedback\Siuf\DmClient
\Microsoft\Windows\Feedback\Siuf\DmClientOnScenario
```
> If a task is missing on your build/edition, it’s simply skipped.

### Office (16.0) Privacy & Telemetry
Applies to the current user **and** all **loaded** user hives (HKEY_USERS):

- `HKCU/HKU\Software\Policies\Microsoft\office\16.0\common\privacy`
  - `DisconnectedState = 2`
  - `UserContentDisabled = 2`
  - `DownloadContentDisabled = 2`
  - `ControllerConnectedServicesEnabled = 2`
- `HKCU/HKU\Software\Policies\Microsoft\office\common\clienttelemetry`
  - `SendTelemetry = 3` *(Neither)*

> Works for Microsoft 365 Apps and Office 2016/2019/2021 (all use the 16.0 policy path).

### Microsoft Edge Policies (Machine)
- `HKLM\SOFTWARE\Policies\Microsoft\Edge`
  - `DiagnosticData = 0`
  - `UserFeedbackAllowed = 0`
  - `PersonalizationReportingEnabled = 0`

### Developer / CLI Telemetry Opt-Outs
- **PowerShell 7+**: `POWERSHELL_TELEMETRY_OPTOUT = 1` (Machine)  
- **.NET SDK/CLI**: `DOTNET_CLI_TELEMETRY_OPTOUT = 1` (Machine)  
- **Azure CLI (az)**: sets `core.collect_telemetry = false` (if `az` exists)  
- **Azure PowerShell (Az)**: runs `Disable-AzDataCollection` (if module present)  
- **PnP.PowerShell**: `PNPPOWERSHELL_DISABLETELEMETRY = true` (Machine) and disables via cmdlet when available  
- **WinGet**: writes `telemetry.disable = true` to both known settings locations  
- **VS Code**: ensures `"telemetry.telemetryLevel": "off"` in `settings.json` (Stable & Insiders)  
- **Visual Studio** (2019/2022): sets `SQM\OptIn=0` (x86/x64 hives) and policy `OptIn=0`

---

## Verify (Built-In)

Click **Verify Selected** (or use Apply → auto-Verify) to get human-readable results, e.g.:

- `✅ Windows Policies — All expected registry values are set.`  
- `⚠️ Scheduled Tasks — Enabled tasks: …`  
- `✅ .NET CLI — DOTNET_CLI_TELEMETRY_OPTOUT=1 (Machine).`  

This helps admins and auditors confirm changes immediately.

---

## Undo (Per Checkbox)

Before applying each group, the tool **captures a snapshot**:
- Registry values (existence + previous value)
- Services (previous StartMode & running state)
- Scheduled tasks (previous `Enabled`)
- Files (e.g., `settings.json`) with `*.bak-devside`
- Environment variables (previous Machine value)

**Undo Selected** restores only the chosen items from the snapshot.  
State file: `%ProgramData%\Devside\DisableMSTelemetry\state.json`.

---

## Supported Platforms

- **Windows 11** (current releases)  
- **Windows 10** (v1809+ recommended; some tasks/keys may not exist on older builds)  
- **PowerShell 5.1+** (inbox). PowerShell 7+ is optional; if installed, its opt-out env var is set.

> Office policies target **Office 16.0**. Edge policies target **Chromium-based Edge** on Windows 10/11.

---

## Run From File

```powershell
# If you saved the script locally as .\win.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\win.ps1
```

---

## Self-Hosting the One-Liner (Apache/SiteGround)

To serve `/win` as the script (so users can run `irm "https://yourdomain/win" | iex`), add this at the **top** of `public_html/.htaccess`:

```apache
RewriteEngine On
RewriteRule ^win$ win.ps1 [L]

<Files "win.ps1">
  Require all granted
  ForceType text/plain
  Header set X-Content-Type-Options "nosniff"
  Header set Cache-Control "no-cache, no-store, must-revalidate"
</Files>
```

Then your users can run:

```powershell
irm "https://yourdomain.example/win" | iex
```

---

## Security & Design Notes

- No hosts/DNS/firewall rules; no network-level blocking.  
- No background services installed.  
- No persistence beyond the **Undo state** and `*.bak-devside` backups.  
- Changes are limited to registries, scheduled tasks, services, and app settings.  
- External calls are local only, except:
  - `az config set …` when Azure CLI is present  
  - Importing already-installed PowerShell modules (Az, PnP)

---

## Limitations

- **Per-user Office**: applies to current + **loaded** user hives. New profiles created later won’t inherit these keys automatically—rerun if needed.  
- **Edition/build differences**: some tasks/services may not exist; they’re skipped.  
- **MDM/GPO** can override values in managed environments.

---

## Troubleshooting

**GUI fails with “EntityName … position …”**  
Use the latest version (raw `&` in XAML are escaped).

**Script execution blocked**  
The tool already uses a **process-only** ExecutionPolicy bypass. If running from disk:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\win.ps1
.\win.ps1
```

**Azure/PnP modules are missing**  
The tool logs “not found (skipped)”. Nothing else required.

---

## Contributing

PRs welcome for:
- Additional safe opt-out targets (with documented settings & Undo)  
- Preset buttons (e.g., Minimal / Standard / Strict)  
- Localization and accessibility improvements  
- Tests for Verify logic (Pester)

Guidelines:
- **Reversible** (add to snapshot/Undo)  
- **Auditable** (clear logs; no opaque binaries)  
- **Non-destructive** (prefer disable/policy over deletion)

---

## License

MIT — see `LICENSE`.

---

## Screenshot (Optional)

_Add a screenshot of the GUI here once hosted._

```
[ Apply Selected ] [ Verify Selected ] [ Undo Selected ]
-------------------------------------------------------
✅ Windows Policies — All expected registry values are set.
```

---

## File Layout & State

- Single script: `win.ps1` (served as plain text at your URL)  
- Undo state: `%ProgramData%\Devside\DisableMSTelemetry\state.json`  
- Edited files backed up as `*.bak-devside` alongside originals

---

## FAQ

**Does this stop Windows Updates?**  
No. Windows Update is not modified.

**Can I run it offline?**  
Yes, if you already have the script locally. The one-liner needs internet only to fetch it.

**Does it work on Windows Server?**  
Not the primary target, but many keys/tasks overlap. Verify/Undo still work; some tasks may differ.
