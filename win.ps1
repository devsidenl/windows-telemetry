# ===========================
# Disable Microsoft Telemetry — GUI + UNDO + VERIFY (per selection)
# Start via: irm "https://devside.nl/win" | iex
# ===========================
[CmdletBinding()] param()

# ---------- Elevation, EP-Bypass and STA ----------
function Restart-AsAdmin([switch]$ForceSta) {
  $psExe = (Get-Process -Id $PID).Path
  $temp  = Join-Path $env:TEMP 'Disable-MS-Telemetry-GUI.ps1'
  $self  = $MyInvocation.MyCommand.Path ? (Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw) : $MyInvocation.MyCommand.ScriptBlock.ToString()
  Set-Content -LiteralPath $temp -Value $self -Encoding UTF8
  $args = @('-NoProfile','-ExecutionPolicy','Bypass')
  if ($ForceSta -or ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA')) { $args += '-STA' }
  $args += @('-File',"`"$temp`"")
  Start-Process -FilePath $psExe -ArgumentList $args -Verb RunAs | Out-Null
  exit
}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Restart-AsAdmin -ForceSta }
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { Restart-AsAdmin -ForceSta }
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}
try { if ($MyInvocation.MyCommand.Path) { Unblock-File -LiteralPath $MyInvocation.MyCommand.Path } } catch {}

# ---------- WPF ----------
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase,System.Xaml | Out-Null

# ---------- Paths & State ----------
$StateDir  = Join-Path $env:ProgramData 'Devside\DisableMSTelemetry'
$null = New-Item -Path $StateDir -ItemType Directory -Force -ErrorAction SilentlyContinue
$StateFile = Join-Path $StateDir 'state.json'
$STATE = if (Test-Path $StateFile) { try { Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json -ErrorAction Stop } catch { @{ version=1; tweaks=@{} } } } else { @{ version=1; tweaks=@{} } }
function Save-State { param($StateObj) ($StateObj | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $StateFile -Encoding UTF8 }

# ---------- Logging ----------
function Write-Log([string]$Text) {
  $ts=(Get-Date).ToString('HH:mm:ss'); $line="[$ts] $Text"
  if ($global:TB_Log) { $global:TB_Log.AppendText("$line`r`n"); $global:TB_Log.ScrollToEnd() } else { Write-Host $line }
}
function Status-Symbol([string]$status) {
  switch ($status) { 'Pass' {'✅'} 'Warn' {'⚠️'} 'Fail' {'❌'} default {'ℹ️'} }
}
function Show-Result([string]$title,[string]$status,[string]$msg) {
  Write-Log "$(Status-Symbol $status) $title — $msg"
}

# ---------- Helpers (Registry/Service/Task/File/Env) ----------
function Ensure-TweakState { param([string]$Id) if (-not $STATE.tweaks.ContainsKey($Id)) { $STATE.tweaks[$Id] = @{ captured=$false; data=@{} } } return $STATE.tweaks[$Id] }
function Capture-Once { param([string]$Id,[scriptblock]$Block) $ts=Ensure-TweakState $Id; if (-not $ts.captured){ & $Block; $ts.captured=$true; Save-State $STATE } }

# Registry helpers
function Set-RegValue { param([string]$Path,[string]$Name,[string]$Type,[Object]$Value)
  if (!(Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
  New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}
function Reg-GetValue { param([string]$Path,[string]$Name)
  try { $val=(Get-ItemProperty -LiteralPath $Path -ErrorAction Stop).PSObject.Properties[$Name]; if($val){ return @{ exists=$true; value=$val.Value; type='DWord' } } else { return @{ exists=$false } } } catch { return @{ exists=$false } }
}
function Reg-Record { param([string]$Id,[string]$Path,[string]$Name)
  $ts=Ensure-TweakState $Id; if (-not $ts.data.registry){$ts.data.registry=@()} ; $prev=Reg-GetValue -Path $Path -Name $Name ; $ts.data.registry += @{ path=$Path; name=$Name; prev=$prev }
}
function Reg-Restore { param($Entry)
  $p=$Entry.path; $n=$Entry.name; $prev=$Entry.prev
  if ($prev.exists) { Set-RegValue -Path $p -Name $n -Type ($prev.type ?? 'DWord') -Value $prev.value }
  else { try { Remove-ItemProperty -LiteralPath $p -Name $n -ErrorAction SilentlyContinue | Out-Null } catch {} ; try { if ((Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0 -and (Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue) -eq $null) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue } } catch {} }
}

# Service helpers
function Svc-Record { param([string]$Id,[string]$Name)
  $ts=Ensure-TweakState $Id; if (-not $ts.data.services){$ts.data.services=@()}
  $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($svc) {
    $startType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue).StartMode
    $ts.data.services += @{ name=$Name; exists=$true; startType=$startType; status=$svc.Status }
  } else { $ts.data.services += @{ name=$Name; exists=$false } }
}
function Svc-Restore { param($Entry)
  if (-not $Entry.exists) { return }
  try {
    switch ($Entry.startType) { 'Auto' {Set-Service -Name $Entry.name -StartupType Automatic}; 'Automatic' {Set-Service -Name $Entry.name -StartupType Automatic}; 'Manual' {Set-Service -Name $Entry.name -StartupType Manual}; 'Disabled' {Set-Service -Name $Entry.name -StartupType Disabled}; default {Set-Service -Name $Entry.name -StartupType Manual} }
    if ($Entry.status -eq 'Running') { try { Start-Service -Name $Entry.name -ErrorAction SilentlyContinue } catch {} }
    if ($Entry.status -eq 'Stopped') { try { Stop-Service -Name $Entry.name -Force -ErrorAction SilentlyContinue } catch {} }
  } catch {}
}

# Task helpers
function Task-Record { param([string]$Id,[string]$TaskPath,[string]$TaskName)
  $ts=Ensure-TweakState $Id; if (-not $ts.data.tasks){$ts.data.tasks=@()}
  try { $t=Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop; $ts.data.tasks += @{ path=$TaskPath; name=$TaskName; exists=$true; enabled=$t.Enabled } }
  catch { $ts.data.tasks += @{ path=$TaskPath; name=$TaskName; exists=$false } }
}
function Task-Restore { param($Entry)
  if (-not $Entry.exists) { return }
  try { if ($Entry.enabled) { Enable-ScheduledTask -TaskPath $Entry.path -TaskName $Entry.name -ErrorAction SilentlyContinue | Out-Null } else { Disable-ScheduledTask -TaskPath $Entry.path -TaskName $Entry.name -ErrorAction SilentlyContinue | Out-Null } } catch {}
}

# File backup helpers
function Backup-Once { param([string]$Id,[string]$FilePath)
  $ts=Ensure-TweakState $Id; if (-not $ts.data.files){$ts.data.files=@()}
  $entry=$ts.data.files | Where-Object { $_.path -eq $FilePath }; if ($entry){ return }
  $bak="$FilePath.bak-devside"
  if (Test-Path $FilePath -PathType Leaf) { $dir=Split-Path -Parent $bak; if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } ; Copy-Item -LiteralPath $FilePath -Destination $bak -Force }
  $ts.data.files += @{ path=$FilePath; backup=$bak }
}
function Files-Restore { param($TweakData)
  if (-not $TweakData.files) { return }
  foreach ($f in $TweakData.files) {
    if (Test-Path $f.backup -PathType Leaf) { $dir=Split-Path -Parent $f.path; if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } ; Copy-Item -LiteralPath $f.backup -Destination $f.path -Force ; try { Remove-Item -LiteralPath $f.backup -Force -ErrorAction SilentlyContinue } catch {} }
    else { if (Test-Path $f.path -PathType Leaf) { try { Remove-Item -LiteralPath $f.path -Force -ErrorAction SilentlyContinue } catch {} } }
  }
}

# Env helpers
function Env-Record { param([string]$Id,[string]$Name)
  $ts=Ensure-TweakState $Id; if (-not $ts.data.env){$ts.data.env=@()}
  $prev=[Environment]::GetEnvironmentVariable($Name,'Machine')
  $ts.data.env += @{ name=$Name; value=$prev; exists=([string]::IsNullOrEmpty($prev) -eq $false) }
}
function Env-Restore { param($Entry)
  if ($Entry.exists) { [Environment]::SetEnvironmentVariable($Entry.name,$Entry.value,'Machine') } else { [Environment]::SetEnvironmentVariable($Entry.name,$null,'Machine') }
}

# ---------- APPLY TWEAKS ----------
function Apply-WindowsPolicies {
  $id='winpol'
  Capture-Once $id {
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications'
    Reg-Record $id 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod'
    Reg-Record $id 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures'
    Reg-Record $id 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableTailoredExperiencesWithDiagnosticData'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable'
    Save-State $STATE
  }
  Write-Log "Windows: applying privacy policies"
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1
  Set-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0
  Set-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -Type DWord -Value 0
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1
  Set-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
}
function Apply-WER {
  $id='wer'
  Capture-Once $id {
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled'
    Reg-Record $id 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled'
    Save-State $STATE
  }
  Write-Log "Windows Error Reporting: disabling"
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1
  Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1
}
function Apply-ServicesAutologgers {
  $id='svc'
  Capture-Once $id {
    foreach ($n in @('DiagTrack','dmwappushservice','WerSvc')) { Svc-Record $id $n }
    Reg-Record $id 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start'
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger') { Reg-Record $id 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger' 'Start' }
    Save-State $STATE
  }
  Write-Log "Services & ETW autologgers: disabling"
  foreach ($s in @('DiagTrack','dmwappushservice','WerSvc')) { $svc=Get-Service -Name $s -ErrorAction SilentlyContinue; if ($svc){ try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {}; try { Set-Service -Name $s -StartupType Disabled } catch {} } }
  Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0
  if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger') { Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger' -Name 'Start' -Type DWord -Value 0 }
}
function Apply-ScheduledTasks {
  $id='tasks'
  $list=@(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\AitAgent',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver',
    '\Microsoft\Windows\DiskFootprint\Diagnostics',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenario'
  )
  Capture-Once $id { foreach ($t in $list){ $tp=$t.Substring(0,$t.LastIndexOf('\')+1); $tn=$t.Substring($t.LastIndexOf('\')+1); Task-Record $id $tp $tn } ; Save-State $STATE }
  Write-Log "Scheduled Tasks: disabling if present"
  foreach ($t in $list) { $tp=$t.Substring(0,$t.LastIndexOf('\')+1); $tn=$t.Substring($t.LastIndexOf('\')+1); try { if (Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop) { Disable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue | Out-Null ; Write-Log "Disabled: $t" } } catch {} }
}
function Apply-OfficePolicies {
  $id='office'
  Capture-Once $id {
    foreach ($kv in @(
      @{p='Software\Policies\Microsoft\office\16.0\common\privacy'; n='DisconnectedState'},
      @{p='Software\Policies\Microsoft\office\16.0\common\privacy'; n='UserContentDisabled'},
      @{p='Software\Policies\Microsoft\office\16.0\common\privacy'; n='DownloadContentDisabled'},
      @{p='Software\Policies\Microsoft\office\16.0\common\privacy'; n='ControllerConnectedServicesEnabled'},
      @{p='Software\Policies\Microsoft\office\common\clienttelemetry'; n='SendTelemetry'}
    )) {
      Reg-Record $id ("Registry::HKEY_CURRENT_USER\" + $kv.p) $kv.n
      foreach ($sid in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21-\d+-\d+-\d+-\d+$' })) { Reg-Record $id ($sid.PSPath + "\" + $kv.p) $kv.n }
    }
    Save-State $STATE
  }
  Write-Log "Office: applying privacy & diagnostics policies"
  $pairsPrivacy=@{ 'DisconnectedState'=2; 'UserContentDisabled'=2; 'DownloadContentDisabled'=2; 'ControllerConnectedServicesEnabled'=2 }
  $pairsDiag=@{ 'SendTelemetry'=3 }
  function Set-RegValueAllUsers { param([string]$RelPath,[hashtable]$Pairs)
    $hkcuPath = Join-Path 'Registry::HKEY_CURRENT_USER' $RelPath
    if (!(Test-Path -LiteralPath $hkcuPath)) { New-Item -Path $hkcuPath -Force | Out-Null }
    foreach ($k in $Pairs.Keys) { New-ItemProperty -Path $hkcuPath -Name $k -PropertyType DWord -Value $Pairs[$k] -Force | Out-Null }
    $userHives = Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21-\d+-\d+-\d+-\d+$' }
    foreach ($h in $userHives) {
      $userPath = Join-Path $h.PSPath $RelPath
      if (!(Test-Path -LiteralPath $userPath)) { New-Item -Path $userPath -Force | Out-Null }
      foreach ($k in $Pairs.Keys) { New-ItemProperty -Path $userPath -Name $k -PropertyType DWord -Value $Pairs[$k] -Force | Out-Null }
    }
  }
  Set-RegValueAllUsers -RelPath 'Software\Policies\Microsoft\office\16.0\common\privacy' -Pairs $pairsPrivacy
  Set-RegValueAllUsers -RelPath 'Software\Policies\Microsoft\office\common\clienttelemetry' -Pairs $pairsDiag
}
function Apply-EdgePolicies {
  $id='edge'
  Capture-Once $id {
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'DiagnosticData'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'UserFeedbackAllowed'
    Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PersonalizationReportingEnabled'
    Save-State $STATE
  }
  Write-Log "Edge: applying diagnostic & feedback policies"
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DiagnosticData' -Type DWord -Value 0
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'UserFeedbackAllowed' -Type DWord -Value 0
  Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'PersonalizationReportingEnabled' -Type DWord -Value 0
}
function Apply-DevTelemetry {
  param([bool]$ps7,[bool]$dotnet,[bool]$azcli,[bool]$azmod,[bool]$pnp,[bool]$winget,[bool]$vscode,[bool]$vs)
  if ($ps7){ $id='ps7'; Capture-Once $id { Env-Record $id 'POWERSHELL_TELEMETRY_OPTOUT'; Save-State $STATE }; Write-Log "PowerShell 7+: setting telemetry opt-out"; [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','1','Machine') }
  if ($dotnet){ $id='dotnet'; Capture-Once $id { Env-Record $id 'DOTNET_CLI_TELEMETRY_OPTOUT'; Save-State $STATE }; Write-Log ".NET SDK/CLI: setting telemetry opt-out"; [Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT','1','Machine') }
  if ($azcli){ $id='azcli'; Capture-Once $id { $cfg=Join-Path $env:USERPROFILE '.azure\config'; Backup-Once $id $cfg; Save-State $STATE }; Write-Log "Azure CLI: configuring core.collect_telemetry=false"; if (Get-Command az -ErrorAction SilentlyContinue){ try { az config set core.collect_telemetry=false --only-show-errors | Out-Null } catch { Write-Log "Azure CLI configuration failed" } } else { Write-Log "Azure CLI not found (skipped)" } }
  if ($azmod){ $id='azmod'; Capture-Once $id { $STATE.tweaks[$id].data=@{touched=$false}; Save-State $STATE }; Write-Log "Azure PowerShell (Az): Disable-AzDataCollection"; if (Get-Module -ListAvailable -Name Az.Accounts){ try { Import-Module Az.Accounts -ErrorAction SilentlyContinue; Disable-AzDataCollection -ErrorAction SilentlyContinue; $STATE.tweaks[$id].data.touched=$true; Save-State $STATE } catch { Write-Log "Az opt-out failed" } } else { Write-Log "Az module not found (skipped)" } }
  if ($pnp){ $id='pnp'; Capture-Once $id { Env-Record $id 'PNPPOWERSHELL_DISABLETELEMETRY'; $STATE.tweaks[$id].data=@{touched=$false}; Save-State $STATE }; Write-Log "PnP.PowerShell: setting opt-out"; [Environment]::SetEnvironmentVariable('PNPPOWERSHELL_DISABLETELEMETRY','true','Machine'); if (Get-Module -ListAvailable -Name PnP.PowerShell){ try { Import-Module PnP.PowerShell -ErrorAction SilentlyContinue; Disable-PnPPowerShellTelemetry -ErrorAction SilentlyContinue; $STATE.tweaks[$id].data.touched=$true; Save-State $STATE } catch {} } else { Write-Log "PnP.PowerShell not found (skipped)" } }
  if ($winget){ $id='winget'; $wgPaths=@((Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json'),(Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Settings\settings.json')); Capture-Once $id { foreach ($p in $wgPaths){ Backup-Once $id $p } ; Save-State $STATE }; Write-Log "WinGet: writing telemetry.disable = true"; function Set-JsonKey { param([string]$Path,[string]$Key1,[string]$Key2,[object]$Value) $obj=New-Object PSObject; if (Test-Path -LiteralPath $Path){ try { $obj=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop } catch {} } ; if (-not $obj.PSObject.Properties[$Key1]){ $obj | Add-Member -NotePropertyName $Key1 -NotePropertyValue (New-Object PSObject) } ; if ($obj.$Key1.PSObject.Properties[$Key2]){ $obj.$Key1.$Key2=$Value } else { $obj.$Key1 | Add-Member -NotePropertyName $Key2 -NotePropertyValue $Value } ; $dir=Split-Path -Parent $Path; if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null } ; $obj | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8 }
    foreach ($wg in $wgPaths){ try { Set-JsonKey -Path $wg -Key1 'telemetry' -Key2 'disable' -Value $true } catch { Write-Log "WinGet settings not updated: $wg" } } }
  if ($vscode){ $id='vscode'; $paths=@((Join-Path $env:APPDATA 'Code\User\settings.json'),(Join-Path $env:APPDATA 'Code - Insiders\User\settings.json')); Capture-Once $id { foreach ($p in $paths){ Backup-Once $id $p } ; Save-State $STATE }; Write-Log "VS Code: setting telemetry.telemetryLevel = off"; function Set-VSCodeTelemetryOff { param([string]$Path) $dir=Split-Path -Parent $Path; if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } ; $content=(Test-Path $Path) ? (Get-Content -LiteralPath $Path -Raw) : "{}" ; if ($content -match '"telemetry\.telemetryLevel"\s*:'){ $content=[regex]::Replace($content,'("telemetry\.telemetryLevel"\s*:\s*)"(?:off|error|crash|all)"','$1"off"',1) } else { if ($content -match '^{\s*}$'){ $content='{ "telemetry.telemetryLevel": "off" }' } else { $content=$content.TrimEnd("`r","`n"," ","}") + ', "telemetry.telemetryLevel": "off" }' } } ; Set-Content -LiteralPath $Path -Value $content -Encoding UTF8 } ; foreach ($p in $paths){ try { Set-VSCodeTelemetryOff -Path $p } catch { Write-Log "VS Code settings not updated: $p" } } }
  if ($vs){ $id='vs'; Capture-Once $id { foreach ($root in @('HKLM:\SOFTWARE\Microsoft\VSCommon','HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon')){ foreach ($ver in @('16.0','17.0')){ Reg-Record $id (Join-Path (Join-Path $root $ver) 'SQM') 'OptIn' } } ; Reg-Record $id 'HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM' 'OptIn' ; Save-State $STATE } ; Write-Log "Visual Studio: disabling CEIP/telemetry" ; foreach ($root in @('HKLM:\SOFTWARE\Microsoft\VSCommon','HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon')){ foreach ($ver in @('16.0','17.0')){ Set-RegValue -Path (Join-Path (Join-Path $root $ver) 'SQM') -Name 'OptIn' -Type DWord -Value 0 } } ; Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM' -Name 'OptIn' -Type DWord -Value 0 }
}

# ---------- UNDO ----------
function Undo-WindowsPolicies { $id='winpol'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: Windows policies"; foreach ($e in $t.data.registry){ Reg-Restore $e } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for Windows policies" } }
function Undo-WER { $id='wer'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: Windows Error Reporting"; foreach ($e in $t.data.registry){ Reg-Restore $e } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for WER" } }
function Undo-ServicesAutologgers { $id='svc'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: services & autologgers"; if ($t.data.services){ foreach ($s in $t.data.services){ Svc-Restore $s } } ; if ($t.data.registry){ foreach ($e in $t.data.registry){ Reg-Restore $e } } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for services/autologgers" } }
function Undo-ScheduledTasks { $id='tasks'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: scheduled tasks"; foreach ($x in $t.data.tasks){ Task-Restore $x } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for scheduled tasks" } }
function Undo-OfficePolicies { $id='office'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: Office policies"; foreach ($e in $t.data.registry){ Reg-Restore $e } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for Office" } }
function Undo-EdgePolicies { $id='edge'; $t=$STATE.tweaks[$id]; if ($t){ Write-Log "Undo: Edge policies"; foreach ($e in $t.data.registry){ Reg-Restore $e } ; $t.captured=$false; Save-State $STATE } else { Write-Log "No snapshot for Edge" } }
function Undo-DevTelemetry { param([bool]$ps7,[bool]$dotnet,[bool]$azcli,[bool]$azmod,[bool]$pnp,[bool]$winget,[bool]$vscode,[bool]$vs)
  if ($ps7){ $id='ps7'; if ($STATE.tweaks[$id]){ Write-Log "Undo: PowerShell 7+"; foreach ($e in $STATE.tweaks[$id].data.env){ Env-Restore $e } ; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($dotnet){ $id='dotnet'; if ($STATE.tweaks[$id]){ Write-Log "Undo: .NET CLI"; foreach ($e in $STATE.tweaks[$id].data.env){ Env-Restore $e } ; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($azcli){ $id='azcli'; if ($STATE.tweaks[$id]){ Write-Log "Undo: Azure CLI"; Files-Restore $STATE.tweaks[$id].data; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($azmod){ $id='azmod'; if ($STATE.tweaks[$id]){ Write-Log "Undo: Azure PowerShell (Az)"; if ($STATE.tweaks[$id].data.touched -and (Get-Module -ListAvailable -Name Az.Accounts)){ try { Import-Module Az.Accounts -ErrorAction SilentlyContinue; Enable-AzDataCollection -ErrorAction SilentlyContinue } catch {} } ; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($pnp){ $id='pnp'; if ($STATE.tweaks[$id]){ Write-Log "Undo: PnP.PowerShell"; foreach ($e in $STATE.tweaks[$id].data.env){ Env-Restore $e } ; if ($STATE.tweaks[$id].data.touched -and (Get-Module -ListAvailable -Name PnP.PowerShell)){ try { Import-Module PnP.PowerShell -ErrorAction SilentlyContinue; Enable-PnPPowerShellTelemetry -ErrorAction SilentlyContinue } catch {} } ; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($winget){ $id='winget'; if ($STATE.tweaks[$id]){ Write-Log "Undo: WinGet settings"; Files-Restore $STATE.tweaks[$id].data; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($vscode){ $id='vscode'; if ($STATE.tweaks[$id]){ Write-Log "Undo: VS Code settings"; Files-Restore $STATE.tweaks[$id].data; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
  if ($vs){ $id='vs'; if ($STATE.tweaks[$id]){ Write-Log "Undo: Visual Studio"; foreach ($e in $STATE.tweaks[$id].data.registry){ Reg-Restore $e } ; $STATE.tweaks[$id].captured=$false; Save-State $STATE } }
}

# ---------- VERIFY (checks with clear English feedback) ----------
function Verify-WindowsPolicies {
  $title='Windows Policies'
  $expected = @(
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Expected=0 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Expected=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name='DisabledByGroupPolicy'; Expected=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsConsumerFeatures'; Expected=1 },
    @{ Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableTailoredExperiencesWithDiagnosticData'; Expected=1 },
    @{ Path='HKCU:\SOFTWARE\Microsoft\Siuf\Rules'; Name='NumberOfSIUFInPeriod'; Expected=0 },
    @{ Path='HKCU:\SOFTWARE\Microsoft\Siuf\Rules'; Name='PeriodInNanoSeconds'; Expected=0 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'; Name='CEIPEnable'; Expected=0 }
  )
  $bad=@()
  foreach ($e in $expected) {
    $v = Reg-GetValue -Path $e.Path -Name $e.Name
    if (-not $v.exists -or [int]$v.value -ne [int]$e.Expected) { $bad += "$($e.Path)\$($e.Name) -> found: $([int]($v.value)) expected: $($e.Expected)" }
  }
  if ($bad.Count -eq 0) { Show-Result $title 'Pass' 'All expected registry values are set.' }
  else { Show-Result $title 'Warn' ("Some values differ:`n  - " + ($bad -join "`n  - ")) }
}
function Verify-WER {
  $title='Windows Error Reporting'
  $paths = @(
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'; Name='Disabled'; Expected=1 },
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'; Name='Disabled'; Expected=1 }
  )
  $bad=@()
  foreach ($p in $paths) {
    $v=Reg-GetValue -Path $p.Path -Name $p.Name
    if (-not $v.exists -or [int]$v.value -ne [int]$p.Expected) { $bad += "$($p.Path)\$($p.Name) -> found: $([int]($v.value)) expected: $($p.Expected)" }
  }
  if ($bad.Count -eq 0) { Show-Result $title 'Pass' 'WER is disabled in both policy and local keys.' }
  else { Show-Result $title 'Warn' ("Mismatch:`n  - " + ($bad -join "`n  - ")) }
}
function Verify-ServicesAutologgers {
  $title='Services & Autologgers'
  $svcBad=@()
  foreach ($s in 'DiagTrack','dmwappushservice','WerSvc') {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
      $mode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue).StartMode
      if ($mode -ne 'Disabled') { $svcBad += "$s StartType=$mode (expected Disabled)" }
    }
  }
  $alBad=@()
  $v = Reg-GetValue 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start'
  if (-not $v.exists -or [int]$v.value -ne 0) { $alBad += 'AutoLogger-Diagtrack-Listener Start != 0' }
  if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger') {
    $v2 = Reg-GetValue 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger' 'Start'
    if ($v2.exists -and [int]$v2.value -ne 0) { $alBad += 'SQMLogger Start != 0' }
  }
  if ($svcBad.Count -eq 0 -and $alBad.Count -eq 0) { Show-Result $title 'Pass' 'All present services are Disabled and autologgers are off.' }
  else {
    $msg = @()
    if ($svcBad.Count) { $msg += ('Services: ' + ($svcBad -join '; ')) }
    if ($alBad.Count)  { $msg += ('Autologgers: ' + ($alBad -join '; ')) }
    Show-Result $title 'Warn' ($msg -join ' | ')
  }
}
function Verify-ScheduledTasks {
  $title='Scheduled Tasks'
  $list=@(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\AitAgent',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver',
    '\Microsoft\Windows\DiskFootprint\Diagnostics',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenario'
  )
  $present=0; $disabled=0; $bad=@()
  foreach ($t in $list) {
    $tp=$t.Substring(0,$t.LastIndexOf('\')+1); $tn=$t.Substring($t.LastIndexOf('\')+1)
    try {
      $task = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop
      $present++
      if (-not $task.Enabled) { $disabled++ } else { $bad += $t }
    } catch { }
  }
  if ($present -eq 0) { Show-Result $title 'Pass' 'None of the targeted tasks exist on this build.' }
  elseif ($bad.Count -eq 0) { Show-Result $title 'Pass' "All present tasks are disabled ($disabled/$present)." }
  else { Show-Result $title 'Warn' ("Enabled tasks: " + ($bad -join '; ')) }
}
function Verify-OfficePolicies {
  $title='Office Policies'
  $ok=@(); $bad=@()
  $check = {
    param($base)
    $p1 = Join-Path $base 'Software\Policies\Microsoft\office\16.0\common\privacy'
    $p2 = Join-Path $base 'Software\Policies\Microsoft\office\common\clienttelemetry'
    $p1ok=$false; $p2ok=$false
    if (Test-Path $p1) {
      $o = Get-ItemProperty -LiteralPath $p1 -ErrorAction SilentlyContinue
      if ($o.DisconnectedState -eq 2 -and $o.UserContentDisabled -eq 2 -and $o.DownloadContentDisabled -eq 2 -and $o.ControllerConnectedServicesEnabled -eq 2) { $p1ok=$true }
    }
    if (Test-Path $p2) {
      $t = Get-ItemProperty -LiteralPath $p2 -ErrorAction SilentlyContinue
      if ($t.SendTelemetry -eq 3) { $p2ok=$true }
    }
    return ($p1ok -and $p2ok)
  }
  if (& $check 'HKCU:') { $ok += 'HKCU' } else { $bad += 'HKCU' }
  $sids = Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21-\d+-\d+-\d+-\d+$' }
  foreach ($h in $sids) {
    if (& $check $h.PSPath) { $ok += $h.PSChildName } else { $bad += $h.PSChildName }
  }
  if ($bad.Count -eq 0) { Show-Result $title 'Pass' "All loaded user hives OK: $($ok -join ', ')" }
  else { Show-Result $title 'Warn' ("OK: " + ($ok -join ', ') + "; Missing/incorrect: " + ($bad -join ', ')) }
}
function Verify-EdgePolicies {
  $title='Microsoft Edge Policies'
  $d = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue
  if ($null -ne $d -and $d.DiagnosticData -eq 0 -and $d.UserFeedbackAllowed -eq 0 -and $d.PersonalizationReportingEnabled -eq 0) {
    Show-Result $title 'Pass' 'Diagnostic data OFF, feedback OFF, personalization OFF.'
  } else {
    Show-Result $title 'Warn' 'One or more Edge policy values differ from expected (0).'
  }
}
function Verify-DevTelemetry {
  param([bool]$ps7,[bool]$dotnet,[bool]$azcli,[bool]$azmod,[bool]$pnp,[bool]$winget,[bool]$vscode,[bool]$vs)
  if ($ps7)   { $v=[Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','Machine'); if ($v -eq '1') { Show-Result 'PowerShell 7+' 'Pass' 'POWERSHELL_TELEMETRY_OPTOUT=1 (Machine).' } else { Show-Result 'PowerShell 7+' 'Warn' "POWERSHELL_TELEMETRY_OPTOUT is '$v' (expected 1)." } }
  if ($dotnet){ $v=[Environment]::GetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT','Machine'); if ($v -eq '1') { Show-Result '.NET CLI' 'Pass' 'DOTNET_CLI_TELEMETRY_OPTOUT=1 (Machine).' } else { Show-Result '.NET CLI' 'Warn' "DOTNET_CLI_TELEMETRY_OPTOUT is '$v' (expected 1)." } }
  if ($azcli) { if (Get-Command az -ErrorAction SilentlyContinue) {
                  try { $out = az config get core.collect_telemetry --only-show-errors 2>$null; if ($out -match 'False|false|0') { Show-Result 'Azure CLI' 'Pass' 'core.collect_telemetry = false.' } else { Show-Result 'Azure CLI' 'Warn' "core.collect_telemetry not false (output: $out)" } }
                  catch { Show-Result 'Azure CLI' 'Warn' 'Unable to read az configuration.' }
                } else { Show-Result 'Azure CLI' 'Skip' 'Azure CLI not found (skipped).' } }
  if ($azmod) { if (Get-Module -ListAvailable -Name Az.Accounts) {
                  try {
                    Import-Module Az.Accounts -ErrorAction SilentlyContinue
                    if (Get-Command Get-AzDataCollection -ErrorAction SilentlyContinue) {
                      $st = Get-AzDataCollection
                      Show-Result 'Azure PowerShell (Az)' 'Pass' ("DataCollection Disabled? " + $st)
                    } else {
                      Show-Result 'Azure PowerShell (Az)' 'Skip' 'Module present, but status cmdlet not available — manual check may be required.'
                    }
                  } catch { Show-Result 'Azure PowerShell (Az)' 'Warn' 'Unable to query Az status.' }
                } else { Show-Result 'Azure PowerShell (Az)' 'Skip' 'Az module not found (skipped).' } }
  if ($pnp)   { $v=[Environment]::GetEnvironmentVariable('PNPPOWERSHELL_DISABLETELEMETRY','Machine'); if ($v -match '^(?i:true|1)$') { Show-Result 'PnP.PowerShell' 'Pass' "PNPPOWERSHELL_DISABLETELEMETRY=$v (Machine)." } else { Show-Result 'PnP.PowerShell' 'Warn' "PNPPOWERSHELL_DISABLETELEMETRY is '$v' (expected true/1)." } }
  if ($winget) {
    $ok=$false; $paths=@((Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json'),(Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Settings\settings.json'))
    foreach ($p in $paths) {
      if (Test-Path $p) {
        try { $j = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json -ErrorAction Stop; if ($j.telemetry.disable -eq $true) { $ok=$true } } catch {}
      }
    }
    if ($ok) { Show-Result 'WinGet' 'Pass' 'telemetry.disable = true in settings.' } else { Show-Result 'WinGet' 'Warn' 'Could not confirm telemetry.disable = true in settings.' }
  }
  if ($vscode){
    $paths=@((Join-Path $env:APPDATA 'Code\User\settings.json'),(Join-Path $env:APPDATA 'Code - Insiders\User\settings.json'))
    $allOk=$true; foreach ($p in $paths) {
      if (Test-Path $p) {
        $raw = Get-Content -LiteralPath $p -Raw
        $m = [regex]::Match($raw,'"telemetry\.telemetryLevel"\s*:\s*"([^"]+)"')
        if ($m.Success) { if ($m.Groups[1].Value -ne 'off') { $allOk=$false } }
      }
    }
    if ($allOk) { Show-Result 'VS Code' 'Pass' 'telemetry.telemetryLevel = "off" (where present).' }
    else { Show-Result 'VS Code' 'Warn' 'telemetry.telemetryLevel is not "off" in at least one settings file.' }
  }
  if ($vs){
    $bad=@()
    foreach ($rp in @('HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM','HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM','HKLM:\SOFTWARE\Microsoft\VSCommon\17.0\SQM','HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM','HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM')) {
      if (Test-Path $rp) {
        $v = (Get-ItemProperty -LiteralPath $rp -Name OptIn -ErrorAction SilentlyContinue).OptIn
        if ($v -ne 0) { $bad += "$rp OptIn=$v" }
      }
    }
    if ($bad.Count -eq 0) { Show-Result 'Visual Studio' 'Pass' 'OptIn=0 (and policy) detected.' }
    else { Show-Result 'Visual Studio' 'Warn' ("Non-zero OptIn: " + ($bad -join '; ')) }
  }
}
function Verify-Selected {
  Write-Log "=== Start Verify ==="
  if ($CB_WinPolicies.IsChecked) { Verify-WindowsPolicies }
  if ($CB_WER.IsChecked)         { Verify-WER }
  if ($CB_Services.IsChecked)    { Verify-ServicesAutologgers }
  if ($CB_Tasks.IsChecked)       { Verify-ScheduledTasks }
  if ($CB_Office.IsChecked)      { Verify-OfficePolicies }
  if ($CB_Edge.IsChecked)        { Verify-EdgePolicies }
  Verify-DevTelemetry -ps7:$CB_PS7.IsChecked -dotnet:$CB_DotNet.IsChecked -azcli:$CB_AzCLI.IsChecked -azmod:$CB_AzModule.IsChecked -pnp:$CB_PnP.IsChecked -winget:$CB_WinGet.IsChecked -vscode:$CB_VSCode.IsChecked -vs:$CB_VS.IsChecked
  Write-Log "Verification complete."
}

# ---------- UI (WinUtil-like) ----------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Disable Microsoft Telemetry — Devside" Height="610" Width="920" WindowStartupLocation="CenterScreen">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <DockPanel Grid.Row="0" LastChildFill="False" Margin="0,0,0,10">
      <TextBlock Text="Recommended: leave all boxes checked (Enterprise: fully off; Pro/Home: maximal reduction)" FontSize="12" VerticalAlignment="Center"/>
      <CheckBox x:Name="CB_All" Content="Select all" Margin="20,0,0,0" VerticalAlignment="Center"/>
    </DockPanel>
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="1.1*"/>
        <ColumnDefinition Width="0.9*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" Margin="0,0,10,0">
        <GroupBox Header="Essential Tweaks" Margin="0,0,0,10">
          <StackPanel Margin="10">
            <CheckBox x:Name="CB_WinPolicies" Content="Windows policies (Telemetry/Feedback/Tailored)" IsChecked="True"/>
            <CheckBox x:Name="CB_WER" Content="Windows Error Reporting" IsChecked="True"/>
            <CheckBox x:Name="CB_Services" Content="Services (DiagTrack/dmwappush/WerSvc) + ETW autologgers" IsChecked="True"/>
            <CheckBox x:Name="CB_Tasks" Content="Scheduled Tasks (CEIP/Compat/Feedback)" IsChecked="True"/>
            <CheckBox x:Name="CB_Edge" Content="Microsoft Edge diagnostic data &amp; feedback" IsChecked="True"/>
            <CheckBox x:Name="CB_Office" Content="Office: disable connected experiences + Telemetry = 'Neither'" IsChecked="True"/>
          </StackPanel>
        </GroupBox>
        <GroupBox Header="Developer / CLI Tweaks">
          <StackPanel Margin="10">
            <CheckBox x:Name="CB_PS7" Content="PowerShell 7+ telemetry opt-out (env)" IsChecked="True"/>
            <CheckBox x:Name="CB_DotNet" Content=".NET SDK/CLI telemetry opt-out (env)" IsChecked="True"/>
            <CheckBox x:Name="CB_AzCLI" Content="Azure CLI: core.collect_telemetry=false" IsChecked="True"/>
            <CheckBox x:Name="CB_AzModule" Content="Azure PowerShell (Az): Disable-AzDataCollection" IsChecked="True"/>
            <CheckBox x:Name="CB_PnP" Content="PnP.PowerShell: disable telemetry (env + cmdlet)" IsChecked="True"/>
            <CheckBox x:Name="CB_WinGet" Content="WinGet: telemetry.disable = true" IsChecked="True"/>
            <CheckBox x:Name="CB_VSCode" Content="VS Code: telemetry.telemetryLevel = off" IsChecked="True"/>
            <CheckBox x:Name="CB_VS" Content="Visual Studio: CEIP OptIn=0 + Policy" IsChecked="True"/>
          </StackPanel>
        </GroupBox>
      </StackPanel>
      <GroupBox Header="Log / Output" Grid.Column="1">
        <TextBox x:Name="TB_Log" FontFamily="Consolas" FontSize="12" IsReadOnly="True" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
      </GroupBox>
    </Grid>
    <DockPanel Grid.Row="2" LastChildFill="False" Margin="0,10,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BTN_Run" Content="Apply Selected" Width="140" Height="36" Margin="0,0,10,0"/>
        <Button x:Name="BTN_Verify" Content="Verify Selected" Width="140" Height="36" Margin="0,0,10,0"/>
        <Button x:Name="BTN_Undo" Content="Undo Selected" Width="140" Height="36" Margin="0,0,10,0"/>
        <Button x:Name="BTN_Close" Content="Close" Width="100" Height="36"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
"@

# Safety: escape bare '&' (keeps &amp; etc. intact)
$xaml = $xaml -replace '&(?!(amp|lt|gt|quot|apos);)','&amp;'

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Bindings
$CB_All       = $Window.FindName('CB_All')
$CB_WinPolicies = $Window.FindName('CB_WinPolicies')
$CB_WER       = $Window.FindName('CB_WER')
$CB_Services  = $Window.FindName('CB_Services')
$CB_Tasks     = $Window.FindName('CB_Tasks')
$CB_Office    = $Window.FindName('CB_Office')
$CB_Edge      = $Window.FindName('CB_Edge')
$CB_PS7       = $Window.FindName('CB_PS7')
$CB_DotNet    = $Window.FindName('CB_DotNet')
$CB_AzCLI     = $Window.FindName('CB_AzCLI')
$CB_AzModule  = $Window.FindName('CB_AzModule')
$CB_PnP       = $Window.FindName('CB_PnP')
$CB_WinGet    = $Window.FindName('CB_WinGet')
$CB_VSCode    = $Window.FindName('CB_VSCode')
$CB_VS        = $Window.FindName('CB_VS')
$TB_Log       = $Window.FindName('TB_Log'); $global:TB_Log = $TB_Log
$BTN_Run      = $Window.FindName('BTN_Run')
$BTN_Verify   = $Window.FindName('BTN_Verify')
$BTN_Undo     = $Window.FindName('BTN_Undo')
$BTN_Close    = $Window.FindName('BTN_Close')

# Select/Deselect All
$allBoxes = @($CB_WinPolicies,$CB_WER,$CB_Services,$CB_Tasks,$CB_Office,$CB_Edge,$CB_PS7,$CB_DotNet,$CB_AzCLI,$CB_AzModule,$CB_PnP,$CB_WinGet,$CB_VSCode,$CB_VS)
$CB_All.Add_Checked({ foreach ($cb in $allBoxes) { $cb.IsChecked = $true } })
$CB_All.Add_Unchecked({ foreach ($cb in $allBoxes) { $cb.IsChecked = $false } })

# Actions
$BTN_Run.Add_Click({
  try {
    Write-Log "=== Start Apply ==="
    if ($CB_WinPolicies.IsChecked) { Apply-WindowsPolicies }
    if ($CB_WER.IsChecked)         { Apply-WER }
    if ($CB_Services.IsChecked)    { Apply-ServicesAutologgers }
    if ($CB_Tasks.IsChecked)       { Apply-ScheduledTasks }
    if ($CB_Office.IsChecked)      { Apply-OfficePolicies }
    if ($CB_Edge.IsChecked)        { Apply-EdgePolicies }
    Apply-DevTelemetry -ps7:$CB_PS7.IsChecked -dotnet:$CB_DotNet.IsChecked -azcli:$CB_AzCLI.IsChecked -azmod:$CB_AzModule.IsChecked -pnp:$CB_PnP.IsChecked -winget:$CB_WinGet.IsChecked -vscode:$CB_VSCode.IsChecked -vs:$CB_VS.IsChecked
    Write-Log "Apply complete. You can sign out/restart for full effect."
    Verify-Selected  # run verification automatically after apply
  } catch { Write-Log "Error (apply): $($_.Exception.Message)" }
})
$BTN_Verify.Add_Click({ try { Verify-Selected } catch { Write-Log "Error (verify): $($_.Exception.Message)" } })
$BTN_Undo.Add_Click({
  try {
    Write-Log "=== Start Undo (selected) ==="
    if ($CB_WinPolicies.IsChecked) { Undo-WindowsPolicies }
    if ($CB_WER.IsChecked)         { Undo-WER }
    if ($CB_Services.IsChecked)    { Undo-ServicesAutologgers }
    if ($CB_Tasks.IsChecked)       { Undo-ScheduledTasks }
    if ($CB_Office.IsChecked)      { Undo-OfficePolicies }
    if ($CB_Edge.IsChecked)        { Undo-EdgePolicies }
    Undo-DevTelemetry -ps7:$CB_PS7.IsChecked -dotnet:$CB_DotNet.IsChecked -azcli:$CB_AzCLI.IsChecked -azmod:$CB_AzModule.IsChecked -pnp:$CB_PnP.IsChecked -winget:$CB_WinGet.IsChecked -vscode:$CB_VSCode.IsChecked -vs:$CB_VS.IsChecked
    Write-Log "Undo complete."
  } catch { Write-Log "Error (undo): $($_.Exception.Message)" }
})
$BTN_Close.Add_Click({ $Window.Close() })
$Window.ShowDialog() | Out-Null
