# ===== Safety & TLS =====
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "PowerShell is too old ($($PSVersionTable.PSVersion)). Need 5.1+." -ForegroundColor Red
    Pause
    exit 1
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ===== Banner =====
$banner = @'
 /$$$$$$$$ /$$                           /$$             /$$   /$$ /$$                          
|__  $$__/| $$                          | $$            | $$$ | $$| $$                          
   | $$   | $$$$$$$   /$$$$$$  /$$$$$$$ | $$$$$$$       | $$$$| $$| $$$$$$$   /$$$$$$  /$$$$$$$ 
   | $$   | $$__  $$ |____  $$| $$__  $$| $$__  $$      | $$ $$ $$| $$__  $$ |____  $$| $$__  $$
   | $$   | $$  \ $$  /$$$$$$$| $$  \ $$| $$  \ $$      | $$  $$$$| $$  \ $$  /$$$$$$$| $$  \ $$
   | $$   | $$  | $$ /$$__  $$| $$  | $$| $$  | $$      | $$\  $$$| $$  | $$ /$$__  $$| $$  | $$
   | $$   | $$  | $$|  $$$$$$$| $$  | $$| $$  | $$      | $$ \  $$| $$  | $$|  $$$$$$$| $$  | $$
   |__/   |__/  |__/ \_______/|__/  |__/|__/  |__/      |__/  \__/|__/  |__/ \_______/|__/  |__/
'@

function Pause-Script {
    Write-Host "Press Enter to continue..."
    while ($true) { $k=[Console]::ReadKey($true); if ($k.Key -eq "Enter"){ break } }
}

# ===== Roblox Tools =====
function Kill-Roblox {
    Write-Host "Closing Roblox processes..." -ForegroundColor Yellow
    "RobloxPlayerBeta.exe","RobloxStudioBeta.exe","RobloxCrashHandler.exe" | ForEach-Object {
        taskkill /F /T /IM $_ > $null 2>&1
    }
}

function Remove-Roblox {
    Kill-Roblox
    $paths = @(
        "$env:LOCALAPPDATA\Roblox",
        "$env:LOCALAPPDATA\Temp\Roblox",
        "$env:ProgramFiles\Roblox",
        "$env:ProgramFiles(x86)\Roblox"
    )
    $pkgRoot = "$env:LOCALAPPDATA\Packages"
    if (Test-Path $pkgRoot) {
        Get-ChildItem $pkgRoot -Directory |
            Where-Object { $_.Name -like "ROBLOXCORPORATION.ROBLOX*" } |
            ForEach-Object {
                $paths += "$($_.FullName)\LocalCache"
                $paths += "$($_.FullName)\LocalState"
                $paths += "$($_.FullName)\TempState"
            }
    }
    $deleted = 0
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Host "Deleting $p" -ForegroundColor Cyan
            try { Remove-Item -Path $p -Recurse -Force -ErrorAction Stop; $deleted++ }
            catch { Write-Warning "Unable to delete $p" }
        }
    }
    if ($deleted -gt 0) {
        Write-Host "Roblox cleanup completed ($deleted folders)" -ForegroundColor Green
    } else {
        Write-Host "No Roblox data found to delete" -ForegroundColor Yellow
    }
    Pause-Script
}

# ===== MAC Change Tool (option 2) =====
# Elevate if not admin (for adapter changes)
$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($me)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    if ($scriptPath) {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        return
    } else {
        Write-Host "Please run PowerShell as Administrator."; Start-Sleep 3
    }
}

function Show-Adapters {
    try {
        $global:adapters = Get-NetAdapter | Sort-Object ifIndex
    } catch {
        $global:adapters = @()
    }
    Clear-Host
    Write-Host "[r] Refresh   [t] Back to Menu`n"
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Host "(No network adapters found)"
        return
    }
    $rows = for ($i=0; $i -lt $adapters.Count; $i++) {
        [PSCustomObject]@{
            ID     = $i
            Name   = $adapters[$i].Name
            Status = $adapters[$i].Status
            Speed  = $adapters[$i].LinkSpeed
            MAC    = $adapters[$i].MacAddress
        }
    }
    $rows | Format-Table -AutoSize
}

function New-RandomMac {
    $b = @(for ($i=0; $i -lt 6; $i++) { Get-Random -Minimum 0 -Maximum 256 })
    $b[0] = ($b[0] -bor 0x02) -band 0xFE   # LAA=1, multicast=0
    -join ($b | ForEach-Object { "{0:X2}" -f $_ })
}

function Apply-Mac($adapter, $mac) {
    try {
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "NetworkAddress" -RegistryValue $mac -NoRestart -ErrorAction Stop
        return $true
    } catch {
        try {
            $keyRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\"
            $target = Get-ChildItem $keyRoot -ErrorAction Stop | Where-Object {
                try { (Get-ItemProperty $_.PSPath).NetCfgInstanceId -eq $adapter.InterfaceGuid.ToString() } catch { $false }
            } | Select-Object -First 1
            if (-not $target) { return $false }
            New-ItemProperty -Path $target.PSPath -Name "NetworkAddress" -Value $mac -PropertyType String -Force | Out-Null
            return $true
        } catch { return $false }
    }
}

function Bounce-Adapter($adapterName, $statusText) {
    if ($statusText -eq 'Not Present') { return }
    try {
        Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
        Enable-NetAdapter  -Name $adapterName -Confirm:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 1
    } catch {
        Write-Host "Failed to disable/enable: $($_.Exception.Message)"
    }
}

function Run-MacTool {
    while ($true) {
        Show-Adapters
        $choice = Read-Host "Enter adapter ID"
        if ($choice -eq 'r') { continue }
        if ($choice -eq 't') { return }
        if ($choice -notmatch '^\d+$') { Write-Host "Invalid input."; Start-Sleep 1.2; continue }
        if (-not $adapters -or $adapters.Count -eq 0) { Start-Sleep 1; continue }

        $idx = [int]$choice
        if ($idx -lt 0 -or $idx -ge $adapters.Count) { Write-Host "Invalid ID."; Start-Sleep 1.2; continue }

        $adapter = $adapters[$idx]
        $mac = New-RandomMac
        if (-not (Apply-Mac -adapter $adapter -mac $mac)) {
            Write-Host "Failed to set MAC."; Start-Sleep 1.5; continue
        }

        Bounce-Adapter -adapterName $adapter.Name -statusText $adapter.Status
        $after = Get-NetAdapter -Name $adapter.Name -ErrorAction SilentlyContinue
        $seen  = if ($after) { $after.MacAddress } else { "(N/A)" }

        Write-Host ("Successfully changed MAC for {0} > {1}. Press Enter to continue selecting an adapter..." -f $adapter.Name, $seen) -ForegroundColor Green
        while ($true) { $k=[Console]::ReadKey($true); if ($k.Key -eq "Enter"){ break } }
    }
}

# ===== Menu =====
function Show-Menu {
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
    Write-Host "===== MENU TOOLS ====="
    Write-Host "[1] Delete Roblox Data"
    Write-Host "[2] Change MAC Address [IP]"
    Write-Host "======================"
    Write-Host ""
}

:MENU while ($true) {
    Show-Menu
    $choice = (Read-Host "Enter your choice").Trim().ToLower()
    switch ($choice) {
        '1' { Remove-Roblox; continue }
        '2' { Run-MacTool;  continue }
        default { Write-Warning "Invalid choice"; Pause-Script }
    }
}
