# GPerf.ps1
# Author: Gorstak (gorstak.eu)
# Drop into GSecurity Scripts folder. GSecurity.bat starts it with:
#   Start "" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "GPerf.ps1"
# Behavior: apply tweaks, exit 0. No switches, no prompts, no pauses, no scheduled task.
# Does not block GSecurity.bat when started with Start.
#Requires -RunAsAdministrator

function Set-RegKey {
    param (
        [string]$path,
        [string]$name,
        [string]$value,
        [string]$type = "DWord"
    )
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    if ($type -eq "DWord") {
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force -ErrorAction SilentlyContinue
    }
}

# BCD
bcdedit /set disabledynamictick yes | Out-Null
bcdedit /set quietboot yes | Out-Null

# CPU
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
powercfg -setactive scheme_current | Out-Null
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name "DistributeTimers" -value 1
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -name "Win32PrioritySeparation" -value 26

# Memory
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name "DisablePagingExecutive" -value 1
# IoPageLockLimit 64MB helps bulk unbuffered copies on high-RAM hosts
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name "IoPageLockLimit" -value 0x4000000

# Network
netsh.exe interface tcp set supplemental Internet congestionprovider=ctcp | Out-Null
netsh.exe interface tcp set global fastopen=enabled | Out-Null
netsh.exe interface tcp set global rss=enabled | Out-Null
Set-NetTCPSetting -SettingName * -InitialCongestionWindow 10 -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue
Disable-NetAdapterPowerManagement -Name * -ErrorAction SilentlyContinue
Disable-NetAdapterLso -Name * -ErrorAction SilentlyContinue
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Tcp1323Opts" -value 1
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "MaxUserPort" -value 65534
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "TcpTimedWaitDelay" -value 30

# Disable Nagle
$tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$tcpInterfaces = Get-ChildItem -Path $tcpipPath -ErrorAction SilentlyContinue
foreach ($tcpInterface in $tcpInterfaces) {
    Set-RegKey -path $tcpInterface.PSPath -name "TCPNoDelay" -value 1
    Set-RegKey -path $tcpInterface.PSPath -name "TcpAckFrequency" -value 1
}

# AFD buffers
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -name "DefaultReceiveWindow" -value 33178
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -name "DefaultSendWindow" -value 33178

# Power plan High Performance
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# NVMe / HMB: keep drives out of deep idle (DRAM-less e.g. 990 EVO Plus)
# Does not make Explorer multi-file copies multi-GB/s; use robocopy /MT for that.
try {
    powercfg /setacvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 | Out-Null
} catch {}
try {
    powercfg /setacvalueindex SCHEME_CURRENT SUB_DISK DISKIDLE 0 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_DISK DISKIDLE 0 | Out-Null
} catch {}
try {
    powercfg /setacvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 | Out-Null
} catch {}
powercfg /setactive SCHEME_CURRENT | Out-Null

Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Storage" -name "StorageD3InModernStandby" -value 0
$stornvmeDev = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
if (-not (Test-Path $stornvmeDev)) { New-Item -Path $stornvmeDev -Force | Out-Null }
Set-RegKey -path $stornvmeDev -name "IdlePowerMode" -value 0
try { fsutil behavior set disablelastaccess 1 | Out-Null } catch {}
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -name "NtfsDisableLastAccessUpdate" -value 1
try { fsutil behavior set memoryusage 2 | Out-Null } catch {}
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\disk" -name "UserWriteCacheSetting" -value 1

# Explorer
Set-RegKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "FolderContentsInfoTip" -value 1
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "HideFileExt" -value 0
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "ShowSecondsInSystemClock" -value 1

# Visual
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "DragFullWindows" -value "1" -type "String"
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "FontSmoothing" -value "2" -type "String"
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "FontSmoothingType" -value 2

# Graphics
Set-RegKey -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -name "SystemResponsiveness" -value 0
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -name "VisualFXSetting" -value 3

# Services
$services = @("Spooler", "WSearch")
foreach ($service in $services) {
    if ((Get-Service -Name $service -ErrorAction SilentlyContinue).StartType -ne "Disabled") {
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }
}

# SvcHostSplitDisable on all services
$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$allServices = Get-ChildItem -Path $servicesPath -ErrorAction SilentlyContinue
foreach ($service in $allServices) {
    Set-RegKey -path $service.PSPath -name "SvcHostSplitDisable" -value 1
}

# No optional-feature DISM (slow). Registry and power only.

# SvcHost split threshold
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $ram = [int64]$os.TotalVisibleMemorySize + 1024000
    Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control" -name "SvcHostSplitThresholdInKB" -value $ram
} catch {}

exit 0
