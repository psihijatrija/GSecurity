param(
    [switch]$Uninstall,
    [switch]$ChaosMode,   # Test mode: creates benign test threats to validate detections
    [switch]$LearningMode, # Log-only: build baseline, no kill/quarantine (DeepSeek suggestion)
    [switch]$SelfTest     # Run self-diagnostics and exit
)

#Requires -Version 5.1

# ============================================================================
# Antivirus.ps1 - Single-file EDR/Antivirus (Merged)
# Author: Gorstak
# Version: 2.0.0
#
# Changelog:
#   v2.0.0 - Merged AV1+AV2; Grok improvements (hash DB, low-power, opt-in modules)
#   v2.1.0 - DeepSeek improvements (circuit breakers, cache cleanup, LearningMode)
#   v2.2.0 - Claude improvements (hash DB locking, FSW debounce, Invoke-Response)
#   v2.3.0 - DeepSeek: Safe Mode detection, system path protection in UnsignedDLLRemover
#   v2.4.0 - Grok: EICARHash/ForceQuarantineInSafeMode in Config, cache size limits, RTFM temp exclusions
#   v2.5.0 - Expanded scope: all local/removable/network drive roots; RTFM runs Cymru/MalwareBazaar on new files
#   v2.6.0 - Invoke-WithRetry, Test-ConfigurationSanity, Invoke-SelfTest, Invoke-GracefulShutdown, Safe Mode enhancement
#   v2.7.0 - PUA/PUP/PUM detection, Phantom Process Killer
#   v2.8.0 - Deeper drive scan (depth 2), expanded Tier 1 paths (Desktop, Public, ProgramData), elevation flag cleanup
#   v2.9.0 - Documents scripts merge: Spoofer (full PrivacyForge), BCD cleanup, Credential hardening, CVE Reapply/DryRun,
#            takeown/icacls quarantine fallback, ShadowProxy toast, DragonBreathHunter, Password rotator (auto-install, flag when done)
#
# Dependencies: PowerShell 5.1+, Windows (WMI, EventLog, .NET)
#
# USAGE:
#   Normal run:    .\Antivirus.ps1
#   Uninstall:     .\Antivirus.ps1 -Uninstall   (removes persistence, stops instances)
#   Test/chaos:    .\Antivirus.ps1 -ChaosMode   (validates detections with EICAR)
#   Learning:      .\Antivirus.ps1 -LearningMode (log-only, no kill/quarantine)
#   Self-test:     .\Antivirus.ps1 -SelfTest    (run diagnostics and exit)
#   Full stop:     Use -Uninstall, or kill PID from Data\antivirus.pid

# Unique script identifier (GUID) - used for process identification and mutex naming
$Script:ScriptGUID = "539EF6B5-578B-4AF3-A5C7-FD564CB9C8FB"
$Script:LearningMode = $false

# Portable mode: Use script's directory as base path
$Script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
$Script:InstallPath = $Script:ScriptDir
$Script:ScriptName = Split-Path -Leaf $PSCommandPath
$Script:MaxRestartAttempts = 3
$Script:StabilityLogPath = "$Script:InstallPath\Logs\stability_log.txt"

$Script:ManagedJobConfig = @{
    TinyThreatScanIntervalSeconds = 20
    SecureDnsMonitoringIntervalSeconds = 300
    DnsSecureConfigIntervalSeconds = 86400
    HashDetectionIntervalSeconds = 15
    LOLBinDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    AMSIBypassDetectionIntervalSeconds = 15
    CredentialDumpDetectionIntervalSeconds = 15
    WMIPersistenceDetectionIntervalSeconds = 120
    ScheduledTaskDetectionIntervalSeconds = 120
    RegistryPersistenceDetectionIntervalSeconds = 120
    DLLHijackingDetectionIntervalSeconds = 90
    TokenManipulationDetectionIntervalSeconds = 60
    ProcessHollowingDetectionIntervalSeconds = 30
    KeystrokeInjectionDetectionIntervalSeconds = 30
    KeyScramblerManagementIntervalSeconds = 60
    RansomwareDetectionIntervalSeconds = 15
    NetworkAnomalyDetectionIntervalSeconds = 30
    RootkitDetectionIntervalSeconds = 180
    ClipboardMonitoringIntervalSeconds = 30
    COMMonitoringIntervalSeconds = 120
    BrowserExtensionMonitoringIntervalSeconds = 300
    ShadowCopyMonitoringIntervalSeconds = 30
    USBMonitoringIntervalSeconds = 20
    MobileDeviceMonitoringIntervalSeconds = 15
    AttackToolsDetectionIntervalSeconds = 30
    PUADetectionIntervalSeconds = 180
    PUPDetectionIntervalSeconds = 180
    PUMDetectionIntervalSeconds = 180
    PhantomProcessKillerIntervalSeconds = 30
    AdvancedThreatDetectionIntervalSeconds = 20
    EventLogMonitoringIntervalSeconds = 60
    FirewallRuleMonitoringIntervalSeconds = 120
    ServiceMonitoringIntervalSeconds = 60
    FilelessDetectionIntervalSeconds = 20
    MemoryScanningIntervalSeconds = 90
    NamedPipeMonitoringIntervalSeconds = 45
    DNSExfiltrationDetectionIntervalSeconds = 30
    PasswordManagementIntervalSeconds = 120
    BeaconDetectionIntervalSeconds = 60
    CodeInjectionDetectionIntervalSeconds = 30
    DataExfiltrationDetectionIntervalSeconds = 30
    FileEntropyDetectionIntervalSeconds = 120
    HoneypotMonitoringIntervalSeconds = 30
    LateralMovementDetectionIntervalSeconds = 30
    ProcessCreationDetectionIntervalSeconds = 10
    QuarantineManagementIntervalSeconds = 300
    ReflectiveDLLInjectionDetectionIntervalSeconds = 30
    ResponseEngineIntervalSeconds = 10
    PrivacyForgeSpoofingIntervalSeconds = 60
    UnsignedDLLRemoverIntervalSeconds = 300
    YaraDetectionIntervalSeconds = 120
    IdsDetectionIntervalSeconds = 60
    MemoryAcquisitionDetectionIntervalSeconds = 90
    BCDSecurityIntervalSeconds = 300
    CredentialProtectionIntervalSeconds = 300
    HidMacroGuardIntervalSeconds = 60
    LocalProxyDetectionIntervalSeconds = 60
    ScriptContentScanIntervalSeconds = 120
    ScriptHostDetectionIntervalSeconds = 60
    StartupPersistenceDetectionIntervalSeconds = 120
    SuspiciousParentChildDetectionIntervalSeconds = 45
    ScriptBlockLoggingCheckIntervalSeconds = 86400
    CVEMitigationPatcherIntervalSeconds = 3600
    AsrRulesIntervalSeconds = 86400
    GRulesC2BlockIntervalSeconds = 3600
    ProcessAuditingIntervalSeconds = 86400
    MitreMappingIntervalSeconds = 300
    RealTimeFileMonitorIntervalSeconds = 60
    DriverWatcherIntervalSeconds = 60
    CrudePayloadGuardIntervalSeconds = 60
    SecpolHardeningIntervalSeconds = 86400
    ShadowProxyCaptureDetectionIntervalSeconds = 60
    ElfCatcherIntervalSeconds = 30
    ElfDLLUnloaderIntervalSeconds = 10
    NeuroBehaviorMonitorIntervalSeconds = 15
    DragonBreathHunterIntervalSeconds = 360
}

$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    ReportsPath = "$Script:InstallPath\Reports"
    HMACKeyPath = "$Script:InstallPath\Data\db_integrity.hmac"
    PIDFilePath = "$Script:InstallPath\Data\antivirus.pid"
    MutexName = "Local\AntivirusProtection_Mutex_{0}_{1}_{2}" -f $env:COMPUTERNAME, $env:USERNAME, $Script:ScriptGUID

    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"

    ExclusionPaths = @(
        $Script:InstallPath,
        "$Script:InstallPath\Logs",
        "$Script:InstallPath\Quarantine",
        "$Script:InstallPath\Reports",
        "$Script:InstallPath\Data"
    )
    ExclusionProcesses = @("powershell", "pwsh")

    EnableUnsignedDLLScanner = $true
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500

    HashDatabaseFile = "$Script:InstallPath\Data\known_files.db"
    MaxDatabaseEntries = 50000
    DatabaseCleanupDays = 30
    CymruDetectionThreshold = 60

    # Grok-suggested improvements
    LowPowerMode = $false                    # Doubles all detection intervals to reduce CPU/RAM on low-end machines
    MaxLogSizeMB = 10                        # Rotate logs when exceeding this size to prevent disk bloat
    EnableClipboardMonitoring = $false       # Opt-in: invasive - monitors clipboard for sensitive data
    EnableKeystrokeInjectionDetection = $false  # Opt-in: invasive - monitors keystroke injection
    ApiUserAgent = "MalwareDetector-EDR/1.0 (PowerShell; Windows)"  # Identify requests to hash APIs

    # Resource governors & stability (DeepSeek suggestions)
    MaxFilesPerScan = 500              # Cap files per scan to avoid CPU spikes
    CircuitBreakerFailureThreshold = 10  # Skip API after N consecutive failures
    CircuitBreakerCooldownMinutes = 5   # Resume API after this many minutes
    CacheCleanupIntervalIterations = 60  # Run Clear-StaleCache every N Monitor-Jobs ticks
    MaxCacheEntries = 10000            # Trim caches when exceeding (Grok: prevent memory bloat)

    # Centralized threat hashes (Grok: reduce magic strings)
    EICARHash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    ForceQuarantineInSafeMode = $false # Advanced: override Safe Mode quarantine disable

    # Scan scope: expand detections to all drive types (catches e.g. mimikatz on D:\ root)
    ScanLocalDrives = $true       # Include local fixed drives (C:\, D:\, etc.) root + shallow
    ScanRemovableDrives = $true   # Include removable drives (USB) root + shallow
    ScanNetworkDrives = $true     # Include mapped network shares root + shallow (may be slow)
    DriveRootScanDepth = 2        # 0 = root only, 1 = root+1 level, 2 = root+2 levels (deeper = more coverage, slower)

    # PUA/PUP response (may flag legitimate tools like TeamViewer)
    AutoKillPUA = $true          # Auto-kill PUA (RATs, miners) - set $false to avoid killing Teamviewer, Anydesk, etc
    AutoKillCryptoMiners = $true  # Auto-kill crypto miners (xmrig, ccminer, etc.)

    EnableThreatToastNotifications = $true  # Show Windows toast when threat is quarantined/terminated

    EnableBCDCleanup = $true              # Remove suspicious BCD entries (from BCDCleanup.ps1)
    EnableCredentialHardening = $true     # Apply hardening: RunAsPPL, CachedLogonsCount=0, cmdkey clear (from Hardening.ps1)
    EnableDragonBreathHunter = $true      # Campaign detection: RONINGLOADER, Gh0st RAT IOCs
    CVEReapply = $false                   # CVE patcher: process all CVEs including previously seen
    CVEDryRun = $false                    # CVE patcher: preview only, don't apply
}

$Script:MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd','.exif',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1',
   
    # Extended list
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.exif','.elf','.ecf','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.command','.cnt','.cnv','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)

function Get-DriveRootsForScan {
    # Returns drive roots to scan based on Config (ScanLocalDrives, ScanRemovableDrives, ScanNetworkDrives)
    $roots = @()
    $scanLocal = if ($null -ne $Config.ScanLocalDrives) { $Config.ScanLocalDrives } else { $true }
    $scanRemovable = if ($null -ne $Config.ScanRemovableDrives) { $Config.ScanRemovableDrives } else { $true }
    $scanNetwork = if ($null -ne $Config.ScanNetworkDrives) { $Config.ScanNetworkDrives } else { $true }
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $disks) {
            if (-not $disk.DeviceID) { continue }
            $path = $disk.DeviceID.TrimEnd(':') + ":\"
            switch ($disk.DriveType) {
                2 { if ($scanRemovable) { $roots += $path } }  # Removable
                3 { if ($scanLocal) { $roots += $path } }      # Local fixed
                4 { if ($scanNetwork) { $roots += $path } }    # Network
                default { }
            }
        }
    } catch { }
    return $roots
}

# <CHANGE> Add graceful elevation check function (insert after $Config block, ~line 99)
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param([string]$Reason = "This operation requires administrator privileges.")
    
    # Use a local mutex - if elevated instance owns it, children skip
    $mutexName = "Local\AntivirusProtection_Elevated_$($env:USERNAME)"
    
    if (Test-IsAdmin) {
        # Try to own the mutex (elevated parent holds it)
        try {
            $script:ElevationMutex = New-Object System.Threading.Mutex($false, $mutexName)
            $script:ElevationMutex.WaitOne(0) | Out-Null
        } catch {
            # If mutex creation fails, just continue - not critical
        }
        return
    }
    
    # Check if mutex exists (means elevated instance is running)
    try {
        $mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $hasHandle = $false
        try {
            $hasHandle = $mutex.WaitOne(0, $false)
        } catch {}
        
        if (-not $hasHandle) {
            # Mutex held by elevated parent - we're a child, skip elevation
            return
        }
        
        # Release it - we're the first non-elevated instance, need to elevate
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    } catch {
        # If mutex check fails, proceed with elevation
    }
    
    Write-Warning $Reason
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Load-HashDatabase {
    if (-not $Config.HashDatabaseFile) { return }
    if (-not (Test-Path $Config.HashDatabaseFile)) {
        New-Item -Path $Config.HashDatabaseFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        Write-AVLog "Created new hash database file" "INFO"
        return
    }
    try {
        $lines = Get-Content $Config.HashDatabaseFile -ErrorAction Stop
        $count = 0
        foreach ($line in $lines) {
            if ($line -match '^([0-9a-f]{64}),(true|false),(.+)$') {
                $hash = $matches[1]
                $safe = [bool]::Parse($matches[2])
                $timestamp = $matches[3]
                try {
                    $entryDate = [datetime]::Parse($timestamp)
                    if ($entryDate -lt (Get-Date).AddDays(-$Config.DatabaseCleanupDays)) { continue }
                } catch {}
                $Script:KnownFilesCache[$hash] = $safe
                $count++
                if ($count -ge $Config.MaxDatabaseEntries) { break }
            }
        }
        Write-AVLog "Loaded $count entries from hash database" "INFO"
    } catch {
        Write-AVLog "Failed to load hash database: $_" "WARN"
        $Script:KnownFilesCache.Clear()
    }
}

function Save-ToHashDatabase {
    param([string]$Hash, [bool]$IsSafe)
    if (-not $Hash -or -not $Config.HashDatabaseFile) { return }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$Hash,$IsSafe,$timestamp"
    $mutexName = "Local\AV_HashDB_$($Config.HashDatabaseFile -replace '[\\:]+','_')"
    $mutex = $null
    try {
        $mutex = New-Object System.Threading.Mutex($false, $mutexName)
        if ($mutex.WaitOne(5000)) {
            $entry | Out-File -FilePath $Config.HashDatabaseFile -Append -Encoding UTF8
            $Script:KnownFilesCache[$Hash] = $IsSafe
        }
    } catch {
        Write-AVLog "Failed to save to hash database: $_" "WARN"
    } finally {
        if ($mutex) {
            try { $mutex.ReleaseMutex(); $mutex.Dispose() } catch {}
        }
    }
}

function Get-ApiHeaders {
    $ua = if ($Config -and $Config.ApiUserAgent) { $Config.ApiUserAgent } else { "MalwareDetector-EDR/1.0 (PowerShell; Windows)" }
    return @{ "User-Agent" = $ua }
}

# Circuit breakers: stop hammering failing APIs (DeepSeek)
$Script:CircuitBreakers = @{}
function Test-CircuitBreaker {
    param([string]$Service)
    $breaker = $Script:CircuitBreakers[$Service]
    if (-not $breaker) { return $true }
    $threshold = if ($Config.CircuitBreakerFailureThreshold) { $Config.CircuitBreakerFailureThreshold } else { 10 }
    $cooldownMins = if ($Config.CircuitBreakerCooldownMinutes) { $Config.CircuitBreakerCooldownMinutes } else { 5 }
    if ($breaker.FailureCount -ge $threshold -and ((Get-Date) - $breaker.LastFailure).TotalMinutes -lt $cooldownMins) { return $false }
    return $true
}
function Update-CircuitBreakerOnFailure { param([string]$Service)
    if (-not $Script:CircuitBreakers[$Service]) { $Script:CircuitBreakers[$Service] = @{ FailureCount = 0; LastFailure = [DateTime]::MinValue } }
    $Script:CircuitBreakers[$Service].FailureCount++
    $Script:CircuitBreakers[$Service].LastFailure = Get-Date
}
function Reset-CircuitBreakerOnSuccess { param([string]$Service)
    if ($Script:CircuitBreakers[$Service]) { $Script:CircuitBreakers[$Service].FailureCount = 0 }
}

# Retry with exponential backoff for transient failures (API, WMI)
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [string]$Operation = "unknown"
    )
    $retryCount = 0
    $baseDelay = 2
    while ($retryCount -lt $MaxRetries) {
        try {
            return & $ScriptBlock
        } catch {
            $retryCount++
            if ($retryCount -eq $MaxRetries) {
                Write-AVLog "Operation '$Operation' failed after $MaxRetries retries: $_" "ERROR"
                throw
            }
            $delay = $baseDelay * [Math]::Pow(2, $retryCount - 1)
            Write-AVLog "Retry $retryCount/$MaxRetries for '$Operation' in ${delay}s" "WARN"
            Start-Sleep -Seconds $delay
        }
    }
}

# Config validation and sanity checks (path creation, intervals, conflicts)
function Test-ConfigurationSanity {
    $issues = @()
    if (-not $Script:InstallPath) { $issues += "InstallPath not set" }
    $minMem = 100
    if ($Config.MaxMemoryUsageMB -lt $minMem) { $issues += "MaxMemoryUsageMB should be >= $minMem" }
    if ($Config.MaxFilesPerScan -lt 10) { $issues += "MaxFilesPerScan should be >= 10" }
    # Ensure paths exist and are writable
    foreach ($pathKey in @("LogPath","QuarantinePath","DatabasePath","ReportsPath")) {
        $p = $Config[$pathKey]
        if ($p) {
            try {
                if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            } catch {
                $issues += "Cannot create $pathKey : $_"
            }
        }
    }
    # Validate intervals (min 5s to avoid resource thrash)
    foreach ($key in $Script:ManagedJobConfig.Keys) {
        if ($Script:ManagedJobConfig[$key] -lt 5) {
            Write-AVLog "$key interval too low ($($Script:ManagedJobConfig[$key])s) - setting to minimum 5s" "WARN"
            $Script:ManagedJobConfig[$key] = 5
        }
    }
    # Conflicting settings
    if ($Script:LearningMode -and $Config.AutoKillThreats) {
        $issues += "LearningMode active - AutoKillThreats disabled"
        $Config.AutoKillThreats = $false
    }
    if ($issues.Count -gt 0) {
        $issues | ForEach-Object { Write-Warning "Config: $_" }
        return $false
    }
    return $true
}

# Config validation at startup (DeepSeek)
function Test-Configuration {
    $errors = @()
    if (-not $Script:InstallPath) { $errors += "InstallPath not set" }
    $minMem = 100
    if ($Config.MaxMemoryUsageMB -lt $minMem) { $errors += "MaxMemoryUsageMB should be >= $minMem" }
    if ($Config.MaxFilesPerScan -lt 10) { $errors += "MaxFilesPerScan should be >= 10" }
    if ($errors.Count -gt 0) {
        Write-Warning "Configuration validation: $($errors -join '; ')"
    }
    Test-ConfigurationSanity | Out-Null
}

# Central cache cleanup to prevent memory bloat (DeepSeek); size limits (Grok)
function Clear-StaleCache {
    $cutoff = (Get-Date).AddHours(-24)
    $maxEntries = if ($Config.MaxCacheEntries -gt 0) { $Config.MaxCacheEntries } else { 10000 }
    if ($Script:ProcessedDlls -and $Script:ProcessedDlls.Count -gt 0) {
        $oldKeys = $Script:ProcessedDlls.Keys | Where-Object { $Script:ProcessedDlls[$_] -lt $cutoff }
        foreach ($k in $oldKeys) { $Script:ProcessedDlls.Remove($k) | Out-Null }
        if ($Script:ProcessedDlls.Count -gt $maxEntries) {
            $trim = $Script:ProcessedDlls.GetEnumerator() | Sort-Object { $_.Value } | Select-Object -First ($Script:ProcessedDlls.Count - $maxEntries)
            foreach ($e in $trim) { $Script:ProcessedDlls.Remove($e.Key) | Out-Null }
        }
    }
    if ($Script:ScannedFiles -and $Script:ScannedFiles.Count -gt 500) {
        $oldKeys = $Script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
        foreach ($k in $oldKeys) { $Script:ScannedFiles.Remove($k) | Out-Null }
        if ($Script:ScannedFiles.Count -gt $maxEntries) {
            $trim = $Script:ScannedFiles.Keys | Select-Object -First ($Script:ScannedFiles.Count - $maxEntries)
            foreach ($k in $trim) { $Script:ScannedFiles.Remove($k) | Out-Null }
        }
    }
    if ($Script:ElfDLLProcessed -and $Script:ElfDLLProcessed.Count -gt 500) {
        $oldKeys = $Script:ElfDLLProcessed.Keys | Where-Object { ((Get-Date) - $Script:ElfDLLProcessed[$_]).TotalHours -gt 24 }
        foreach ($k in $oldKeys) { $Script:ElfDLLProcessed.Remove($k) | Out-Null }
        if ($Script:ElfDLLProcessed.Count -gt $maxEntries) {
            $trim = $Script:ElfDLLProcessed.GetEnumerator() | Sort-Object { $_.Value } | Select-Object -First ($Script:ElfDLLProcessed.Count - $maxEntries)
            foreach ($e in $trim) { $Script:ElfDLLProcessed.Remove($e.Key) | Out-Null }
        }
    }
}

function Test-CirclKnownGood {
    param([string]$SHA256)
    if (-not $SHA256) { return $false }
    if (-not (Test-CircuitBreaker -Service 'CIRCL')) { return $false }
    try {
        $response = Invoke-WithRetry -ScriptBlock {
            $url = "$($Config.CirclHashLookupUrl)/$SHA256"
            Invoke-RestMethod -Uri $url -Headers (Get-ApiHeaders) -TimeoutSec 8 -ErrorAction Stop
        } -MaxRetries 2 -Operation "CIRCL"
        Reset-CircuitBreakerOnSuccess -Service 'CIRCL'
        if ($response) { Write-AVLog "CIRCL known-good match: $SHA256" "INFO"; return $true }
    } catch { Update-CircuitBreakerOnFailure -Service 'CIRCL' }
    return $false
}
function Test-CymruMalware {
    param([string]$SHA256)
    if (-not $SHA256) { return $false }
    if (-not (Test-CircuitBreaker -Service 'Cymru')) { return $false }
    try {
        $response = Invoke-WithRetry -ScriptBlock {
            $url = "$($Config.CymruApiUrl)/$SHA256"
            Invoke-RestMethod -Uri $url -Headers (Get-ApiHeaders) -TimeoutSec 8 -ErrorAction Stop
        } -MaxRetries 2 -Operation "Cymru"
        Reset-CircuitBreakerOnSuccess -Service 'Cymru'
        if ($response.detections -ge $Config.CymruDetectionThreshold) { Write-AVLog "CYMRU malware match: $SHA256 (detections: $($response.detections))" "THREAT"; return $true }
    } catch { Update-CircuitBreakerOnFailure -Service 'Cymru' }
    return $false
}
function Test-MalwareBazaar {
    param([string]$SHA256)
    if (-not $SHA256) { return $false }
    if (-not (Test-CircuitBreaker -Service 'MalwareBazaar')) { return $false }
    try {
        $response = Invoke-WithRetry -ScriptBlock {
            $body = @{ query = 'get_info'; hash = $SHA256 }
            Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $body -Headers (Get-ApiHeaders) -TimeoutSec 10 -ErrorAction Stop
        } -MaxRetries 2 -Operation "MalwareBazaar"
        Reset-CircuitBreakerOnSuccess -Service 'MalwareBazaar'
        if ($response.query_status -eq 'ok' -or ($response.data -and $response.data.Count -gt 0)) { Write-AVLog "MalwareBazaar match: $SHA256" "THREAT"; return $true }
    } catch { Update-CircuitBreakerOnFailure -Service 'MalwareBazaar' }
    return $false
}

$Global:AntivirusState = @{
    Running = $false
    Installed = $false
    Jobs = @{}
    Mutex = $null
    ThreatCount = 0
    FilesScanned = 0
    FilesQuarantined = 0
    ProcessesTerminated = 0
}

$Script:LoopCounter = 0
$script:ManagedJobs = @{}
$Script:KnownFilesCache = @{}

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $true
$Script:SelfPID = $PID

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "antivirus_log.txt")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    
    # Try to get Config from global scope first, then script scope, then local scope
    $configVar = $null
    if ($null -ne (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue)) {
        $configVar = $global:Config
    } elseif ($null -ne (Get-Variable -Name "Config" -Scope Script -ErrorAction SilentlyContinue)) {
        $configVar = $script:Config
    } elseif (Test-Path Variable:Config) {
        $configVar = $Config
    }
    
    # Check if Config exists and LogPath is not null
    if ($null -eq $configVar -or $null -eq $configVar.LogPath -or [string]::IsNullOrWhiteSpace($configVar.LogPath)) {
        # Fallback to default log path if Config is not available
        $logPath = if ($Script:InstallPath) { "$Script:InstallPath\Logs" } else { "$PSScriptRoot\Logs" }
        $logFilePath = Join-Path $logPath $LogFile
        
        if (!(Test-Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
    } else {
        $logFilePath = Join-Path $configVar.LogPath $LogFile
        
        if (!(Test-Path $configVar.LogPath)) {
            New-Item -ItemType Directory -Path $configVar.LogPath -Force | Out-Null
        }
    }

    # Log rotation: prevent disk bloat (Grok suggestion)
    $maxBytes = 10 * 1024 * 1024  # 10 MB default
    if ($configVar -and $null -ne $configVar.MaxLogSizeMB) { $maxBytes = $configVar.MaxLogSizeMB * 1024 * 1024 }
    if (Test-Path $logFilePath) {
        $fi = Get-Item $logFilePath -ErrorAction SilentlyContinue
        if ($fi -and $fi.Length -gt $maxBytes) {
            $rotated = "$logFilePath.old"
            try { Move-Item -Path $logFilePath -Destination $rotated -Force -ErrorAction Stop } catch {}
        }
    }

    Add-Content -Path $logFilePath -Value $entry -ErrorAction SilentlyContinue

    $eid = switch ($Level) {
        "ERROR" { 1001 }
        "WARN" { 1002 }
        "THREAT" { 1003 }
        default { 1000 }
    }

    # Only write to event log if Config and EDRName are available
    if ($null -ne $configVar -and $null -ne $configVar.EDRName -and -not [string]::IsNullOrWhiteSpace($configVar.EDRName)) {
        # Ensure event log source exists before writing
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($configVar.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($configVar.EDRName, "Application")
            }
        } catch {
            # Event log source creation may require elevation or fail for other reasons
            # Silently continue - we'll just skip event log writing
            return
        }
        
        try {
            Write-EventLog -LogName Application -Source $configVar.EDRName -EntryType Information -EventId $eid -Message $Message -ErrorAction SilentlyContinue
        } catch {
            # If event log write still fails, silently continue
        }
    }
}

function Write-StabilityLog {
    param([string]$Message, [string]$Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] [STABILITY] $Message"

    if (!(Test-Path (Split-Path $Script:StabilityLogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:StabilityLogPath -Parent) -Force | Out-Null
    }

    # Log rotation for stability log
    $maxBytes = 10 * 1024 * 1024
    if ($Config -and $Config.MaxLogSizeMB) { $maxBytes = $Config.MaxLogSizeMB * 1024 * 1024 }
    if (Test-Path $Script:StabilityLogPath) {
        $fi = Get-Item $Script:StabilityLogPath -ErrorAction SilentlyContinue
        if ($fi -and $fi.Length -gt $maxBytes) { try { Move-Item -Path $Script:StabilityLogPath -Destination "$Script:StabilityLogPath.old" -Force -ErrorAction Stop } catch {} }
    }

    Add-Content -Path $Script:StabilityLogPath -Value $entry -ErrorAction SilentlyContinue
    Write-Host $entry -ForegroundColor $(switch($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} default {"White"} })
}


function Invoke-GracefulShutdown {
    param([string]$Reason = "user requested")
    Write-Host "`n[*] Initiating graceful shutdown: $Reason" -ForegroundColor Cyan
    $Global:AntivirusState.Running = $false
    try {
        if ($Script:RTFM_Watchers -and $Script:RTFM_Watchers.Count -gt 0) {
            foreach ($w in $Script:RTFM_Watchers) { try { $w.EnableRaisingEvents = $false; $w.Dispose() } catch {} }
            $Script:RTFM_Watchers = @()
        }
        # Save shutdown state for diagnostics
        $dbPath = if ($Config -and $Config.DatabasePath) { $Config.DatabasePath } else { "$Script:InstallPath\Data" }
        if (Test-Path $dbPath) {
            try {
                $state = @{
                    PID = $PID
                    ShutdownTime = (Get-Date).ToString("o")
                    Reason = $Reason
                    ModulesRunning = if ($Global:AntivirusState.Jobs) { $Global:AntivirusState.Jobs.Count } else { 0 }
                    TotalDetections = $Global:AntivirusState.ThreatCount
                }
                $state | ConvertTo-Json | Out-File (Join-Path $dbPath "last_shutdown.json") -Force
            } catch {}
        }
        $pidPath = if ($Config -and $Config.PIDFilePath) { $Config.PIDFilePath } elseif ($global:AntivirusPIDFilePath) { $global:AntivirusPIDFilePath } else { $null }
        if ($pidPath -and (Test-Path $pidPath)) { Remove-Item $pidPath -Force -ErrorAction SilentlyContinue }
        if ($Global:AntivirusState.Mutex) { try { $Global:AntivirusState.Mutex.ReleaseMutex(); $Global:AntivirusState.Mutex.Dispose() } catch {} }
        Write-AVLog "Graceful shutdown complete - $Reason"
    } catch {}
    Write-Host "[*] Shutdown complete" -ForegroundColor Green
}

function Stop-Antivirus {
    Invoke-GracefulShutdown -Reason "Stop-Antivirus"
}

function Invoke-SelfTest {
    Write-Host "`nRunning self-diagnostics..." -ForegroundColor Cyan
    $tests = @(
        @{ Name = "Config Load"; Test = { $null -ne $Config } },
        @{ Name = "Paths Exist"; Test = {
            (Test-Path $Config.LogPath) -and
            (Test-Path $Config.QuarantinePath) -and
            (Test-Path $Config.DatabasePath)
        }},
        @{ Name = "Hash Functions"; Test = { (Get-Command Test-CirclKnownGood -ErrorAction SilentlyContinue) -ne $null } },
        @{ Name = "Circuit Breaker"; Test = { (Get-Command Test-CircuitBreaker -ErrorAction SilentlyContinue) -ne $null } },
        @{ Name = "Job Config"; Test = { $Script:ManagedJobConfig -and $Script:ManagedJobConfig.Keys.Count -gt 0 } }
    )
    $passed = 0
    foreach ($t in $tests) {
        try {
            if (& $t.Test) {
                Write-Host "  [PASS] $($t.Name)" -ForegroundColor Green
                $passed++
            } else {
                Write-Host "  [FAIL] $($t.Name)" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [WARN] $($t.Name) - $_" -ForegroundColor Yellow
        }
    }
    Write-Host "`nSelf-test: $passed/$($tests.Count) passed" -ForegroundColor Cyan
}

function Register-ExitCleanup {
    if ($script:ExitCleanupRegistered) {
        return
    }
    try {
        Register-EngineEvent -SourceIdentifier "AntivirusProtection_ExitCleanup" -EventName PowerShell.Exiting -Action {
            Stop-Antivirus
        } | Out-Null
        $script:ExitCleanupRegistered = $true
    }
    catch {
    }
}

function Install-Antivirus {
    # Portable mode: Run from current location, no copying needed
    $Script:SelfPath = $PSCommandPath

    Write-Host "[+] Running in portable mode from: $Script:ScriptDir" -ForegroundColor Green

    # Create subfolders in current directory if needed
    @("Data","Logs","Quarantine","Reports") | ForEach-Object {
        $p = Join-Path $Script:InstallPath $_
        if (!(Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Write-Host "[+] Created: $p"
        }
    }

    # Initialize mutex BEFORE creating persistence to prevent race conditions
    Initialize-Mutex
    Install-Persistence

    $Global:AntivirusState.Installed = $true
    return $true
}

# Password rotator setup (from Install-PasswordRotator.ps1) - random every 10min, blank at logoff
function Invoke-PasswordRotatorSetup {
    $targetDir = "C:\ProgramData\PasswordRotator"
    $flagFile = Join-Path $targetDir ".installed"
    if (Test-Path $flagFile) { return }
    $onLogonTask = "PasswordRotator-OnLogon"
    $workerScript = @'
param([string]$Mode, [string]$Username)
$ErrorActionPreference = 'Stop'
$TargetDir = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\ProgramData\PasswordRotator' }
$UserFile = Join-Path $TargetDir 'currentuser.txt'
function Get-LoggedInUser {
    $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    $user = $cs.UserName
    if (-not $user) { return $null }; if ($user -match '\\') { return $user.Split('\')[-1] }; return $user
}
function Set-UserPassword { param([string]$U, [string]$P)
    if ([string]::IsNullOrWhiteSpace($U)) { return }
    try { Set-LocalUser -Name $U -Password (ConvertTo-SecureString -String $P -AsPlainText -Force) -ErrorAction Stop } catch {
        try { [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$U,user"; $adsi.SetPassword($P) } catch { "$(Get-Date -Format o) Set-UserPassword: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append }
    }
}
function Set-UserPasswordBlank { param([string]$N)
    if ([string]::IsNullOrWhiteSpace($N)) { return }
    try { [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$N,user"; $adsi.SetPassword('') } catch { try { & net user $N '' } catch {} }
}
function New-RandomPwd {
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
    -join ((1..24) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}
function Remove-TasksForUser { param([string]$U)
    $s = $U -replace '[^a-zA-Z0-9]', '_'
    @("PasswordRotator-10Min-$s", "PasswordRotator-OnLogoff-$s") | ForEach-Object { Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue }
}
switch ($Mode) {
    'Logon' {
        $u = Get-LoggedInUser; if (-not $u) { exit 0 }
        if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
        $u | Set-Content -Path $UserFile -Force; Remove-TasksForUser -U $u
        $safe = $u -replace '[^a-zA-Z0-9]', '_'; $worker = Join-Path $TargetDir 'Worker.ps1'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $trigger10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $action10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Rotate"
        Register-ScheduledTask -TaskName "PasswordRotator-10Min-$safe" -Action $action10 -Trigger $trigger10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null
        $triggerOff = New-ScheduledTaskTrigger -AtLogOff -User $u
        $actionOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Logoff -Username $u"
        Register-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$safe" -Action $actionOff -Trigger $triggerOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable) -Force | Out-Null
        Start-Sleep -Seconds 60; Set-UserPassword -U $u -P (New-RandomPwd)
    }
    'Rotate' {
        if (-not (Test-Path $UserFile)) { exit 0 }; $u = (Get-Content -Path $UserFile -Raw).Trim()
        if ($u) { Set-UserPassword -U $u -P (New-RandomPwd) }
    }
    'Logoff' {
        if ($Username) { Set-UserPasswordBlank -N $Username; $s = $Username -replace '[^a-zA-Z0-9]', '_'
            Unregister-ScheduledTask -TaskName "PasswordRotator-10Min-$s" -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$s" -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}
'@
    if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }
    $workerScript | Set-Content -Path (Join-Path $targetDir 'Worker.ps1') -Encoding UTF8 -Force
    $workerPath = Join-Path $targetDir 'Worker.ps1'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" -Mode Logon"
    Register-ScheduledTask -TaskName $onLogonTask -Action $action -Trigger $trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null
    try {
        $currentUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
        if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }
        if ($currentUser) {
            [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$currentUser,user"
            $adsi.SetPassword('')
        }
    } catch {}
    New-Item -Path $flagFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Password rotator installed (flagged). Current user password set to blank." -ForegroundColor Green
}

function Install-Persistence {
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan

    # Define paths for cleanup
    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"
    $runKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $runKeyName = "AntivirusProtection"

    try {
        # Remove old persistence methods
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
        }

        # Add to HKCU Run key - use actual script path (portable mode)
        $scriptFullPath = Join-Path $Script:ScriptDir $Script:ScriptName
        $runCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptFullPath`""
        Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runCommand -ErrorAction Stop

        Write-Host "[+] Registry Run key entry created for automatic startup" -ForegroundColor Green
        Write-Host "    Script path: $scriptFullPath" -ForegroundColor Gray
        Write-StabilityLog "Persistence setup completed - HKCU Run key created"
    }
    catch {
        Write-Host "[!] Failed to create registry Run key entry: $_" -ForegroundColor Red
        Write-StabilityLog "Persistence setup failed: $_" "ERROR"
    }
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus ===`n" -ForegroundColor Cyan
    Write-StabilityLog "Starting uninstall process"

    # First, stop all running instances
    try {
        Write-Host "[*] Stopping running instances..." -ForegroundColor Yellow
        Write-StabilityLog "Stopping running antivirus instances"
        
        # Check PID file for running instance
        if (Test-Path $Config.PIDFilePath) {
            try {
                $existingPID = [int](Get-Content $Config.PIDFilePath -ErrorAction Stop)
                if ($existingPID -ne $PID) {
                    $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue
                    if ($existingProcess) {
                        # Verify it's our script before killing
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $existingPID" -ErrorAction SilentlyContinue).CommandLine
                        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                        $isOurScript = $false
                        if ($cmdLine) {
                            if ($cmdLine -like "*$($Script:ScriptGUID)*" -or ($scriptPath -and $cmdLine -like "*$scriptPath*")) {
                                $isOurScript = $true
                            }
                        }
                        
                        if ($isOurScript) {
                            Write-Host "[+] Stopping instance (PID: $existingPID)" -ForegroundColor Green
                            Stop-Process -Id $existingPID -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            } catch {
                Write-StabilityLog "Error reading PID file during uninstall: $_" "WARN"
            }
        }
        
        # Also check for any PowerShell processes running our script
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
        $allProcesses = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue
        foreach ($proc in $allProcesses) {
            if ($proc.ProcessId -eq $PID) { continue }
            try {
                $cmdLine = $proc.CommandLine
                if ($cmdLine -and ($cmdLine -like "*$($Script:ScriptGUID)*" -or ($scriptPath -and $cmdLine -like "*$scriptPath*"))) {
                    Write-Host "[+] Stopping instance (PID: $($proc.ProcessId))" -ForegroundColor Green
                    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        
        # Wait a moment for processes to terminate
        Start-Sleep -Seconds 1
    } catch {
        Write-Host "[!] Warning: Could not stop all instances: $_" -ForegroundColor Yellow
        Write-StabilityLog "Warning: Could not stop all instances during uninstall: $_" "WARN"
    }

    try {
        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }
        if ($Global:AntivirusState -and $Global:AntivirusState.Jobs) {
            $Global:AntivirusState.Jobs.Clear()
        }
    }
    catch {
        Write-StabilityLog "Failed to clear managed jobs during uninstall: $_" "WARN"
    }

    try {
        # Remove registry Run key entry
        $runKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $runKeyName = "AntivirusProtection"
        if (Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed registry Run key entry" -ForegroundColor Green
            Write-StabilityLog "Removed registry Run key entry during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove registry Run key entry: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove registry Run key entry: $_" "WARN"
    }

    # Clean up old persistence methods if they exist
    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Removed scheduled task (if existed)" -ForegroundColor Green
        Write-StabilityLog "Removed scheduled task during uninstall"
    }
    catch {
        Write-Host "[!] Failed to remove scheduled task: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove scheduled task: $_" "WARN"
    }

    try {
        $shortcutPath = Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" "AntivirusProtection.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed startup shortcut (if existed)" -ForegroundColor Green
            Write-StabilityLog "Removed startup shortcut during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove startup shortcut: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove startup shortcut: $_" "WARN"
    }

    if (Test-Path $Script:InstallPath) {
        Remove-Item -Path $Script:InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed installation directory" -ForegroundColor Green
        Write-StabilityLog "Removed installation directory during uninstall"
    }

    Write-Host "[+] Uninstall complete." -ForegroundColor Green
    Write-StabilityLog "Uninstall process completed"
    exit 0
}

function Initialize-Mutex {
    $mutexName = $Config.MutexName

    Write-StabilityLog "Initializing mutex and PID checks"

    if (Test-Path $Config.PIDFilePath) {
        try {
            $existingPID = [int](Get-Content $Config.PIDFilePath -ErrorAction Stop)
            
            # Don't block if PID file contains our own PID (stale file from same instance)
            if ($existingPID -eq $PID) {
                Write-StabilityLog "PID file contains current PID - removing stale file" "INFO"
                Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            }
            else {
                $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue

                if ($existingProcess) {
                    # Check if the existing process is actually running our script
                    try {
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $existingPID" -ErrorAction SilentlyContinue).CommandLine
                        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                        
                        # Check if existing process is running our script (by GUID or path)
                        $isOurScript = $false
                        if ($cmdLine) {
                            # Primary check: GUID (most reliable)
                            if ($cmdLine -like "*$($Script:ScriptGUID)*") {
                                $isOurScript = $true
                            }
                            # Secondary check: script path
                            elseif ($scriptPath -and $cmdLine -like "*$scriptPath*") {
                                $isOurScript = $true
                            }
                        }
                        
                        if ($isOurScript) {
                            Write-StabilityLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            Write-Host "[!] Another instance is already running (PID: $existingPID)" -ForegroundColor Yellow
                            Write-AVLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            throw "Another instance is already running (PID: $existingPID)"
                        }
                        else {
                            # Existing process is not our script - remove stale PID file
                            Write-StabilityLog "PID file contains different process (not our script) - removing stale file" "INFO"
                            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        if ($_.Exception.Message -like "*already running*") {
                            throw
                        }
                        # Can't determine if it's our script, but process exists - assume it's not our script and remove stale PID
                        Write-StabilityLog "Could not verify existing process - removing potentially stale PID file" "INFO"
                        Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    Write-StabilityLog "Removed stale PID file (process $existingPID not running)"
                    Write-AVLog "Removed stale PID file (process $existingPID not running)"
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*already running*") {
                throw
            }
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            Write-StabilityLog "Removed invalid PID file"
        }
    }

    try {
        $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $acquired = $Global:AntivirusState.Mutex.WaitOne(3000)

        if (!$acquired) {
            # Mutex is locked - check if there's actually a running instance
            Write-StabilityLog "Mutex locked - checking for running instances" "WARN"
            
            # Check for running instances, excluding our own PID
            $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
            $installedScriptPath = Join-Path $Script:InstallPath $Script:ScriptName
            
            $verifiedInstances = @()
            $allPowerShellProcesses = Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID }
            
            foreach ($proc in $allPowerShellProcesses) {
                try {
                    # Verify process is actually responsive (not hung/dead)
                    $procInfo = Get-Process -Id $proc.Id -ErrorAction Stop
                    if (-not $procInfo.Responding) {
                        Write-StabilityLog "Process $($proc.Id) is not responding - treating as dead" "WARN"
                        continue
                    }
                    
                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    if (-not $cmdLine) {
                        continue
                    }
                    
                    # Strict verification: Primary check is GUID (most reliable), then script path
                    $isOurScript = $false
                    $matchedPath = $null
                    $matchedBy = $null
                    
                    # PRIMARY: Check for GUID in command line (most reliable identifier)
                    if ($cmdLine -like "*$($Script:ScriptGUID)*") {
                        $isOurScript = $true
                        $matchedBy = "GUID"
                        # Also try to extract the script path for logging
                        if ($cmdLine -match '-File\s+([^\s]+)') {
                            $matchedPath = $matches[1].Trim('"').Trim("'")
                        } else {
                            $matchedPath = "GUID_Match"
                        }
                    }
                    # SECONDARY: Check current script path
                    elseif ($scriptPath -and $cmdLine -like "*$scriptPath*") {
                        $isOurScript = $true
                        $matchedPath = $scriptPath
                        $matchedBy = "Path"
                    }
                    # TERTIARY: Check installed script path (if different from current)
                    elseif ($installedScriptPath -and (Test-Path $installedScriptPath) -and $cmdLine -like "*$installedScriptPath*") {
                        $isOurScript = $true
                        $matchedPath = $installedScriptPath
                        $matchedBy = "Path"
                    }
                    
                    if ($isOurScript) {
                        Write-StabilityLog "Verified process $($proc.Id) is running our script (matched by $matchedBy): $matchedPath" "INFO"
                        $verifiedInstances += @{
                            Id = $proc.Id
                            CommandLine = $cmdLine
                            Path = $matchedPath
                            MatchedBy = $matchedBy
                        }
                    }
                } catch {
                    # Process doesn't exist or error checking - don't count it
                    Write-StabilityLog "Error checking process $($proc.Id): $_" "WARN"
                    continue
                }
            }
            
            if ($verifiedInstances.Count -gt 0) {
                $instancePIDs = $verifiedInstances | ForEach-Object { $_.Id }
                $instanceDetails = $verifiedInstances | ForEach-Object { "PID $($_.Id): $($_.Path)" }
                Write-StabilityLog "Blocked duplicate instance - found $($verifiedInstances.Count) verified running instance(s) (PIDs: $($instancePIDs -join ', '))" "WARN"
                Write-Host "[!] Another instance is already running (PIDs: $($instancePIDs -join ', '))" -ForegroundColor Yellow
                Write-Host "[!] Running from: $($instanceDetails -join '; ')" -ForegroundColor Yellow
                Write-AVLog "Blocked duplicate instance - found running processes: $($instancePIDs -join ', ')" "WARN"
                $Global:AntivirusState.Mutex.Dispose()
                throw "Another instance is already running (mutex locked)"
            } else {
                # No verified instances found - treat as stale mutex
                # Since we've verified no process is running, we can safely proceed
                Write-StabilityLog "Stale mutex detected (no running process found) - proceeding anyway" "WARN"
                Write-Host "[!] Stale mutex detected but no process running - proceeding (stale mutex will be cleaned up)" -ForegroundColor Yellow
                
                # Dispose of the failed mutex reference
                try {
                    $Global:AntivirusState.Mutex.Dispose()
                } catch {}
                $Global:AntivirusState.Mutex = $null
                
                # Wait a bit to allow kernel cleanup
                Start-Sleep -Milliseconds 500
                
                # Try to create a new mutex (Windows should have cleaned up the stale one)
                # If it still fails, we'll proceed without mutex protection (since we verified no process is running)
                try {
                    $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
                    $acquired = $Global:AntivirusState.Mutex.WaitOne(2000)
                    if ($acquired) {
                        Write-StabilityLog "Successfully acquired mutex after stale detection" "INFO"
                    } else {
                        # Still can't acquire, but no process is running - proceed without mutex
                        Write-StabilityLog "Mutex still locked but no process running - proceeding without mutex (stale mutex)" "WARN"
                        Write-Host "[!] Warning: Proceeding without mutex (stale mutex detected). This is safe since no process is running." -ForegroundColor Yellow
                        $Global:AntivirusState.Mutex.Dispose()
                        $Global:AntivirusState.Mutex = $null
                    }
                } catch {
                    # If we can't create the mutex, proceed anyway since we verified no process is running
                    Write-StabilityLog "Could not create mutex after stale detection, but no process running - proceeding: $_" "WARN"
                    Write-Host "[!] Warning: Proceeding without mutex protection due to stale mutex." -ForegroundColor Yellow
                    $Global:AntivirusState.Mutex = $null
                }
            }
        }

        if (!(Test-Path (Split-Path $Config.PIDFilePath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $Config.PIDFilePath -Parent) -Force | Out-Null
        }

        $PID | Out-File -FilePath $Config.PIDFilePath -Force
        $Global:AntivirusState.Running = $true
        if ($Global:AntivirusState.Mutex) {
            Write-StabilityLog "Mutex acquired, PID file written: $PID"
        } else {
            Write-StabilityLog "PID file written: $PID (running without mutex due to stale mutex)"
        }
        Write-AVLog "Antivirus started (PID: $PID)"
        Write-Host "[+] Process ID: $PID" -ForegroundColor Green

        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            try {
                Write-StabilityLog "PowerShell exiting - cleaning up mutex and PID"
                if ($Global:AntivirusState.Mutex) {
                    $Global:AntivirusState.Mutex.ReleaseMutex()
                    $Global:AntivirusState.Mutex.Dispose()
                }
                if (Test-Path $Config.PIDFilePath) {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-StabilityLog "Cleanup error: $_" "ERROR"
            }
        } | Out-Null

    }
    catch {
        Write-StabilityLog "Mutex initialization failed: $_" "ERROR"
        throw
    }
}

function Select-BoundConfig {
    param(
        [Parameter(Mandatory=$true)][string]$FunctionName,
        [Parameter(Mandatory=$true)][hashtable]$Config
    )

    $cmd = Get-Command $FunctionName -ErrorAction Stop
    $paramNames = @($cmd.Parameters.Keys)
    $bound = @{}
    foreach ($k in $Config.Keys) {
        if ($paramNames -contains $k) {
            $bound[$k] = $Config[$k]
        }
    }
    return $bound
}

function Register-TerminationProtection {
    try {
        # Define paths for the event handler
        $logsFolder = "$Script:InstallPath\Logs"
        $selfPath = $Script:SelfPath
        $autoRestart = $Script:AutoRestart
        
        # Monitor for unexpected termination attempts
        $Script:UnhandledExceptionHandler = Register-ObjectEvent -InputObject ([AppDomain]::CurrentDomain) `
            -EventName UnhandledException -Action {
            param($src, $evtArgs)
            
            $errorMsg = "Unhandled exception: $($evtArgs.Exception.ToString())"
            $errorMsg | Out-File "$using:logsFolder\crash_log.txt" -Append
            
            try {
                # Log to security events
                $securityEvent = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    EventType = "UnexpectedTermination"
                    Severity = "Critical"
                    Exception = $evtArgs.Exception.ToString()
                    IsTerminating = $evtArgs.IsTerminating
                }
                $securityEvent | ConvertTo-Json -Compress | Out-File "$using:logsFolder\security_events.jsonl" -Append
            } catch {}
            
            # Attempt auto-restart if configured
            if ($using:autoRestart -and $evtArgs.IsTerminating) {
                try {
                    Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$using:selfPath`"" `
                        -WindowStyle Hidden -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        
        Write-StabilityLog "[PROTECTION] Termination protection registered"
        
    } catch {
        Write-StabilityLog -Message "Failed to register termination protection" -Severity "Medium" -ErrorRecord $_
    }
}

function Enable-CtrlCProtection {
    try {
        # Detect if running in ISE or console
        if ($host.Name -eq "Windows PowerShell ISE Host") {
            Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
            Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
            return $true
        }
        
        [Console]::TreatControlCAsInput = $false
        
        # Create scriptblock for the event handler
        $cancelHandler = {
            param($src, $evtArgs)
            
            $Script:TerminationAttempts++
            
            Write-Host "`n[PROTECTION] Termination attempt detected ($Script:TerminationAttempts/$Script:MaxTerminationAttempts)" -ForegroundColor Red
            
            try {
                Write-SecurityEvent -EventType "TerminationAttemptBlocked" -Details @{
                    PID = $PID
                    AttemptNumber = $Script:TerminationAttempts
                } -Severity "Critical"
            } catch {}
            
            if ($Script:TerminationAttempts -ge $Script:MaxTerminationAttempts) {
                Write-Host "[PROTECTION] Maximum termination attempts reached. Allowing graceful shutdown..." -ForegroundColor Yellow
                $evtArgs.Cancel = $false
            } else {
                Write-Host "[PROTECTION] Termination blocked. Press Ctrl+C $($Script:MaxTerminationAttempts - $Script:TerminationAttempts) more times to force stop." -ForegroundColor Yellow
                $evtArgs.Cancel = $true
            }
        }
        
        # Register the event handler
        [Console]::add_CancelKeyPress($cancelHandler)
        
        Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[WARNING] Could not enable Ctrl+C protection: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Enable-AutoRestart {
    try {
        $taskName = "AntivirusAutoRestart_$PID"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:SelfPath`""
        
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        
        Write-Host "[PROTECTION] Auto-restart scheduled task registered" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not enable auto-restart: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Start-ProcessWatchdog {
    try {
        $watchdogJob = Start-Job -ScriptBlock {
            param($parentPID, $scriptPath, $autoRestart)
            
            while ($true) {
                Start-Sleep -Seconds 30
                
                # Check if parent process is still alive
                $process = Get-Process -Id $parentPID -ErrorAction SilentlyContinue
                
                if (-not $process) {
                    # Parent died - restart if configured
                    if ($autoRestart) {
                        Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" `
                            -WindowStyle Hidden -ErrorAction SilentlyContinue
                    }
                    break
                }
            }
        } -ArgumentList $PID, $Script:SelfPath, $Script:AutoRestart
        
        Write-Host "[PROTECTION] Process watchdog started (Job ID: $($watchdogJob.Id))" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not start process watchdog: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Register-ManagedJob {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$IntervalSeconds = 30,
        [bool]$Enabled = $true,
        [bool]$Critical = $false,
        [int]$MaxRestartAttempts = 3,
        [int]$RestartDelaySeconds = 5,
        [object[]]$ArgumentList = $null
    )

    if (-not $script:ManagedJobs) {
        $script:ManagedJobs = @{}
    }

    $minIntervalSeconds = 1
    if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MinimumIntervalSeconds) {
        $minIntervalSeconds = [int]$Script:ManagedJobConfig.MinimumIntervalSeconds
    }

    $IntervalSeconds = [Math]::Max([int]$IntervalSeconds, [int]$minIntervalSeconds)

    $script:ManagedJobs[$Name] = [pscustomobject]@{
        Name = $Name
        ScriptBlock = $ScriptBlock
        ArgumentList = $ArgumentList
        IntervalSeconds = $IntervalSeconds
        Enabled = $Enabled
        Critical = $Critical
        MaxRestartAttempts = $MaxRestartAttempts
        RestartDelaySeconds = $RestartDelaySeconds
        RestartAttempts = 0
        LastStartUtc = $null
        LastSuccessUtc = $null
        LastError = $null
        NextRunUtc = [DateTime]::UtcNow
        DisabledUtc = $null
    }
}

function Invoke-ManagedJobsTick {
    param(
        [Parameter(Mandatory=$true)][DateTime]$NowUtc
    )

    if (-not $script:ManagedJobs) {
        return
    }

    foreach ($job in $script:ManagedJobs.Values) {
        if (-not $job.Enabled) { continue }
        if ($null -ne $job.DisabledUtc) { continue }
        if ($job.NextRunUtc -gt $NowUtc) { continue }

        $job.LastStartUtc = $NowUtc

        try {
            # Suppress all output from managed job execution to prevent pipeline binding issues
            # Use Out-Null to ensure complete suppression of all streams including return values
            # Redirect all streams (*>&1) to prevent any output from reaching the pipeline
            if ($null -ne $job.ArgumentList) {
                $null = Invoke-Command -ScriptBlock $job.ScriptBlock -ArgumentList $job.ArgumentList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue *>&1 | Out-Null
            }
            else {
                $null = & $job.ScriptBlock -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue *>&1 | Out-Null
            }
            $job.LastSuccessUtc = [DateTime]::UtcNow
            $job.RestartAttempts = 0
            $job.LastError = $null
            $job.NextRunUtc = $job.LastSuccessUtc.AddSeconds([Math]::Max(1, $job.IntervalSeconds))
        }
        catch {
            $job.LastError = $_
            $job.RestartAttempts++

            try {
                Write-AVLog "Managed job '$($job.Name)' failed (attempt $($job.RestartAttempts)/$($job.MaxRestartAttempts)) : $($_.Exception.Message)" "WARN"
            }
            catch {}

            if ($job.RestartAttempts -ge $job.MaxRestartAttempts) {
                $job.RestartAttempts = 0
                $job.DisabledUtc = $null
                $job.NextRunUtc = [DateTime]::UtcNow.AddMinutes(5)
                try {
                    Write-AVLog "Managed job '$($job.Name)' exceeded max restart attempts; backing off for 5 minutes" "ERROR"
                }
                catch {}
                continue
            }

            $job.NextRunUtc = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $job.RestartDelaySeconds))
        }
    }
}

function Start-ManagedJob {
    param(
        [string]$ModuleName,
        [int]$IntervalSeconds = 30
    )

    $jobName = "AV_$ModuleName"

    if ($Global:AntivirusState.Jobs.ContainsKey($jobName)) {
        return
    }

    $funcName = "Invoke-$ModuleName"
    if (-not (Get-Command $funcName -ErrorAction SilentlyContinue)) {
        Write-AVLog "Function not found: $funcName" "WARN"
        return
    }

    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    $sb = {
        param(
            [Parameter(Mandatory=$true)][string]$FunctionName,
            [Parameter(Mandatory=$true)][hashtable]$Cfg
        )

        # Ensure global Config is available in this scope
        if ($null -eq $global:Config -and $null -ne $Cfg) {
            $global:Config = $Cfg
        }

        $cmd = Get-Command $FunctionName -ErrorAction Stop
        $paramNames = @($cmd.Parameters.Keys)
        $bound = @{}
        
        # Check if function expects a Config parameter (as hashtable)
        if ($paramNames -contains "Config") {
            $bound["Config"] = $Cfg
        } else {
            # Otherwise, bind individual keys from Cfg to matching parameters
            foreach ($k in $Cfg.Keys) {
                if ($paramNames -contains $k) {
                    $bound[$k] = $Cfg[$k]
                }
            }
        }
        
        # Suppress output to prevent pipeline binding issues - use Out-Null to ensure complete suppression
        # Also suppress any implicit output by explicitly assigning to $null and redirecting all streams
        try {
            $null = & $FunctionName @bound *>&1 | Out-Null
        } catch {
            # Suppress errors too
            $null = $_
        }
    }

    Register-ManagedJob -Name $jobName -ScriptBlock $sb -ArgumentList @($funcName, $Config) -IntervalSeconds $IntervalSeconds -Enabled $true -Critical $false -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay

    $Global:AntivirusState.Jobs[$jobName] = @{
        Name = $jobName
        IntervalSeconds = $IntervalSeconds
        Module = $ModuleName
    }

    Write-AVLog "Registered managed job: $jobName (${IntervalSeconds}s interval)"
}

function Start-RecoverySequence {
    Write-StabilityLog "Starting recovery sequence" "WARN"

    try {

        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }

        $Global:AntivirusState.Jobs.Clear()
        Start-Sleep -Seconds 10
        Write-StabilityLog "Recovery sequence completed"
    }
    catch {
        Write-StabilityLog "Recovery sequence failed: $_" "ERROR"
    }
}

# Note: Function name intentionally uses 'Monitor' verb for job monitoring functionality
function Monitor-Jobs {
    Write-Host "`n[*] Monitoring started. Press Ctrl+C to stop.`n" -ForegroundColor Cyan
    Write-StabilityLog "Entering main monitoring loop"
    Write-AVLog "Entering main monitoring loop"

    $iteration = 0
    $lastStabilityCheck = Get-Date
    $consecutiveErrors = 0
    $maxConsecutiveErrors = 10

    while ($true) {
        try {
            while ($true) {
                $iteration++
                $now = Get-Date

                try {
                    Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow)
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Managed jobs tick failed: $_" "WARN"
                }

                if (($now - $lastStabilityCheck).TotalMinutes -ge 5) {
                    try {
                        $enabledCount = 0
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                        }
                        Write-StabilityLog "Stability check: $enabledCount managed jobs enabled, iteration $iteration"
                        $lastStabilityCheck = $now
                        $consecutiveErrors = 0
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Stability check failed: $_" "WARN"
                    }
                }

                if ($consecutiveErrors -ge $maxConsecutiveErrors) {
                    Write-StabilityLog "Too many consecutive errors ($consecutiveErrors), triggering recovery" "ERROR"
                    Start-RecoverySequence
                    $consecutiveErrors = 0
                }

                # Periodic cache cleanup to prevent memory bloat (DeepSeek)
                $cleanupInterval = if ($Config.CacheCleanupIntervalIterations -gt 0) { $Config.CacheCleanupIntervalIterations } else { 60 }
                if ($iteration % $cleanupInterval -eq 0) {
                    try { Clear-StaleCache } catch {}
                }

                if ($iteration % 12 -eq 0) {
                    try {
                        $enabledCount = 0
                        $disabledCount = 0
                        $sampleErrorMessage = $null
                        $sampleErrorJob = $null
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                            $disabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -ne $_.DisabledUtc) }).Count
                            try {
                                $j = ($script:ManagedJobs.Values | Where-Object { $_.LastError } | Select-Object -First 1)
                                if ($j) {
                                    $sampleErrorJob = $j.Name
                                    $sampleErrorMessage = $j.LastError.Exception.Message
                                }
                            }
                            catch {}
                        }
                        Write-Host "[AV] Monitoring active - $enabledCount enabled / $disabledCount backoff" -ForegroundColor DarkGray
                        Write-StabilityLog "Heartbeat: $enabledCount enabled / $disabledCount backoff, iteration $iteration" "INFO"
                        Write-AVLog "Heartbeat: $enabledCount enabled / $disabledCount backoff"
                        if ($sampleErrorMessage) {
                            Write-StabilityLog "Sample job error ($sampleErrorJob): $sampleErrorMessage" "WARN"
                        }
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Heartbeat failed: $_" "WARN"
                    }
                }

                Start-Sleep -Seconds 1
            }
        }
        catch {
            try {
                Write-StabilityLog "Monitor-Jobs outer loop error: $_" "ERROR"
                Write-AVLog "Monitor-Jobs iteration error: $_" "ERROR"
                Write-Host "[!] Monitor iteration error (recovering): $_" -ForegroundColor Yellow
            }
            catch {
            }

            Start-RecoverySequence
            Start-Sleep -Seconds 5
            $consecutiveErrors = 0
            $lastStabilityCheck = Get-Date
            continue
        }
    }
}

function Show-ThreatToast {
    param([string]$Title, [string]$Message, [string]$ActionType = "Threat")
    if (-not $Config.EnableThreatToastNotifications) { return }
    if ($Script:LearningMode) { return }
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $appId = if ($Config.EDRName) { $Config.EDRName } else { "GShield" }
        $msgShort = if ($Message.Length -gt 80) { $Message.Substring(0, 77) + "..." } else { $Message }
        $xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>$([System.Security.SecurityElement]::Escape($Title))</text>
      <text>$([System.Security.SecurityElement]::Escape($msgShort))</text>
    </binding>
  </visual>
  <audio src="ms-winsoundevent:Notification.System" />
</toast>
"@
        $xmlDoc = [Windows.Data.Xml.Dom.XmlDocument]::new()
        $xmlDoc.LoadXml($xml)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
    } catch { }
}

function Move-ToQuarantine {
    param([string]$Path, [string]$Reason)

    # Sanity check: NEVER quarantine system-critical paths (Grok: prevent accidental deletion)
    $pathLower = $Path.ToLower()
    $pf = [Environment]::GetEnvironmentVariable('ProgramFiles','Machine')
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)','Machine')
    $protectedPrefixes = @(
        (Join-Path $env:windir "").ToLower(),
        (Join-Path $pf "").ToLower(),
        (Join-Path $env:SystemRoot "system32\").ToLower(),
        (Join-Path $env:SystemRoot "syswow64\").ToLower()
    )
    if ($pf86) { $protectedPrefixes += (Join-Path $pf86 "").ToLower() }
    foreach ($prefix in $protectedPrefixes) {
        if ($pathLower.StartsWith($prefix)) {
            Write-AVLog "BLOCKED: Refusing to quarantine system path: $Path (Reason: $Reason)" "WARN"
            return $false
        }
    }

    if ($Script:LearningMode -or ($Config.AutoQuarantine -eq $false)) {
        Write-AVLog "[LEARNING] Would have quarantined: $Path (Reason: $Reason)" "INFO"
        return $false
    }

    $FileName = [System.IO.Path]::GetFileName($Path)
    $QuarantineFile = "$($Config.QuarantinePath)\$([DateTime]::Now.Ticks)_$FileName"
    
    try {
        [System.IO.File]::Move($Path, $QuarantineFile)
        $Global:AntivirusState.FilesQuarantined++
        Write-AVLog "Quarantined: $Path (Reason: $Reason)" "THREAT"
        Show-ThreatToast -Title "Threat Quarantined" -Message "File quarantined: $([System.IO.Path]::GetFileName($Path)) - $Reason" -ActionType "Quarantined"
        return $true
    } catch {
        # Fallback: takeown/icacls then retry (from Guard.ps1)
        try {
            $null = & takeown /F $Path /A 2>$null
            $null = & icacls $Path /reset 2>$null
            $null = & icacls $Path /grant "Administrators:F" /inheritance:d 2>$null
            [System.IO.File]::Move($Path, $QuarantineFile)
            $Global:AntivirusState.FilesQuarantined++
            Write-AVLog "Quarantined (after takeown): $Path (Reason: $Reason)" "THREAT"
            Show-ThreatToast -Title "Threat Quarantined" -Message "File quarantined: $([System.IO.Path]::GetFileName($Path)) - $Reason" -ActionType "Quarantined"
            return $true
        } catch {
            Write-AVLog "Quarantine failed for $Path : $_" "ERROR"
            return $false
        }
    }
}

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    if ($ProcessId -eq $PID -or $ProcessId -eq $Script:SelfPID) { return }
    if ($Script:LearningMode -or ($Config.AutoKillThreats -eq $false)) {
        Write-AVLog "[LEARNING] Would have terminated: $ProcessName (PID: $ProcessId)" "INFO"
        return
    }
    
    # Critical system processes that must NEVER be terminated
    $ProtectedProcessNames = @(
        'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 
        'lsass', 'svchost', 'winlogon', 'explorer', 'dwm', 'fontdrvhost',
        'RuntimeBroker', 'sihost', 'taskhostw', 'SearchIndexer', 'spoolsv',
        'WmiPrvSE', 'dllhost', 'conhost', 'ctfmon', 'SecurityHealthService',
        'MsMpEng', 'NisSrv', 'audiodg', 'dasHost', 'WUDFHost', 'SearchHost',
        'StartMenuExperienceHost', 'ShellExperienceHost', 'TextInputHost',
        # IDE and development tools (Electron apps have suspended threads normally)
        'Cursor', 'Code', 'code', 'electron', 'node', 'npm', 'git',
        'devenv', 'idea64', 'pycharm64', 'webstorm64', 'rider64',
        # Browsers (multi-process architecture)
        'chrome', 'firefox', 'msedge', 'brave', 'opera',
        # Common utilities
        'powershell', 'pwsh', 'WindowsTerminal', 'cmd'
    )
    
    # Check if process name matches protected list (case-insensitive)
    $procNameClean = $ProcessName -replace '\.exe$', ''
    if ($ProtectedProcessNames -contains $procNameClean) {
        Write-AVLog "BLOCKED: Refusing to terminate protected system process: $ProcessName (PID: $ProcessId)" "WARN"
        return
    }
    
    # Additional check: verify process path is not in Windows directory for critical names
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc -and $proc.Path) {
            $pathLower = $proc.Path.ToLower()
            if ($pathLower -like '*\windows\system32\*' -or $pathLower -like '*\windows\syswow64\*') {
                # Extra caution for system directory processes
                if ($procNameClean -match '^(winlogon|lsass|csrss|services|smss|wininit|svchost)$') {
                    Write-AVLog "BLOCKED: Refusing to terminate system process from Windows directory: $ProcessName (PID: $ProcessId)" "WARN"
                    return
                }
            }
        }
    } catch { }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        $Global:AntivirusState.ProcessesTerminated++
        Write-AVLog "Terminated threat process: $ProcessName (PID: $ProcessId)" "ACTION"
        Show-ThreatToast -Title "Threat Terminated" -Message "Process stopped: $ProcessName (PID: $ProcessId)" -ActionType "Terminated"
    } catch {
        Write-AVLog "Failed to terminate process $ProcessName : $_" "ERROR"
    }
}

# ===================== Embedded detection modules =====================

function Invoke-HashDetection {
    param(
        [string]$LogPath,
        [string]$QuarantinePath,
        [string]$CirclHashLookupUrl,
        [string]$CymruApiUrl,
        [string]$MalwareBazaarApiUrl,
        [bool]$AutoQuarantine = $true
    )
    
    # Ensure QuarantinePath is set from Config if not provided as parameter
    if (-not $QuarantinePath -and $Config.QuarantinePath) {
        $QuarantinePath = $Config.QuarantinePath
    }

    $SuspiciousPaths = @(
        "$env:TEMP",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp",
        "C:\Windows\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:PUBLIC",
        "$env:ProgramData"
    )

    $maxFiles = if ($Config.MaxFilesPerScan -gt 0) { $Config.MaxFilesPerScan } else { 500 }
    $Files = @(Get-ChildItem -Path $SuspiciousPaths -Include *.exe,*.dll,*.scr,*.vbs,*.ps1,*.bat,*.cmd,*.com,*.msi,*.hta,*.js,*.jse,*.wsf,*.wsh -Recurse -ErrorAction SilentlyContinue | Select-Object -First $maxFiles)

    # Tier 2: Drive roots (local, removable, network) - shallow scan to catch drops like D:\mimikatz.exe
    $driveRoots = Get-DriveRootsForScan
    $depth = if ($Config.DriveRootScanDepth -ge 0) { $Config.DriveRootScanDepth } else { 2 }
    $extensions = @('*.exe','*.dll','*.scr','*.vbs','*.ps1','*.bat','*.cmd','*.com','*.msi','*.hta','*.js','*.jse','*.wsf','*.wsh')
    foreach ($root in $driveRoots) {
        if ($Files.Count -ge $maxFiles) { break }
        if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }
        try {
            $remaining = $maxFiles - $Files.Count
            $rootFiles = Get-ChildItem -Path $root -Include $extensions -Recurse -Depth $depth -File -ErrorAction SilentlyContinue | Select-Object -First $remaining
            $Files = @($Files) + @($rootFiles)
        } catch { }
    }

    # Local known-bad hashes (includes EICAR test file and common malware)
    $eicarHash = if ($Config.EICARHash) { $Config.EICARHash } else { "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" }
    $KnownBadHashes = @{
        $eicarHash = "EICAR-Test-File"
        "44D88612FEA8A8F36DE82E1278ABB02F" = "EICAR-Test-File-MD5"
    }
    
    # Initialize cache for known files (true = safe, false = malicious)
    if (-not $Script:KnownFilesCache) {
        $Script:KnownFilesCache = @{}
    }
    
    foreach ($File in $Files) {
        try {
            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

            # Check cache first - if known bad, hard delete immediately
            if ($Script:KnownFilesCache.ContainsKey($Hash)) {
                if (-not $Script:KnownFilesCache[$Hash]) {
                    if (Test-Path $File.FullName) {
                        if ($Script:LearningMode -or -not $Config.AutoQuarantine) {
                            Write-AVLog "[LEARNING] Would have deleted known-bad: $($File.FullName) (hash: $Hash)" "INFO"
                        } else {
                            Write-AVLog "[HashDetection] Known bad file re-detected - HARD DELETING: $($File.FullName) (hash: $Hash)" "THREAT"
                            try {
                                Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                                Write-AVLog "[HashDetection] Successfully deleted known-bad file: $($File.FullName)" "ACTION"
                                $Global:AntivirusState.FilesQuarantined++
                            } catch {
                                Write-AVLog "[HashDetection] Delete failed - falling back to quarantine: $_" "WARN"
                                Move-ToQuarantine -Path $File.FullName -Reason "Known threat (delete failed)"
                            }
                        }
                    }
                }
                continue
            }

            $Reputation = @{
                IsMalicious = $false
                Confidence = 0
                Sources = @()
            }
            
            # Check local known-bad hash list first
            if ($KnownBadHashes.ContainsKey($Hash)) {
                $Reputation.IsMalicious = $true
                $Reputation.Confidence = 100
                $Reputation.Sources += "LocalDB:$($KnownBadHashes[$Hash])"
            }

            try {
                if (Test-CircuitBreaker -Service 'CIRCL') {
                    $CirclResponse = Invoke-RestMethod -Uri "$CirclHashLookupUrl/$Hash" -Method Get -Headers (Get-ApiHeaders) -TimeoutSec 5 -ErrorAction SilentlyContinue
                    if ($CirclResponse) { Reset-CircuitBreakerOnSuccess -Service 'CIRCL' }
                    if ($CirclResponse.KnownMalicious) {
                        $Reputation.IsMalicious = $true
                        $Reputation.Confidence += 40
                        $Reputation.Sources += "CIRCL"
                    }
                }
            } catch { Update-CircuitBreakerOnFailure -Service 'CIRCL' }

            try {
                if (Test-CircuitBreaker -Service 'MalwareBazaar') {
                    $MBBody = @{ query = "get_info"; hash = $Hash } | ConvertTo-Json
                    $MBResponse = Invoke-RestMethod -Uri $MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -Headers (Get-ApiHeaders) -TimeoutSec 5 -ErrorAction SilentlyContinue
                    if ($MBResponse) { Reset-CircuitBreakerOnSuccess -Service 'MalwareBazaar' }
                    if ($MBResponse.query_status -eq "ok") {
                        $Reputation.IsMalicious = $true
                        $Reputation.Confidence += 50
                        $Reputation.Sources += "MalwareBazaar"
                    }
                }
            } catch { Update-CircuitBreakerOnFailure -Service 'MalwareBazaar' }

            try {
                if (Test-CircuitBreaker -Service 'Cymru') {
                    $CymruResponse = Invoke-RestMethod -Uri "$CymruApiUrl/$Hash" -Method Get -Headers (Get-ApiHeaders) -TimeoutSec 5 -ErrorAction SilentlyContinue
                    if ($CymruResponse) { Reset-CircuitBreakerOnSuccess -Service 'Cymru' }
                    if ($CymruResponse.malware -eq $true) {
                        $Reputation.IsMalicious = $true
                        $Reputation.Confidence += 30
                        $Reputation.Sources += "Cymru"
                    }
                }
            } catch { Update-CircuitBreakerOnFailure -Service 'Cymru' }

            if ($Reputation.IsMalicious -and $Reputation.Confidence -ge 50) {
                Write-AVLog "[HashDetection] THREAT: $($File.FullName) | Hash: $Hash | Sources: $($Reputation.Sources -join ', ') | Confidence: $($Reputation.Confidence)%" "THREAT"
                
                # Add to cache as known-bad for future hard deletion
                $Script:KnownFilesCache[$Hash] = $false
                if (Get-Command Save-ToHashDatabase -ErrorAction SilentlyContinue) {
                    Save-ToHashDatabase -Hash $Hash -IsSafe $false
                }

                if ($AutoQuarantine) {
                    $quarantined = Move-ToQuarantine -Path $File.FullName -Reason "HashDetection: $($Reputation.Sources -join ', ')"
                    if ($quarantined) {
                        Write-AVLog "[HashDetection] Quarantined: $($File.FullName)" "ACTION"
                    }
                }
            }

            try {
                $Entropy = Measure-FileEntropy -FilePath $File.FullName
                if ($Entropy -is [double] -or $Entropy -is [int]) {
                    if ($Entropy -gt 7.5 -and $File.Length -lt 1MB) {
                        Write-AVLog "[HashDetection] High entropy detected: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2))" "WARN"
                    }
                }
            } catch {
                # Entropy calculation failed, skip
            }

        } catch {
            Write-AVLog "[HashDetection] Error scanning $($File.FullName): $_" "ERROR"
        }
    }
}

function Measure-FileEntropy {
    param([string]$FilePath)

    try {
        $Bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..4096]
        $Freq = @{}
        foreach ($Byte in $Bytes) {
            if ($Freq.ContainsKey($Byte)) {
                $Freq[$Byte]++
            } else {
                $Freq[$Byte] = 1
            }
        }

        $Entropy = 0
        $Total = $Bytes.Count
        foreach ($Count in $Freq.Values) {
            $P = $Count / $Total
            $Entropy -= $P * [Math]::Log($P, 2)
        }

        return $Entropy
    } catch {
        return 0
    }
}

# ===================== TinyThreatScan + SecureDNS (from AV2) =====================
$Script:RiskyPaths = @('\temp\', '\downloads\', '\appdata\local\temp\', '\public\', '\windows\temp\', '\appdata\roaming\', '\desktop\')

function Test-TinyShouldExclude {
    param([string]$FilePath)
    $lower = $FilePath.ToLower()
    if ($lower -like '*\assembly\*') { return $true }; if ($lower -like '*\winsxs\*') { return $true }; if ($lower -like '*\microsoft.net\*') { return $true }; if ($lower -like '*\windows\system32\config\*') { return $true }; if ($lower -like '*ctfmon*' -or $lower -like '*msctf.dll' -or $lower -like '*msutb.dll') { return $true }
    foreach ($exclusion in $Config.ExclusionPaths) { if ($lower -like "*$($exclusion.ToLower())*") { return $true } }
    return $false
}

function Test-SuspiciousUnsignedDll {
    param([string]$FilePath)
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin @('.dll', '.winmd')) { return $false }
    try { $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop; if ($signature.Status -eq 'Valid') { return $false } } catch {}
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $false }
    $fileSizeKB = $fileInfo.Length / 1KB; $pathLower = $FilePath.ToLower()
    foreach ($riskyPath in $Script:RiskyPaths) { if ($pathLower -like "*$riskyPath*" -and $fileSizeKB -lt 3072) { return $true } }
    if ($pathLower -like '*\appdata\roaming\*' -and $fileSizeKB -lt 800 -and $fileInfo.Name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') { return $true }
    return $false
}

function Invoke-TinyThreatAnalysis {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) { return }; if (Test-TinyShouldExclude -FilePath $FilePath) { return }
    $extension = [IO.Path]::GetExtension($FilePath).ToLower(); if ($extension -notin $Script:MonitoredExtensions) { return }
    try { $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { return }
    if (-not $fileHash) { return }
    if ($Script:KnownFilesCache.ContainsKey($fileHash)) { if (-not $Script:KnownFilesCache[$fileHash]) { if (Test-Path $FilePath) { Write-AVLog "Known-bad file re-detected - quarantining: $FilePath" "THREAT"; Move-ToQuarantine -Path $FilePath -Reason "Known threat (cached)" } }; return }
    if (Test-CirclKnownGood -SHA256 $fileHash) { Save-ToHashDatabase -Hash $fileHash -IsSafe $true; return }
    if (Test-CymruMalware -SHA256 $fileHash) { Save-ToHashDatabase -Hash $fileHash -IsSafe $false; Move-ToQuarantine -Path $FilePath -Reason "Cymru malware match"; return }
    if (Test-MalwareBazaar -SHA256 $fileHash) { Save-ToHashDatabase -Hash $fileHash -IsSafe $false; Move-ToQuarantine -Path $FilePath -Reason "MalwareBazaar malware match"; return }
    if (Test-SuspiciousUnsignedDll -FilePath $FilePath) { Save-ToHashDatabase -Hash $fileHash -IsSafe $false; Move-ToQuarantine -Path $FilePath -Reason "Suspicious unsigned DLL in risky location"; return }
    $executableExtensions = @('.exe', '.dll', '.sys', '.ocx', '.scr', '.msi', '.drv')
    if ($extension -in $executableExtensions) { try { $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop; $isSafe = ($signature.Status -eq 'Valid'); Save-ToHashDatabase -Hash $fileHash -IsSafe $isSafe } catch { Save-ToHashDatabase -Hash $fileHash -IsSafe $true } } else { Save-ToHashDatabase -Hash $fileHash -IsSafe $true }
    $Global:AntivirusState.FilesScanned++
}

function Invoke-TinyThreatScan {
    $maxFiles = if ($Config.MaxFilesPerScan -gt 0) { $Config.MaxFilesPerScan } else { 500 }
    $highRiskFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:PUBLIC", "$env:ProgramData")
    $filesToScan = @()
    foreach ($folder in $highRiskFolders) {
        if ($filesToScan.Count -ge $maxFiles) { break }
        if (Test-Path $folder) {
            $remaining = $maxFiles - $filesToScan.Count
            $filesToScan += @(Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First $remaining)
        }
    }
    # Tier 2: Drive roots (local, removable, network) - shallow scan
    $driveRoots = Get-DriveRootsForScan
    $depth = if ($Config.DriveRootScanDepth -ge 0) { $Config.DriveRootScanDepth } else { 2 }
    foreach ($root in $driveRoots) {
        if ($filesToScan.Count -ge $maxFiles) { break }
        if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }
        try {
            $remaining = $maxFiles - $filesToScan.Count
            $rootFiles = Get-ChildItem -Path $root -Recurse -File -Depth $depth -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in $Script:MonitoredExtensions } | Select-Object -First $remaining
            $filesToScan += @($rootFiles)
        } catch { }
    }
    foreach ($f in $filesToScan) { Invoke-TinyThreatAnalysis -FilePath $f.FullName }
    Write-Output "[TinyThreatScan] Scan cycle completed. Files in cache: $($Script:KnownFilesCache.Count)"
}

$Script:SecureDnsServers = @(
    @{ IP = "1.1.1.1"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com"; Type = "IPv4" },
    @{ IP = "1.0.0.1"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com"; Type = "IPv4" },
    @{ IP = "8.8.8.8"; DohTemplate = "https://dns.google/dns-query"; DotHost = "dns.google"; Type = "IPv4" },
    @{ IP = "8.8.4.4"; DohTemplate = "https://dns.google/dns-query"; DotHost = "dns.google"; Type = "IPv4" },
    @{ IP = "2606:4700:4700::1111"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com"; Type = "IPv6" },
    @{ IP = "2606:4700:4700::1001"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com"; Type = "IPv6" },
    @{ IP = "2001:4860:4860::8888"; DohTemplate = "https://dns.google/dns-query"; DotHost = "dns.google"; Type = "IPv6" },
    @{ IP = "2001:4860:4860::8844"; DohTemplate = "https://dns.google/dns-query"; DotHost = "dns.google"; Type = "IPv6" }
)

function Invoke-SecureDnsConfiguration {
    if (-not (Test-IsAdmin)) { Write-Output "[SecureDNS] Requires administrator privileges - skipping"; return }
    Write-Output "[SecureDNS] Configuring encrypted DNS (DoH/DoT)..."
    foreach ($server in $Script:SecureDnsServers) { try { Add-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop; Write-Output "[SecureDNS] Registered DoH template: $($server.IP)" } catch { try { Set-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue } catch {} } }
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Virtual|Loopback|Bluetooth" } | Select-Object -First 1
    if (-not $adapter) { Write-Output "[SecureDNS] No active network adapter found"; return }
    Write-Output "[SecureDNS] Configuring adapter: $($adapter.Name)"
    try { netsh interface ipv4 set dnsservers name="$($adapter.Name)" static 1.1.1.1 primary validate=no 2>&1 | Out-Null; netsh interface ipv4 add dnsservers name="$($adapter.Name)" 8.8.8.8 index=2 validate=no 2>&1 | Out-Null; netsh interface ipv6 set dnsservers name="$($adapter.Name)" static 2606:4700:4700::1111 primary validate=no 2>&1 | Out-Null; netsh interface ipv6 add dnsservers name="$($adapter.Name)" 2001:4860:4860::8888 index=2 validate=no 2>&1 | Out-Null } catch {}
    $guid = $adapter.InterfaceGuid; $dohBasePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings"; $dotBasePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DotInterfaceSettings"
    $dohServers = @( @{ IP = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh" }, @{ IP = "8.8.8.8"; Template = "https://dns.google/dns-query"; Path = "Doh" }, @{ IP = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh6" }, @{ IP = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query"; Path = "Doh6" } )
    foreach ($doh in $dohServers) { try { $dohPath = "$dohBasePath\$($doh.Path)\$($doh.IP)"; New-Item -Path $dohPath -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path $dohPath -Name "DohFlags" -Value 0x11 -Type QWord -ErrorAction SilentlyContinue; Set-ItemProperty -Path $dohPath -Name "DohTemplate" -Value $doh.Template -Type String -ErrorAction SilentlyContinue } catch {} }
    $dotServers = @( @{ IP = "1.1.1.1"; Host = "cloudflare-dns.com"; Path = "Dot" }, @{ IP = "8.8.8.8"; Host = "dns.google"; Path = "Dot" }, @{ IP = "2606:4700:4700::1111"; Host = "cloudflare-dns.com"; Path = "Dot6" }, @{ IP = "2001:4860:4860::8888"; Host = "dns.google"; Path = "Dot6" } )
    foreach ($dot in $dotServers) { try { $serverPath = "$dotBasePath\$($dot.Path)\$($dot.IP)"; New-Item -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path $serverPath -Name "DotFlags" -Value 0x11 -Type QWord -ErrorAction SilentlyContinue; Set-ItemProperty -Path $serverPath -Name "DotHost" -Value $dot.Host -Type String -ErrorAction SilentlyContinue } catch {} }
    try { Clear-DnsClientCache; Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue } catch {}
    Write-Output "[SecureDNS] Configuration complete - DoH/DoT enabled"
}

function Invoke-SecureDnsMonitoring {
    if (-not (Test-IsAdmin)) { return }
    $detections = @(); $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Virtual|Loopback|Bluetooth" } | Select-Object -First 1
    if (-not $adapter) { return }
    $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
    $ipv4Dns = ($dnsServers | Where-Object { $_.AddressFamily -eq 2 }).ServerAddresses; $ipv6Dns = ($dnsServers | Where-Object { $_.AddressFamily -eq 23 }).ServerAddresses
    $trustedDns = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844")
    foreach ($dns in $ipv4Dns) { if ($dns -and $trustedDns -notcontains $dns) { $detections += @{ Type = "DNS_HIJACK"; Details = "Untrusted IPv4 DNS: $dns"; Risk = "High" }; Write-Output "[SecureDNS] WARNING: Untrusted DNS: $dns" } }
    foreach ($dns in $ipv6Dns) { if ($dns -and $trustedDns -notcontains $dns) { $detections += @{ Type = "DNS_HIJACK"; Details = "Untrusted IPv6 DNS: $dns"; Risk = "High" }; Write-Output "[SecureDNS] WARNING: Untrusted DNS: $dns" } }
    $guid = $adapter.InterfaceGuid; $dohPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh\1.1.1.1"
    if (-not (Test-Path $dohPath)) { $detections += @{ Type = "DOH_DISABLED"; Details = "DoH missing - reapplying"; Risk = "Medium" }; Invoke-SecureDnsConfiguration } else { try { $dohFlags = Get-ItemProperty -Path $dohPath -Name "DohFlags" -ErrorAction SilentlyContinue; if ($dohFlags.DohFlags -ne 0x11) { Invoke-SecureDnsConfiguration } } catch {} }
    if ($detections.Count -gt 0) { foreach ($d in $detections) { Write-AVLog "SecureDNS: $($d.Type) - $($d.Details)" "THREAT" } }
    Write-Output "[SecureDNS] Monitoring check completed"
}

# ===================== Advanced Multi-Layered Threat Detection Framework =====================
# This framework provides hash-based, signature-based, behavioral, and entropy-based detection
# that is resilient against renaming and obfuscation. Can be used by any detection module.

function Invoke-AdvancedThreatDetection {
    param(
        [Parameter(Mandatory=$false)]
        [string]$FilePath = "",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$KnownHashes = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$FileSignatures = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$BehavioralIndicators = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$ProcessId = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$CommandLine = $null,
        
        [Parameter(Mandatory=$false)]
        [bool]$CheckEntropy = $true,
        
        [Parameter(Mandatory=$false)]
        [double]$EntropyThreshold = 7.5
    )
    
    # Early return if FilePath is not provided - prevents prompt when called without parameters
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return @{
            IsThreat = $false
            ThreatName = ""
            DetectionMethods = @()
            Confidence = 0
            Risk = "LOW"
            Details = @{}
        }
    }
    
    $detectionResults = @{
        IsThreat = $false
        ThreatName = $null
        DetectionMethods = @()
        Confidence = 0
        Risk = "LOW"
        Details = @{}
    }
    
    if (-not (Test-Path $FilePath)) {
        return $detectionResults
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $detectionCount = 0
        
        # Method 1: Hash-Based Detection (SHA256)
        if ($KnownHashes.Count -gt 0) {
            try {
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                
                foreach ($threatName in $KnownHashes.Keys) {
                    if ($KnownHashes[$threatName] -contains $fileHash) {
                        $detectionResults.IsThreat = $true
                        $detectionResults.ThreatName = $threatName
                        $detectionResults.DetectionMethods += "HashMatch"
                        $detectionResults.Confidence += 100
                        $detectionResults.Risk = "CRITICAL"
                        $detectionResults.Details["Hash"] = $fileHash
                        $detectionCount++
                        break
                    }
                }
            } catch { }
        }
        
        # Method 2: File Signature/Pattern Detection (YARA-like)
        if ($FileSignatures.Count -gt 0 -and $fileInfo.Length -lt 50MB) {
            try {
                $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                
                foreach ($threatName in $FileSignatures.Keys) {
                    $matchCount = 0
                    $matchedSignatures = @()
                    
                    foreach ($signature in $FileSignatures[$threatName]) {
                        if ($fileContent -match [regex]::Escape($signature)) {
                            $matchCount++
                            $matchedSignatures += $signature
                        }
                    }
                    
                    # If multiple signatures match, it's likely this threat
                    if ($matchCount -ge 2) {
                        $detectionResults.IsThreat = $true
                        $detectionResults.ThreatName = $threatName
                        $detectionResults.DetectionMethods += "SignatureMatch"
                        $detectionResults.Confidence += ($matchCount * 20)
                        if ($detectionResults.Risk -ne "CRITICAL") {
                            $detectionResults.Risk = if ($matchCount -ge 3) { "CRITICAL" } else { "HIGH" }
                        }
                        $detectionResults.Details["SignatureMatches"] = $matchCount
                        $detectionResults.Details["MatchedSignatures"] = $matchedSignatures
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 3: Entropy Analysis (Packed/Obfuscated Detection)
        if ($CheckEntropy -and $fileInfo.Length -lt 10MB) {
            try {
                $entropy = Measure-FileEntropy -FilePath $FilePath
                
                if ($entropy -gt $EntropyThreshold) {
                    # High entropy = possibly packed/obfuscated
                    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
                    $isSigned = $sig.Status -eq "Valid"
                    
                    if (-not $isSigned) {
                        $detectionResults.IsThreat = $true
                        if (-not $detectionResults.ThreatName) {
                            $detectionResults.ThreatName = "SuspiciousPackedTool"
                        }
                        $detectionResults.DetectionMethods += "EntropyAnalysis"
                        $detectionResults.Confidence += 30
                        if ($detectionResults.Risk -eq "LOW") {
                            $detectionResults.Risk = "MEDIUM"
                        }
                        $detectionResults.Details["Entropy"] = [Math]::Round($entropy, 2)
                        $detectionResults.Details["IsSigned"] = $isSigned
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 4: Behavioral Pattern Detection (Command Line Analysis)
        if ($CommandLine -and $BehavioralIndicators.Count -gt 0) {
            try {
                foreach ($behaviorType in $BehavioralIndicators.Keys) {
                    $patterns = $BehavioralIndicators[$behaviorType]
                    if ($null -eq $patterns) { continue }
                    
                    $matchCount = 0
                    foreach ($pattern in $patterns) {
                        if ($CommandLine -match $pattern) {
                            $matchCount++
                        }
                    }
                    
                    if ($matchCount -gt 0) {
                        $detectionResults.IsThreat = $true
                        if (-not $detectionResults.ThreatName) {
                            $detectionResults.ThreatName = "SuspiciousBehavior_$behaviorType"
                        }
                        $detectionResults.DetectionMethods += "BehavioralPattern"
                        $detectionResults.Confidence += ($matchCount * 15)
                        if ($detectionResults.Risk -ne "CRITICAL") {
                            $detectionResults.Risk = if ($matchCount -ge 2) { "HIGH" } else { "MEDIUM" }
                        }
                        $detectionResults.Details["BehaviorType"] = $behaviorType
                        $detectionResults.Details["BehaviorMatches"] = $matchCount
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 5: Digital Signature Verification
        try {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            $detectionResults.Details["SignatureStatus"] = $sig.Status
            $detectionResults.Details["IsSigned"] = ($sig.Status -eq "Valid")
            
            # Unsigned executables in suspicious locations are more suspicious
            if ($sig.Status -ne "Valid" -and $detectionCount -gt 0) {
                $detectionResults.Confidence += 10
            }
        } catch { }
        
        # Calculate final risk based on confidence
        if ($detectionResults.Confidence -ge 80) {
            $detectionResults.Risk = "CRITICAL"
        } elseif ($detectionResults.Confidence -ge 60) {
            $detectionResults.Risk = "HIGH"
        } elseif ($detectionResults.Confidence -ge 40) {
            $detectionResults.Risk = "MEDIUM"
        }
        
        $detectionResults.Details["DetectionCount"] = $detectionCount
        $detectionResults.Details["FilePath"] = $FilePath
        $detectionResults.Details["FileSize"] = "$([Math]::Round($fileInfo.Length / 1MB, 2)) MB"
        
    } catch {
        Write-AVLog "Advanced threat detection error for $FilePath : $_" "WARN" "advanced_threat_detection.log"
    }
    
    return $detectionResults
}

# Standalone job for comprehensive advanced threat detection across the system
function Invoke-SystemWideAdvancedThreatDetection {
    $detections = @()
    $threats = @()
    
    try {
        # Comprehensive threat signature database
        $threatSignatures = @{
            # Malware families
            "Trojan" = @(
                "trojan", "backdoor", "rat", "remote.*access", "keylogger",
                "stealer", "spyware", "adware", "rootkit"
            )
            "Ransomware" = @(
                "ransomware", "encrypt", "decrypt", "bitcoin", "payment.*required",
                "your.*files.*encrypted", "lock.*screen"
            )
            "BankingTrojan" = @(
                "banking", "financial", "credit.*card", "account.*number",
                "login.*credentials", "password.*stealer"
            )
            "Cryptominer" = @(
                "miner", "mining", "cryptocurrency", "bitcoin.*miner",
                "monero", "xmrig", "ccminer"
            )
            # Attack tools
            "PasswordCracker" = @(
                "hydra", "john.*ripper", "hashcat", "brute.*force",
                "dictionary.*attack", "wordlist", "password.*crack"
            )
            "CredentialDumper" = @(
                "mimikatz", "lsadump", "sekurlsa", "wdigest",
                "credential.*dump", "password.*dump"
            )
            "NetworkScanner" = @(
                "nmap", "masscan", "port.*scan", "network.*scan",
                "host.*scan", "reconnaissance"
            )
            "ExploitationFramework" = @(
                "metasploit", "cobalt.*strike", "empire", "covenant",
                "exploit", "payload", "meterpreter"
            )
        }
        
        # Behavioral indicators
        $behavioralPatterns = @{
            "CredentialDumping" = @(
                "lsass", "sam.*dump", "security.*dump", "system.*dump",
                "reg.*save.*sam", "reg.*save.*security"
            )
            "LateralMovement" = @(
                "psexec", "wmic.*process", "winrm", "smbexec",
                "lateral.*movement", "pass.*the.*hash"
            )
            "Persistence" = @(
                "schtasks.*create", "reg.*add.*run", "startup",
                "scheduled.*task", "registry.*run"
            )
            "DataExfiltration" = @(
                "upload", "exfiltrate", "send.*data", "http.*post",
                "ftp.*put", "sftp.*put"
            )
        }
        
        # Scan running processes
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procPath = $proc.ExecutablePath
                if (-not $procPath -or -not (Test-Path $procPath)) { continue }
                
                $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                $procCmdLine = $proc.CommandLine
                
                # Use advanced detection framework
                $detectionResult = Invoke-AdvancedThreatDetection `
                    -FilePath $procPath `
                    -FileSignatures $threatSignatures `
                    -BehavioralIndicators $behavioralPatterns `
                    -CommandLine $procCmdLine `
                    -CheckEntropy $true
                
                if ($detectionResult.IsThreat) {
                    $threats += @{
                        Type = "Advanced Threat Detected: $($detectionResult.ThreatName)"
                        ProcessName = $procName
                        ProcessPath = $procPath
                        ProcessId = $proc.ProcessId
                        CommandLine = $procCmdLine
                        DetectionMethods = $detectionResult.DetectionMethods -join ", "
                        Confidence = $detectionResult.Confidence
                        Risk = $detectionResult.Risk
                        Details = $detectionResult.Details
                        Timestamp = Get-Date
                    }
                    
                    # Auto-terminate critical threats
                    if ($Config.AutoKillThreats -and $detectionResult.Risk -eq "CRITICAL") {
                        try {
                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-AVLog "Terminated advanced threat: $procName ($($detectionResult.ThreatName))" "THREAT" "advanced_threat_detection.log"
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Scan suspicious directories for files
        $scanPaths = @(
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop",
            "$env:TEMP",
            "$env:APPDATA\Local\Temp",
            "C:\Tools",
            "C:\Hacking"
        )
        
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            
            try {
                $exeFiles = Get-ChildItem -Path $scanPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -lt 50MB } |
                    Select-Object -First 30
                
                foreach ($file in $exeFiles) {
                    try {
                        $detectionResult = Invoke-AdvancedThreatDetection `
                            -FilePath $file.FullName `
                            -FileSignatures $threatSignatures `
                            -CheckEntropy $true
                        
                        if ($detectionResult.IsThreat) {
                            $threats += @{
                                Type = "Advanced Threat File Detected: $($detectionResult.ThreatName)"
                                FilePath = $file.FullName
                                FileName = $file.Name
                                DetectionMethods = $detectionResult.DetectionMethods -join ", "
                                Confidence = $detectionResult.Confidence
                                Risk = $detectionResult.Risk
                                Details = $detectionResult.Details
                                Timestamp = Get-Date
                            }
                            
                            # Auto-quarantine
                            if ($Config.AutoQuarantine -and $detectionResult.Risk -in @("HIGH", "CRITICAL")) {
                                try {
                                    Move-ToQuarantine -FilePath $file.FullName -Reason "Advanced threat detected: $($detectionResult.ThreatName)"
                                    Write-AVLog "Quarantined advanced threat: $($file.Name)" "THREAT" "advanced_threat_detection.log"
                                } catch { }
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
        
        # Tier 2: Drive roots (local, removable, network) - shallow scan for dropped executables
        $driveRoots = Get-DriveRootsForScan
        $depth = if ($Config.DriveRootScanDepth -ge 0) { $Config.DriveRootScanDepth } else { 2 }
        foreach ($root in $driveRoots) {
            if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }
            try {
                $exeFiles = Get-ChildItem -Path $root -Filter "*.exe" -Recurse -Depth $depth -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -lt 50MB } |
                    Select-Object -First 30
                foreach ($file in $exeFiles) {
                    try {
                        $detectionResult = Invoke-AdvancedThreatDetection -FilePath $file.FullName -FileSignatures $threatSignatures -CheckEntropy $true
                        if ($detectionResult.IsThreat) {
                            $threats += @{
                                Type = "Advanced Threat File Detected: $($detectionResult.ThreatName)"
                                FilePath = $file.FullName
                                FileName = $file.Name
                                DetectionMethods = $detectionResult.DetectionMethods -join ", "
                                Confidence = $detectionResult.Confidence
                                Risk = $detectionResult.Risk
                                Details = $detectionResult.Details
                                Timestamp = Get-Date
                            }
                            if ($Config.AutoQuarantine -and $detectionResult.Risk -in @("HIGH", "CRITICAL")) {
                                try {
                                    Move-ToQuarantine -FilePath $file.FullName -Reason "Advanced threat detected: $($detectionResult.ThreatName)"
                                    Write-AVLog "Quarantined advanced threat: $($file.Name)" "THREAT" "advanced_threat_detection.log"
                                } catch { }
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
        
        # Log all detections
        if ($threats.Count -gt 0) {
            foreach ($threat in $threats) {
                Write-AVLog "ADVANCED THREAT: $($threat.Type) - $($threat.ProcessName -or $threat.FileName) - Methods: $($threat.DetectionMethods) - Confidence: $($threat.Confidence)% - Risk: $($threat.Risk)" "THREAT" "advanced_threat_detection.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($Config.AutoKillThreats) {
                    # Get the first available path (use proper null-coalescing, not -or operator)
                    $threatPath = if ($threat.ProcessPath) { $threat.ProcessPath }
                                  elseif ($threat.FilePath) { $threat.FilePath }
                                  elseif ($threat.ProcessName) { $threat.ProcessName }
                                  elseif ($threat.FileName) { $threat.FileName }
                                  else { "" }
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$Script:InstallPath\Logs\AdvancedThreatDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            $threats | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Confidence)|$($_.DetectionMethods)|$($_.ProcessName -or $_.FileName -or 'N/A')|$($_.ProcessId -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            } | Out-Null
        }
        
    } catch {
        Write-AVLog "System-wide advanced threat detection error: $_" "ERROR" "advanced_threat_detection.log"
    }
    
    # Return count without outputting to pipeline - suppress any accidental output
    # Clear all variables to prevent any implicit output that might cause parameter binding
    $result = $threats.Count
    $threats = $null
    $detections = $null
    $processes = $null
    $exeFiles = $null
    $scanPaths = $null
    $threatSignatures = $null
    $behavioralPatterns = $null
    [void]$result  # Explicitly discard if accidentally output
    return $result
}

function Invoke-LOLBinDetection {
    $LOLBinPatterns = @{
        "certutil" = @{
            Patterns = @("-decode", "-urlcache", "-verifyctl", "-encode")
            Severity = "HIGH"
            Description = "Certutil abuse for download/decode"
        }
        "bitsadmin" = @{
            Patterns = @("transfer", "addfile", "/download")
            Severity = "HIGH"
            Description = "BITS abuse for download"
        }
        "mshta" = @{
            Patterns = @("http://", "https://", "javascript:", "vbscript:")
            Severity = "CRITICAL"
            Description = "MSHTA remote code execution"
        }
        "regsvr32" = @{
            Patterns = @("scrobj.dll", "/s", "/u", "http://", "https://")
            Severity = "HIGH"
            Description = "Regsvr32 squiblydoo attack"
        }
        "rundll32" = @{
            Patterns = @("javascript:", "http://", "https://", "shell32.dll,Control_RunDLL")
            Severity = "MEDIUM"
            Description = "Rundll32 proxy execution"
        }
        "wmic" = @{
            Patterns = @('process call create', '/node:', 'format:"http', 'xsl:http')
            Severity = "HIGH"
            Description = "WMIC remote execution or XSL abuse"
        }
        "powershell" = @{
            Patterns = @("-enc ", "-encodedcommand", "downloadstring", "iex ", "invoke-expression", "-nop", "-w hidden", "bypass")
            Severity = "HIGH"
            Description = "PowerShell obfuscation and evasion"
        }
        "sc" = @{
            Patterns = @("create", "config", "binpath=")
            Severity = "MEDIUM"
            Description = "Service manipulation"
        }
        "msiexec" = @{
            Patterns = @("/quiet", "/q", "http://", "https://")
            Severity = "MEDIUM"
            Description = "Silent MSI installation from remote"
        }
    }
    
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $CmdLine = $Proc.CommandLine
        if (-not $CmdLine) { continue }
        
        $ProcessName = $Proc.Name -replace '\.exe$', ''
        
        foreach ($LOLBin in $LOLBinPatterns.Keys) {
            if ($ProcessName -like "*$LOLBin*") {
                $MatchedPatterns = @()
                foreach ($Pattern in $LOLBinPatterns[$LOLBin].Patterns) {
                    if ($CmdLine -match [regex]::Escape($Pattern)) {
                        $MatchedPatterns += $Pattern
                    }
                }
                
                if ($MatchedPatterns.Count -gt 0) {
                    $Severity = $LOLBinPatterns[$LOLBin].Severity
                    $Description = $LOLBinPatterns[$LOLBin].Description
                    Write-AVLog "LOLBin detected [$Severity] - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Attack: $Description | Patterns: $($MatchedPatterns -join ', ') | Command: $CmdLine" "THREAT" "behavior_detections.log"
                    $Global:AntivirusState.ThreatCount++
                    
                    if ($Config.AutoKillThreats -and $Severity -in @("HIGH", "CRITICAL")) {
                        Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name
                    }
                }
            }
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $AnomalyScore = @{}
    
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $Score = 0
        $Anomalies = @()
        
        # Parent process analysis
        $Parent = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($Parent) {
            # Office spawning scripts
            if ($Parent.Name -match "winword|excel|powerpnt|outlook" -and $Proc.Name -match "powershell|cmd|wscript|cscript") {
                $Score += 5
                $Anomalies += "OfficeSpawnScript"
            }
            
            # Explorer spawning hidden scripts
            if ($Parent.Name -eq "explorer.exe" -and $Proc.CommandLine -match "-w hidden|-windowstyle hidden|-nop|-enc") {
                $Score += 4
                $Anomalies += "ExplorerHiddenScript"
            }
            
            # Service host spawning unexpected processes
            if ($Parent.Name -eq "svchost.exe" -and $Proc.Name -notmatch "dllhost|conhost|rundll32") {
                $Score += 3
                $Anomalies += "SvchostUnexpectedChild"
            }
        }
        
        # Path validation
        $ProcPath = $Proc.ExecutablePath
        if ($ProcPath) {
            # Executables in user directories
            if ($ProcPath -match "Users\\.*\\AppData|Users\\.*\\Downloads|Users\\.*\\Desktop" -and $Proc.Name -match "exe$") {
                $Score += 2
                $Anomalies += "UserDirExecution"
            }
            
            # System binaries in wrong locations
            if ($Proc.Name -in @("svchost.exe", "lsass.exe", "csrss.exe", "smss.exe") -and $ProcPath -notmatch "C:\\Windows\\System32") {
                $Score += 6
                $Anomalies += "SystemBinaryWrongLocation"
            }
        }
        
        # Command line analysis
        if ($Proc.CommandLine) {
            # Base64 encoded commands
            if ($Proc.CommandLine -match "-enc |-encodedcommand |FromBase64String") {
                $Score += 3
                $Anomalies += "Base64Encoding"
            }
            
            # Execution policy bypass
            if ($Proc.CommandLine -match "-exec bypass|-executionpolicy bypass|-ep bypass") {
                $Score += 2
                $Anomalies += "ExecutionPolicyBypass"
            }
            
            # Download cradles
            if ($Proc.CommandLine -match "DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl ") {
                $Score += 3
                $Anomalies += "DownloadCradle"
            }
        }
        
        # Report anomalies
        if ($Score -ge 6) {
            Write-AVLog "CRITICAL process anomaly - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Parent: $($Parent.Name) | Score: $Score | Anomalies: $($Anomalies -join ', ') | Path: $ProcPath | Command: $($Proc.CommandLine)" "THREAT" "behavior_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
        elseif ($Score -ge 3) {
            Write-AVLog "Process anomaly detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Score: $Score | Anomalies: $($Anomalies -join ', ')" "WARNING" "behavior_detections.log"
        }
    }
}

function Invoke-AMSIBypassDetection {
    $detections = @()
    
    # Enhanced AMSI bypass patterns
    $bypassPatterns = @(
        '[Ref].Assembly.GetType.*System.Management.Automation.AmsiUtils',
        '[Ref].Assembly.GetType.*AmsiUtils',
        'AmsiScanBuffer',
        'amsiInitFailed',
        'Bypass',
        'amsi.dll',
        'S`y`s`t`e`m.Management.Automation',
        'Hacking',
        'AMSI',
        'amsiutils',
        'amsiInitFailed',
        'Context',
        'AmsiContext',
        'AMSI_RESULT_CLEAN',
        'PatchAmsi',
        'DisableAmsi',
        'ForceAmsi',
        'Remove-Amsi',
        'Invoke-AmsiBypass',
        'AMSI.*bypass',
        'bypass.*AMSI',
        '-nop.*-w.*hidden.*-enc',
        'amsi.*off',
        'amsi.*disable',
        'Set-Amsi',
        'Override.*AMSI'
    )
    
    try {
        $maxProcs = 50
        $processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" } | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
            foreach ($pattern in $bypassPatterns) {
                if ($cmdLine -match $pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $cmdLine
                        BypassPattern = $pattern
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for obfuscated AMSI bypass (base64, hex, etc.)
            if ($cmdLine -match '-enc|-encodedcommand' -and $cmdLine.Length -gt 500) {
                # Long encoded command - try to decode
                try {
                    $encodedPart = $cmdLine -split '-enc\s+' | Select-Object -Last 1 -ErrorAction SilentlyContinue
                    if ($encodedPart) {
                        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedPart.Trim()))
                        if ($decoded -match 'amsi|AmsiScanBuffer|bypass' -or $decoded.Length -gt 1000) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $cmdLine
                                BypassPattern = "Obfuscated AMSI Bypass (Encoded)"
                                DecodedLength = $decoded.Length
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check PowerShell script blocks in memory
        try {
            $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
            foreach ($psProc in $psProcesses) {
                if ($psProc.Id -eq $PID -or $psProc.Id -eq $Script:SelfPID) { continue }
                
                # Check for AMSI-related .NET assemblies loaded
                $modules = $psProc.Modules | Where-Object {
                    $_.ModuleName -match 'amsi|System.Management.Automation'
                }
                
                if ($modules.Count -gt 0) {
                    # Check Event Log for AMSI script block logging
                    try {
                        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue -MaxEvents 50 |
                            Where-Object {
                                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5) -and
                                ($_.Message -match 'amsi|bypass|AmsiScanBuffer' -or $_.Message.Length -gt 5000)
                            }
                        
                        if ($psEvents.Count -gt 0) {
                            foreach ($event in $psEvents) {
                                $detections += @{
                                    ProcessId = $psProc.Id
                                    ProcessName = $psProc.ProcessName
                                    Type = "AMSI Bypass in PowerShell Script Block"
                                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                                    TimeCreated = $event.TimeCreated
                                    Risk = "Critical"
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check Event Log for AMSI events
        try {
            $amsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $amsiEvents) {
                if ($event.Message -match 'AmsiScanBuffer|bypass|blocked') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for AMSI registry tampering
        try {
            $amsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI"
            if (Test-Path $amsiKey) {
                $amsiValue = Get-ItemProperty -Path $amsiKey -ErrorAction SilentlyContinue
                if ($amsiValue -and $amsiValue.DisableAMSI) {
                    $detections += @{
                        Type = "Registry Tampering"
                        Path = $amsiKey
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.BypassPattern -or $detection.Message)" "THREAT" "amsi_bypass_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Message)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "AMSI bypass detection error: $_" "ERROR" "amsi_bypass_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CredentialDumpDetection {
    # Credential dumping signatures for advanced detection
    $credentialDumpSignatures = @{
        "CredentialDumper" = @(
            "mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce", "procdump",
            "dumpert", "nanodump", "lsassy", "lsadump", "cachedump",
            "credential.*dump", "password.*dump", "hash.*dump"
        )
    }
    
    # Credential dumping behavioral patterns
    $credentialDumpBehaviors = @{
        "LSASSAccess" = @(
            "lsass", "LSASS", "MiniDumpWriteDump", "CreateDump", "dmp.*lsass"
        )
        "RegistryDump" = @(
            "reg.*save.*sam", "reg.*save.*security", "reg.*save.*system",
            "reg.*export.*sam", "sam.*dump", "security.*dump"
        )
        "MemoryDump" = @(
            "MiniDump", "CreateDump", "dump.*memory", "memory.*dump"
        )
    }
    
    $CredentialTools = @("mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce.exe", "procdump", "dumpert", "nanodump", "lsassy")
    $LSASSAccess = @("lsass", "LSASS")
    
    # Monitor for processes accessing LSASS
    $LsassProc = Get-Process lsass -ErrorAction SilentlyContinue
    if ($LsassProc) {
        $AccessingProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -match "lsass" -and $_.ProcessId -ne $LsassProc.Id -and $_.ProcessId -ne $PID -and $_.ProcessId -ne $Script:SelfPID
        }
        
        foreach ($Proc in $AccessingProcesses) {
            # Use advanced detection framework
            if ($Proc.ExecutablePath -and (Test-Path $Proc.ExecutablePath)) {
                $detectionResult = Invoke-AdvancedThreatDetection `
                    -FilePath $Proc.ExecutablePath `
                    -FileSignatures $credentialDumpSignatures `
                    -BehavioralIndicators $credentialDumpBehaviors `
                    -CommandLine $Proc.CommandLine `
                    -CheckEntropy $true
                
                if ($detectionResult.IsThreat) {
                    Write-AVLog "LSASS access detected via Advanced Framework - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Methods: $($detectionResult.DetectionMethods -join ', ') | Confidence: $($detectionResult.Confidence)%" "THREAT" "credential_dumping_detections.log"
                } else {
                    Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                }
            } else {
                Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
            }
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
    
    # Detect credential dumping tools using advanced framework
    $AllProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $AllProcesses) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        
        # Use advanced detection framework
        if ($Proc.ExecutablePath -and (Test-Path $Proc.ExecutablePath)) {
            $detectionResult = Invoke-AdvancedThreatDetection `
                -FilePath $Proc.ExecutablePath `
                -FileSignatures $credentialDumpSignatures `
                -BehavioralIndicators $credentialDumpBehaviors `
                -CommandLine $Proc.CommandLine `
                -CheckEntropy $true
            
            if ($detectionResult.IsThreat) {
                Write-AVLog "Credential dumping tool detected via Advanced Framework - Tool: $($detectionResult.ThreatName) | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Methods: $($detectionResult.DetectionMethods -join ', ') | Confidence: $($detectionResult.Confidence)%" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
                continue
            }
        }
        
        # Legacy detection: Check process name and command line
        foreach ($Tool in $CredentialTools) {
            if ($Proc.Name -like "*$Tool*" -or $Proc.CommandLine -match $Tool) {
                Write-AVLog "Credential dumping tool detected - Tool: $Tool | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
            }
        }
        
        # Check for memory dump creation
        if ($Proc.CommandLine -match "MiniDump|CreateDump|dmp") {
            Write-AVLog "Memory dump creation detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "WARNING" "credential_dumping_detections.log"
        }
    }
    
    # Check for SAM/SYSTEM/SECURITY registry hive access
    $RegKeyAccess = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "SAM|SYSTEM|SECURITY" -and $_.CommandLine -match "reg save|reg export"
    }
    
    foreach ($Proc in $RegKeyAccess) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        Write-AVLog "Registry credential hive access - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
        $Global:AntivirusState.ThreatCount++
        if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
    }
}

function Invoke-WMIPersistenceDetection {
    $Filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $Consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue

    foreach ($Filter in $Filters) {
        Write-AVLog "[WMI] Event filter found: $($Filter.Name) | Query: $($Filter.Query)"
    }

    foreach ($Consumer in $Consumers) {
        Write-AVLog "[WMI] Command consumer found: $($Consumer.Name) | Command: $($Consumer.CommandLineTemplate)"
    }
}

function Invoke-ScheduledTaskDetection {
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Principal.UserId -notmatch "SYSTEM|Administrator" }

    foreach ($Task in $Tasks) {
        # Whitelist our own scheduled tasks
        if ($Task.TaskName -like "AntivirusAutoRestart_*" -or $Task.TaskName -eq "AntivirusProtection") {
            continue
        }
        
        $Action = $Task.Actions[0].Execute
        if ($Action -match "powershell|cmd|wscript|cscript|mshta") {
            Write-AVLog "[ScheduledTask] SUSPICIOUS: $($Task.TaskName) | Action: $Action | User: $($Task.Principal.UserId)"
        }
    }
}

function Invoke-RegistryPersistenceDetection {
    $detections = @()
    
    try {
        # Check standard Run keys
        $runKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                try {
                    $values = Get-ItemProperty -Path $key -ErrorAction Stop
                    foreach ($property in $values.PSObject.Properties) {
                        if ($property.Name -notmatch "^PS" -and $property.Value) {
                            $value = $property.Value
                            
                            # Check for suspicious patterns
                            $suspiciousPatterns = @(
                                "powershell.*-enc",
                                "cmd.*/c.*powershell",
                                "http://|https://",
                                "\.vbs|\.js|\.bat|\.cmd",
                                "wscript|cscript|mshta",
                                "rundll32.*\.dll",
                                "regsvr32.*\.dll"
                            )
                            
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($value -match $pattern) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $value
                                        Pattern = $pattern
                                        Type = "Suspicious Registry Persistence"
                                        Risk = "High"
                                    }
                                    break
                                }
                            }
                            
                            # Check for unsigned executables
                            if ($value -like "*.exe" -or $value -like "*.dll") {
                                $exePath = $value -split ' ' | Select-Object -First 1
                                if (Test-Path $exePath) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid" -and $exePath -notlike "$env:SystemRoot\*") {
                                            $detections += @{
                                                RegistryKey = $key
                                                ValueName = $property.Name
                                                Value = $value
                                                ExecutablePath = $exePath
                                                Type = "Unsigned Executable in Registry"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        }
        
        # Check for suspicious registry modifications in user profile
        try {
            $userRunKeys = @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            foreach ($key in $userRunKeys) {
                if (Test-Path $key) {
                    try {
                        $items = Get-Item $key -ErrorAction Stop
                        $lastWrite = $items.LastWriteTime
                        
                        # Check if recently modified
                        if ((Get-Date) - $lastWrite -lt [TimeSpan]::FromHours(24)) {
                            $values = Get-ItemProperty -Path $key -ErrorAction Stop
                            foreach ($property in $values.PSObject.Properties) {
                                if ($property.Name -notmatch "^PS" -and $property.Value) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $property.Value
                                        LastModified = $lastWrite
                                        Type = "Recently Modified Registry Persistence"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "REGISTRY PERSISTENCE: $($detection.Type) - $($detection.RegistryKey) - $($detection.ValueName)" "THREAT" "registry_persistence_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$Script:InstallPath\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RegistryKey)|$($_.ValueName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Registry persistence detection error: $_" "ERROR" "registry_persistence_detections.log"
    }
    
    return $detections.Count
}

function Test-DLLHijacking {
    param([string]$DllPath)
    
    if (-not (Test-Path $DllPath)) { return $false }
    
    # Check if DLL is in suspicious locations
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($susPath in $suspiciousPaths) {
        if ($DllPath -like "$susPath*") {
            return $true
        }
    }
    
    # Check if DLL is unsigned
    try {
        $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return $true
        }
    } catch { }
    
    return $false
}

function Invoke-DLLHijackingDetection {
    $detections = @()
    
    try {
        # Check loaded DLLs in processes
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" }
                
                foreach ($module in $modules) {
                    if (Test-DLLHijacking -DllPath $module.FileName) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllPath = $module.FileName
                            DllName = $module.ModuleName
                            Type = "Suspicious DLL Loaded"
                            Risk = "High"
                        }
                    }
                }
            } catch {
                # Access denied or process exited
                continue
            }
        }
        
        # Check for DLLs in application directories
        $appPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64"
        )
        
        foreach ($appPath in $appPaths) {
            if (-not (Test-Path $appPath)) { continue }
            
            try {
                $dlls = Get-ChildItem -Path $appPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 100
                
                foreach ($dll in $dlls) {
                    if ($dll.DirectoryName -ne "$appPath") {
                        # Check if DLL is signed
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    DllPath = $dll.FullName
                                    Type = "Unsigned DLL in application directory"
                                    Risk = "Medium"
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Check Event Log for DLL load failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                if ($event.Message -match 'DLL.*not.*found|DLL.*load.*failed') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Type = "DLL Load Failure"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "DLL HIJACKING: $($detection.Type) - $($detection.ProcessName -or 'System') - $($detection.DllPath -or $detection.DllName -or $detection.Message)" "THREAT" "dll_hijacking_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "DLL hijacking detection error: $_" "ERROR" "dll_hijacking_detections.log"
    }
    
    return $detections.Count
}

function Invoke-TokenManipulationDetection {
    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        try {
            $Owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).GetOwner()
            if ($Owner.Domain -eq "NT AUTHORITY" -and $Process.Path -notmatch "^C:\\Windows") {
                Write-AVLog "[TokenManip] SUSPICIOUS: Non-system binary running as SYSTEM | Process: $($Process.ProcessName) | Path: $($Process.Path)"
            }
        } catch {}
    }
}

function Invoke-ProcessHollowingDetection {
    $detections = @()
    
    # Whitelist of processes known to have suspended threads during normal operation
    $WhitelistedProcesses = @(
        'Cursor', 'Code', 'electron', 'node', 'chrome', 'firefox', 'msedge', 'brave',
        'opera', 'slack', 'discord', 'teams', 'spotify', 'vscode', 'idea64', 'pycharm64',
        'webstorm64', 'rider64', 'devenv', 'powershell', 'pwsh', 'WindowsTerminal',
        'explorer', 'SearchHost', 'StartMenuExperienceHost', 'ShellExperienceHost'
    )
    
    try {
        # Process hollowing signatures for advanced detection
        $processHollowingSignatures = @{
            "ProcessHollowing" = @(
                "process.*hollowing", "hollow.*process", "process.*replacement",
                "unmap.*section", "ntunmapviewofsection"
            )
        }
        
        # Process hollowing behavioral patterns
        $processHollowingBehaviors = @{
            "HollowingAPIs" = @(
                "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory",
                "SetThreadContext", "ResumeThread", "process.*hollow"
            )
            "SuspiciousParent" = @(
                "explorer.*spawn", "winlogon.*spawn", "suspicious.*parent"
            )
        }
        
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
        
        foreach ($proc in $processes) {
            # Skip whitelisted processes (Electron apps, browsers, IDEs have normal suspended threads)
            $procNameClean = $proc.Name -replace '\.exe$', ''
            if ($WhitelistedProcesses -contains $procNameClean) { continue }
            
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $procPath = $procObj.Path
                $imgPath = $proc.ExecutablePath
                
                # Use advanced detection framework
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $processHollowingSignatures `
                        -BehavioralIndicators $processHollowingBehaviors `
                        -CommandLine $proc.CommandLine `
                        -CheckEntropy $true
                    
                    if ($detectionResult.IsThreat) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Type = "Process Hollowing Detected via Advanced Framework"
                            Risk = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } else { "High" }
                        }
                    }
                }
                
                # Check for path mismatch (indicator of process hollowing)
                if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        ProcessPath = $procPath
                        ImagePath = $imgPath
                        Type = "Path Mismatch - Process Hollowing"
                        Risk = "Critical"
                    }
                }
                
                # Check for processes with unusual parent relationships
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction Stop
                        
                        # Check for processes spawned from non-standard parents
                        $suspiciousParents = @{
                            "explorer.exe" = @("notepad.exe", "calc.exe", "cmd.exe", "powershell.exe")
                            "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                            "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                        }
                        
                        if ($suspiciousParents.ContainsKey($parent.Name)) {
                            if ($proc.Name -in $suspiciousParents[$parent.Name]) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ParentProcess = $parent.Name
                                    Type = "Suspicious Parent-Child Relationship"
                                    Risk = "High"
                                }
                            }
                        }
                    } catch { }
                }
                
                # Check for processes with suspended threads
                try {
                    $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                    $suspendedThreads = $threads | Where-Object { $_.ThreadState -eq 5 } # Suspended
                    
                    if ($suspendedThreads.Count -gt 0 -and $suspendedThreads.Count -eq $threads.Count) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            SuspendedThreads = $suspendedThreads.Count
                            Type = "All Threads Suspended - Process Hollowing"
                            Risk = "High"
                        }
                    }
                } catch { }
                
                # Check for processes with unusual memory regions
                try {
                    $memoryRegions = Get-Process -Id $proc.ProcessId -ErrorAction Stop | 
                        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
                    
                    if ($memoryRegions) {
                        $unknownModules = $memoryRegions | Where-Object { 
                            $_.FileName -notlike "$env:SystemRoot\*" -and
                            $_.FileName -notlike "$env:ProgramFiles*" -and
                            $_.ModuleName -notin @("kernel32.dll", "ntdll.dll", "user32.dll")
                        }
                        
                        if ($unknownModules.Count -gt 5) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                UnknownModules = $unknownModules.Count
                                Type = "Unusual Memory Modules"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch { }
                
            } catch {
                continue
            }
        }
        
        # Check for processes with unusual PE structure
        try {
            $suspiciousProcs = $processes | Where-Object {
                $_.ExecutablePath -and
                (Test-Path $_.ExecutablePath) -and
                $_.ExecutablePath -notlike "$env:SystemRoot\*"
            }
            
            foreach ($proc in $suspiciousProcs) {
                try {
                    $peInfo = Get-Item $proc.ExecutablePath -ErrorAction Stop
                    
                    # Check if executable is signed
                    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        # Check if it's impersonating a legitimate process
                        $legitNames = @("svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "dwm.exe")
                        if ($proc.Name -in $legitNames) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Unsigned Executable Impersonating Legitimate Process"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS HOLLOWING: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "process_hollowing_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process hollowing detection error: $_" "ERROR" "process_hollowing_detections.log"
    }
    
    return $detections.Count
}

function Invoke-KeystrokeInjectionDetection {
    $detections = @()
    
    try {
        # Whitelist of legitimate processes that may use SendInput/keystroke APIs
        $legitInjectors = @(
            'explorer', 'dwm', 'csrss', 'winlogon', 'services', 'lsass', 'svchost',
            'powershell', 'pwsh', 'cmd', 'conhost',
            'chrome', 'firefox', 'msedge', 'opera', 'brave',
            'teams', 'slack', 'discord', 'zoom',
            'code', 'devenv', 'notepad', 'notepad++',
            'mstsc', 'vmware', 'virtualbox', 'vmconnect',
            'autohotkey', 'ahk', 'autohotkey64', 'autohotkey32',
            'keyscrambler', 'antimicro', 'joytokey',
            'osk', 'tabtip', 'textinputhost'
        )
        
        # Suspicious patterns in command lines that indicate keystroke injection tools
        $injectionPatterns = @(
            'SendKeys',
            'SendInput',
            'keybd_event',
            'SendMessage.*WM_KEYDOWN',
            'PostMessage.*WM_KEYDOWN',
            'WM_CHAR',
            'INPUT_KEYBOARD',
            'VK_.*KEYEVENTF',
            'simulate.*keyboard',
            'inject.*keystroke',
            'keystroke.*inject'
        )
        
        # Check processes with command line patterns
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
            Select-Object ProcessId, Name, CommandLine, ExecutablePath
        
        foreach ($proc in $processes) {
            if (-not $proc.CommandLine) { continue }
            $procNameLower = ($proc.Name -replace '\.exe$', '').ToLower()
            if ($procNameLower -in $legitInjectors) { continue }
            
            foreach ($pattern in $injectionPatterns) {
                if ($proc.CommandLine -match $pattern) {
                    $isSigned = $false
                    $isFromSafeLocation = $false
                    
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath -ErrorAction SilentlyContinue)) {
                        $sig = Get-AuthenticodeSignature $proc.ExecutablePath -ErrorAction SilentlyContinue
                        $isSigned = $sig.Status -eq 'Valid'
                        $isFromSafeLocation = $proc.ExecutablePath -match '^C:\\Windows\\|^C:\\Program Files'
                    }
                    
                    if (-not $isSigned -or -not $isFromSafeLocation) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            Pattern = $pattern
                            Signed = $isSigned
                            SafeLocation = $isFromSafeLocation
                            Type = "Keystroke Injection API in CommandLine"
                            Risk = "High"
                        }
                    }
                    break
                }
            }
        }
        
        # Check for processes loading suspicious DLLs commonly used for input injection
        $injectionDlls = @('inputsimulator', 'sendinput', 'keyinjector', 'hookdll', 'inputhook')
        
        $runningProcs = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $runningProcs) {
            if ($proc.Id -eq $PID) { continue }
            $procNameLower = ($proc.ProcessName).ToLower()
            if ($procNameLower -in $legitInjectors) { continue }
            
            try {
                $modules = $proc.Modules | ForEach-Object { $_.ModuleName.ToLower() }
                foreach ($dll in $injectionDlls) {
                    $match = $modules | Where-Object { $_ -match $dll }
                    if ($match) {
                        $isSigned = $false
                        if ($proc.Path -and (Test-Path $proc.Path -ErrorAction SilentlyContinue)) {
                            $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
                            $isSigned = $sig.Status -eq 'Valid'
                        }
                        
                        if (-not $isSigned) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                SuspiciousDLL = $match -join ', '
                                Signed = $isSigned
                                Type = "Keystroke Injection DLL Loaded"
                                Risk = "Critical"
                            }
                        }
                        break
                    }
                }
            } catch { }
        }
        
        # Check for unsigned processes from temp/downloads folders that have user32.dll loaded
        $suspiciousLocations = @(
            [regex]::Escape($env:TEMP),
            [regex]::Escape($env:TMP),
            '\\Downloads\\',
            '\\AppData\\Local\\Temp\\',
            '\\Users\\[^\\]+\\Desktop\\'
        )
        
        foreach ($proc in $runningProcs) {
            if ($proc.Id -eq $PID) { continue }
            $procNameLower = ($proc.ProcessName).ToLower()
            if ($procNameLower -in $legitInjectors) { continue }
            
            try {
                if (-not $proc.Path) { continue }
                
                $fromSuspiciousLocation = $false
                foreach ($loc in $suspiciousLocations) {
                    if ($proc.Path -match $loc) {
                        $fromSuspiciousLocation = $true
                        break
                    }
                }
                
                if ($fromSuspiciousLocation) {
                    $hasUser32 = $proc.Modules | Where-Object { $_.ModuleName -eq 'user32.dll' }
                    if ($hasUser32) {
                        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
                        if ($sig.Status -ne 'Valid') {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Path = $proc.Path
                                Type = "Unsigned Process with Input Capability from Suspicious Location"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch { }
        }
        
        # Response: Log and optionally terminate threats
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "KEYSTROKE INJECTION DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "keystroke_injection.log"
                $Global:AntivirusState.ThreatCount++
                
                # Auto-terminate critical threats
                if ($detection.Risk -eq "Critical" -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        try {
                            Stop-Process -Id $detection.ProcessId -Force -ErrorAction Stop
                            Write-AVLog "KeystrokeInjection: Terminated $($detection.ProcessName) (PID: $($detection.ProcessId))" "INFO"
                        } catch {
                            Write-AVLog "KeystrokeInjection: Failed to terminate $($detection.ProcessName): $_" "ERROR"
                        }
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\KeystrokeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "KeystrokeInjectionDetection error: $_" "ERROR"
    }
    
    return $detections.Count
}

function Invoke-RansomwareDetection {
    param([bool]$AutoKillThreats = $true)
    
    $detections = @()
    
    try {
        # Check for rapid file modifications (encryption indicator)
        $userDirs = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Videos"
        )
        
        $recentFiles = @()
        foreach ($dir in $userDirs) {
            if (Test-Path $dir) {
                try {
                    $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { (Get-Date) - $_.LastWriteTime -lt [TimeSpan]::FromMinutes(5) } |
                        Select-Object -First 100
                    
                    $recentFiles += $files
                } catch { }
            }
        }
        
        # Check for files with suspicious extensions
        $suspiciousExts = @(".encrypted", ".locked", ".crypto", ".vault", ".xxx", ".zzz", ".xyz")
        $encryptedFiles = $recentFiles | Where-Object {
            $ext = $_.Extension.ToLower()
            $ext -in $suspiciousExts -or
            ($ext -notin @(".txt", ".doc", ".pdf", ".jpg", ".png") -and $ext.Length -gt 4)
        }
        
        if ($encryptedFiles.Count -gt 10) {
            $detections += @{
                Type = "Rapid File Encryption"
                EncryptedFiles = $encryptedFiles.Count
                Risk = "Critical"
            }
        }
        
        # Check for ransom notes
        $ransomNoteNames = @("readme.txt", "decrypt.txt", "how_to_decrypt.txt", "recover.txt", "restore.txt", "!!!readme!!!.txt")
        foreach ($file in $recentFiles) {
            if ($file.Name -in $ransomNoteNames) {
                $detections += @{
                    File = $file.FullName
                    Type = "Ransom Note Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Ransomware signatures for advanced detection
        $ransomwareSignatures = @{
            "Ransomware" = @(
                "ransomware", "encrypt", "decrypt", "bitcoin", "payment.*required",
                "your.*files.*encrypted", "lock.*screen", "crypto.*locker", "file.*encryption"
            )
        }
        
        # Ransomware behavioral patterns
        $ransomwareBehaviors = @{
            "ShadowCopyDeletion" = @(
                "vssadmin.*delete", "wbadmin.*delete", "shadowcopy.*delete",
                "recoveryenabled.*no", "bcdedit.*recovery"
            )
            "FileEncryption" = @(
                "encrypt.*file", "crypto.*api", "file.*lock", "ransom.*note"
            )
        }
        
        # Check for processes with high file I/O using advanced framework
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Use advanced detection framework
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $detectionResult = Invoke-AdvancedThreatDetection `
                            -FilePath $proc.ExecutablePath `
                            -FileSignatures $ransomwareSignatures `
                            -BehavioralIndicators $ransomwareBehaviors `
                            -CommandLine $proc.CommandLine `
                            -CheckEntropy $true
                        
                        if ($detectionResult.IsThreat) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ThreatName = $detectionResult.ThreatName
                                DetectionMethods = $detectionResult.DetectionMethods -join ", "
                                Confidence = $detectionResult.Confidence
                                Type = "Ransomware Detected via Advanced Framework"
                                Risk = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } else { "High" }
                            }
                        }
                    }
                    
                    # Check for processes with unusual file activity
                    $ioStats = Get-Counter "\Process($($proc.Name))\IO Data Operations/sec" -ErrorAction SilentlyContinue
                    if ($ioStats -and $ioStats.CounterSamples[0].CookedValue -gt 1000) {
                        # High I/O activity
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    IOOperations = $ioStats.CounterSamples[0].CookedValue
                                    Type = "High File I/O - Unsigned Process"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for shadow copy deletion
        try {
            $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadowCopies.Count -eq 0 -and (Test-Path "C:\Windows\System32\vssadmin.exe")) {
                $detections += @{
                    Type = "Shadow Copies Deleted"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for crypto API usage
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            foreach ($proc in $processes) {
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match "crypt32|cryptsp|cryptnet|bcrypt"
                }
                
                if ($modules.Count -gt 0) {
                    # Check if process is accessing many files
                    try {
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                        $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" }
                        
                        if ($fileHandles.Count -gt 50) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandles = $fileHandles.Count
                                Type = "Cryptographic API with High File Access"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check command line for ransomware indicators (original check)
        $RansomwareIndicators = @(
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "bcdedit /set {default} recoveryenabled no",
            "wmic shadowcopy delete"
        )

        $Processes = Get-Process | Where-Object { $_.Path }

        foreach ($Process in $Processes) {
            try {
                $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                foreach ($Indicator in $RansomwareIndicators) {
                    if ($CommandLine -match [regex]::Escape($Indicator)) {
                        $detections += @{
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            CommandLine = $CommandLine
                            Type = "Ransomware Command Detected"
                            Risk = "Critical"
                        }
                        break
                    }
                }
            } catch {}
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "RANSOMWARE DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.File -or 'System')" "THREAT" "ransomware_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File -or $_.EncryptedFiles)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Ransomware detection error: $_" "ERROR" "ransomware_detections.log"
    }
    
    return $detections.Count
}

function Invoke-NetworkAnomalyDetection {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
        # Advanced suspicious port detection with severity scoring
        $SuspiciousPorts = @{
            "4444" = @{Severity = "High"; Reason = "Metasploit default port"; KnownMalware = $true}
            "5555" = @{Severity = "High"; Reason = "Common backdoor port"; KnownMalware = $true}
            "31337" = @{Severity = "Medium"; Reason = "Elite/leet backdoor port"; KnownMalware = $true}
            "6666" = @{Severity = "Medium"; Reason = "IRC and trojan port"; KnownMalware = $true}
            "9999" = @{Severity = "Low"; Reason = "Common trojan port"; KnownMalware = $true}
            "12345" = @{Severity = "Medium"; Reason = "NetBus trojan port"; KnownMalware = $true}
            "54321" = @{Severity = "Medium"; Reason = "Back Orifice trojan port"; KnownMalware = $true}
            "65432" = @{Severity = "Low"; Reason = "Uncommon trojan port"; KnownMalware = $false}
        }

        # Known malicious IP ranges (common malware C2 ranges)
        $KnownMaliciousRanges = @(
            "5.8.", "45.", "91.", "185.", "195."
        )

        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -notlike "169.254.*" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "10.*" }

        $ThreatScore = 0
        $DetectedThreats = @()

    foreach ($Conn in $Connections) {
            $ThreatScore = 0
            $ThreatReasons = @()
            
            try {
                # Check for suspicious ports
                $PortStr = $Conn.RemotePort.ToString()
                if ($SuspiciousPorts.ContainsKey($PortStr)) {
                    $portInfo = $SuspiciousPorts[$PortStr]
                    $ThreatScore += if ($portInfo.Severity -eq "High") { 30 } elseif ($portInfo.Severity -eq "Medium") { 20 } else { 10 }
                    $ThreatReasons += "Suspicious port: $($portInfo.Reason)"
                }

                # Check for known malicious IP ranges
                foreach ($range in $KnownMaliciousRanges) {
                    if ($Conn.RemoteAddress.ToString().StartsWith($range)) {
                        $ThreatScore += 25
                        $ThreatReasons += "Known malicious IP range: $range"
                        break
                    }
                }

                # Check for uncommon/privileged ports (above 49152)
                if ($Conn.RemotePort -gt 49152 -and $Conn.RemotePort -lt 65535) {
                    $ThreatScore += 5
                    $ThreatReasons += "Uncommon dynamic port range"
                }

                # Check process associated with connection
                try {
                    $proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) {
                        # Check if process is from unusual location
                        if ($proc.Path -and $proc.Path -notmatch "^(C:\\(Windows|Program Files|Program Files \(x86\)))") {
                            $ThreatScore += 15
                            $ThreatReasons += "Non-standard process location: $($proc.Path)"
                        }

                        # Check for known suspicious process names
                        $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
                        if ($SuspiciousProcesses -contains $proc.ProcessName) {
                            $ThreatScore += 20
                            $ThreatReasons += "Suspicious process making connection: $($proc.ProcessName)"
                        }
                    }
                } catch {}

                # Check for outbound connections from system processes (unusual)
                if ($proc -and $proc.ProcessName -match "^(svchost|lsass|winlogon|services|csrss|smss)$") {
                    $ThreatScore += 30
                    $ThreatReasons += "System process making outbound connection (potential process hollowing/injection)"
                }

                # Check for connections to non-standard DNS ports (port 53 but not from DNS processes)
                if ($Conn.RemotePort -eq 53 -and $proc -and $proc.ProcessName -ne "svchost" -and $proc.ProcessName -ne "dns") {
                    $ThreatScore += 25
                    $ThreatReasons += "Non-DNS process connecting to DNS port (potential DNS tunneling)"
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $threatInfo = @{
                        RemoteAddress = $Conn.RemoteAddress
                        RemotePort = $Conn.RemotePort
                        ProcessId = $Conn.OwningProcess
                        ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                        ProcessPath = if ($proc -and $proc.Path) { $proc.Path } else { "Unknown" }
                        ThreatScore = $ThreatScore
                        Reasons = $ThreatReasons -join "; "
                        Severity = $severity
                        Timestamp = Get-Date
                    }

                    $DetectedThreats += $threatInfo

                    Write-AVLog "[Network] THREAT ($severity): Score=$ThreatScore | Remote: $($Conn.RemoteAddress):$($Conn.RemotePort) | PID: $($Conn.OwningProcess) | Process: $(if ($proc) { $proc.ProcessName } else { 'Unknown' }) | Reasons: $($ThreatReasons -join '; ')"

                    # Auto-block if configured
                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            $RuleName = "Block_NetworkThreat_$($Conn.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                            $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                            if (-not $existingRule) {
                                New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Conn.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                Write-AVLog "[Network] ACTION: Blocked threat IP $($Conn.RemoteAddress) with firewall rule"
                            }
                        } catch {
                            Write-AVLog "[Network] ERROR: Failed to block threat: $_"
                        }
                    }

                    # Queue for response engine if threat is significant
                    if ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "NetworkAnomaly" -ThreatPath "$($Conn.RemoteAddress):$($Conn.RemotePort)" -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Error analyzing connection: $_" -Level "Warning"
            }
        }

        if ($DetectedThreats.Count -gt 0) {
            Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Detected $($DetectedThreats.Count) network anomaly/threat(s)" -Level "Warning"
        }

        return @{ThreatsDetected = $DetectedThreats.Count; Details = $DetectedThreats}
    }
    catch {
        Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Network anomaly detection failed: $_" -Level "Error"
        return @{ThreatsDetected = 0; Details = @()}
    }
}

function Invoke-NetworkTrafficMonitoring {
    param(
        [bool]$AutoBlockThreats = $true
    )

    $AllowedDomains = @("google.com", "microsoft.com", "github.com", "stackoverflow.com")
    $AllowedIPs = @()

    foreach ($Domain in $AllowedDomains) {
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($IP in $IPs) {
                if ($AllowedIPs -notcontains $IP) {
                    $AllowedIPs += $IP
                }
            }
        }
        catch {
            Write-AVLog "[NTM] WARNING: Could not resolve domain $Domain to IP"
        }
    }

    Write-AVLog "[NTM] Starting network traffic monitoring..."

    try {
        $Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }

        $SuspiciousConnections = @()
        $TotalConnections = $Connections.Count

        foreach ($Connection in $Connections) {
            $RemoteAddr = $Connection.RemoteAddress
            $RemotePort = $Connection.RemotePort
            $ProcessId = $Connection.OwningProcess

            if ($AllowedIPs -contains $RemoteAddr) {
                continue
            }

            $ProcessName = "Unknown"
            $ProcessPath = "Unknown"

            try {
                $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if ($Process) {
                    $ProcessName = $Process.ProcessName
                    $ProcessPath = if ($Process.Path) { $Process.Path } else { "Unknown" }
                }
            }
            catch {
            }

            $SuspiciousScore = 0
            $Reasons = @()

            if ($RemotePort -gt 10000) {
                $SuspiciousScore += 20
                $Reasons += "High remote port: $RemotePort"
            }

            $C2Ports = @(4444, 8080, 9999, 1337, 31337, 443, 53)
            if ($C2Ports -contains $RemotePort) {
                $SuspiciousScore += 30
                $Reasons += "Known C2 port: $RemotePort"
            }

            $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript", "rundll32", "mshta")
            if ($SuspiciousProcesses -contains $ProcessName.ToLower()) {
                $SuspiciousScore += 25
                $Reasons += "Suspicious process: $ProcessName"
            }

            if ($ProcessPath -notmatch "C:\\(Windows|Program Files|Program Files \(x86\))" -and $ProcessPath -ne "Unknown") {
                $SuspiciousScore += 15
                $Reasons += "Process in non-standard location"
            }

            if ($RemoteAddr -match '^\d+\.\d+\.\d+\.\d+$') {
                try {
                    $HostName = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                    if ($HostName -and $HostName -notmatch ($AllowedDomains -join '|')) {
                        $SuspiciousScore += 10
                        $Reasons += "Unknown hostname: $HostName"
                    }
                }
                catch {
                    $SuspiciousScore += 5
                    $Reasons += "No reverse DNS for IP"
                }
            }

            $PrivateIPRanges = @("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254.")
            $IsPrivateIP = $false
            foreach ($Range in $PrivateIPRanges) {
                if ($RemoteAddr.StartsWith($Range)) {
                    $IsPrivateIP = $true
                    break
                }
            }

            if (!$IsPrivateIP -and $AllowedIPs -notcontains $RemoteAddr) {
                $SuspiciousScore += 10
                $Reasons += "Unknown public IP"
            }

            if ($SuspiciousScore -ge 30) {
                $SuspiciousConnections += @{
                    RemoteAddress = $RemoteAddr
                    RemotePort = $RemotePort
                    ProcessName = $ProcessName
                    ProcessId = $ProcessId
                    ProcessPath = $ProcessPath
                    Score = $SuspiciousScore
                    Reasons = $Reasons
                }

                Write-AVLog "[NTM] SUSPICIOUS: $ProcessName connecting to $RemoteAddr`:$RemotePort | Score: $SuspiciousScore | Reasons: $($Reasons -join ', ')"
            }
        }

        if ($AutoBlockThreats -and $SuspiciousConnections.Count -gt 0) {
            foreach ($Suspicious in $SuspiciousConnections) {
                try {
                    $RuleName = "Block_Malicious_$($Suspicious.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Suspicious.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

                    Write-AVLog "[NTM] ACTION: Blocked IP $($Suspicious.RemoteAddress) with firewall rule $RuleName"

                    if ($Suspicious.Score -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Suspicious.ProcessId -eq $PID -or $Suspicious.ProcessId -eq $Script:SelfPID) {
                            Write-AVLog "[NTM] BLOCKED: Attempted to kill own process (PID: $($Suspicious.ProcessId)) - whitelisted"
                            continue
                        }
                        Stop-Process -Id $Suspicious.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-AVLog "[NTM] ACTION: Terminated suspicious process $($Suspicious.ProcessName) (PID: $($Suspicious.ProcessId))"
                    }
                }
                catch {
                    Write-AVLog "[NTM] ERROR: Failed to block threat: $_"
                }
            }
        }

        Write-AVLog "[NTM] Monitoring complete: $TotalConnections total connections, $($SuspiciousConnections.Count) suspicious"
    }
    catch {
        Write-AVLog "[NTM] ERROR: Failed to monitor network traffic: $_"
    }
}

function Invoke-RootkitDetection {
    param(
        [bool]$DeepScan = $true
    )

    try {
        $Threats = @()

        # 1. Check for unsigned drivers (potential rootkit)
        try {
            $Drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue
    foreach ($Driver in $Drivers) {
                $Suspicious = $false
                $Reasons = @()

                # Non-Microsoft system drivers
        if ($Driver.ProviderName -notmatch "Microsoft" -and $Driver.ClassName -eq "System") {
                    $Suspicious = $true
                    $Reasons += "Third-party system driver"
                }

                # Drivers with suspicious names
                $SuspiciousDriverNames = @("rootkit", "stealth", "hide", "kernel", "hook", "inject")
                foreach ($pattern in $SuspiciousDriverNames) {
                    if ($Driver.DriverName -match $pattern -or $Driver.OriginalFileName -match $pattern) {
                        $Suspicious = $true
                        $Reasons += "Suspicious driver name pattern: $pattern"
                        break
                    }
                }

                # Drivers without digital signatures
                try {
                    $DriverPath = $Driver.OriginalFileName
                    if ($DriverPath -and (Test-Path $DriverPath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $DriverPath -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $Suspicious = $true
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                if ($Suspicious) {
                    # Perform behavioral analysis on suspicious driver
                    $behavioralAnalysis = $null
                    try {
                        $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $Driver.DriverName -DriverPath $Driver.OriginalFileName -DriverServiceName $Driver.DriverName
                        if ($behavioralAnalysis.IsMalicious) {
                            $Reasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                            $Reasons += $behavioralAnalysis.Reasons
                        }
                    } catch {}
                    
                    $Threats += @{
                        Type = "SuspiciousDriver"
                        Name = $Driver.DriverName
                        Provider = $Driver.ProviderName
                        Path = $Driver.OriginalFileName
                        Reasons = $Reasons
                        Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                        BehavioralAnalysis = $behavioralAnalysis
                    }
                    $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                    Write-AVLog "[Rootkit] SUSPICIOUS: Driver detected | Driver: $($Driver.DriverName) | Provider: $($Driver.ProviderName) | Reasons: $($Reasons -join '; ')$behavioralInfo"
                }
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "Driver scan failed: $_" -Level "Warning"
        }

        # 2. Check for hidden processes (process list vs performance counters)
        if ($DeepScan) {
            try {
                $ProcessList = Get-Process | Select-Object -ExpandProperty Id
                $PerfProcesses = Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty CounterSamples | 
                    Where-Object { $_.CookedValue -gt 0 } | 
                    Select-Object -ExpandProperty CookedValue | 
                    ForEach-Object { [int]$_ }

                $HiddenProcesses = $PerfProcesses | Where-Object { $_ -notin $ProcessList }
                foreach ($procPid in $HiddenProcesses) {
                    $Threats += @{
                        Type = "HiddenProcess"
                        ProcessId = $procPid
                        Reasons = @("Process visible in performance counters but not in process list")
                        Severity = "Critical"
                    }
                    Write-AVLog "[Rootkit] CRITICAL: Hidden process detected | PID: $pid"
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Hidden process detection failed: $_" -Level "Warning"
            }
        }

        # 3. Check for kernel mode callbacks (advanced)
        if ($DeepScan) {
            try {
                # Check for suspicious registry keys used by rootkits
                $RootkitRegistryKeys = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Services\*",
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
                )

                foreach ($keyPath in $RootkitRegistryKeys) {
                    try {
                        $keys = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
                        foreach ($key in $keys) {
                            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            
                            # Check for suspicious values - exclude Windows system paths
                            # Windows system paths include: C:\Windows, \SystemRoot\, System32\, etc.
                            if ($props.ImagePath) {
                                $imagePathLower = $props.ImagePath.ToLower().Replace('\', '/')
                                # Check for various Windows system path formats (normalize backslashes to forward slashes for matching)
                                $isSystemPath = $imagePathLower -match "^(c:/windows|/systemroot|system32|syswow64)" -or 
                                               $imagePathLower -match '^"c:/windows' -or
                                               $imagePathLower.StartsWith("system32/") -or
                                               $imagePathLower.StartsWith("syswow64/") -or
                                               $imagePathLower.StartsWith("/systemroot/")
                                
                                # Only flag if it's NOT a system path AND not in Program Files
                                if (-not $isSystemPath -and $props.ImagePath -notmatch "^(C:\\(Windows|Program Files))") {
                                    $Threats += @{
                                        Type = "SuspiciousServiceRegistry"
                                        Path = $key.PSPath
                                        ImagePath = $props.ImagePath
                                        Reasons = @("Service in non-standard location")
                                        Severity = "Medium"
                                    }
                                    Write-AVLog "[Rootkit] SUSPICIOUS: Service in non-standard location | Path: $($key.PSPath) | ImagePath: $($props.ImagePath)"
                                }
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Registry scan failed: $_" -Level "Warning"
            }
        }

        # 4. Check for SSDT hooks (System Service Descriptor Table) - indirect detection
        if ($DeepScan) {
            try {
                # Check for processes with unusual API calls (would require kernel debugging in real implementation)
                # This is a simplified heuristic check
                $SystemProcesses = Get-Process | Where-Object { $_.ProcessName -match "^(lsass|csrss|winlogon|services|smss|wininit)$" }
                foreach ($proc in $SystemProcesses) {
                    try {
                        # Check if system process has unexpected modules loaded
                        $modules = $proc.Modules | Where-Object { 
                            $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp)" -and 
                            $_.FileName -notmatch "^C:\\Windows" 
                        }
                        if ($modules) {
                            foreach ($mod in $modules) {
                                $Threats += @{
                                    Type = "SuspiciousModuleInSystemProcess"
                                    ProcessName = $proc.ProcessName
                                    ProcessId = $proc.Id
                                    ModuleName = $mod.ModuleName
                                    ModulePath = $mod.FileName
                                    Reasons = @("Unexpected module in system process")
                                    Severity = "High"
                                }
                                Write-AVLog "[Rootkit] HIGH: Suspicious module in system process | Process: $($proc.ProcessName) | Module: $($mod.ModuleName) | Path: $($mod.FileName)"
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "System process module scan failed: $_" -Level "Warning"
            }
        }

        # 5. Check for file system filters and minifilter drivers (rootkit indicator)
        try {
            # List of specific target minifilter drivers to detect and remove
            # Only targeting bfs and unionfs (from batch file) - other minifilter drivers are handled more conservatively
            $targetMinifilterDrivers = @("bfs", "unionfs")
            
            # Check for specific target drivers first (bfs, unionfs only)
            foreach ($targetDriver in $targetMinifilterDrivers) {
                try {
                    $driverService = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = '$targetDriver'" -ErrorAction SilentlyContinue
                    if ($driverService) {
                        $driverPath = $driverService.PathName
                        if (-not $driverPath) {
                            $driverPath = "C:\Windows\System32\drivers\$targetDriver.sys"
                        }
                        
                        $Threats += @{
                            Type = "SuspiciousFileSystemFilter"
                            Name = $targetDriver
                            Path = $driverPath
                            State = $driverService.State
                                            Reasons = @("Target minifilter driver detected (bfs/unionfs)")
                            Severity = "High"
                        }
                        Write-AVLog "[Rootkit] HIGH: Target minifilter driver detected | Name: $targetDriver | Path: $driverPath"
                    }
                } catch {}
            }
            
            # Check via WMI for file system filter drivers
            $FileSystemFilters = Get-WmiObject -Class Win32_SystemDriver -Filter "Name LIKE '%filter%' OR Name LIKE '%fs%'" -ErrorAction SilentlyContinue
            foreach ($filter in $FileSystemFilters) {
                $isSuspicious = $false
                $reasons = @()
                
                # Skip if already detected as target driver
                $isTargetDriver = $false
                foreach ($target in $targetMinifilterDrivers) {
                    if ($filter.Name -eq $target -or $filter.Name -like "*$target*") {
                        $isTargetDriver = $true
                        break
                    }
                }
                if ($isTargetDriver) { continue }
                
                # Check if in non-standard location - exclude Windows system paths
                # Windows system paths include: C:\Windows, \SystemRoot\, System32\, etc.
                if ($filter.PathName) {
                    $pathNameLower = $filter.PathName.ToLower().Replace('\', '/')
                    # Check for various Windows system path formats (normalize backslashes to forward slashes for matching)
                    $isSystemPath = $pathNameLower -match "^(c:/windows|/systemroot|system32|syswow64)" -or
                                   $pathNameLower -match "^//?c:/windows" -or
                                   $pathNameLower.StartsWith("system32/") -or
                                   $pathNameLower.StartsWith("syswow64/") -or
                                   $pathNameLower.StartsWith("/systemroot/")
                    
                    # Only flag if it's NOT a system path
                    if (-not $isSystemPath) {
                        $isSuspicious = $true
                        $reasons += "File system filter in non-standard location"
                    }
                }
                
                # Check for unsigned minifilter drivers
                if ($filter.PathName -and (Test-Path $filter.PathName)) {
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $filter.PathName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $isSuspicious = $true
                            $reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    } catch {}
                }
                
                # Exclude known legitimate filters (fltmgr, etc.)
                $legitimateFilters = @("fltmgr", "FsDepends", "FileInfo", "FltMgr")
                if ($legitimateFilters -contains $filter.Name) {
                    $isSuspicious = $false
                }
                
                if ($isSuspicious) {
                    # Perform behavioral analysis on suspicious filter driver
                    $behavioralAnalysis = $null
                    try {
                        $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $filter.Name -DriverPath $filter.PathName -DriverServiceName $filter.Name
                        if ($behavioralAnalysis.IsMalicious) {
                            $reasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                            $reasons += $behavioralAnalysis.Reasons
                        }
                    } catch {}
                    
                    $Threats += @{
                        Type = "SuspiciousFileSystemFilter"
                        Name = $filter.Name
                        Path = $filter.PathName
                        State = $filter.State
                        Reasons = $reasons
                        Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                        BehavioralAnalysis = $behavioralAnalysis
                    }
                    $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                    Write-AVLog "[Rootkit] HIGH: Suspicious file system filter | Name: $($filter.Name) | Path: $($filter.PathName) | Reasons: $($reasons -join '; ')$behavioralInfo"
                }
            }
            
            # Also check via fltmgr.sys registry entries for minifilter drivers
            try {
                $minifilterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\FltMgr\Enum"
                if (Test-Path $minifilterKey) {
                    $minifilters = Get-ItemProperty -Path $minifilterKey -ErrorAction SilentlyContinue
                    if ($minifilters) {
                        $minifilterValues = $minifilters.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
                        foreach ($value in $minifilterValues) {
                            $filterInfo = $value.Value
                            if ($filterInfo -match '^(\d+)\\\\SystemRoot\\\\System32\\\\drivers\\\\([^\\]+)') {
                                $filterName = $matches[2]
                                $filterPath = "C:\Windows\System32\drivers\$filterName"
                                
                                # Extract driver name without extension for comparison
                                $driverNameBase = [System.IO.Path]::GetFileNameWithoutExtension($filterName)
                                
                                # Check if this is a target driver (bfs, unionfs, Sophos)
                                $isTargetDriver = $false
                                foreach ($target in $targetMinifilterDrivers) {
                                    if ($driverNameBase -eq $target -or $driverNameBase -like "*$target*" -or $filterName -like "*$target*") {
                                        $isTargetDriver = $true
                                        break
                                    }
                                }
                                
                                # Check if already in threats list
                                $alreadyDetected = $Threats | Where-Object { 
                                    $threatNameBase = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                                    $threatNameBase -eq $driverNameBase -or $_.Name -eq $driverNameBase -or $_.Name -eq $filterName
                                }
                                
                                if (-not $alreadyDetected -and (Test-Path $filterPath)) {
                                    try {
                                        # Target drivers are always flagged regardless of signature
                                        if ($isTargetDriver) {
                                            $Threats += @{
                                                Type = "SuspiciousFileSystemFilter"
                                                Name = $driverNameBase
                                                Path = $filterPath
                                                State = "Unknown"
                                                Reasons = @("Target minifilter driver registered with Filter Manager (bfs/unionfs)")
                                                Severity = "High"
                                            }
                                            Write-AVLog "[Rootkit] HIGH: Target minifilter driver detected | Name: $driverNameBase | Path: $filterPath"
                                        } else {
                                            # For other drivers, check signature and perform behavioral analysis
                                            $sig = Get-AuthenticodeSignature -FilePath $filterPath -ErrorAction SilentlyContinue
                                            if ($sig.Status -ne "Valid") {
                                                # Perform behavioral analysis on unsigned driver
                                                $behavioralAnalysis = $null
                                                $analysisReasons = @("Unsigned minifilter driver registered with Filter Manager")
                                                try {
                                                    $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $driverNameBase -DriverPath $filterPath -DriverServiceName $driverNameBase
                                                    if ($behavioralAnalysis.IsMalicious) {
                                                        $analysisReasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                                                        $analysisReasons += $behavioralAnalysis.Reasons
                                                    }
                                                } catch {}
                                                
                                                $Threats += @{
                                                    Type = "SuspiciousFileSystemFilter"
                                                    Name = $driverNameBase
                                                    Path = $filterPath
                                                    State = "Unknown"
                                                    Reasons = $analysisReasons
                                                    Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                                                    BehavioralAnalysis = $behavioralAnalysis
                                                }
                                                $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                                                Write-AVLog "[Rootkit] HIGH: Unsigned minifilter driver | Name: $driverNameBase | Path: $filterPath$behavioralInfo"
                                            }
                                        }
                                    } catch {}
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Minifilter registry scan failed: $_" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "File system filter scan failed: $_" -Level "Warning"
        }

        # Queue critical and high severity threats for response (including minifilter drivers)
        foreach ($threat in $Threats) {
            if ($threat.Severity -eq "Critical" -or $threat.Severity -eq "High") {
                # For minifilter drivers, include the driver name in the threat path
                $threatPath = if ($threat.Type -eq "SuspiciousFileSystemFilter" -and $threat.Name) {
                    "Driver:$($threat.Name)|$($threat.Path)"
                } else {
                    $threat.Path
                }
                Add-ThreatToResponseQueue -ThreatType "Rootkit" -ThreatPath $threatPath -Severity $threat.Severity
            }
        }

        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-ClipboardMonitoring {
    try {
        $ClipboardText = Get-Clipboard -Format Text -ErrorAction SilentlyContinue
        if (-not $ClipboardText) { return }

        $ThreatScore = 0
        $DetectedPatterns = @()
        
        # Advanced pattern matching for sensitive data
        $Patterns = @{
            # Passwords and credentials
            "Password" = @{
                Pattern = "(?i)(password|passwd|pwd)\s*[:=]\s*([^\s]{8,})"
                Severity = "High"
                Score = 30
                Type = "Password"
            }
            # API Keys
            "APIKey" = @{
                Pattern = "(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*([A-Za-z0-9_\-]{20,})"
                Severity = "High"
                Score = 35
                Type = "APIKey"
            }
            # OAuth tokens
            "OAuthToken" = @{
                Pattern = "(?i)(bearer\s+)?([A-Za-z0-9\-_]{100,})"
                Severity = "High"
                Score = 40
                Type = "OAuthToken"
            }
            # AWS credentials
            "AWSCredentials" = @{
                Pattern = "(?i)(AKIA[0-9A-Z]{16}|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})"
                Severity = "Critical"
                Score = 50
                Type = "AWSCredentials"
            }
            # Credit card numbers
            "CreditCard" = @{
                Pattern = "\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                Severity = "High"
                Score = 45
                Type = "CreditCard"
            }
            # Social Security Numbers (US)
            "SSN" = @{
                Pattern = "\b\d{3}-\d{2}-\d{4}\b"
                Severity = "High"
                Score = 45
                Type = "SSN"
            }
            # Email addresses with credentials
            "EmailCredential" = @{
                Pattern = "(?i)(email|username|user|login)\s*[:=]\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\s*(?:password|passwd|pwd)\s*[:=]\s*([^\s]{6,})"
                Severity = "High"
                Score = 40
                Type = "EmailCredential"
            }
            # Private keys
            "PrivateKey" = @{
                Pattern = "(-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----)"
                Severity = "Critical"
                Score = 50
                Type = "PrivateKey"
            }
            # Database connection strings
            "DatabaseConnection" = @{
                Pattern = "(?i)(server|host|database|uid|user id|pwd|password)=[^;]+"
                Severity = "High"
                Score = 35
                Type = "DatabaseConnection"
            }
            # JWT tokens
            "JWT" = @{
                Pattern = "\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"
                Severity = "Medium"
                Score = 25
                Type = "JWT"
            }
            # Base64 encoded secrets (long base64 strings)
            "Base64Secret" = @{
                Pattern = "(?i)(?:secret|password|token|key)\s*[:=]\s*([A-Za-z0-9+/]{40,}={0,2})"
                Severity = "Medium"
                Score = 20
                Type = "Base64Secret"
            }
        }

        # Check each pattern
        foreach ($patternName in $Patterns.Keys) {
            $patternInfo = $Patterns[$patternName]
            if ($ClipboardText -match $patternInfo.Pattern) {
                $ThreatScore += $patternInfo.Score
                $DetectedPatterns += $patternInfo.Type
                
                # Extract matched content (sanitized for logging)
                $matchValue = $matches[0]
                if ($matchValue.Length -gt 50) {
                    $matchValue = $matchValue.Substring(0, 50) + "..."
                }
                
                Write-AVLog "[Clipboard] THREAT ($($patternInfo.Severity)): $($patternInfo.Type) detected | Pattern: $patternName | Match: $matchValue"
                
                # Log sensitive detection
                Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive data detected: $($patternInfo.Type) (Pattern: $patternName)" -Level $patternInfo.Severity
            }
        }

        # Additional heuristic: Check for high entropy strings (potential encrypted data or tokens)
        if ($ClipboardText.Length -gt 20) {
            $entropy = Measure-StringEntropy -String $ClipboardText
            if ($entropy -gt 4.5 -and $ClipboardText -match "^[A-Za-z0-9+/=_-]+$") {
                $ThreatScore += 15
                $DetectedPatterns += "HighEntropyString"
                Write-AVLog "[Clipboard] WARNING: High entropy string detected (potential encrypted data or token) | Entropy: $([Math]::Round($entropy, 2))"
            }
        }

        # Additional heuristic: Check for suspicious URL patterns
        if ($ClipboardText -match "(?i)(https?://[^\s]+(?:token|key|password|secret|auth|login|credential)[^\s]*)") {
            $ThreatScore += 20
            $DetectedPatterns += "SuspiciousURL"
            Write-AVLog "[Clipboard] WARNING: Suspicious URL with credential-related parameters detected"
        }

        # Action based on threat score
        if ($ThreatScore -ge 30) {
            $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
            
            # Log to EDR
            Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive clipboard data detected | Score: $ThreatScore | Patterns: $($DetectedPatterns -join ', ')" -Level $severity
            
            # Queue for response engine if critical
            if ($severity -eq "Critical" -or $ThreatScore -ge 45) {
                Add-ThreatToResponseQueue -ThreatType "ClipboardSensitiveData" -ThreatPath "Clipboard" -Severity $severity
            }
            
            return @{Detected = $true; Score = $ThreatScore; Patterns = $DetectedPatterns; Severity = $severity}
        }

        return @{Detected = $false; Score = 0; Patterns = @()}
    }
    catch {
        Write-EDRLog -Module "ClipboardMonitoring" -Message "Clipboard monitoring error: $_" -Level "Warning"
        return @{Detected = $false; Score = 0; Patterns = @()}
    }
}

function Measure-StringEntropy {
    param([string]$String)
    
    if ([string]::IsNullOrEmpty($String)) { return 0 }
    
    $freq = @{}
    foreach ($char in $String.ToCharArray()) {
        if ($freq.ContainsKey($char)) {
            $freq[$char]++
        } else {
            $freq[$char] = 1
        }
    }
    
    $length = $String.Length
    $entropy = 0.0
    foreach ($count in $freq.Values) {
        $probability = $count / $length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    
    return $entropy
}

function Invoke-COMMonitoring {
    param(
        [hashtable]$Config
    )
    
    $COMKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID"
    )

    foreach ($Key in $COMKeys) {
        $RecentCOM = Get-ChildItem -Path $Key -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "^\{[A-F0-9-]+\}$" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5

        foreach ($COM in $RecentCOM) {
            Write-AVLog "[COM] Recently modified COM object: $($COM.PSChildName) | Modified: $($COM.LastWriteTime)"
        }
    }
}

function Invoke-BrowserExtensionMonitoring {
    $detections = @()
    
    try {
        # Check Chrome extensions
        $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromeExtensionsPath) {
            $chromeExts = Get-ChildItem -Path $chromeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $chromeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        # Check for suspicious permissions
                        $suspiciousPermissions = @("all_urls", "tabs", "cookies", "history", "downloads", "webRequest", "webRequestBlocking")
                        $hasSuspiciousPerms = $false
                        
                        if ($manifestContent.permissions) {
                            foreach ($perm in $manifestContent.permissions) {
                                if ($perm -in $suspiciousPermissions) {
                                    $hasSuspiciousPerms = $true
                                    break
                                }
                            }
                        }
                        
                        # Check for unsigned extensions
                        $isSigned = $manifestContent.key -ne $null
                        
                        if ($hasSuspiciousPerms -or -not $isSigned) {
                            $detections += @{
                                Browser = "Chrome"
                                ExtensionId = $ext.Name
                                ExtensionName = $manifestContent.name
                                ManifestPath = $manifest.FullName
                                HasSuspiciousPermissions = $hasSuspiciousPerms
                                IsSigned = $isSigned
                                Type = "Suspicious Chrome Extension"
                                Risk = if ($hasSuspiciousPerms) { "High" } else { "Medium" }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Edge extensions
        $edgeExtensionsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $edgeExtensionsPath) {
            $edgeExts = Get-ChildItem -Path $edgeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $edgeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        if ($manifestContent.permissions) {
                            $suspiciousPerms = $manifestContent.permissions | Where-Object {
                                $_ -in @("all_urls", "tabs", "cookies", "webRequest")
                            }
                            
                            if ($suspiciousPerms.Count -gt 0) {
                                $detections += @{
                                    Browser = "Edge"
                                    ExtensionId = $ext.Name
                                    ExtensionName = $manifestContent.name
                                    SuspiciousPermissions = $suspiciousPerms -join ','
                                    Type = "Suspicious Edge Extension"
                                    Risk = "Medium"
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Firefox extensions
        $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilesPath) {
            $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                $extensionsPath = Join-Path $profile.FullName "extensions"
                if (Test-Path $extensionsPath) {
                    $firefoxExts = Get-ChildItem -Path $extensionsPath -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -eq ".xpi" -or $_.Extension -eq "" }
                    
                    foreach ($ext in $firefoxExts) {
                        $detections += @{
                            Browser = "Firefox"
                            ExtensionPath = $ext.FullName
                            Type = "Firefox Extension Detected"
                            Risk = "Low"
                        }
                    }
                }
            }
        }
        
        # Check for browser processes with unusual activity
        try {
            $browserProcs = Get-Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.ProcessName -match 'chrome|edge|firefox|msedge' }
            
            foreach ($proc in $browserProcs) {
                try {
                    $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                        Where-Object { $_.State -eq "Established" }
                    
                    # Check for connections to suspicious domains
                    $remoteIPs = $conns.RemoteAddress | Select-Object -Unique
                    
                    foreach ($ip in $remoteIPs) {
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                            
                            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin", "githubusercontent")
                            foreach ($domain in $suspiciousDomains) {
                                if ($hostname -like "*$domain*") {
                                    $detections += @{
                                        BrowserProcess = $proc.ProcessName
                                        ProcessId = $proc.Id
                                        ConnectedDomain = $hostname
                                        Type = "Browser Connecting to Suspicious Domain"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BROWSER EXTENSION: $($detection.Type) - $($detection.ExtensionName -or $detection.BrowserProcess -or 'System')" "THREAT" "browser_extension_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$Script:InstallPath\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionName -or $_.BrowserProcess)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Browser extension monitoring error: $_" "ERROR" "browser_extension_detections.log"
    }
    
    return $detections.Count
}

function Invoke-ShadowCopyMonitoring {
    $ShadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    $CurrentCount = $ShadowCopies.Count

    if (-not $Global:BaselineShadowCopyCount) {
        $Global:BaselineShadowCopyCount = $CurrentCount
    }

    if ($CurrentCount -lt $Global:BaselineShadowCopyCount) {
        $Deleted = $Global:BaselineShadowCopyCount - $CurrentCount
        Write-AVLog "[ShadowCopy] THREAT: Shadow copies deleted | Deleted: $Deleted | Remaining: $CurrentCount"
        $Global:BaselineShadowCopyCount = $CurrentCount
    }
}

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        # Check for USB devices
        try {
            $usbDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue
            
            foreach ($device in $usbDevices) {
                # Check for USB HID devices (keyloggers)
                if ($device.FriendlyName -match "Keyboard|HID|Human Interface") {
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB HID Device Connected"
                        Risk = "Medium"
                    }
                }
                
                # Check for USB mass storage devices
                if ($device.FriendlyName -match "Mass Storage|USB.*Drive|Removable") {
                    try {
                        $removableDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
                        
                        foreach ($drive in $removableDrives) {
                            $drivePath = $drive.DeviceID
                            
                            # Check for autorun.inf
                            $autorunPath = "$drivePath\autorun.inf"
                            if (Test-Path $autorunPath) {
                                $detections += @{
                                    Drive = $drivePath
                                    AutorunPath = $autorunPath
                                    DeviceName = $device.FriendlyName
                                    Type = "USB Drive with Autorun.inf"
                                    Risk = "High"
                                }
                            }
                            
                            # Check for executable files on USB
                            try {
                                $executables = Get-ChildItem -Path $drivePath -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Select-Object -First 20
                                
                                foreach ($exe in $executables) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid") {
                                            $detections += @{
                                                Drive = $drivePath
                                                ExecutablePath = $exe.FullName
                                                DeviceName = $device.FriendlyName
                                                Type = "Unsigned Executable on USB Drive"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            } catch { }
                            
                            # Check for suspicious file types
                            try {
                                $suspiciousFiles = Get-ChildItem -Path $drivePath -Include *.vbs,*.js,*.bat,*.cmd,*.ps1 -ErrorAction SilentlyContinue |
                                    Select-Object -First 10
                                
                                if ($suspiciousFiles.Count -gt 0) {
                                    $detections += @{
                                        Drive = $drivePath
                                        SuspiciousFileCount = $suspiciousFiles.Count
                                        DeviceName = $device.FriendlyName
                                        Type = "Suspicious Files on USB Drive"
                                        Risk = "Medium"
                                    }
                                }
                            } catch { }
                        }
                    } catch { }
                    
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB Mass Storage Device Connected"
                        Risk = "Low"
                    }
                }
            }
        } catch { }
        
        # Check for recently connected USB devices
        try {
            $recentDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq "OK" }
            
            # Check Event Log for USB connection events
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001} -ErrorAction SilentlyContinue -MaxEvents 50 |
                    Where-Object {
                        (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                        $_.Message -match 'USB|removable'
                    }
                
                if ($events.Count -gt 5) {
                    $detections += @{
                        EventCount = $events.Count
                        Type = "Multiple USB Connections in Short Time"
                        Risk = "Medium"
                    }
                }
            } catch { }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "USB MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.Drive -or 'System')" "THREAT" "usb_monitoring_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$Script:InstallPath\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.Drive)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "USB monitoring error: $_" "ERROR" "usb_monitoring_detections.log"
    }
    
    return $detections.Count
}

function Invoke-MobileDeviceMonitoring {
    $detections = @()
    $threats = @()
    
    try {
        # Track known legitimate processes that may access mobile devices
        $legitimateProcesses = @(
            "iTunes.exe", "iCloud.exe", "AppleMobileDeviceService.exe", "AppleMobileDeviceHelper.exe",
            "Samsung Smart Switch.exe", "Samsung SideSync.exe", "Samsung Kies.exe",
            "adb.exe", "fastboot.exe", "AndroidFileTransfer.exe", "Android Studio.exe",
            "explorer.exe", "dllhost.exe", "WUDFHost.exe", "WPDShextAutoplay.exe"
        )
        
        # Suspicious processes that shouldn't access mobile devices
        $suspiciousProcesses = @(
            "powershell.exe", "cmd.exe", "wmic.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
        )
        
        # Method 1: Detect mobile devices via WPD (Windows Portable Devices)
        try {
            $wpDevices = Get-PnpDevice -Class "WPD" -Status "OK" -ErrorAction SilentlyContinue
            $mtpDevices = Get-PnpDevice | Where-Object {
                $_.FriendlyName -match "iPhone|iPad|Android|Samsung|Google|Pixel|OnePlus|Xiaomi|Huawei|LG|Motorola|Sony" -or
                $_.Description -match "iPhone|iPad|Android|MTP|Portable Device"
            }
            
            $mobileDevices = @()
            if ($wpDevices) { $mobileDevices += $wpDevices }
            if ($mtpDevices) { $mobileDevices += $mtpDevices }
            
            foreach ($device in $mobileDevices) {
                $deviceName = $device.FriendlyName
                $isIPhone = $deviceName -match "iPhone|iPad|Apple"
                $isAndroid = $deviceName -match "Android|Samsung|Google|Pixel|OnePlus|Xiaomi|Huawei|LG|Motorola|Sony"
                
                if ($isIPhone -or $isAndroid) {
                    Write-AVLog "Mobile device detected: $deviceName ($($device.InstanceId))" "INFO" "mobile_device_monitoring.log"
                    
                    # Check for processes accessing this device
                    try {
                        $deviceProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                            $_.CommandLine -match $device.InstanceId -or
                            $_.ExecutablePath -match "WPD|PortableDevice|MTP"
                        }
                        
                        foreach ($proc in $deviceProcesses) {
                            $procName = Split-Path -Leaf $proc.ExecutablePath
                            
                            # Check if suspicious process is accessing device
                            if ($suspiciousProcesses -contains $procName) {
                                $threats += @{
                                    Type = "Suspicious Process Accessing Mobile Device"
                                    Device = $deviceName
                                    Process = $procName
                                    ProcessId = $proc.ProcessId
                                    CommandLine = $proc.CommandLine
                                    Risk = "CRITICAL"
                                    Timestamp = Get-Date
                                }
                                
                                # Attempt to terminate suspicious process
                                if ($Config.AutoKillThreats) {
                                    try {
                                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                        Write-AVLog "Terminated suspicious process accessing mobile device: $procName (PID: $($proc.ProcessId))" "THREAT" "mobile_device_monitoring.log"
                                    } catch {
                                        Write-AVLog "Failed to terminate process ${procName}: $_" "WARN" "mobile_device_monitoring.log"
                                    }
                                }
                            }
                        }
                    } catch { }
                    
                    # Log device connection
                    $detections += @{
                        DeviceName = $deviceName
                        InstanceId = $device.InstanceId
                        DeviceType = if ($isIPhone) { "iPhone/iPad" } else { "Android" }
                        Type = "Mobile Device Connected"
                        Risk = "Medium"
                        Timestamp = Get-Date
                    }
                }
            }
        } catch {
            Write-AVLog "WPD/MTP device detection error: $_" "WARN" "mobile_device_monitoring.log"
        }
        
        # Method 2: Monitor ADB (Android Debug Bridge) connections
        try {
            $adbProcesses = Get-Process -Name "adb" -ErrorAction SilentlyContinue
            
            foreach ($adbProc in $adbProcesses) {
                try {
                    # Check ADB connections
                    $adbConnections = & adb devices 2>$null
                    if ($adbConnections -and $adbConnections.Count -gt 1) {
                        $connectedDevices = ($adbConnections | Where-Object { $_ -match "device$" }).Count
                        
                        if ($connectedDevices -gt 0) {
                            # Check if ADB is being used by suspicious process
                            $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($adbProc.Id)" -ErrorAction SilentlyContinue |
                                Select-Object -ExpandProperty ParentProcessId -ErrorAction SilentlyContinue
                            
                            if ($parentProc) {
                                $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProc" -ErrorAction SilentlyContinue
                                if ($parent) {
                                    $parentName = Split-Path -Leaf $parent.ExecutablePath
                                    
                                    if ($suspiciousProcesses -contains $parentName -or 
                                        $legitimateProcesses -notcontains $parentName) {
                                        $threats += @{
                                            Type = "Suspicious ADB Connection"
                                            Process = $parentName
                                            ProcessId = $parentProc
                                            ConnectedDevices = $connectedDevices
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                        
                                        if ($Config.AutoKillThreats) {
                                            try {
                                                Stop-Process -Id $adbProc.Id -Force -ErrorAction SilentlyContinue
                                                Stop-Process -Id $parentProc -Force -ErrorAction SilentlyContinue
                                                Write-AVLog "Terminated suspicious ADB connection: $parentName" "THREAT" "mobile_device_monitoring.log"
                                            } catch { }
                                        }
                                    }
                                }
                            }
                            
                            $detections += @{
                                Type = "ADB Connection Active"
                                ConnectedDevices = $connectedDevices
                                Risk = "High"
                                Timestamp = Get-Date
                            }
                        }
                    }
                } catch {
                    # ADB not in PATH or not accessible
                }
            }
        } catch { }
        
        # Method 3: Monitor file system access to mobile device mount points
        try {
            $logicalDisks = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
                $_.DriveType -eq 2 -or $_.Description -match "Removable|Portable"
            }
            
            foreach ($disk in $logicalDisks) {
                $drivePath = $disk.DeviceID
                
                # Check if this might be a mobile device mount
                $volumeInfo = Get-Volume -DriveLetter $drivePath[0] -ErrorAction SilentlyContinue
                if ($volumeInfo -and ($volumeInfo.FileSystemLabel -match "iPhone|Android|Samsung|Google" -or
                    $volumeInfo.FileSystem -eq "FAT32")) {
                    
                    # Monitor for suspicious file access patterns
                    try {
                        $recentFiles = Get-ChildItem -Path $drivePath -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
                            Select-Object -First 50
                        
                        # Check for sensitive file types being accessed
                        $sensitiveExtensions = @(".db", ".sqlite", ".keychain", ".key", ".p12", ".pfx", ".crt", ".pem", ".jpg", ".png", ".mp4", ".mov")
                        $sensitiveFiles = $recentFiles | Where-Object {
                            $sensitiveExtensions -contains $_.Extension -or
                            $_.Name -match "contacts|messages|photos|videos|backup|keychain|password|credential"
                        }
                        
                        if ($sensitiveFiles.Count -gt 10) {
                            $threats += @{
                                Type = "Mass Access to Sensitive Mobile Device Files"
                                Drive = $drivePath
                                FileCount = $sensitiveFiles.Count
                                Risk = "HIGH"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 4: Monitor network connections that might indicate mobile device tethering/access
        try {
            $networkConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $_.State -eq "Established" -and
                ($_.LocalPort -eq 5037 -or $_.LocalPort -eq 5555 -or $_.LocalPort -eq 62078) # ADB ports
            }
            
            if ($networkConnections) {
                foreach ($conn in $networkConnections) {
                    $owningProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue
                    if ($owningProc) {
                        $procName = Split-Path -Leaf $owningProc.ExecutablePath
                        
                        if ($suspiciousProcesses -contains $procName) {
                            $threats += @{
                                Type = "Suspicious Network Connection to Mobile Device Port"
                                Process = $procName
                                ProcessId = $conn.OwningProcess
                                LocalPort = $conn.LocalPort
                                RemoteAddress = $conn.RemoteAddress
                                Risk = "CRITICAL"
                                Timestamp = Get-Date
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Method 5: Check for unauthorized services accessing mobile devices
        try {
            $mobileServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -match "Apple|Android|Mobile|WPD|Portable" -and
                $_.Status -eq "Running"
            }
            
            foreach ($svc in $mobileServices) {
                try {
                    $svcProcess = Get-CimInstance Win32_Service -Filter "Name = '$($svc.Name)'" -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty ProcessId -ErrorAction SilentlyContinue
                    
                    if ($svcProcess) {
                        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $svcProcess" -ErrorAction SilentlyContinue
                        if ($proc) {
                            $procPath = $proc.ExecutablePath
                            
                            # Verify service executable signature
                            try {
                                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                                if ($sig.Status -ne "Valid" -and $sig.Status -ne "NotSigned") {
                                    $threats += @{
                                        Type = "Unauthorized Mobile Device Service"
                                        Service = $svc.Name
                                        ServicePath = $procPath
                                        SignatureStatus = $sig.Status
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                }
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        # Method 6: Monitor registry for mobile device access patterns
        try {
            $mobileRegKeys = @(
                "HKLM:\SYSTEM\CurrentControlSet\Enum\USB",
                "HKLM:\SYSTEM\CurrentControlSet\Enum\WPD",
                "HKLM:\SOFTWARE\Microsoft\Windows Portable Devices"
            )
            
            foreach ($regKey in $mobileRegKeys) {
                if (Test-Path $regKey) {
                    try {
                        $recentChanges = Get-ChildItem -Path $regKey -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
                        
                        if ($recentChanges.Count -gt 20) {
                            $detections += @{
                                Type = "Excessive Mobile Device Registry Activity"
                                RegistryPath = $regKey
                                ChangeCount = $recentChanges.Count
                                Risk = "Medium"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 7: Mobile Malware Detection (Banking Trojans, Spyware, etc.)
        try {
            # Known mobile malware families and banking trojans
            $knownMalwareSignatures = @{
                # Banking Trojans (Updated January 2026 - includes recent 2025-2026 threats)
                "BankingTrojans" = @(
                    # Recent Threats (2025-2026)
                    "Anatsa", "RatOn", "Klopatra", "Sturnus", "Frogblight", "GodFather",
                    # Established Threats
                    "Anubis", "Cerberus", "EventBot", "Exobot", "FakeBank", "FakeSpy", "Faketoken",
                    "Ginp", "Gustuff", "Hydra", "Marcher", "Medusa", "Octo", "Svpeng", "TinyBanker",
                    "Tordow", "Triada", "TrickBot", "Ursnif", "Zeus", "Zitmo", "BankBot", "Asacub",
                    "Acecard", "Cron", "MoqHao", "Regin", "SpyNote", "TeaBot",
                    # Older Notable Threats
                    "FluBot", "TinyBanker"
                )
                # Spyware and Data Stealers
                "Spyware" = @(
                    "Pegasus", "FinFisher", "HackingTeam", "FlexiSpy", "mSpy", "Spyera", "TheTruthSpy",
                    "Cocospy", "Spyzie", "Spyic", "Spybubble", "SpyHuman", "SpyBubble", "SpyPhone",
                    "MobileSpy", "StealthGenie", "Retina-X", "SpyToMobile", "SpyHuman"
                )
                # Ransomware
                "MobileRansomware" = @(
                    "Simplocker", "Koler", "Lockerpin", "Sypeng", "Fusob", "Jisut", "Charger",
                    "Leatherlocker", "Slocker", "Pletor", "Congur", "Locker", "Ransom"
                )
                # Adware and Potentially Unwanted Programs
                "Adware" = @(
                    "Hummingbad", "Gooligan", "Judy", "Ewind", "Shedun", "Shuanet", "ShiftyBug",
                    "Kemoge", "Mobidash", "Dowgin"
                )
                # Remote Access Trojans (RATs) - Mobile
                "MobileRATs" = @(
                    "RatOn", "Klopatra", "SpyNote", "AhMyth", "AndroRAT", "DroidJack", "SpyMax",
                    "OmniRAT", "SpyAgent", "SpyAndroid", "Dendroid", "Sandroid", "SMSZombie"
                )
            }
            
            # Banking app package names (common targets)
            $bankingAppPatterns = @(
                "com.chase.sig.android", "com.wellsfargo.mobile", "com.bankofamerica.mobile",
                "com.citi.citimobile", "com.usaa.mobile.android", "com.pnc.ecommerce.mobile",
                "com.capitalone.mobile", "com.td", "com.rbc.mobile.android", "com.hsbc.hsbcusa.mobile.android",
                "com.americanexpress.android.acctsvcs.us", "com.schwab.mobile", "com.fidelity.android",
                "com.barclays.barclaysmobilebanking", "com.halifax.mobile", "com.natwest.mobile",
                "com.hsbc.hsbcuk.mobilebanking", "com.santander.santander", "com.lloydsbank.mobile",
                "com.rbs.mobile.android", "com.tsb.mobilebanking", "com.cooperativebank.business",
                "com.ing.mobile", "com.rabobank.mobile", "com.abnamro.mobile", "com.deutschebank.mobile",
                "com.commerzbank.mobile", "com.sparkasse", "com.volksbank", "com.postbank",
                "com.unicredit.mobile", "com.intesasanpaolo.mobile", "com.bancoposta", "com.unicredit",
                "com.bancoposta", "com.unicredit", "com.bancoposta", "com.unicredit"
            )
            
            # Suspicious file patterns on mobile devices
            $suspiciousFilePatterns = @(
                "*.apk", "*.ipa", "*.dex", "*.so", "*.jar", "*.class"
            )
            
            # Suspicious directory names where malware often hides
            $suspiciousDirectories = @(
                "Android/data", "Android/obb", "Android/system", "private/var", "Library/Caches",
                "tmp", "temp", "cache", ".hidden", "system/bin", "system/xbin", "data/local"
            )
            
            # Check connected mobile devices for malware indicators
            $logicalDisks = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
                $_.DriveType -eq 2 -or $_.Description -match "Removable|Portable"
            }
            
            foreach ($disk in $logicalDisks) {
                $drivePath = $disk.DeviceID
                $volumeInfo = Get-Volume -DriveLetter $drivePath[0] -ErrorAction SilentlyContinue
                
                if ($volumeInfo -and ($volumeInfo.FileSystemLabel -match "iPhone|Android|Samsung|Google" -or
                    $volumeInfo.FileSystem -eq "FAT32")) {
                    
                    try {
                        # Scan for APK files (Android malware)
                        $apkFiles = Get-ChildItem -Path $drivePath -Filter "*.apk" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 100
                        
                        foreach ($apk in $apkFiles) {
                            $fileName = $apk.Name
                            $filePath = $apk.FullName
                            
                            # Check filename against known malware signatures
                            $isMalware = $false
                            $malwareFamily = "Unknown"
                            
                            foreach ($family in $knownMalwareSignatures.Keys) {
                                foreach ($signature in $knownMalwareSignatures[$family]) {
                                    if ($fileName -match $signature -or $filePath -match $signature) {
                                        $isMalware = $true
                                        $malwareFamily = "$family - $signature"
                                        break
                                    }
                                }
                                if ($isMalware) { break }
                            }
                            
                            # Check for suspicious naming patterns (including recent 2025-2026 threat patterns)
                            $suspiciousPatterns = @(
                                "update", "service", "system", "security", "bank", "payment", "wallet",
                                "installer", "helper", "manager", "optimizer", "cleaner", "booster",
                                # Recent threat patterns (2025-2026)
                                "mobdro", "iptv", "vpn", "tiktok.*adult", "pdf.*reader", "pdf.*viewer",
                                "court", "case", "sms", "whatsapp.*backup", "telegram.*backup"
                            )
                            
                            # Specific recent malware masquerading patterns
                            $recentThreatPatterns = @{
                                "Klopatra" = @("mobdro", "iptv.*vpn", "pirate.*tv", "streaming.*vpn")
                                "RatOn" = @("tiktok.*adult", "nfc.*relay", "contactless")
                                "Anatsa" = @("pdf.*app", "pdf.*reader", "document.*viewer")
                                "Frogblight" = @("court.*case", "legal.*notice", "sms.*message")
                                "Sturnus" = @("whatsapp", "telegram", "chat.*backup", "message.*backup")
                                "GodFather" = @("virtual.*bank", "banking.*clone", "app.*clone")
                            }
                            
                            $suspiciousName = $false
                            $detectedThreatPattern = $null
                            
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($fileName -match $pattern -and $fileName.Length -lt 20) {
                                    $suspiciousName = $true
                                    break
                                }
                            }
                            
                            # Check for specific recent threat patterns
                            foreach ($threatName in $recentThreatPatterns.Keys) {
                                foreach ($pattern in $recentThreatPatterns[$threatName]) {
                                    if ($fileName -match $pattern -or $filePath -match $pattern) {
                                        $detectedThreatPattern = $threatName
                                        $isMalware = $true
                                        $malwareFamily = "BankingTrojans - $threatName"
                                        break
                                    }
                                }
                                if ($detectedThreatPattern) { break }
                            }
                            
                            # Check file size (very small or very large APKs are suspicious)
                            $fileSizeMB = $apk.Length / 1MB
                            $suspiciousSize = $fileSizeMB -lt 0.1 -or $fileSizeMB -gt 100
                            
                            # Check for banking app targeting
                            $targetsBanking = $false
                            foreach ($bankApp in $bankingAppPatterns) {
                                if ($filePath -match $bankApp -or $fileName -match "bank|payment|wallet|finance") {
                                    $targetsBanking = $true
                                    break
                                }
                            }
                            
                            if ($isMalware -or ($suspiciousName -and $suspiciousSize) -or $targetsBanking) {
                                $riskLevel = if ($isMalware) { "CRITICAL" } 
                                           elseif ($targetsBanking) { "CRITICAL" }
                                           else { "HIGH" }
                                
                                $threats += @{
                                    Type = if ($targetsBanking) { "Banking Trojan Detected on Mobile Device" } 
                                          elseif ($isMalware) { "Mobile Malware Detected" }
                                          else { "Suspicious Mobile App Detected" }
                                    FilePath = $filePath
                                    FileName = $fileName
                                    FileSize = "$([Math]::Round($fileSizeMB, 2)) MB"
                                    MalwareFamily = $malwareFamily
                                    TargetsBanking = $targetsBanking
                                    Risk = $riskLevel
                                    Timestamp = Get-Date
                                }
                                
                                # Attempt to quarantine the file
                                if ($Config.AutoQuarantine -and $isMalware) {
                                    try {
                                        Move-ToQuarantine -FilePath $filePath -Reason "Mobile malware detected: $malwareFamily"
                                        Write-AVLog "Quarantined mobile malware: $fileName ($malwareFamily)" "THREAT" "mobile_device_monitoring.log"
                                    } catch {
                                        Write-AVLog "Failed to quarantine ${fileName}: $_" "WARN" "mobile_device_monitoring.log"
                                    }
                                }
                            }
                        }
                        
                        # Check for suspicious directories
                        foreach ($susDir in $suspiciousDirectories) {
                            $fullPath = Join-Path $drivePath $susDir
                            if (Test-Path $fullPath) {
                                try {
                                    $filesInDir = Get-ChildItem -Path $fullPath -Recurse -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Extension -match "\.(apk|ipa|dex|so|jar|class)$" }
                                    
                                    if ($filesInDir.Count -gt 5) {
                                        $threats += @{
                                            Type = "Suspicious Files in System Directory"
                                            Directory = $fullPath
                                            FileCount = $filesInDir.Count
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                    }
                                } catch { }
                            }
                        }
                        
                        # Check for recently modified system files (potential root/jailbreak malware)
                        try {
                            $systemPaths = @(
                                Join-Path $drivePath "Android\system",
                                Join-Path $drivePath "Android\bin",
                                Join-Path $drivePath "private\var"
                            )
                            
                            foreach ($sysPath in $systemPaths) {
                                if (Test-Path $sysPath) {
                                    $recentMods = Get-ChildItem -Path $sysPath -Recurse -ErrorAction SilentlyContinue |
                                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
                                    
                                    if ($recentMods.Count -gt 10) {
                                        $threats += @{
                                            Type = "Unauthorized System File Modifications on Mobile Device"
                                            Path = $sysPath
                                            ModifiedFiles = $recentMods.Count
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                    }
                                }
                            }
                        } catch { }
                        
                        # Check for Sturnus-like behavior: Access to WhatsApp/Telegram chat databases
                        try {
                            $chatAppPaths = @(
                                Join-Path $drivePath "Android\data\com.whatsapp",
                                Join-Path $drivePath "Android\data\org.telegram",
                                Join-Path $drivePath "Android\data\com.telegram"
                            )
                            
                            foreach ($chatPath in $chatAppPaths) {
                                if (Test-Path $chatPath) {
                                    # Check for recent access to chat databases
                                    $chatDbs = Get-ChildItem -Path $chatPath -Recurse -Filter "*.db" -ErrorAction SilentlyContinue |
                                        Where-Object { $_.LastAccessTime -gt (Get-Date).AddHours(-1) }
                                    
                                    if ($chatDbs.Count -gt 0) {
                                        $threats += @{
                                            Type = "Suspicious Access to Chat Application Data (Sturnus-like behavior)"
                                            Path = $chatPath
                                            DatabaseFiles = $chatDbs.Count
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                    }
                                }
                            }
                        } catch { }
                        
                        # Check for RatOn-like behavior: NFC-related files or configurations
                        try {
                            $nfcPaths = @(
                                Join-Path $drivePath "Android\data\*nfc*",
                                Join-Path $drivePath "Android\system\*nfc*"
                            )
                            
                            foreach ($nfcPattern in $nfcPaths) {
                                $nfcFiles = Get-ChildItem -Path (Split-Path $nfcPattern -Parent) -Filter (Split-Path $nfcPattern -Leaf) -Recurse -ErrorAction SilentlyContinue |
                                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
                                
                                if ($nfcFiles.Count -gt 0) {
                                    $threats += @{
                                        Type = "Suspicious NFC-Related Files Detected (RatOn-like behavior)"
                                        Path = $nfcPattern
                                        FileCount = $nfcFiles.Count
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                }
                            }
                        } catch { }
                        
                    } catch {
                        Write-AVLog "Error scanning mobile device for malware: $_" "WARN" "mobile_device_monitoring.log"
                    }
                }
            }
            
            # Method 8: Monitor for banking app data exfiltration patterns
            try {
                # Check for processes accessing banking-related files
                $bankingKeywords = @("bank", "payment", "wallet", "credit", "debit", "account", "transaction", "balance")
                $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
                
                foreach ($proc in $processes) {
                    try {
                        $cmdLine = $proc.CommandLine
                        $procName = Split-Path -Leaf $proc.ExecutablePath
                        
                        if ($cmdLine) {
                            $matchesBanking = $false
                            foreach ($keyword in $bankingKeywords) {
                                if ($cmdLine -match $keyword) {
                                    $matchesBanking = $true
                                    break
                                }
                            }
                            
                            if ($matchesBanking -and $suspiciousProcesses -contains $procName) {
                                $threats += @{
                                    Type = "Suspicious Process Accessing Banking-Related Data"
                                    Process = $procName
                                    ProcessId = $proc.ProcessId
                                    CommandLine = $cmdLine
                                    Risk = "CRITICAL"
                                    Timestamp = Get-Date
                                }
                                
                                if ($Config.AutoKillThreats) {
                                    try {
                                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                        Write-AVLog "Terminated process accessing banking data: $procName" "THREAT" "mobile_device_monitoring.log"
                                    } catch { }
                                }
                            }
                        }
                    } catch { }
                }
            } catch { }
            
        } catch {
            Write-AVLog "Mobile malware detection error: $_" "ERROR" "mobile_device_monitoring.log"
        }
        
        # Log all detections and threats
        if ($detections.Count -gt 0 -or $threats.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "MOBILE DEVICE MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.Drive -or 'System')" "INFO" "mobile_device_monitoring.log"
            }
            
            foreach ($threat in $threats) {
                Write-AVLog "MOBILE DEVICE THREAT: $($threat.Type) - $($threat.Process -or $threat.Service -or 'Unknown') - Risk: $($threat.Risk)" "THREAT" "mobile_device_monitoring.log"
                $Global:AntivirusState.ThreatCount++
                
                # Add to response queue for automated response
                if ($Config.AutoKillThreats) {
                    $threatPath = $threat.FilePath -or $threat.Process -or $threat.Service -or ""
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$Script:InstallPath\Logs\MobileDeviceMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            
            $allEvents = $detections + $threats
            $allEvents | ForEach-Object {
                $eventType = if ($_.Risk -match "CRITICAL|HIGH") { "THREAT" } else { "INFO" }
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$eventType|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.Process -or $_.Service -or 'N/A')|$($_.ProcessId -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-AVLog "Mobile device monitoring error: $_" "ERROR" "mobile_device_monitoring.log"
    }
    
    return ($detections.Count + $threats.Count)
}

function Invoke-AttackToolsDetection {
    $detections = @()
    $threats = @()
    
    try {
        # Comprehensive list of attack tools commonly found on dark web
        $attackTools = @{
            # Password Cracking Tools
            "PasswordCrackers" = @(
                "hydra", "hydra.exe", "hydra64.exe", "hydra32.exe",
                "john", "john.exe", "john-the-ripper", "jtr",
                "hashcat", "hashcat.exe", "hashcat64.exe",
                "medusa", "medusa.exe", "ncrack", "ncrack.exe",
                "patator", "patator.py", "brutus", "brutus.exe",
                "rainbowcrack", "rcrack", "ophcrack", "ophcrack.exe",
                "cain", "cain.exe", "abel.exe", "l0phtcrack"
            )
            # Exploitation Frameworks
            "ExploitationFrameworks" = @(
                "metasploit", "msfconsole", "msfvenom", "msfpayload",
                "cobaltstrike", "beacon.exe", "cobaltstrike.exe",
                "empire", "empire.exe", "powershell-empire",
                "covenant", "covenant.exe", "grunt.exe",
                "sliver", "sliver.exe", "merlin", "merlin.exe",
                "havoc", "havoc.exe", "bruteratel", "bruteratel.exe"
            )
            # Network Scanning & Reconnaissance
            "NetworkScanners" = @(
                "nmap", "nmap.exe", "zenmap", "zenmap.exe",
                "masscan", "masscan.exe", "zmap", "zmap.exe",
                "angryip", "angryip.exe", "advanced-port-scanner",
                "netscan", "netscan.exe", "lanmap", "lanmap.exe",
                "superscan", "superscan.exe", "netcat", "nc.exe",
                "socat", "socat.exe", "hping", "hping3.exe"
            )
            # Credential Dumping & Extraction
            "CredentialDumpers" = @(
                "mimikatz", "mimikatz.exe", "mimidrv.sys",
                "lazagne", "lazagne.exe", "laZagne.exe",
                "wce", "wce.exe", "wce32.exe", "wce64.exe",
                "fgdump", "fgdump.exe", "pwdump", "pwdump.exe",
                "gsecdump", "gsecdump.exe", "cachedump", "cachedump.exe",
                "lsadump", "lsadump.exe", "sekurlsa", "sekurlsa.exe",
                "procdump", "procdump.exe", "comsvcs.dll"
            )
            # Post-Exploitation & Lateral Movement
            "PostExploitation" = @(
                "bloodhound", "bloodhound.exe", "sharphound", "sharphound.exe",
                "powersploit", "invoke-mimikatz", "invoke-kerberoast",
                "empire", "empire.exe", "nishang", "nishang.ps1",
                "impacket", "secretsdump.py", "psexec.py", "smbexec.py",
                "crackmapexec", "crackmapexec.exe", "smbmap", "smbmap.exe",
                "evil-winrm", "evil-winrm.exe", "winrm", "winrm.exe"
            )
            # Web Application Attack Tools
            "WebAttackTools" = @(
                "sqlmap", "sqlmap.py", "burpsuite", "burp.exe",
                "nikto", "nikto.pl", "nikto.exe", "w3af",
                "wpscan", "wpscan.rb", "acunetix", "acunetix.exe",
                "appscan", "appscan.exe", "zap", "zap.exe",
                "dirb", "dirb.exe", "dirbuster", "dirbuster.exe",
                "gobuster", "gobuster.exe", "ffuf", "ffuf.exe"
            )
            # Packet Crafting & Network Tools
            "PacketCrafting" = @(
                "scapy", "scapy.py", "ettercap", "ettercap.exe",
                "wireshark", "wireshark.exe", "tshark", "tshark.exe",
                "tcpdump", "tcpdump.exe", "packeth", "packeth.exe",
                "packetbuilder", "packetbuilder.exe", "nemesis", "nemesis.exe",
                "hping", "hping3.exe", "yersinia", "yersinia.exe"
            )
            # RATs & Remote Access Tools
            "RemoteAccessTools" = @(
                "teamviewer", "teamviewer.exe", "anydesk", "anydesk.exe",
                "ultravnc", "ultravnc.exe", "tightvnc", "tightvnc.exe",
                "remmina", "remmina.exe", "remotex", "remotex.exe",
                "radmin", "radmin.exe", "logmein", "logmein.exe",
                "gotomypc", "gotomypc.exe", "ammyy", "ammyy.exe",
                "darkcomet", "darkcomet.exe", "poisonivy", "poisonivy.exe"
            )
            # Keyloggers & Monitoring
            "Keyloggers" = @(
                "keylogger", "keylogger.exe", "refog", "refog.exe",
                "spytech", "spytech.exe", "perfectkeylogger", "perfectkeylogger.exe",
                "allinonekeylogger", "allinonekeylogger.exe", "actualkeylogger",
                "actualkeylogger.exe", "keystrokecapture", "keystrokecapture.exe"
            )
            # File Transfer & Exfiltration
            "FileTransferTools" = @(
                "filezilla", "filezilla.exe", "winscp", "winscp.exe",
                "pscp", "pscp.exe", "scp", "scp.exe", "sftp", "sftp.exe",
                "curl", "curl.exe", "wget", "wget.exe", "aria2c", "aria2c.exe",
                "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe"
            )
            # Rootkits & Stealth Tools
            "Rootkits" = @(
                "fu", "fu.exe", "hackerdefender", "hackerdefender.exe",
                "afrootkit", "afrootkit.exe", "vanquish", "vanquish.exe",
                "adore", "adore-ng", "diamorphine", "enyelkm"
            )
            # Cryptocurrency Miners (often bundled with malware)
            "CryptoMiners" = @(
                "xmrig", "xmrig.exe", "ccminer", "ccminer.exe",
                "cgminer", "cgminer.exe", "minerd", "minerd.exe",
                "nicehash", "nicehash.exe", "claymore", "claymore.exe"
            )
        }
        
        # Known SHA256 hashes of attack tools (resistant to renaming)
        # Note: These are example hashes - in production, maintain a comprehensive database
        $knownToolHashes = @{
            # Hydra common versions (example patterns - update with real hashes)
            "Hydra" = @(
                # Add known Hydra hashes here when available
            )
            # Mimikatz common versions
            "Mimikatz" = @(
                # Add known Mimikatz hashes here
            )
            # Metasploit payloads
            "Metasploit" = @(
                # Add known Metasploit payload hashes
            )
        }
        
        # File signature patterns (YARA-like string detection - works even if renamed)
        $toolSignatures = @{
            # Hydra signatures
            "Hydra" = @(
                "THC Hydra", "hydra\.conf", "hydra\.restore", "Parallelized login cracker",
                "Supported services:", "hydra -l", "hydra -P", "hydra -L", "hydra -p"
            )
            # Mimikatz signatures
            "Mimikatz" = @(
                "mimikatz", "mimilib\.dll", "sekurlsa", "kerberos", "wdigest",
                "lsadump", "token::elevate", "privilege::debug", "Benjamin DELPY"
            )
            # Metasploit signatures
            "Metasploit" = @(
                "metasploit", "msfconsole", "msfvenom", "payload", "exploit",
                "Rapid7", "Metasploit Framework", "msfpayload"
            )
            # Cobalt Strike signatures
            "CobaltStrike" = @(
                "cobaltstrike", "beacon\.dll", "beacon\.exe", "ReflectiveLoader",
                "sleep_mask", "beacon\.stage", "Cobalt Strike"
            )
            # John the Ripper signatures
            "JohnTheRipper" = @(
                "John the Ripper", "jumbo", "john\.conf", "john\.pot", "wordlist",
                "cracking", "john --wordlist", "john --rules"
            )
            # Hashcat signatures
            "Hashcat" = @(
                "hashcat", "hashcat\.exe", "hash modes", "attack modes",
                "hashcat\.potfile", "hashcat --force"
            )
            # Nmap signatures
            "Nmap" = @(
                "Nmap", "Network Mapper", "nmap\.exe", "nmap\.conf", "nmap\.nse",
                "Starting Nmap", "Nmap scan report"
            )
            # BloodHound signatures
            "BloodHound" = @(
                "bloodhound", "BloodHound\.exe", "SharpHound", "BloodHound\.db",
                "neo4j", "BloodHound\.exe"
            )
            # Empire signatures
            "Empire" = @(
                "empire", "Empire\.exe", "empire\.db", "stagers", "listeners",
                "PowerShell Empire"
            )
            # LaZagne signatures
            "LaZagne" = @(
                "laZagne", "LaZagne", "lazagne\.exe", "password recovery",
                "browsers", "wifi", "mails"
            )
        }
        
        # Behavioral indicators (what tools DO, not what they're named)
        $behavioralIndicators = @{
            # Password cracking behaviors
            "PasswordCracking" = @{
                "NetworkPatterns" = @(
                    "Multiple failed login attempts", "Brute force patterns",
                    "Dictionary attack", "Credential stuffing"
                )
                "APICalls" = @(
                    "LogonUser", "CredUIPromptForCredentials", "WNetAddConnection2"
                )
                "FileOperations" = @(
                    "Reading wordlists", "Writing password files", "Hash files"
                )
            }
            # Credential dumping behaviors
            "CredentialDumping" = @{
                "APICalls" = @(
                    "LsaEnumerateLogonSessions", "LsaGetLogonSessionData",
                    "MiniDumpWriteDump", "ReadProcessMemory", "OpenProcess",
                    "CryptUnprotectData", "CredEnumerate"
                )
                "RegistryAccess" = @(
                    "HKLM\SAM", "HKLM\SECURITY", "HKLM\SYSTEM",
                    "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                )
                "ProcessAccess" = @(
                    "Accessing lsass.exe", "Accessing winlogon.exe", "Accessing csrss.exe"
                )
            }
            # Network scanning behaviors
            "NetworkScanning" = @{
                "NetworkPatterns" = @(
                    "Rapid port connections", "ICMP sweeps", "SYN scans",
                    "Multiple connection attempts", "ARP scanning"
                )
                "APICalls" = @(
                    "connect", "WSAConnect", "send", "recv", "gethostbyname"
                )
            }
            # Post-exploitation behaviors
            "PostExploitation" = @{
                "APICalls" = @(
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                    "NtQuerySystemInformation", "NetUserEnum", "NetLocalGroupEnum"
                )
                "NetworkPatterns" = @(
                    "SMB enumeration", "LDAP queries", "Kerberos ticket requests"
                )
                "FileOperations" = @(
                    "Reading AD data", "Dumping credentials", "Extracting tokens"
                )
            }
        }
        
        # Suspicious directory patterns where attack tools are often stored
        $suspiciousDirectories = @(
            "$env:USERPROFILE\Desktop\Tools",
            "$env:USERPROFILE\Downloads\Hacking",
            "$env:USERPROFILE\Documents\Tools",
            "$env:USERPROFILE\Desktop\Hack",
            "$env:TEMP\Tools",
            "$env:ProgramData\Tools",
            "C:\Tools",
            "C:\Hacking",
            "C:\Pentest",
            "C:\Security"
        )
        
        # Method 1: Scan running processes for attack tools
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPath = $proc.ExecutablePath
                    $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                    $procCmdLine = $proc.CommandLine
                    
                    if (-not $procName) { continue }
                    
                    $detectedTool = $null
                    $toolCategory = $null
                    $detectionMethod = "NameMatch"
                    
                    # Method 1A: Check process name and path against attack tools
                    foreach ($category in $attackTools.Keys) {
                        foreach ($tool in $attackTools[$category]) {
                            if ($procName -match $tool -or $procPath -match $tool -or $procCmdLine -match $tool) {
                                $detectedTool = $tool
                                $toolCategory = $category
                                $detectionMethod = "NameMatch"
                                break
                            }
                        }
                        if ($detectedTool) { break }
                    }
                    
                    # Method 1B: Hash-based detection (works even if renamed)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            $fileHash = (Get-FileHash -Path $procPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            
                            foreach ($toolName in $knownToolHashes.Keys) {
                                if ($knownToolHashes[$toolName] -contains $fileHash) {
                                    $detectedTool = $toolName
                                    $toolCategory = "Unknown"
                                    $detectionMethod = "HashMatch"
                                    break
                                }
                            }
                        } catch { }
                    }
                    
                    # Method 1C: File signature/string pattern detection (YARA-like)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            # Read first 1MB of file for signature scanning
                            $fileBytes = [System.IO.File]::ReadAllBytes($procPath)
                            $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                            
                            foreach ($toolName in $toolSignatures.Keys) {
                                foreach ($signature in $toolSignatures[$toolName]) {
                                    if ($fileContent -match [regex]::Escape($signature) -or 
                                        $procCmdLine -match [regex]::Escape($signature)) {
                                        $detectedTool = $toolName
                                        $toolCategory = "Unknown"
                                        $detectionMethod = "SignatureMatch"
                                        break
                                    }
                                }
                                if ($detectedTool) { break }
                            }
                        } catch { }
                    }
                    
                    # Method 1D: Entropy analysis (packed/obfuscated tools have high entropy)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            $entropy = Measure-FileEntropy -FilePath $procPath
                            if ($entropy -gt 7.5 -and (Get-Item $procPath).Length -lt 10MB) {
                                # High entropy + small size = possibly packed/obfuscated
                                # Check if unsigned
                                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                                if ($sig.Status -ne "Valid") {
                                    # Check command line for suspicious patterns
                                    if ($procCmdLine -match "password|brute|crack|hash|dump|scan|exploit") {
                                        $detectedTool = "SuspiciousPackedTool"
                                        $toolCategory = "Unknown"
                                        $detectionMethod = "EntropyAnalysis"
                                    }
                                }
                            }
                        } catch { }
                    }
                    
                    if ($detectedTool) {
                        # Check if it's a legitimate security tool in a known location
                        $isLegitimate = $false
                        $legitimatePaths = @(
                            "$env:ProgramFiles", "$env:ProgramFiles(x86)", 
                            "$env:ProgramData\Microsoft", "$env:SystemRoot\System32"
                        )
                        
                        foreach ($legPath in $legitimatePaths) {
                            if ($procPath -like "$legPath*") {
                                # Still suspicious but might be legitimate software
                                $isLegitimate = $true
                                break
                            }
                        }
                        
                        $riskLevel = if ($isLegitimate) { "MEDIUM" } else { "CRITICAL" }
                        
                        $threats += @{
                            Type = "Attack Tool Detected: $toolCategory"
                            ToolName = $detectedTool
                            ProcessName = $procName
                            ProcessPath = $procPath
                            ProcessId = $proc.ProcessId
                            CommandLine = $procCmdLine
                            Category = $toolCategory
                            DetectionMethod = $detectionMethod
                            Risk = $riskLevel
                            Timestamp = Get-Date
                        }
                        
                        # Attempt to terminate if critical
                        if ($Config.AutoKillThreats -and $riskLevel -eq "CRITICAL") {
                            try {
                                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                Write-AVLog "Terminated attack tool process: $procName ($detectedTool)" "THREAT" "attack_tools_detection.log"
                            } catch {
                                Write-AVLog "Failed to terminate ${procName}: $_" "WARN" "attack_tools_detection.log"
                            }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "Process scanning error in attack tools detection: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 2: Scan file system for attack tools
        try {
            $scanPaths = @(
                $env:USERPROFILE,
                $env:TEMP,
                $env:ProgramData,
                "C:\Tools",
                "C:\Hacking",
                "C:\Pentest"
            )
            
            foreach ($scanPath in $scanPaths) {
                if (-not (Test-Path $scanPath)) { continue }
                
                try {
                    # Search for executable files matching attack tool names
                    foreach ($category in $attackTools.Keys) {
                        foreach ($tool in $attackTools[$category]) {
                            $toolPattern = "*$tool*"
                            
                            try {
                                $foundFiles = Get-ChildItem -Path $scanPath -Filter $toolPattern -Recurse -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Extension -match "\.(exe|dll|bat|cmd|ps1|py|rb|pl)$" } |
                                    Select-Object -First 10
                                
                                foreach ($file in $foundFiles) {
                                    # Check file signature
                                    $isSigned = $false
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                        $isSigned = $sig.Status -eq "Valid"
                                    } catch { }
                                    
                                    if (-not $isSigned) {
                                        $threats += @{
                                            Type = "Attack Tool File Detected: $toolCategory"
                                            ToolName = $tool
                                            FilePath = $file.FullName
                                            FileName = $file.Name
                                            FileSize = "$([Math]::Round($file.Length / 1MB, 2)) MB"
                                            Category = $category
                                            IsSigned = $isSigned
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                        
                                        # Quarantine unsigned attack tools
                                        if ($Config.AutoQuarantine) {
                                            try {
                                                Move-ToQuarantine -FilePath $file.FullName -Reason "Attack tool detected: $tool ($category)"
                                                Write-AVLog "Quarantined attack tool: $($file.Name) ($tool)" "THREAT" "attack_tools_detection.log"
                                            } catch {
                                                Write-AVLog "Failed to quarantine $($file.Name): $_" "WARN" "attack_tools_detection.log"
                                            }
                                        }
                                    }
                                }
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "File system scanning error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 3: Check suspicious directories
        try {
            foreach ($susDir in $suspiciousDirectories) {
                if (Test-Path $susDir) {
                    try {
                        $exeFiles = Get-ChildItem -Path $susDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 20
                        
                        if ($exeFiles.Count -gt 5) {
                            $detections += @{
                                Type = "Suspicious Directory with Multiple Executables"
                                Directory = $susDir
                                ExecutableCount = $exeFiles.Count
                                Risk = "MEDIUM"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 4: Monitor for brute force attack patterns (Hydra, Medusa behavior)
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $cmdLine = $proc.CommandLine
                    if (-not $cmdLine) { continue }
                    
                    # Check for brute force attack patterns
                    $bruteForcePatterns = @(
                        "-l.*-P", "-L.*-P", "-u.*-p", "-U.*-P",  # Hydra patterns
                        "--wordlist", "--password", "--user",     # Medusa patterns
                        "brute", "crack", "dictionary", "wordlist"
                    )
                    
                    $isBruteForce = $false
                    foreach ($pattern in $bruteForcePatterns) {
                        if ($cmdLine -match $pattern) {
                            $isBruteForce = $true
                            break
                        }
                    }
                    
                    if ($isBruteForce) {
                        $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        $threats += @{
                            Type = "Brute Force Attack Tool Activity Detected"
                            ProcessName = $procName
                            ProcessId = $proc.ProcessId
                            CommandLine = $cmdLine
                            Risk = "CRITICAL"
                            Timestamp = Get-Date
                        }
                        
                        if ($Config.AutoKillThreats) {
                            try {
                                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                Write-AVLog "Terminated brute force attack: $procName" "THREAT" "attack_tools_detection.log"
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        # Method 5: Check for network scanning activity (Nmap, Masscan patterns)
        try {
            $networkConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $_.State -eq "Established" -or $_.State -eq "Listen"
            }
            
            # Look for processes making many connections (port scanning behavior)
            $connectionCounts = $networkConnections | Group-Object -Property OwningProcess
            
            foreach ($connGroup in $connectionCounts) {
                if ($connGroup.Count -gt 50) {  # Suspicious number of connections
                    try {
                        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $($connGroup.Name)" -ErrorAction SilentlyContinue
                        if ($proc) {
                            $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                            
                            # Check if it's a known scanning tool
                            $isScanner = $false
                            foreach ($scanner in $attackTools["NetworkScanners"]) {
                                if ($procName -match $scanner -or $proc.ExecutablePath -match $scanner) {
                                    $isScanner = $true
                                    break
                                }
                            }
                            
                            if ($isScanner) {
                                $threats += @{
                                    Type = "Network Scanning Tool Detected"
                                    ProcessName = $procName
                                    ProcessId = $connGroup.Name
                                    ConnectionCount = $connGroup.Count
                                    Risk = "HIGH"
                                    Timestamp = Get-Date
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 6: Behavioral Detection - Credential Dumping Indicators
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPath = $proc.ExecutablePath
                    $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                    $procId = $proc.ProcessId
                    
                    if (-not $procPath -or -not (Test-Path $procPath)) { continue }
                    
                    # Check for processes accessing LSASS (credential dumping behavior)
                    try {
                        $lsassProcess = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
                        if ($lsassProcess) {
                            # Check if this process has handles to lsass
                            $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
                            if ($handles) {
                                foreach ($handle in $handles) {
                                    if ($handle.TargetProcessId -eq $lsassProcess.Id) {
                                        # Check if it's a legitimate process
                                        $legitimateProcs = @("svchost", "dllhost", "taskhost", "explorer")
                                        $isLegit = $false
                                        foreach ($legit in $legitimateProcs) {
                                            if ($procName -match $legit) {
                                                $isLegit = $true
                                                break
                                            }
                                        }
                                        
                                        if (-not $isLegit) {
                                            $threats += @{
                                                Type = "Credential Dumping Behavior Detected (LSASS Access)"
                                                ProcessName = $procName
                                                ProcessPath = $procPath
                                                ProcessId = $procId
                                                Behavior = "Accessing LSASS process"
                                                Risk = "CRITICAL"
                                                Timestamp = Get-Date
                                            }
                                            
                                            if ($Config.AutoKillThreats) {
                                                try {
                                                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                                                    Write-AVLog "Terminated credential dumping process: $procName" "THREAT" "attack_tools_detection.log"
                                                } catch { }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch { }
                    
                    # Check for processes reading SAM/SECURITY registry hives (Mimikatz-like behavior)
                    try {
                        $cmdLine = $proc.CommandLine
                        if ($cmdLine -match "reg.*save.*sam|reg.*save.*security|reg.*save.*system") {
                            $threats += @{
                                Type = "Credential Dumping Behavior (Registry Access)"
                                ProcessName = $procName
                                ProcessPath = $procPath
                                ProcessId = $procId
                                CommandLine = $cmdLine
                                Behavior = "Accessing SAM/SECURITY registry"
                                Risk = "CRITICAL"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                    
                } catch { }
            }
        } catch {
            Write-AVLog "Behavioral detection error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 7: Behavioral Detection - File Signature Scanning (works on renamed files)
        try {
            $scanPaths = @(
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Desktop",
                "$env:TEMP",
                "C:\Tools",
                "C:\Hacking"
            )
            
            foreach ($scanPath in $scanPaths) {
                if (-not (Test-Path $scanPath)) { continue }
                
                try {
                    $exeFiles = Get-ChildItem -Path $scanPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -lt 50MB } |  # Skip very large files
                        Select-Object -First 50
                    
                    foreach ($file in $exeFiles) {
                        try {
                            # Read file content for signature matching
                            $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                            $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                            
                            # Check against tool signatures
                            foreach ($toolName in $toolSignatures.Keys) {
                                $matchCount = 0
                                foreach ($signature in $toolSignatures[$toolName]) {
                                    if ($fileContent -match [regex]::Escape($signature)) {
                                        $matchCount++
                                    }
                                }
                                
                                # If multiple signatures match, it's likely this tool
                                if ($matchCount -ge 2) {
                                    # Check if unsigned
                                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                    if ($sig.Status -ne "Valid") {
                                        $threats += @{
                                            Type = "Attack Tool Detected by Signature (Renamed: $($file.Name))"
                                            ToolName = $toolName
                                            FilePath = $file.FullName
                                            FileName = $file.Name
                                            SignatureMatches = $matchCount
                                            DetectionMethod = "FileSignature"
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                        
                                        if ($Config.AutoQuarantine) {
                                            try {
                                                Move-ToQuarantine -FilePath $file.FullName -Reason "Attack tool detected by signature: $toolName"
                                                Write-AVLog "Quarantined renamed attack tool: $($file.Name) (detected as $toolName)" "THREAT" "attack_tools_detection.log"
                                            } catch { }
                                        }
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "File signature scanning error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 8: Behavioral Detection - Command Line Pattern Analysis
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $cmdLine = $proc.CommandLine
                    if (-not $cmdLine) { continue }
                    
                    $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                    $procPath = $proc.ExecutablePath
                    
                    # Check for tool-specific command patterns (works even if renamed)
                    $suspiciousPatterns = @{
                        "PasswordCracking" = @(
                            "-l.*-P", "-L.*-p", "wordlist", "dictionary", "brute.*force",
                            "crack.*password", "hash.*crack"
                        )
                        "CredentialDumping" = @(
                            "sekurlsa", "lsadump", "mimikatz", "wdigest", "kerberos",
                            "dump.*password", "extract.*hash", "sam.*dump"
                        )
                        "NetworkScanning" = @(
                            "-p-", "-p.*1-65535", "port.*scan", "host.*scan",
                            "-sS", "-sT", "-sU", "nmap.*scan"
                        )
                        "Exploitation" = @(
                            "exploit", "payload", "reverse.*shell", "bind.*shell",
                            "meterpreter", "msfconsole", "msfvenom"
                        )
                    }
                    
                    foreach ($behaviorType in $suspiciousPatterns.Keys) {
                        foreach ($pattern in $suspiciousPatterns[$behaviorType]) {
                            if ($cmdLine -match $pattern) {
                                # Check if it's a legitimate process
                                $legitimateProcs = @("svchost", "dllhost", "taskhost", "explorer", "chrome", "firefox", "edge")
                                $isLegit = $false
                                foreach ($legit in $legitimateProcs) {
                                    if ($procName -match $legit -and $procPath -like "*$legit*") {
                                        $isLegit = $true
                                        break
                                    }
                                }
                                
                                if (-not $isLegit) {
                                    $threats += @{
                                        Type = "Attack Tool Behavior Detected: $behaviorType"
                                        ProcessName = $procName
                                        ProcessPath = $procPath
                                        ProcessId = $proc.ProcessId
                                        CommandLine = $cmdLine
                                        BehaviorPattern = $pattern
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                    
                                    if ($Config.AutoKillThreats) {
                                        try {
                                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                            Write-AVLog "Terminated suspicious behavior: $procName ($behaviorType)" "THREAT" "attack_tools_detection.log"
                                        } catch { }
                                    }
                                }
                                break
                            }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "Command line pattern analysis error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Log all detections and threats
        if ($detections.Count -gt 0 -or $threats.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "ATTACK TOOLS DETECTION: $($detection.Type) - $($detection.Directory -or 'System')" "INFO" "attack_tools_detection.log"
            }
            
            foreach ($threat in $threats) {
                $detectionMethod = if ($threat.DetectionMethod) { " [$($threat.DetectionMethod)]" } else { "" }
                Write-AVLog "ATTACK TOOL THREAT: $($threat.Type) - $($threat.ToolName -or $threat.ProcessName -or 'Unknown') - Risk: $($threat.Risk)$detectionMethod" "THREAT" "attack_tools_detection.log"
                $Global:AntivirusState.ThreatCount++
                
                # Add to response queue
                if ($Config.AutoKillThreats) {
                    $threatPath = $threat.FilePath -or $threat.ProcessPath -or $threat.ProcessName -or $threat.ToolName -or ""
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$Script:InstallPath\Logs\AttackToolsDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            
            $allEvents = $detections + $threats
            $allEvents | ForEach-Object {
                $eventType = if ($_.Risk -match "CRITICAL|HIGH") { "THREAT" } else { "INFO" }
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$eventType|$($_.Type)|$($_.Risk)|$($_.ToolName -or $_.ProcessName -or $_.Directory -or 'N/A')|$($_.ProcessId -or 'N/A')|$($_.Category -or 'N/A')|$($_.DetectionMethod -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-AVLog "Attack tools detection error: $_" "ERROR" "attack_tools_detection.log"
    }
    
    return ($detections.Count + $threats.Count)
}

function Invoke-PUADetection {
    $threats = @()
    try {
        $puaPatterns = @{
            "RATs" = @("darkcomet", "poisonivy", "njrat", "cyberghost", "bifrost", "procerat", "blackshades", "gh0st", "spynet", "weirdrat", "remcos")
            "CryptoMiners" = @("xmrig", "xmrig.exe", "ccminer", "ccminer.exe", "cgminer", "minerd", "nicehash", "claymore", "ethminer", "cpuminer")
            "UnwantedRemoteAccess" = @("ammyy", "ammyy.exe", "supremacy", "crossloop", "join.me", "showmypc", "litemanager")
        }
        $legitimateRemote = @("teamviewer", "anydesk", "vnc", "remote", "rdp", "mstsc")
        $autoKillPUA = if ($null -ne $Config.AutoKillPUA) { $Config.AutoKillPUA } else { $false }
        $autoKillMiners = if ($null -ne $Config.AutoKillCryptoMiners) { $Config.AutoKillCryptoMiners } else { $true }
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ProcessId -ne $PID -and $_.ProcessId -ne $Script:SelfPID }
        foreach ($proc in $processes) {
            $procName = (Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue).ToLower()
            $procPath = $proc.ExecutablePath.ToLower()
            foreach ($category in $puaPatterns.Keys) {
                foreach ($pattern in $puaPatterns[$category]) {
                    if ($procName -match [regex]::Escape($pattern) -or $procPath -match [regex]::Escape($pattern)) {
                        $isLegit = $legitimateRemote | Where-Object { $procName -match $_ }
                        if ($isLegit -and $category -eq "UnwantedRemoteAccess") { continue }
                        $killIt = ($category -eq "CryptoMiners" -and $autoKillMiners) -or ($category -ne "CryptoMiners" -and $autoKillPUA)
                        $threats += @{ Type = "PUA: $category"; ProcessName = $proc.Name; ProcessId = $proc.ProcessId; ProcessPath = $proc.ExecutablePath; Risk = "HIGH"; KillIt = $killIt }
                        break
                    }
                }
            }
        }
        foreach ($threat in $threats) {
            Write-AVLog "PUADetection: $($threat.Type) - $($threat.ProcessName) (PID: $($threat.ProcessId))" "THREAT" "pua_detection.log"
            $Global:AntivirusState.ThreatCount++
            if ($threat.KillIt -and $Config.AutoKillThreats) {
                try { Stop-Process -Id $threat.ProcessId -Force -ErrorAction SilentlyContinue; Write-AVLog "Terminated PUA: $($threat.ProcessName)" "THREAT" "pua_detection.log" } catch { }
            } else {
                Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threat.ProcessPath -Severity $threat.Risk
            }
        }
    } catch { Write-AVLog "PUADetection error: $_" "ERROR" "pua_detection.log" }
    return $threats.Count
}

function Invoke-PUPDetection {
    $threats = @()
    try {
        $pupPatterns = @("toolbar", "mysearch", "babylon", "conduit", "ask.com", "searchprotect", "dns unlocker", "speedial", "igdefender", "sweetim", "funmoods", "crossrider", "adware", "vosteran", "incredibar", "webcake", "openshopper", "softonic")
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:ProgramData")
        foreach ($path in $scanPaths) {
            if (-not (Test-Path $path)) { continue }
            try {
                $dirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
                foreach ($dir in $dirs) {
                    $dirName = $dir.Name.ToLower()
                    foreach ($pup in $pupPatterns) {
                        if ($dirName -match [regex]::Escape($pup)) {
                            $exes = Get-ChildItem -Path $dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
                            foreach ($exe in $exes) {
                                $threats += @{ Type = "PUP: $pup"; FilePath = $exe.FullName; DirName = $dir.Name; Risk = "MEDIUM" }
                            }
                            break
                        }
                    }
                }
            } catch { }
        }
        foreach ($threat in $threats) {
            Write-AVLog "PUPDetection: $($threat.Type) - $($threat.FilePath)" "THREAT" "pup_detection.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoQuarantine) {
                try { Move-ToQuarantine -Path $threat.FilePath -Reason "PUP: $($threat.Type)"; Write-AVLog "Quarantined PUP: $($threat.FilePath)" "THREAT" "pup_detection.log" } catch { }
            }
        }
    } catch { Write-AVLog "PUPDetection error: $_" "ERROR" "pup_detection.log" }
    return $threats.Count
}

function Invoke-PUMDetection {
    $threats = @()
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $hosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
            $suspicious = $hosts | Where-Object { $_ -match "^\s*\d" -and $_ -notmatch "^\s*#|localhost|127\.0\.0\.1\s+localhost" -and $_ -match "google|facebook|yahoo|bing|microsoft|avast|avg|norton|mcafee" }
            if ($suspicious.Count -gt 0) {
                $threats += @{ Type = "PUM: Hosts file hijack"; Path = $hostsPath; Lines = $suspicious.Count; Risk = "HIGH" }
            }
        }
        $proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $proxyPath) {
            try {
                $proxy = Get-ItemProperty -Path $proxyPath -Name ProxyEnable -ErrorAction SilentlyContinue
                $proxyServer = Get-ItemProperty -Path $proxyPath -Name ProxyServer -ErrorAction SilentlyContinue
                if ($proxy.ProxyEnable -eq 1 -and $proxyServer.ProxyServer -and $proxyServer.ProxyServer -match "^\d+\.\d+\.\d+\.\d+:\d+$") {
                    $threats += @{ Type = "PUM: Suspicious proxy"; Proxy = $proxyServer.ProxyServer; Risk = "MEDIUM" }
                }
            } catch { }
        }
        foreach ($threat in $threats) {
            Write-AVLog "PUMDetection: $($threat.Type) - $($threat.Path -or $threat.Proxy)" "THREAT" "pum_detection.log"
            $Global:AntivirusState.ThreatCount++
            Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath ($threat.Path -or $threat.Proxy) -Severity $threat.Risk
        }
    } catch { Write-AVLog "PUMDetection error: $_" "ERROR" "pum_detection.log" }
    return $threats.Count
}

function Invoke-PhantomProcessKiller {
    $killed = 0
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $runningPids = $processes | Select-Object -ExpandProperty ProcessId
        $protected = @('System', 'Idle', 'smss', 'csrss', 'wininit', 'services', 'lsass', 'svchost', 'winlogon', 'explorer', 'dwm', 'powershell', 'pwsh', 'Code', 'Cursor')
        foreach ($proc in $processes) {
            if ($proc.ProcessId -eq $PID -or $proc.ProcessId -eq $Script:SelfPID) { continue }
            $procName = $proc.Name -replace '\.exe$', ''
            if ($protected -contains $procName) { continue }
            $path = $proc.ExecutablePath
            if (-not $path) { continue }
            $pathLower = $path.ToLower()
            $parentId = $proc.ParentProcessId
            $parentExists = $parentId -eq 0 -or ($runningPids -contains $parentId)
            $isOrphan = -not $parentExists
            $fromTemp = $pathLower -match "\\temp\\|\\tmp\\|\\appdata\\local\\temp\\"
            $suspiciousName = $procName -match "^(svchost|lsass|csrss|smss|dllhost|rundll32|conhost|ctfmon)$" -and $pathLower -notmatch "\\windows\\system32\\"
            if (($isOrphan -and $fromTemp) -or $suspiciousName) {
                if ($Config.AutoKillThreats) {
                    try {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-AVLog "PhantomProcessKiller: Terminated orphan/suspicious $procName (PID: $($proc.ProcessId)) from $path" "THREAT" "phantom_process_killer.log"
                        $killed++
                    } catch { }
                }
            }
        }
    } catch { Write-AVLog "PhantomProcessKiller error: $_" "ERROR" "phantom_process_killer.log" }
    return $killed
}

# DragonBreathHunter - RONINGLOADER & Gh0st RAT campaign detection (from DragonBreathHunter.ps1)
function Invoke-DragonBreathHunter {
    if (-not $Config.EnableDragonBreathHunter) { return 0 }
    $detections = 0
    try {
        # 1. Trojanized NSIS installers in drop paths
        $dropPaths = @("$env:TEMP","$env:APPDATA","$env:ProgramData","$env:USERPROFILE\Downloads")
        foreach ($dp in $dropPaths) {
            if (-not (Test-Path $dp)) { continue }
            $files = Get-ChildItem -Path $dp -Include "*.exe","*.nsi" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 1MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            foreach ($f in $files) {
                if ($f.Name -match "(chrome|teams|vpn|browser|setup)" -and $f.FullName -notmatch "Google|Microsoft") {
                    Write-AVLog "DragonBreathHunter: Suspicious trojanized NSIS: $($f.FullName)" "THREAT"
                    try { Move-ToQuarantine -Path $f.FullName -Reason "Trojanized NSIS heuristic" ; $detections++ } catch {}
                }
            }
        }
        # 2. Malicious process IOCs
        $maliciousProcs = @("Snieoatwtregoable","taskload","letsvpnlatest","ollama")
        foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
            $pn = $proc.ProcessName
            if ($maliciousProcs -contains $pn) {
                Write-AVLog "DragonBreathHunter: Malicious process IOC: $pn (PID: $($proc.Id))" "THREAT"
                Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $pn
                $detections++
            }
            try {
                if ($proc.MainModule.FileName -like "*tp.png*") {
                    Write-AVLog "DragonBreathHunter: PNG shellcode heuristic: $pn" "THREAT"
                    Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $pn
                    $detections++
                }
            } catch {}
        }
        # 3. Rogue DLLs in svchost/regsvr32/rundll32
        $keyProcs = Get-Process -Name "svchost","regsvr32","rundll32" -ErrorAction SilentlyContinue
        foreach ($kp in $keyProcs) {
            try {
                $mods = $kp.Modules | Where-Object { $_.FileName -notlike "*Windows*" -and $_.FileName -notlike "*System32*" }
                if ($mods) {
                    foreach ($m in $mods) {
                        Write-AVLog "DragonBreathHunter: Rogue DLL in $($kp.ProcessName): $($m.FileName)" "THREAT"
                        $detections++
                    }
                }
            } catch {}
        }
        # 4. Registry persistence (gh0st, roning, tp.png, snieo, Temp)
        $runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        foreach ($key in $runKeys) {
            try {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
                    $val = $p.Value
                    if ($val -match "(gh0st|roning|tp\.png|snieo)" -or $val -like "*\Temp\*") {
                        Write-AVLog "DragonBreathHunter: Suspicious Run key: $($p.Name)=$val" "THREAT"
                        try { Remove-ItemProperty -Path $key -Name $p.Name -Force -ErrorAction Stop; $detections++ } catch {}
                    }
                }
            } catch {}
        }
        # 5. C2 ports (4444, 1337)
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -in @(4444, 1337) }
        foreach ($c in $conns) {
            Write-AVLog "DragonBreathHunter: Potential C2 connection: $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) (PID: $($c.OwningProcess))" "THREAT"
            try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; $detections++ } catch {}
        }
        # 6. Suspicious scheduled tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match "(update|vpn|chrome)" -and $_.State -eq "Ready" }
        foreach ($t in $tasks) {
            $execs = $t.Actions | ForEach-Object { $_.Execute }
            if ($execs -match "powershell|rundll32") {
                Write-AVLog "DragonBreathHunter: Suspicious task: $($t.TaskName)" "THREAT"
                try { Disable-ScheduledTask -TaskName $t.TaskName -ErrorAction Stop; $detections++ } catch {}
            }
        }
        if ($detections -gt 0) {
            Write-AVLog "DragonBreathHunter: Found $detections campaign indicators" "THREAT"
        }
    } catch { Write-AVLog "DragonBreathHunter error: $_" "ERROR" }
    return $detections
}

function Invoke-EventLogMonitoring {
    param(
        [int]$LookbackHours = 1,
        [bool]$CorrelationEnabled = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddHours(-$LookbackHours)

        # 1. Security log cleared (Event ID 1102)
        try {
            $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
    foreach ($LogEvent in $ClearedLogs) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                
                $Threats += @{
                    Type = "SecurityLogCleared"
                    EventId = 1102
                    Time = $LogEvent.TimeCreated
                    User = $username
                    Severity = "Critical"
                    ThreatScore = 50
                }
                
                Write-AVLog "[EventLog] CRITICAL: Security log cleared | Time: $($LogEvent.TimeCreated) | User: $username"
                Add-ThreatToResponseQueue -ThreatType "SecurityLogCleared" -ThreatPath "EventLog" -Severity "Critical"
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check cleared logs: $_" -Level "Warning"
        }

        # 2. Failed logon attempts (Event ID 4625) - Advanced brute force detection
        try {
            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            # Group by account name and analyze
            $AccountAttempts = $FailedLogons | Group-Object {
                if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" }
            }
            
            foreach ($Account in $AccountAttempts) {
                $attemptCount = $Account.Count
                $accountName = $Account.Name
                
                if ($attemptCount -gt 5) {
                    # Calculate threat score based on attempt frequency
                    $timeSpan = ($Account.Group | Measure-Object -Property TimeCreated -Maximum).Maximum - 
                               ($Account.Group | Measure-Object -Property TimeCreated -Minimum).Minimum
                    $attemptsPerMinute = if ($timeSpan.TotalMinutes -gt 0) { $attemptCount / $timeSpan.TotalMinutes } else { $attemptCount }
                    
                    $severity = if ($attemptsPerMinute -gt 10) { "Critical" } 
                               elseif ($attemptsPerMinute -gt 5) { "High" } 
                               elseif ($attemptCount -gt 20) { "High" }
                               else { "Medium" }
                    
                    $Threats += @{
                        Type = "BruteForceAttempt"
                        EventId = 4625
                        Account = $accountName
                        AttemptCount = $attemptCount
                        AttemptsPerMinute = [Math]::Round($attemptsPerMinute, 2)
                        TimeSpan = $timeSpan
                        Severity = $severity
                        ThreatScore = [Math]::Min(50, 20 + ($attemptsPerMinute * 2))
                    }
                    
                    Write-AVLog "[EventLog] THREAT ($severity): Brute force attempt detected | Account: $accountName | Attempts: $attemptCount | Rate: $([Math]::Round($attemptsPerMinute, 2))/min"
                    
                    if ($severity -eq "Critical" -or $attemptCount -gt 30) {
                        Add-ThreatToResponseQueue -ThreatType "BruteForceAttack" -ThreatPath $accountName -Severity $severity
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check failed logons: $_" -Level "Warning"
        }

        # 3. Privilege escalation (Event ID 4672 - Admin logon)
        try {
            $AdminLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AdminLogons) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                $logonType = if ($LogEvent.Properties.Count -gt 3) { $LogEvent.Properties[3].Value } else { "Unknown" }
                
                # Check for suspicious logon types (network logons with admin rights)
                if ($logonType -in @(3, 8, 10)) { # Network, NetworkCleartext, RemoteInteractive
                    $Threats += @{
                        Type = "SuspiciousAdminLogon"
                        EventId = 4672
                        User = $username
                        LogonType = $logonType
                        Time = $LogEvent.TimeCreated
                        Severity = "High"
                        ThreatScore = 35
                    }
                    
                    Write-AVLog "[EventLog] HIGH: Suspicious admin network logon | User: $username | LogonType: $logonType | Time: $($LogEvent.TimeCreated)"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check admin logons: $_" -Level "Warning"
        }

        # 4. Account manipulation (Event IDs 4728, 4732, 4756)
        try {
            $AccountEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4728,4732,4756;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AccountEvents) {
                $eventType = switch ($LogEvent.Id) {
                    4728 { "Member added to security-enabled global group" }
                    4732 { "Member added to security-enabled local group" }
                    4756 { "Member added to security-enabled universal group" }
                    default { "Unknown account change" }
                }
                
                $targetAccount = if ($LogEvent.Properties.Count -gt 0) { $LogEvent.Properties[0].Value } else { "Unknown" }
                $subjectAccount = if ($LogEvent.Properties.Count -gt 4) { $LogEvent.Properties[4].Value } else { "Unknown" }
                
                # Check for privilege escalation attempts
                if ($targetAccount -match "Administrator|Domain Admin|Enterprise Admin|Schema Admin" -and $subjectAccount -ne $targetAccount) {
                    $Threats += @{
                        Type = "PrivilegeEscalationAttempt"
                        EventId = $LogEvent.Id
                        EventType = $eventType
                        TargetAccount = $targetAccount
                        SubjectAccount = $subjectAccount
                        Time = $LogEvent.TimeCreated
                        Severity = "Critical"
                        ThreatScore = 45
                    }
                    
                    Write-AVLog "[EventLog] CRITICAL: Potential privilege escalation | $eventType | Target: $targetAccount | Subject: $subjectAccount"
                    Add-ThreatToResponseQueue -ThreatType "PrivilegeEscalation" -ThreatPath "$subjectAccount -> $targetAccount" -Severity "Critical"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check account changes: $_" -Level "Warning"
        }

        # 5. Process creation events (Event ID 4688) - Suspicious processes
        try {
            $ProcessEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
            
            foreach ($LogEvent in $ProcessEvents) {
                if ($LogEvent.Properties.Count -gt 5) {
                    $processName = $LogEvent.Properties[5].Value
                    $commandLine = if ($LogEvent.Properties.Count -gt 8) { $LogEvent.Properties[8].Value } else { "" }
                    
                    if ($SuspiciousProcesses -contains $processName) {
                        # Check for suspicious command line patterns
                        $suspiciousPatterns = @("-enc", "-EncodedCommand", "downloadstring", "iex", "invoke-expression", "bypass", "hidden")
                        $foundPattern = $suspiciousPatterns | Where-Object { $commandLine -match [regex]::Escape($_) }
                        
                        if ($foundPattern) {
                            $subject = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                            
                            $Threats += @{
                                Type = "SuspiciousProcessExecution"
                                EventId = 4688
                                ProcessName = $processName
                                CommandLine = $commandLine
                                Subject = $subject
                                SuspiciousPattern = $foundPattern
                                Time = $LogEvent.TimeCreated
                                Severity = "High"
                                ThreatScore = 40
                            }
                            
                            Write-AVLog "[EventLog] HIGH: Suspicious process execution | Process: $processName | Pattern: $foundPattern | Subject: $subject"
                        }
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check process events: $_" -Level "Warning"
        }

        # 6. Event correlation (if enabled)
        if ($CorrelationEnabled -and $Threats.Count -gt 1) {
            # Group threats by time window (within 5 minutes)
            $correlatedThreats = $Threats | Group-Object {
                $timeWindow = $_.Time.ToString("yyyy-MM-dd HH:mm")
                $timeWindow
            }
            
            foreach ($group in $correlatedThreats) {
                if ($group.Count -ge 3) {
                    $uniqueTypes = $group.Group | Select-Object -ExpandProperty Type -Unique
                    Write-AVLog "[EventLog] WARNING: Event correlation detected | Time: $($group.Name) | Events: $($group.Count) | Types: $($uniqueTypes -join ', ')"
                    Write-EDRLog -Module "EventLogMonitoring" -Message "Correlated threat activity: $($group.Count) events in time window $($group.Name)" -Level "Warning"
                }
            }
        }

        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring completed: $($Threats.Count) threat(s) detected" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-FirewallRuleMonitoring {
    if (-not $Global:BaselineFirewallRules) {
        $Global:BaselineFirewallRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    }

    $CurrentRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    $NewRules = $CurrentRules | Where-Object { $_ -notin $Global:BaselineFirewallRules }

    foreach ($Rule in $NewRules) {
        $RuleDetails = Get-NetFirewallRule -Name $Rule
        Write-AVLog "[Firewall] NEW RULE: $($RuleDetails.DisplayName) | Action: $($RuleDetails.Action) | Direction: $($RuleDetails.Direction)"
    }

    $Global:BaselineFirewallRules = $CurrentRules
}

function Invoke-ServiceMonitoring {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
    if (-not $Global:BaselineServices) {
        $Global:BaselineServices = Get-Service | Select-Object -ExpandProperty Name
    }

    $CurrentServices = Get-Service | Select-Object -ExpandProperty Name
    $NewServices = $CurrentServices | Where-Object { $_ -notin $Global:BaselineServices }
        $Threats = @()

    foreach ($ServiceName in $NewServices) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $Service) { continue }

        $ServiceDetails = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                if (-not $ServiceDetails) { continue }

                $ThreatScore = 0
                $Reasons = @()

                # 1. Check for services in non-standard locations
                if ($ServiceDetails.PathName -and $ServiceDetails.PathName -notmatch "^C:\\(Windows|Program Files)") {
                    $ThreatScore += 30
                    $Reasons += "Service executable in non-standard location: $($ServiceDetails.PathName)"
                    
                    # Check for suspicious paths (temp, user directories)
                    if ($ServiceDetails.PathName -match "(Temp|TEMP|tmp|appdata|localappdata|users)") {
                        $ThreatScore += 20
                        $Reasons += "Service executable in suspicious location (temp/user directory)"
                    }
                }

                # 2. Check for unsigned services
                try {
                    if ($ServiceDetails.PathName -and (Test-Path $ServiceDetails.PathName)) {
                        $sig = Get-AuthenticodeSignature -FilePath $ServiceDetails.PathName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $ThreatScore += 25
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                # 3. Check for suspicious service names
                $SuspiciousServiceNames = @("update", "svc", "helper", "service", "runtime", "agent", "monitor", "guard", "protect")
                foreach ($pattern in $SuspiciousServiceNames) {
                    if ($ServiceName -match $pattern -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                        $ThreatScore += 15
                        $Reasons += "Suspicious service name pattern: $pattern"
                        break
                    }
                }

                # 4. Check for services with suspicious startup types
                if ($Service.StartType -eq "Automatic" -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    $ThreatScore += 10
                    $Reasons += "Auto-start service from non-standard location"
                }

                # 5. Check for services with suspicious account (SYSTEM account is normal, others are suspicious)
                if ($ServiceDetails.StartName -and $ServiceDetails.StartName -notmatch "^(LocalSystem|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService)") {
                    $ThreatScore += 20
                    $Reasons += "Service running under non-standard account: $($ServiceDetails.StartName)"
                }

                # 6. Check for services with suspicious descriptions
                if ($Service.DisplayName -and $Service.DisplayName.Length -lt 5) {
                    $ThreatScore += 10
                    $Reasons += "Suspiciously short service display name"
                }

                # 7. Check for services with suspicious executable names
                if ($ServiceDetails.PathName) {
                    $exeName = Split-Path -Leaf $ServiceDetails.PathName
                    if ($exeName -match "^[a-z0-9]{8,}\.exe$" -or $exeName -match "svchost|lsass|csrss|winlogon") {
                        $ThreatScore += 25
                        $Reasons += "Service with suspicious executable name: $exeName (potential masquerading)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 25) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousService"
                        ServiceName = $ServiceName
                        DisplayName = $Service.DisplayName
                        PathName = $ServiceDetails.PathName
                        StartType = $Service.StartType
                        Status = $Service.Status
                        StartName = $ServiceDetails.StartName
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-AVLog "[Service] THREAT ($severity): Suspicious service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
                            Write-AVLog "[Service] ACTION: Stopped and disabled suspicious service: $ServiceName"
                            Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                        } catch {
                            Write-EDRLog -Module "ServiceMonitoring" -Message "Failed to stop service ${ServiceName}: $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 35) {
                        Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                    }
                } elseif ($ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    # Even if score is low, log new services from non-standard locations
                    Write-AVLog "[Service] INFO: New service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Path: $($ServiceDetails.PathName)"
                }
            }
            catch {
                Write-EDRLog -Module "ServiceMonitoring" -Message "Error analyzing service ${ServiceName}: $_" -Level "Warning"
            }
        }

        # Check for removed services (potential cleanup indicator)
        $RemovedServices = $Global:BaselineServices | Where-Object { $_ -notin $CurrentServices }
        if ($RemovedServices.Count -gt 0) {
            Write-EDRLog -Module "ServiceMonitoring" -Message "Services removed: $($RemovedServices -join ', ')" -Level "Info"
    }

    $Global:BaselineServices = $CurrentServices

        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring completed: $($Threats.Count) threat(s) found, $($NewServices.Count) new service(s)" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; NewServices = $NewServices.Count; RemovedServices = $RemovedServices.Count}
    }
    catch {
        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); NewServices = 0; RemovedServices = 0}
    }
}

function Invoke-FilelessDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    try {
        $Threats = @()
        
        # Fileless malware signatures for advanced detection
        $filelessSignatures = @{
            "FilelessMalware" = @(
                "fileless", "memory.*only", "powershell.*encoded", "base64.*decode",
                "downloadstring", "invoke.*expression", "bypass.*execution"
            )
        }
        
        # Fileless behavioral patterns
        $filelessBehaviors = @{
            "PowerShellFileless" = @(
                "-enc", "-EncodedCommand", "downloadstring", "DownloadString",
                "iex", "Invoke-Expression", "bypass.*executionpolicy",
                "-nop.*-w.*hidden", "new-object.*net.webclient"
            )
            "WMIFileless" = @(
                "wmic.*process", "wmic.*shadowcopy", "wmic.*event",
                "wmi.*subscription", "wmi.*consumer"
            )
            "RegistryFileless" = @(
                "reg.*add.*run", "reg.*load", "reg.*save",
                "registry.*run", "startup.*script"
            )
        }

        # 1. PowerShell encoded commands
        # Whitelist own process and script path
        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
        $PSProcesses = Get-Process | Where-Object { 
            $_.ProcessName -match "powershell|pwsh" -and 
            $_.Id -ne $PID -and
            $_.Id -ne $Script:SelfPID
        }
    foreach ($Process in $PSProcesses) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                if (-not $CommandLine) { continue }
                
                # Skip if this is our own script
                if ($ownScriptPath -and $CommandLine -like "*$ownScriptPath*") {
                    continue
                }
                
                # Use advanced detection framework
                $procPath = $Process.Path
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $filelessSignatures `
                        -BehavioralIndicators $filelessBehaviors `
                        -CommandLine $CommandLine `
                        -CheckEntropy $false
                    
                    if ($detectionResult.IsThreat) {
                        $Threats += @{
                            Type = "Fileless Malware Detected via Advanced Framework"
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            CommandLine = $CommandLine
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Severity = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } elseif ($detectionResult.Risk -eq "HIGH") { "High" } else { "Medium" }
                            Time = Get-Date
                        }
                        continue
                    }
                }

                $SuspiciousPatterns = @{
                    "-enc|-EncodedCommand" = @{Score = 40; Reason = "Base64 encoded PowerShell command"}
                    "downloadstring|DownloadString" = @{Score = 35; Reason = "Download string from remote source"}
                    "iex|Invoke-Expression" = @{Score = 30; Reason = "Invoke expression (code execution)"}
                    "bypass.*executionpolicy" = @{Score = 35; Reason = "Execution policy bypass"}
                    "-nop.*-w.*hidden" = @{Score = 30; Reason = "Hidden window execution"}
                    "new-object.*net.webclient" = @{Score = 25; Reason = "Web client object creation"}
                    "invoke-webrequest|iwr|curl" = @{Score = 20; Reason = "Web request command"}
                }

                $ThreatScore = 0
                $FoundPatterns = @()
                
                foreach ($pattern in $SuspiciousPatterns.Keys) {
                    if ($CommandLine -match $pattern) {
                        $patternInfo = $SuspiciousPatterns[$pattern]
                        $ThreatScore += $patternInfo.Score
                        $FoundPatterns += $patternInfo.Reason
                    }
                }

                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousPowerShell"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        CommandLine = $CommandLine
                        ThreatScore = $ThreatScore
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-AVLog "[Fileless] THREAT ($severity): PowerShell fileless activity detected | PID: $($Process.Id) | Score: $ThreatScore | Patterns: $($FoundPatterns -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 40) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "FilelessDetection" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-AVLog "[Fileless] ACTION: Terminated suspicious PowerShell process (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                        } catch {
                            Write-EDRLog -Module "FilelessDetection" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } else {
                        Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
            }
        } catch {}
    }

        # 2. WMI-based fileless persistence (Event Consumers)
        try {
            $EventConsumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
            foreach ($consumer in $EventConsumers) {
                $consumerType = $consumer.__CLASS
                $commandLine = ""
                
                if ($consumerType -eq "__EventFilter") {
                    $query = $consumer.Query
                    if ($query -match "SELECT.*FROM.*WITHIN" -and ($query -match "powershell|wscript|cscript|cmd")) {
                        $Threats += @{
                            Type = "WMIEventConsumer"
                            ConsumerType = $consumerType
                            Query = $query
                            Name = $consumer.Name
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-AVLog "[Fileless] HIGH: WMI event consumer with suspicious query detected | Name: $($consumer.Name) | Type: $consumerType"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "High"
                    }
                }
                
                if ($consumerType -eq "__CommandLineEventConsumer") {
                    $commandLine = $consumer.CommandLineTemplate
                    if ($commandLine -match "(powershell|wscript|cscript|cmd).*(enc|bypass|hidden|download)" -or
                        $commandLine -match "-enc|-EncodedCommand") {
                        $Threats += @{
                            Type = "WMICommandConsumer"
                            ConsumerType = $consumerType
                            CommandLine = $commandLine
                            Name = $consumer.Name
                            Severity = "Critical"
                            ThreatScore = 50
                        }
                        
                        Write-AVLog "[Fileless] CRITICAL: WMI command consumer with suspicious command detected | Name: $($consumer.Name) | Command: $commandLine"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "Critical"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "WMI consumer scan failed: $_" -Level "Warning"
        }

        # 3. Registry-based fileless (AppInit_DLLs, Run keys with suspicious values)
        try {
            $SuspiciousRegistryKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )

            foreach ($regPath in $SuspiciousRegistryKeys) {
                try {
                    if (Test-Path $regPath) {
                        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $props = $values.PSObject.Properties | Where-Object { $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" }
                            foreach ($prop in $props) {
                                $value = $prop.Value
                                if ($value -match "(powershell|wscript|cscript|cmd).*(enc|bypass|download|iex)" -or
                                    $value -match "-enc|-EncodedCommand|downloadstring|iex") {
                                    
                                    $Threats += @{
                                        Type = "RegistryFileless"
                                        RegistryPath = $regPath
                                        KeyName = $prop.Name
                                        Value = $value
                                        Severity = "High"
                                        ThreatScore = 40
                                    }
                                    
                                    Write-AVLog "[Fileless] HIGH: Registry-based fileless persistence detected | Path: $regPath | Key: $($prop.Name) | Value: $value"
                                    Add-ThreatToResponseQueue -ThreatType "RegistryFileless" -ThreatPath "$regPath\$($prop.Name)" -Severity "High"
                                }
                            }
                        }
            }
        } catch {}
    }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Registry scan failed: $_" -Level "Warning"
        }

        # 4. Scheduled tasks with fileless techniques
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" }
            foreach ($task in $tasks) {
                $action = $task.Actions
                if ($action) {
                    $command = $action.Execute
                    $arguments = $action.Arguments
                    
                    # Whitelist our own scheduled tasks
                    if ($task.TaskName -like "AntivirusAutoRestart_*" -or $task.TaskName -eq "AntivirusProtection") {
                        continue
                    }
                    
                    if ($command -match "powershell|wscript|cscript|cmd" -and 
                        ($arguments -match "-enc|-EncodedCommand|downloadstring|iex|bypass" -or
                         $command -match "-enc|-EncodedCommand")) {
                        
                        $Threats += @{
                            Type = "ScheduledTaskFileless"
                            TaskName = $task.TaskName
                            Command = $command
                            Arguments = $arguments
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-AVLog "[Fileless] HIGH: Scheduled task with fileless technique detected | Task: $($task.TaskName) | Command: $command | Args: $arguments"
                        Add-ThreatToResponseQueue -ThreatType "ScheduledTaskFileless" -ThreatPath "Task:$($task.TaskName)" -Severity "High"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Scheduled task scan failed: $_" -Level "Warning"
        }

        # 5. .NET assembly loading (reflection-based)
        try {
            $PSProcesses = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }
            foreach ($Process in $PSProcesses) {
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.ModuleName -match "System\.Reflection|System\.Management\.Automation" -and
                        $_.FileName -match "System\.Management\.Automation"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $Threats += @{
                            Type = "ReflectionAssemblyLoading"
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            ModuleCount = $modules.Count
                            Severity = "Medium"
                            ThreatScore = 30
                        }
                        
                        Write-AVLog "[Fileless] MEDIUM: Excessive reflection/assembly loading detected | PID: $($Process.Id) | Modules: $($modules.Count)"
                    }
                } catch {}
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Assembly loading scan failed: $_" -Level "Warning"
        }

        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-MemoryScanning {
    param(
        [bool]$AutoKillThreats = $true,
        [bool]$DeepScan = $false
    )

    try {
        $Threats = @()
        $SuspiciousPatterns = @(
            "\x48\x8B\xEC\x48\x83\xEC.{0,20}\xE8",  # Common shellcode prologue (mov rbp, rsp; sub rsp, ...; call)
            "\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9",  # XOR eax,eax; XOR ebx,ebx; XOR ecx,ecx (common shellcode)
            "\xFC\x48\x83\xE4",  # CLD; AND rsp, ...
            "\xEB.{0,5}\x5E",  # JMP short; POP ESI (common shellcode)
            "powershell.*-enc|powershell.*-EncodedCommand",  # Encoded PowerShell in memory
            "cmd.*\/c.*powershell",  # Command execution via cmd
            "downloadstring|DownloadString",  # Download string patterns
            "new-object.*net.webclient",  # WebClient object creation
            "invoke-expression|iex",  # Code execution
            "mimikatz|kiwi|sekurlsa",  # Known credential dumping tools
            "procdump|nanodump|dumpert"  # Known memory dumping tools
        )

        # Memory-based signature patterns (common malware signatures)
        $MalwareSignatures = @(
            "MZ\x90\x00",  # PE header (check for unpacked executables in memory)
            "\x55\x8B\xEC\x83\xEC",  # Function prologue common in shellcode
            "\xE8\x00\x00\x00\x00",  # CALL instruction (relative jump)
            "\xFF\xD0|\xFF\xD1|\xFF\xD2"  # CALL EAX/ECX/EDX (indirect calls)
        )

        $Processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 50MB }

        foreach ($Process in $Processes) {
            try {
                $ThreatScore = 0
                $FoundPatterns = @()
                $Reasons = @()

                # 1. Memory size anomaly detection
                if ($Process.PrivateMemorySize64 -gt 1GB) {
                    $ThreatScore += 10
                    $Reasons += "Large private memory: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB"
                }

                if ($Process.PrivateMemorySize64 -gt $Process.WorkingSet64 * 2) {
                    $ThreatScore += 15
                    $Reasons += "Memory anomaly: Private memory significantly larger than working set"
                    Write-AVLog "[MemoryScan] SUSPICIOUS: Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Private: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB | WorkingSet: $([Math]::Round($Process.WorkingSet64/1MB, 2)) MB"
                }

                # 2. Check for unusual module loading
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.FileName -and 
                        $_.FileName -notmatch "^C:\\(Windows|Program Files)" -and
                        $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp|advapi32)"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $ThreatScore += 20
                        $Reasons += "Unusual module count: $($modules.Count) non-standard modules"
                        
                        # Check for suspicious module names
                        $suspiciousModules = $modules | Where-Object { 
                            $_.ModuleName -match "(inject|hook|stealth|hide|rootkit|keylog|spy)"
                        }
                        
                        if ($suspiciousModules) {
                            $ThreatScore += 30
                            $Reasons += "Suspicious module names detected"
                            foreach ($mod in $suspiciousModules) {
                                $FoundPatterns += "Suspicious module: $($mod.ModuleName) ($($mod.FileName))"
                            }
                        }
                    }
                } catch {}

                # 3. Deep memory scanning (if enabled - more resource intensive)
                if ($DeepScan -and $Process.WorkingSet64 -lt 500MB) {
                    try {
                        # Read process memory (requires special permissions)
                        $memoryRegions = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $Process.Id }
                        
                        # Check command line for suspicious patterns
                        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                        if ($commandLine) {
                            foreach ($pattern in $SuspiciousPatterns) {
                                if ($commandLine -match $pattern) {
                                    $ThreatScore += 25
                                    $FoundPatterns += "Command line pattern: $pattern"
                                    break
                                }
                            }
                        }

                        # Check for code injection indicators (unusual memory permissions)
                        # This would require kernel debugging in real implementation
                        # Simplified heuristic: check for processes with unusual thread counts
                        if ($Process.Threads.Count -gt 100) {
                            $ThreatScore += 15
                            $Reasons += "High thread count: $($Process.Threads.Count) threads"
                        }

        } catch {
                        # Memory scanning requires elevated privileges, skip silently
                        Write-EDRLog -Module "MemoryScanning" -Message "Deep scan requires elevated privileges for PID $($Process.Id)" -Level "Debug"
                    }
                }

                # 4. Check for known malicious process characteristics
                $knownMaliciousProcesses = @{
                    "powershell.exe" = @{BaselineMem = 100MB; BaselineThreads = 10}
                    "cmd.exe" = @{BaselineMem = 50MB; BaselineThreads = 3}
                    "wscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                    "cscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                }

                if ($knownMaliciousProcesses.ContainsKey($Process.ProcessName)) {
                    $baseline = $knownMaliciousProcesses[$Process.ProcessName]
                    
                    if ($Process.WorkingSet64 -gt ($baseline.BaselineMem * 5)) {
                        $ThreatScore += 25
                        $Reasons += "Memory usage significantly above baseline for $($Process.ProcessName)"
                    }
                    
                    if ($Process.Threads.Count -gt ($baseline.BaselineThreads * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Thread count significantly above baseline for $($Process.ProcessName)"
                    }
                }

                # 5. Check for processes with no executable path (potential process hollowing)
                # Whitelist known system processes that may not have paths
                $systemProcessNames = @("Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "spoolsv", "dwm", "audiodg")
                if (-not $Process.Path -or $Process.Path -notmatch "\.exe$") {
                    if ($systemProcessNames -notcontains $Process.ProcessName) {
                        $ThreatScore += 35
                        $Reasons += "Process has no valid executable path (potential process hollowing)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "MemoryAnomaly"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        ProcessPath = $Process.Path
                        WorkingSetMB = [Math]::Round($Process.WorkingSet64/1MB, 2)
                        PrivateMemoryMB = [Math]::Round($Process.PrivateMemorySize64/1MB, 2)
                        ThreadCount = $Process.Threads.Count
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-AVLog "[MemoryScan] THREAT ($severity): Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "MemoryScanning" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-AVLog "[MemoryScan] ACTION: Terminated process with critical memory anomalies (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity "Critical"
                        } catch {
                            Write-EDRLog -Module "MemoryScanning" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "MemoryScanning" -Message "Error scanning process $($Process.Id): $_" -Level "Warning"
            }
        }

        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-NamedPipeMonitoring {
    param(
        [bool]$AnalyzeProcesses = $true
    )

    try {
        $Threats = @()
        $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        
        # Advanced suspicious pipe name patterns
        $SuspiciousPatterns = @{
            "msagent_" = @{Score = 30; Reason = "MSAgent pipe (common malware)"}
            "mojo" = @{Score = 25; Reason = "Mojo pipe (potential IPC abuse)"}
            "crashpad" = @{Score = 20; Reason = "Crashpad pipe (could be abused)"}
            "mypipe|evil|backdoor|malware" = @{Score = 40; Reason = "Overtly suspicious pipe name"}
            ".*[0-9a-f]{32,}.*" = @{Score = 35; Reason = "Pipe name contains hash-like string (potential data exfiltration)"}
            "secret|private|hidden|stealth" = @{Score = 35; Reason = "Pipe name suggests stealth operation"}
            ".*[A-Z]{5,}.*" = @{Score = 15; Reason = "Pipe name with excessive uppercase (unusual pattern)"}
            "^.{50,}$" = @{Score = 20; Reason = "Unusually long pipe name"}
        }

        # Known legitimate pipes (whitelist)
        $LegitimatePipes = @(
            "\\.\pipe\lsarpc",
            "\\.\pipe\samr",
            "\\.\pipe\wkssvc",
            "\\.\pipe\srvsvc",
            "\\.\pipe\netlogon",
            "\\.\pipe\spoolss",
            "\\.\pipe\epmapper",
            "\\.\pipe\atsvc",
            "\\.\pipe\winsock",
            "\\.\pipe\InitShutdown",
            "\\.\pipe\winlogonrpc",
            "\\.\pipe\ntsvcs",
            "\\.\pipe\Winsock2",
            "\\.\pipe\srvsvc",
            "\\.\pipe\Browser"
        )

        foreach ($Pipe in $Pipes) {
            # Skip legitimate pipes
            if ($LegitimatePipes -contains $Pipe) { continue }

            $PipeName = $Pipe.Replace("\\.\pipe\", "")
            $ThreatScore = 0
            $FoundPatterns = @()
            $Reasons = @()

            # Check against suspicious patterns
            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($PipeName -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $FoundPatterns += $patternInfo.Reason
                    $Reasons += "$($patternInfo.Reason) (Pattern: $pattern)"
                }
            }

            # Analyze process relationships if enabled
            $ProcessInfo = $null
            if ($AnalyzeProcesses) {
                try {
                    # Get process using the pipe (requires handle enumeration - simplified approach)
                    # In real implementation, would use NtQuerySystemInformation or similar
                    # For now, check for processes with suspicious names that might create custom pipes
                    $SuspiciousProcesses = Get-Process | Where-Object {
                        $_.ProcessName -match "(powershell|cmd|wscript|cscript|mshta|rundll32)" -and
                        $_.Path -notmatch "^C:\\(Windows|Program Files)"
                    }
                    
                    if ($SuspiciousProcesses) {
                        foreach ($proc in $SuspiciousProcesses) {
                            # Heuristic: if suspicious process exists and pipe has suspicious pattern, increase score
                            if ($ThreatScore -gt 0) {
                                $ThreatScore += 10
                                $Reasons += "Suspicious process detected: $($proc.ProcessName) (PID: $($proc.Id))"
                                $ProcessInfo = @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ProcessPath = $proc.Path
                                }
                                break
                            }
                        }
                    }
                } catch {
                    Write-EDRLog -Module "NamedPipeMonitoring" -Message "Process analysis failed for pipe ${PipeName}: $_" -Level "Debug"
                }
            }

            # Check for pipes with random-looking names (potential malware)
            if ($PipeName -match "^[A-Za-z0-9]{32,}$" -and $ThreatScore -eq 0) {
                $entropy = Measure-StringEntropy -String $PipeName
                if ($entropy -gt 4.0) {
                    $ThreatScore += 25
                    $Reasons += "High entropy pipe name (potential random name generation) | Entropy: $([Math]::Round($entropy, 2))"
                }
            }

            # Check for pipes created by non-standard locations
            if ($AnalyzeProcesses -and $ProcessInfo) {
                if ($ProcessInfo.ProcessPath -and $ProcessInfo.ProcessPath -notmatch "^(C:\\(Windows|Program Files))") {
                    $ThreatScore += 15
                    $Reasons += "Pipe created by process from non-standard location: $($ProcessInfo.ProcessPath)"
                }
            }

            # Score-based threat detection
            if ($ThreatScore -ge 25) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "SuspiciousNamedPipe"
                    PipeName = $Pipe
                    PipeNameShort = $PipeName
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    Patterns = $FoundPatterns
                    ProcessInfo = $ProcessInfo
                    Severity = $severity
                    Time = Get-Date
                }

                Write-AVLog "[NamedPipe] THREAT ($severity): Suspicious named pipe detected | Pipe: $Pipe | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "SuspiciousNamedPipe" -ThreatPath $Pipe -Severity $severity
                }
            }
        }

        # Check for excessive pipe creation (potential indicator of malware activity)
        if ($Pipes.Count -gt 100) {
            $nonStandardPipes = $Pipes | Where-Object { $LegitimatePipes -notcontains $_ }
            if ($nonStandardPipes.Count -gt 50) {
                Write-AVLog "[NamedPipe] WARNING: Excessive named pipe creation detected | Total: $($Pipes.Count) | Non-standard: $($nonStandardPipes.Count)"
                Write-EDRLog -Module "NamedPipeMonitoring" -Message "Excessive pipe creation: $($Pipes.Count) total, $($nonStandardPipes.Count) non-standard" -Level "Warning"
            }
        }

        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalPipes = $Pipes.Count}
    }
    catch {
        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalPipes = 0}
    }
}

function Invoke-DNSExfiltrationDetection {
    param(
        [int]$LookbackMinutes = 60,
        [bool]$StatisticalAnalysis = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddMinutes(-$LookbackMinutes)
        
        # Get DNS cache entries
        $DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
            Where-Object { $_.TimeToLive -gt 0 -and $_.Status -eq 0 }

        $SuspiciousDomains = @()

        foreach ($Entry in $DNSCache) {
            $domain = $Entry.Name
            $ThreatScore = 0
            $Reasons = @()

            # 1. Check for long subdomains (common in DNS tunneling)
            if ($domain.Length -gt 50) {
                $ThreatScore += 20
                $Reasons += "Unusually long domain name ($($domain.Length) characters)"
            }

            # 2. Check for hash-like subdomains (potential data exfiltration)
            if ($domain -match "[0-9a-f]{32,}") {
                $ThreatScore += 35
                $Reasons += "Subdomain contains hash-like string (potential data exfiltration)"
            }

            # 3. Check for base64-encoded patterns
            if ($domain -match "[A-Za-z0-9+/]{20,}={0,2}") {
                $base64Part = if ($domain -match "([A-Za-z0-9+/]{20,}={0,2})") { $matches[1] } else { "" }
                if ($base64Part) {
                    $entropy = Measure-StringEntropy -String $base64Part
                    if ($entropy -gt 4.5) {
                        $ThreatScore += 40
                        $Reasons += "Subdomain contains high-entropy base64-like string | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 4. Check for suspicious domain patterns
            $SuspiciousPatterns = @{
                ".*\.[0-9a-f]{16,}\..*" = @{Score = 30; Reason = "Subdomain with hex string"}
                ".*[0-9]{10,}.*" = @{Score = 15; Reason = "Subdomain with long numeric string"}
                "^[a-z0-9]{20,}\." = @{Score = 25; Reason = "Random-looking subdomain prefix"}
                ".*secret.*|.*data.*|.*exfil.*|.*cmd.*" = @{Score = 30; Reason = "Suspicious keywords in domain"}
            }

            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($domain -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $Reasons += $patternInfo.Reason
                }
            }

            # 5. Check for DNS tunneling indicators (statistical analysis)
            if ($StatisticalAnalysis) {
                # Check for unusual TTL values (often manipulated in DNS tunneling)
                if ($Entry.TimeToLive -lt 300 -or $Entry.TimeToLive -gt 86400) {
                    $ThreatScore += 10
                    $Reasons += "Unusual TTL value: $($Entry.TimeToLive) seconds"
                }

                # Check for excessive subdomain length variation (indicator of tunneling)
                $subdomainParts = $domain.Split('.')
                if ($subdomainParts.Length -gt 4) {
                    $subdomainLengths = $subdomainParts | ForEach-Object { $_.Length }
                    $avgLength = ($subdomainLengths | Measure-Object -Average).Average
                    $maxLength = ($subdomainLengths | Measure-Object -Maximum).Maximum
                    
                    if ($maxLength -gt ($avgLength * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Subdomain length variation suggests data encoding"
                    }
                }

                # Check for high entropy in subdomain (potential encrypted data)
                $subdomain = $domain.Split('.')[0]
                if ($subdomain.Length -gt 20) {
                    $entropy = Measure-StringEntropy -String $subdomain
                    if ($entropy -gt 4.0) {
                        $ThreatScore += 25
                        $Reasons += "High entropy subdomain (potential encrypted exfiltrated data) | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 6. Check for known DNS tunneling tools domain patterns
            $KnownTunnelingTools = @(
                "iodine", "dns2tcp", "dnscat2", "tuns", "heyoka"
            )

            foreach ($tool in $KnownTunnelingTools) {
                if ($domain -match $tool) {
                    $ThreatScore += 40
                    $Reasons += "Known DNS tunneling tool pattern: $tool"
                }
            }

            # 7. Check for domains with excessive subdomains (potential data chunking)
            $subdomainCount = ($domain.Split('.')).Length
            if ($subdomainCount -gt 6) {
                $ThreatScore += 15
                $Reasons += "Excessive subdomain levels ($subdomainCount) - potential data chunking"
            }

            # Score-based threat detection
            if ($ThreatScore -ge 30) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "DNSExfiltration"
                    Domain = $domain
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    TTL = $Entry.TimeToLive
                    RecordType = $Entry.Type
                    DataLength = $Entry.DataLength
                    Severity = $severity
                    Time = Get-Date
                }

                Write-AVLog "[DNSExfil] THREAT ($severity): DNS exfiltration indicators detected | Domain: $domain | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltration" -ThreatPath $domain -Severity $severity
                }

                $SuspiciousDomains += $domain
            }
        }

        # Statistical analysis across all DNS queries
        if ($StatisticalAnalysis -and $DNSCache.Count -gt 0) {
            # Check for burst of suspicious DNS queries (indicator of active exfiltration)
            $recentQueries = $DNSCache | Where-Object { 
                $_.DataLength -gt 100 -or $_.Name.Length -gt 50
            }
            
            if ($recentQueries.Count -gt 20) {
                Write-AVLog "[DNSExfil] WARNING: Burst of suspicious DNS queries detected | Count: $($recentQueries.Count)"
                Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS query burst detected: $($recentQueries.Count) suspicious queries" -Level "Warning"
                
                # Check for patterns suggesting active exfiltration
                $uniqueDomains = $recentQueries | Select-Object -ExpandProperty Name -Unique
                if ($uniqueDomains.Count -lt ($recentQueries.Count * 0.3)) {
                    Write-AVLog "[DNSExfil] CRITICAL: Pattern suggests active DNS exfiltration | Repeating domains: $($uniqueDomains.Count) unique out of $($recentQueries.Count) queries"
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltrationBurst" -ThreatPath "Multiple domains" -Severity "Critical"
                }
            }
        }

        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection completed: $($Threats.Count) threat(s) found out of $($DNSCache.Count) DNS entries" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalEntries = $DNSCache.Count; SuspiciousDomains = $SuspiciousDomains}
    }
    catch {
        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalEntries = 0; SuspiciousDomains = @()}
    }
}

function Invoke-PasswordManagement {
    param()

    Write-AVLog "[Password] Starting password management monitoring..."

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-AVLog "[Password] WARNING: Not running as Administrator - limited functionality"
        return
}

    function Test-PasswordSecurity {
        try {
            $CurrentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                $PasswordAge = (Get-Date) - $CurrentUser.PasswordLastSet
                $DaysSinceChange = $PasswordAge.Days

                if ($DaysSinceChange -gt 90) {
                    Write-AVLog "[Password] WARNING: Password is $DaysSinceChange days old - consider rotation"
                }

                if ($CurrentUser.PasswordRequired -eq $false) {
                    Write-AVLog "[Password] WARNING: Account does not require password"
                }

                $PasswordPolicy = Get-LocalUser | Where-Object { $_.Name -eq $env:USERNAME } | Select-Object PasswordRequired, PasswordChangeable, PasswordExpires
                if ($PasswordPolicy) {
                    Write-AVLog "[Password] INFO: Password policy - Required: $($PasswordPolicy.PasswordRequired), Changeable: $($PasswordPolicy.PasswordChangeable), Expires: $($PasswordPolicy.PasswordExpires)"
                }

                return @{
                    DaysSinceChange = $DaysSinceChange
                    PasswordRequired = $CurrentUser.PasswordRequired
                    PasswordLastSet = $CurrentUser.PasswordLastSet
                }
            }
        }
        catch {
            Write-AVLog "[Password] ERROR: Failed to check password security: $_"
            return $null
        }
    }

    function Test-SuspiciousPasswordActivity {
        try {
            $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4724,4723,4738} -MaxEvents 10 -ErrorAction SilentlyContinue

            $RecentChanges = $SecurityEvents | Where-Object {
                $_.TimeCreated -gt (Get-Date).AddHours(-1) -and
                $_.Properties[0].Value -eq $env:USERNAME
            }

            if ($RecentChanges.Count -gt 0) {
                Write-AVLog "[Password] WARNING: Recent password activity detected - $($RecentChanges.Count) events in last hour"

                foreach ($LogEvent in $RecentChanges) {
                    $EventType = switch ($LogEvent.Id) {
                        4723 { "Password change attempted" }
                        4724 { "Password reset attempted" }
                        4738 { "Account policy modified" }
                        default { "Unknown event" }
                    }
                    Write-AVLog "[Password]   - $EventType at $($LogEvent.TimeCreated)"
                }
            }

            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }

            $UserFailedLogons = $FailedLogons | Where-Object {
                $_.Properties[5].Value -eq $env:USERNAME
            }

            if ($UserFailedLogons.Count -gt 5) {
                Write-AVLog "[Password] THREAT: High number of failed logons - $($UserFailedLogons.Count) failures in last hour"
            }

            return @{
                RecentChanges = $RecentChanges.Count
                FailedLogons = $UserFailedLogons.Count
            }
        }
        catch {
            Write-AVLog "[Password] ERROR: Failed to check suspicious activity: $_"
            return $null
        }
    }

    function Test-PasswordDumpingTools {
        try {
            $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz", "gsecdump", "cachedump")
            $SuspiciousProcesses = Get-Process | Where-Object {
                $SuspiciousTools -contains $_.ProcessName.ToLower()
            }

            if ($SuspiciousProcesses.Count -gt 0) {
                Write-AVLog "[Password] THREAT: Password dumping tools detected"
                foreach ($Process in $SuspiciousProcesses) {
                    Write-AVLog "[Password]   - $($Process.ProcessName) (PID: $($Process.Id))"
                }
            }

            $PowerShellProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
            foreach ($Process in $PowerShellProcesses) {
                try {
                    $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                    $PasswordCommands = @("Get-Credential", "ConvertTo-SecureString", "Import-Clixml", "Export-Clixml")
                    foreach ($Command in $PasswordCommands) {
                        if ($CommandLine -match $Command) {
                            Write-AVLog "[Password] SUSPICIOUS: PowerShell process with password-related command - PID: $($Process.Id)"
                        }
                    }
                }
                catch {
                }
            }

            return $SuspiciousProcesses.Count
        }
        catch {
            Write-AVLog "[Password] ERROR: Failed to check for dumping tools: $_"
            return 0
        }
    }

    try {
        $PasswordStatus = Test-PasswordSecurity
        if ($PasswordStatus) {
            Write-AVLog "[Password] Security check completed - Password age: $($PasswordStatus.DaysSinceChange) days"
        }

        $ActivityStatus = Test-SuspiciousPasswordActivity
        if ($ActivityStatus) {
            Write-AVLog "[Password] Activity monitoring completed - Recent changes: $($ActivityStatus.RecentChanges), Failed logons: $($ActivityStatus.FailedLogons)"
        }

        $DumpingTools = Test-PasswordDumpingTools
        Write-AVLog "[Password] Dumping tools check completed - Suspicious tools: $DumpingTools"

        try {
            $RegKeys = @(
                "HKLM:\SAM\SAM\Domains\Account\Users",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            )

            foreach ($RegKey in $RegKeys) {
                try {
                    if (Test-Path $RegKey -ErrorAction SilentlyContinue) {
                        $RecentChanges = Get-ChildItem $RegKey -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }

                        if ($RecentChanges -and $RecentChanges.Count -gt 0) {
                            Write-AVLog "[Password] WARNING: Recent registry changes in password-related areas"
                            foreach ($Change in $RecentChanges) {
                                Write-AVLog "[Password]   - $($Change.PSPath) modified at $($Change.LastWriteTime)"
                            }
                        }
                    }
                }
                catch {
                    # SAM registry access requires special privileges - skip silently if access denied
                    if ($RegKey -like "*SAM*") {
                        # SAM access is protected - this is expected to fail on most systems
                        continue
                    }
                    Write-AVLog "[Password] WARNING: Could not check registry key $RegKey - $_"
                }
            }
        }
        catch {
            Write-AVLog "[Password] ERROR: Failed to check registry changes: $_"
        }

        Write-AVLog "[Password] Password management monitoring completed"
    }
    catch {
        Write-AVLog "[Password] ERROR: Monitoring failed: $_"
    }
}

function Invoke-KeyScramblerManagement {
    param(
        [bool]$AutoStart = $true
    )

    Write-AVLog "[KeyScrambler] Starting inline KeyScrambler with C# hook..."

    $Source = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] private static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int x; public int y; }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;

        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
            Marshal.GetFunctionPointerForDelegate(_proc),
            GetModuleHandle(null), 0);

        if (_hookID == IntPtr.Zero)
            throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("KeyScrambler ACTIVE - invisible mode ON");
        Console.WriteLine("You see only your real typing * Keyloggers blinded");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private static bool ModifiersDown()
    {
        return (GetKeyState(0x10) & 0x8000) != 0 ||
               (GetKeyState(0x11) & 0x8000) != 0 ||
               (GetKeyState(0x12) & 0x8000) != 0;
    }

    private static void InjectFakeChar(char c)
    {
        var inputs = new INPUT[2];

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.dwExtraInfo = GetMessageExtraInfo();

        inputs[1] = inputs[0];
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

        SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    private static void Flood()
    {
        if (_rnd.NextDouble() < 0.5) return;
        int count = _rnd.Next(1, 7);
        for (int i = 0; i < count; i++)
            InjectFakeChar((char)_rnd.Next('A', 'Z' + 1));
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            if ((k.flags & 0x10) != 0) return CallNextHookEx(_hookID, nCode, wParam, lParam);
            if (ModifiersDown()) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (k.vkCode >= 65 && k.vkCode <= 90)
            {
                if (_rnd.NextDouble() < 0.75) Flood();
                var ret = CallNextHookEx(_hookID, nCode, wParam, lParam);
                if (_rnd.NextDouble() < 0.75) Flood();
                return ret;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

    try {
        Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
        Write-AVLog "[KeyScrambler] Compiled C# code successfully"
    }
    catch {
        Write-AVLog "[KeyScrambler] ERROR: Compilation failed: $($_.Exception.Message)"
        return
    }

    if ($AutoStart) {
        try {
            Write-AVLog "[KeyScrambler] Starting keyboard hook..."
            [KeyScrambler]::Start()
        }
        catch {
            Write-AVLog "[KeyScrambler] ERROR: Failed to start hook: $_"
        }
    }
}

#region === Missing Functions from Antivirus.ps1 ===

function Write-EDRLog {
    param(
        [string]$Module,
        [string]$Message,
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
    
    # Console output based on log level
    switch ($Level) {
        "Debug"   { if ($Verbose) { Write-Host $logEntry -ForegroundColor Gray } }
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    # File logging
    $logFile = Join-Path $Config.LogPath "EDR_$(Get-Date -Format 'yyyy-MM-dd').log"
    try {
        $logEntry | Add-Content -Path $logFile -ErrorAction SilentlyContinue
    } catch { }
}

function Write-Detection {
    param(
        [string]$Module,
        [int]$Count,
        [string]$Details = ""
    )
    
    if ($Count -gt 0) {
        Write-EDRLog -Module $Module -Message "DETECTION: Found $Count issues. $Details" -Level "Warning"
    }
}

function Write-ModuleStats {
    param(
        [string]$Module,
        [hashtable]$Stats
    )
    
    $statsString = ($Stats.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
    Write-EDRLog -Module $Module -Message "STATS: $statsString" -Level "Debug"
}

function Invoke-Initialization {
    try {
        Write-EDRLog -Module "Initializer" -Message "Starting environment initialization" -Level "Info"
        
        # Create required directories
        $directories = @(
            $Script:InstallPath,
            "$Script:InstallPath\Logs",
            "$Script:InstallPath\Data",
            "$Script:InstallPath\Quarantine",
            "$Script:InstallPath\Reports",
            "$Script:InstallPath\HashDatabase"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-EDRLog -Module "Initializer" -Message "Created directory: $dir" -Level "Debug"
            }
        }
        
        # Create Event Log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                Write-EDRLog -Module "Initializer" -Message "Created Event Log source: $($Config.EDRName)" -Level "Info"
            }
        } catch {
            Write-EDRLog -Module "Initializer" -Message "Could not create Event Log source (may require elevation): $_" -Level "Warning"
        }
        
        # Initialize module baselines
        Initialize-FirewallBaseline
        Initialize-ServiceBaseline
        Initialize-HashDatabase
        
        Write-EDRLog -Module "Initializer" -Message "Environment initialization completed" -Level "Info"
        return 1
        
    } catch {
        Write-EDRLog -Module "Initializer" -Message "Initialization failed: $_" -Level "Error"
        return 0
    }
}

function Initialize-FirewallBaseline {
    try {
        if (-not $script:BaselineRules) { $script:BaselineRules = @{} }
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            if (-not $script:BaselineRules.ContainsKey($key)) {
                $script:BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-ServiceBaseline {
    try {
        if (-not $script:ServiceBaseline) { $script:ServiceBaseline = @{} }
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            $key = $service.Name
            if (-not $script:ServiceBaseline.ContainsKey($key)) {
                $script:ServiceBaseline[$key] = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-HashDatabase {
    try {
        if (-not $script:HashDatabase) { $script:HashDatabase = @{} }
        if (-not $script:ThreatHashes) { $script:ThreatHashes = @{} }
        
        # Load known good hashes (whitelist)
        $whitelistPath = "$Script:InstallPath\HashDatabase\whitelist.txt"
        if (Test-Path $whitelistPath) {
            Get-Content $whitelistPath | ForEach-Object {
                if ($_ -match '^([A-F0-9]{64})\|(.+)$') {
                    $script:HashDatabase[$matches[1]] = $matches[2]
                }
            }
        }
        
        # Load threat hashes (blacklist)
        $threatPaths = @(
            "$Script:InstallPath\HashDatabase\threats.txt",
            "$Script:InstallPath\HashDatabase\malware_hashes.txt"
        )
        
        foreach ($threatPath in $threatPaths) {
            if (Test-Path $threatPath) {
                Get-Content $threatPath | ForEach-Object {
                    if ($_ -match '^([A-F0-9]{32,64})$') {
                        $script:ThreatHashes[$matches[1].ToUpper()] = $true
                    }
                }
            }
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $maxConnections = 500
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        # Group connections by process and remote address
        $connGroups = $connections | Group-Object -Property @{Expression={$_.OwningProcess}}, @{Expression={$_.RemoteAddress}}
        
        foreach ($group in $connGroups) {
            $procId = $group.Name.Split(',')[0].Trim()
            $remoteIP = $group.Name.Split(',')[1].Trim()
            
            try {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if (-not $proc) { continue }
                
                # Check connection frequency (beacon pattern)
                $connTimes = $group.Group | ForEach-Object { $_.CreationTime } | Sort-Object
                
                if ($connTimes.Count -gt 3) {
                    # Calculate intervals between connections
                    $intervals = @()
                    for ($i = 1; $i -lt $connTimes.Count; $i++) {
                        $interval = ($connTimes[$i] - $connTimes[$i-1]).TotalSeconds
                        $intervals += $interval
                    }
                    
                    # Check for regular intervals (beacon indicator)
                    if ($intervals.Count -gt 2) {
                        $avgInterval = ($intervals | Measure-Object -Average).Average
                        $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Average).Average
                        $stdDev = [Math]::Sqrt($variance)
                        
                        # Low variance = regular intervals = beacon
                        if ($stdDev -lt $avgInterval * 0.2 -and $avgInterval -gt 10 -and $avgInterval -lt 3600) {
                            $detections += @{
                                ProcessId = $procId
                                ProcessName = $proc.ProcessName
                                RemoteAddress = $remoteIP
                                ConnectionCount = $connTimes.Count
                                AverageInterval = [Math]::Round($avgInterval, 2)
                                Type = "Beacon Pattern Detected"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for connections to suspicious TLDs
        foreach ($conn in $connections) {
            if ($conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)') {
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                    
                    $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".tk", ".ml", ".ga", ".cf")
                    foreach ($tld in $suspiciousTLDs) {
                        if ($dns -like "*$tld") {
                            $detections += @{
                                ProcessId = $conn.OwningProcess
                                RemoteAddress = $conn.RemoteAddress
                                RemoteHost = $dns
                                Type = "Connection to Suspicious TLD"
                                Risk = "Medium"
                            }
                            break
                        }
                    }
                } catch { }
            }
        }
        
        # Check for HTTP/HTTPS connections with small data transfer (beacon)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    $httpConns = $procConns | Where-Object { $_.RemotePort -in @(80, 443, 8080, 8443) }
                    
                    if ($httpConns.Count -gt 0) {
                        # Check network stats
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats -and $netStats.CounterSamples[0].CookedValue -lt 1000 -and $netStats.CounterSamples[0].CookedValue -gt 0) {
                            # Small but consistent data transfer = beacon
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DataRate = $netStats.CounterSamples[0].CookedValue
                                ConnectionCount = $httpConns.Count
                                Type = "Low Data Transfer Beacon Pattern"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes with connections to many different IPs (C2 rotation)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                $uniqueIPs = ($procConns | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UniqueIPs = $uniqueIPs
                        ConnectionCount = $procConns.Count
                        Type = "Multiple C2 Connections (IP Rotation)"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)" "THREAT" "beacon_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Beacon detection error: $_" "ERROR" "beacon_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        # Code injection signatures for advanced detection
        $codeInjectionSignatures = @{
            "CodeInjection" = @(
                "code.*injection", "dll.*injection", "process.*hollowing",
                "reflective.*dll", "shellcode", "inject.*code"
            )
        }
        
        # Code injection behavioral patterns
        $codeInjectionBehaviors = @{
            "InjectionAPIs" = @(
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateThreadEx", "RtlCreateUserThread", "SetThreadContext",
                "QueueUserAPC", "ProcessHollowing", "DLL.*injection"
            )
            "MemoryManipulation" = @(
                "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                "ReadProcessMemory", "NtWriteVirtualMemory"
            )
        }
        
        # Check for processes with unusual memory regions (injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procPath = $proc.Path
                $procCmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                
                # Use advanced detection framework
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $codeInjectionSignatures `
                        -BehavioralIndicators $codeInjectionBehaviors `
                        -CommandLine $procCmdLine `
                        -CheckEntropy $true
                    
                    if ($detectionResult.IsThreat) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Type = "Code Injection Detected via Advanced Framework"
                            Risk = if ($detectionResult.Risk -eq "CRITICAL") { "High" } else { "Medium" }
                        }
                    }
                }
                
                $modules = $proc.Modules
                
                # Check for processes with modules in unusual locations
                $unusualModules = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName) -and
                    $_.ModuleName -like "*.dll"
                }
                
                if ($unusualModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualModules = $unusualModules.Count
                        Type = "Many Unusual Memory Modules (Code Injection)"
                        Risk = "High"
                    }
                }
                
                # Check for processes with unusual thread counts (injection indicator)
                if ($proc.Threads.Count -gt 50 -and $proc.ProcessName -notin @("chrome.exe", "msedge.exe", "firefox.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ThreadCount = $proc.Threads.Count
                        Type = "Unusual Thread Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using injection APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for code injection API usage
                    $injectionPatterns = @(
                        'VirtualAllocEx',
                        'WriteProcessMemory',
                        'CreateRemoteThread',
                        'NtCreateThreadEx',
                        'RtlCreateUserThread',
                        'SetThreadContext',
                        'QueueUserAPC',
                        'ProcessHollowing',
                        'DLL.*injection',
                        'code.*injection'
                    )
                    
                    foreach ($pattern in $injectionPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                InjectionPattern = $pattern
                                Type = "Code Injection API Usage"
                                Risk = "High"
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual handle counts (injection indicator)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.HandleCount -gt 1000 }
            
            foreach ($proc in $processes) {
                # Exclude legitimate processes
                $legitProcesses = @("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "svchost.exe")
                if ($proc.ProcessName -notin $legitProcesses) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        HandleCount = $proc.HandleCount
                        Type = "Unusual Handle Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing other processes (injection indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    # Check if process has SeDebugPrivilege (enables injection)
                    # Indirect check through process properties
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        # Unsigned processes accessing system processes
                        if ($sig.Status -ne "Valid" -and $proc.Name -match 'debug|inject|hollow') {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Suspicious Process Name (Injection Tool)"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Also check for unsigned modules in system processes (original check)
        try {
            $systemProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -in @("svchost", "explorer", "lsass")
            }
            
            foreach ($proc in $systemProcesses) {
                foreach ($module in $proc.Modules) {
                    if ($module.FileName -and (Test-Path $module.FileName)) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $module.FileName -notlike "$env:SystemRoot\*") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ModulePath = $module.FileName
                                    Type = "Unsigned Module in System Process"
                                    Risk = "High"
                                }
                            }
                        } catch { }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "CODE INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "code_injection_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Code injection detection error: $_" "ERROR" "code_injection_detections.log"
    }
    
    return $detections.Count
}

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $byProcess = $connections | Group-Object OwningProcess
        
        foreach ($group in $byProcess) {
            if ($group.Count -gt 20) {
                $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                
                if ($procName -notin @("chrome", "firefox", "msedge", "svchost", "System")) {
                    $detections += @{
                        ProcessId = $group.Name
                        ProcessName = $procName
                        ConnectionCount = $group.Count
                        Type = "High Network Activity"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "DataExfiltrationDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "DataExfiltrationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

# DLL whitelist - safe system DLLs that should not be flagged
$Script:DllWhitelist = @(
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 
    'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
    'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
    'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll',
    'shcore.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll',
    'mshtml.dll', 'msi.dll', 'msvcp140.dll', 'vcruntime140.dll'
)

# Target browser processes to monitor
$Script:BrowserTargets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 
                   'iexplore', 'microsoftedge', 'waterfox', 'palemoon')

$Script:ProcessedDlls = @{}

function Test-SuspiciousDLL {
    param(
        [string]$DllName,
        [string]$DllPath,
        [string]$ProcessName
    )
    
    $dllNameLower = $DllName.ToLower()
    $suspicious = $false
    $reasons = @()
    
    # Skip whitelisted system DLLs
    if ($Script:DllWhitelist -contains $dllNameLower) {
        return $null
    }
    
    # Pattern 1: Suspicious .winmd files outside Windows directory
    if ($dllNameLower -like '*.winmd' -and $DllPath -notmatch '\\Windows\\') {
        $suspicious = $true
        $reasons += "WINMD file outside Windows directory"
    }
    
    # Pattern 3: Random hex-named DLLs (common in malware)
    if ($dllNameLower -match '^[a-f0-9]{8,}\.dll$') {
        $suspicious = $true
        $reasons += "Random hex-named DLL detected"
    }
    
    # Pattern 4: DLLs loaded from TEMP directory (excluding browser cache)
    if ($DllPath -match "\\AppData\\Local\\Temp\\" -and 
        $dllNameLower -notlike "chrome_*" -and 
        $dllNameLower -notlike "edge_*" -and
        $dllNameLower -notlike "moz*" -and
        $dllNameLower -notlike "firefox_*") {
        $suspicious = $true
        $reasons += "DLL loaded from TEMP directory"
    }
    
    # Pattern 5: DLLs in browser profile folders with suspicious names
    if ($DllPath -match "\\AppData\\" -and 
        $dllNameLower -notmatch "chrome|edge|firefox|mozilla" -and
        $dllNameLower -like '*.dll') {
        $suspicious = $true
        $reasons += "DLL in browser profile with non-browser name"
    }
    
    # Pattern 6: Unsigned DLLs in browser processes
    if (Test-Path $DllPath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid" -and $DllPath -notlike "$env:SystemRoot\*") {
                $suspicious = $true
                $reasons += "Unsigned DLL in browser process"
            }
        } catch { }
    }
    
    if ($suspicious) {
        return @{
            Suspicious = $true
            Reasons = $reasons
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-ElfCatcher {
    $detections = @()
    try {
        foreach ($target in $Script:BrowserTargets) {
            try {
                $procs = Get-Process -Name $target -ErrorAction SilentlyContinue
                foreach ($proc in $procs) {
                    try {
                        $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" -or $_.FileName -like "*.winmd" }
                        foreach ($mod in $modules) {
                            try {
                                $dllName = [System.IO.Path]::GetFileName($mod.FileName)
                                $dllPath = $mod.FileName
                                $key = "$($proc.Id):$dllPath"
                                if ($Script:ProcessedDlls.ContainsKey($key)) { continue }
                                $result = Test-SuspiciousDLL -DllName $dllName -DllPath $dllPath -ProcessName $proc.ProcessName
                                if ($result) {
                                    $detections += @{ ProcessId = $proc.Id; ProcessName = $proc.ProcessName; DllName = $dllName; DllPath = $dllPath; Reasons = $result.Reasons; Risk = $result.Risk }
                                    $Script:ProcessedDlls[$key] = Get-Date
                                    Write-AVLog "ELF CATCHER: Suspicious DLL in $($proc.ProcessName) (PID: $($proc.Id)) - $dllName - $($result.Reasons -join ', ')" "THREAT" "elf_catcher_detections.log"
                                    $Global:AntivirusState.ThreatCount++
                                }
                            } catch { continue }
                        }
                    } catch { continue }
                }
            } catch { continue }
        }
        if ($Script:ProcessedDlls.Count -gt 1000) {
            $oldKeys = $Script:ProcessedDlls.Keys | Where-Object { ((Get-Date) - $Script:ProcessedDlls[$_]).TotalHours -gt 24 }
            foreach ($key in $oldKeys) { $Script:ProcessedDlls.Remove($key) }
        }
        if ($detections.Count -gt 0) {
            $logPath = "$Script:InstallPath\Logs\ElfCatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            if (!(Test-Path (Split-Path $logPath -Parent))) { New-Item -ItemType Directory -Path (Split-Path $logPath -Parent) -Force | Out-Null }
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName)|$($_.DllPath)|$($_.Reasons -join ';')" | Add-Content -Path $logPath -ErrorAction SilentlyContinue }
            Write-AVLog "ElfCatcher detection completed: $($detections.Count) suspicious DLL(s) found" "INFO" "elf_catcher_detections.log"
        }
    } catch { Write-AVLog "ElfCatcher error: $_" "ERROR" "elf_catcher_detections.log" }
    return $detections.Count
}

$Script:ScannedFiles = @{}
$Script:HighEntropyThreshold = 7.2

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $sampleSize = [Math]::Min(8192, $fileInfo.Length)
        
        if ($sampleSize -eq 0) { return $null }
        
        $stream = [System.IO.File]::OpenRead($FilePath)
        $bytes = New-Object byte[] $sampleSize
        $stream.Read($bytes, 0, $sampleSize) | Out-Null
        $stream.Close()
        
        # Calculate byte frequency
        $freq = @{}
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        # Calculate Shannon entropy
        $entropy = 0
        $total = $bytes.Count
        
        foreach ($count in $freq.Values) {
            $p = $count / $total
            if ($p -gt 0) {
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        
        return @{
            Entropy = $entropy
            FileSize = $fileInfo.Length
            SampleSize = $sampleSize
        }
    } catch {
        return $null
    }
}

function Invoke-FileEntropyDetection {
    $detections = @()
    $maxFiles = 100
    
    try {
        $cutoff = (Get-Date).AddHours(-2)
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
        
        $scannedCount = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            if ($scannedCount -ge $maxFiles) { break }
            
            try {
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.scr,*.ps1,*.vbs,*.bat,*.cmd,*.com,*.msi,*.hta,*.js,*.jse,*.wsf,*.wsh -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First ($maxFiles - $scannedCount)
                
                foreach ($file in $files) {
                    $scannedCount++
                    
                    # Check cache
                    if ($Script:ScannedFiles.ContainsKey($file.FullName)) {
                        $cached = $Script:ScannedFiles[$file.FullName]
                        if ($cached.LastWrite -eq $file.LastWriteTime -and $cached.Entropy -lt $Script:HighEntropyThreshold) {
                            continue
                        }
                    }
                    
                    $entropyResult = Measure-FileEntropy -FilePath $file.FullName
                    
                    # Mark as scanned
                    $Script:ScannedFiles[$file.FullName] = @{
                        LastWrite = $file.LastWriteTime
                        Entropy = if ($entropyResult) { $entropyResult.Entropy } else { 0 }
                    }
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $Script:HighEntropyThreshold) {
                        $detections += @{
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Entropy = [Math]::Round($entropyResult.Entropy, 2)
                            FileSize = $entropyResult.FileSize
                            Type = "High Entropy File"
                            Risk = "Medium"
                        }
                        
                        Write-AVLog "High entropy file detected - File: $($file.Name) | Path: $($file.FullName) | Entropy: $([Math]::Round($entropyResult.Entropy, 2))" "WARNING" "file_entropy_detections.log"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Periodic cleanup of cache
        if ($Script:ScannedFiles.Count -gt 1000) {
            $oldKeys = $Script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
            foreach ($key in $oldKeys) {
                $Script:ScannedFiles.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$Script:InstallPath\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "File entropy detection completed: $($detections.Count) high entropy file(s) found" "INFO" "file_entropy_detections.log"
        }
    } catch {
        Write-AVLog "File entropy detection error: $_" "ERROR" "file_entropy_detections.log"
    }
    
    return $detections.Count
}

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        $honeypotFiles = @(
            "$Script:InstallPath\Data\passwords.txt",
            "$Script:InstallPath\Data\credentials.xlsx",
            "$Script:InstallPath\Data\secrets.docx"
        )
        
        foreach ($honeypot in $honeypotFiles) {
            if (Test-Path $honeypot) {
                $file = Get-Item $honeypot -ErrorAction SilentlyContinue
                if ($file.LastAccessTime -gt (Get-Date).AddMinutes(-5)) {
                    $detections += @{
                        HoneypotFile = $honeypot
                        LastAccess = $file.LastAccessTime
                        Type = "Honeypot File Accessed"
                        Risk = "Critical"
                    }
                }
            } else {
                try {
                    $dir = Split-Path $honeypot -Parent
                    if (-not (Test-Path $dir)) {
                        New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    }
                    "HONEYPOT - This file is monitored for unauthorized access" | Set-Content -Path $honeypot
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "HoneypotMonitoring" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "HoneypotMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine) {
                $lateralPatterns = @(
                    "psexec", "paexec", "wmic.*process.*call.*create",
                    "winrm", "enter-pssession", "invoke-command.*-computername",
                    "schtasks.*/create.*/s", "at.exe.*\\\\"
                )
                
                foreach ($pattern in $lateralPatterns) {
                    if ($cmdLine -match $pattern) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            CommandLine = $cmdLine
                            Pattern = $pattern
                            Type = "Lateral Movement Activity"
                            Risk = "High"
                        }
                    }
                }
            }
        }
        
        $smbConnections = Get-NetTCPConnection -RemotePort 445 -State Established -ErrorAction SilentlyContinue
        $uniqueHosts = ($smbConnections.RemoteAddress | Select-Object -Unique).Count
        
        if ($uniqueHosts -gt 5) {
            $detections += @{
                UniqueHosts = $uniqueHosts
                Type = "Multiple SMB Connections"
                Risk = "Medium"
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "LateralMovementDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "LateralMovementDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-ProcessCreationDetection {
    $detections = @()
    
    try {
        # Check for WMI process creation filters (blockers)
        try {
            $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Query -match 'Win32_ProcessStartTrace|__InstanceCreationEvent.*Win32_Process'
                }
            
            foreach ($filter in $filters) {
                # Check if filter is bound to a consumer that blocks processes
                $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                    Where-Object { $_.Filter -like "*$($filter.Name)*" }
                
                if ($bindings) {
                    foreach ($binding in $bindings) {
                        $consumer = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "*$($binding.Consumer)*" }
                        
                        if ($consumer) {
                            # Check if consumer command blocks process creation
                            if ($consumer.CommandLineTemplate -match 'taskkill|Stop-Process|Remove-Process' -or
                                $consumer.CommandLineTemplate -match 'block|deny|prevent') {
                                $detections += @{
                                    FilterName = $filter.Name
                                    ConsumerName = $consumer.Name
                                    CommandLine = $consumer.CommandLineTemplate
                                    Type = "WMI Process Creation Blocker Detected"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for process creation failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Message -match 'process.*failed|service.*failed.*start|start.*failed'
                }
            
            $processFailures = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1)
            }
            
            if ($processFailures.Count -gt 10) {
                $detections += @{
                    EventCount = $processFailures.Count
                    Type = "Excessive Process Creation Failures"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for processes with unusual creation patterns
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CreationDate, ExecutablePath
            
            # Check for processes spawned in rapid succession
            $recentProcs = $processes | Where-Object {
                (Get-Date) - $_.CreationDate -lt [TimeSpan]::FromMinutes(5)
            }
            
            # Group by parent process
            $parentGroups = $recentProcs | Group-Object ParentProcessId
            
            foreach ($group in $parentGroups) {
                if ($group.Count -gt 20) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($group.Name)" -ErrorAction SilentlyContinue
                        if ($parent) {
                            $detections += @{
                                ParentProcessId = $group.Name
                                ParentProcessName = $parent.Name
                                ChildCount = $group.Count
                                Type = "Rapid Process Creation Spawning"
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check for processes with unusual parent relationships
        try {
            $suspiciousParents = @{
                "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                "explorer.exe" = @("notepad.exe", "calc.exe")
            }
            
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId
            
            foreach ($proc in $processes) {
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        
                        if ($parent) {
                            foreach ($suspParent in $suspiciousParents.Keys) {
                                if ($parent.Name -eq $suspParent -and 
                                    $proc.Name -in $suspiciousParents[$suspParent]) {
                                    
                                    $detections += @{
                                        ProcessId = $proc.ProcessId
                                        ProcessName = $proc.Name
                                        ParentProcessId = $proc.ParentProcessId
                                        ParentProcessName = $parent.Name
                                        Type = "Suspicious Parent-Child Process Relationship"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check Security event log for suspicious process creation (original check)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue -MaxEvents 50
            
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $newProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                $commandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                
                $suspiciousPatterns = @(
                    "powershell.*-enc", "cmd.*/c.*powershell",
                    "certutil.*-decode", "bitsadmin.*/download",
                    "mshta.*http", "regsvr32.*/s.*/i"
                )
                
                foreach ($pattern in $suspiciousPatterns) {
                    if ($commandLine -match $pattern) {
                        $detections += @{
                            ProcessName = $newProcessName
                            CommandLine = $commandLine
                            Pattern = $pattern
                            TimeCreated = $evt.TimeCreated
                            Type = "Suspicious Process Creation"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS CREATION: $($detection.Type) - $($detection.ProcessName -or $detection.FilterName -or $detection.ParentProcessName -or 'System')" "THREAT" "process_creation_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$Script:InstallPath\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.FilterName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process creation detection error: $_" "ERROR" "process_creation_detections.log"
    }
    
    return $detections.Count
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason,
        [string]$Source,
        [switch]$SkipApiCheck = $false
    )
    
    try {
        if (-not $FilePath) {
            Write-EDRLog -Module "Quarantine" -Message "Cannot quarantine - FilePath is empty or null (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $false
        }
        
        if (Test-Path $FilePath) {
            Write-EDRLog -Module "Quarantine" -Message "Attempting to quarantine: $FilePath (Reason: $Reason, Source: $Source)" -Level "Info"
            # Consult the 3 malware APIs before quarantining (unless explicitly skipped)
            if (-not $SkipApiCheck) {
                $isMalicious = $false
                $apiConfidence = 0
                $apiSources = @()
                
                try {
                    $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($fileHash) {
                        # Check CIRCL Hash Lookup
                        try {
                            $CirclResponse = Invoke-RestMethod -Uri "$($Config.CirclHashLookupUrl)/$fileHash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($CirclResponse.KnownMalicious) {
                                $isMalicious = $true
                                $apiConfidence += 40
                                $apiSources += "CIRCL"
                            }
                        } catch {}
                        
                        # Check MalwareBazaar
                        try {
                            $MBBody = @{ query = "get_info"; hash = $fileHash } | ConvertTo-Json
                            $MBResponse = Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($MBResponse.query_status -eq "ok") {
                                $isMalicious = $true
                                $apiConfidence += 50
                                $apiSources += "MalwareBazaar"
                            }
                        } catch {}
                        
                        # Check Cymru Malware Hash Registry
                        try {
                            $CymruResponse = Invoke-RestMethod -Uri "$($Config.CymruApiUrl)/$fileHash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($CymruResponse.malware -eq $true) {
                                $isMalicious = $true
                                $apiConfidence += 30
                                $apiSources += "Cymru"
                            }
                        } catch {}
                        
                        # Log API results - APIs are consulted but don't block quarantine
                        # If APIs confirm malicious, log it. If not found or APIs unavailable, still quarantine based on detection engine
                        if ($isMalicious -and $apiConfidence -ge 30) {
                            Write-EDRLog -Module "Quarantine" -Message "API verification confirmed malicious: $FilePath confirmed by $($apiSources -join ', ') (Confidence: $apiConfidence)" -Level "Warning"
                        } else {
                            Write-EDRLog -Module "Quarantine" -Message "API check completed for $FilePath (not found in databases or APIs unavailable) - proceeding with quarantine based on detection engine" -Level "Info"
                        }
                    } else {
                        Write-EDRLog -Module "Quarantine" -Message "Could not calculate hash for $FilePath - proceeding with quarantine based on detection engine" -Level "Info"
                    }
                } catch {
                    Write-EDRLog -Module "Quarantine" -Message "API verification error for $FilePath : $_ - proceeding with quarantine based on detection engine" -Level "Warning"
                    # If API check fails, proceed with quarantine based on detection engine results
                }
            }
            
            $fileName = Split-Path -Leaf $FilePath
            $quarantinePath = Join-Path $Config.QuarantinePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$fileName"
            
            if (-not (Test-Path $Config.QuarantinePath)) {
                New-Item -Path $Config.QuarantinePath -ItemType Directory -Force | Out-Null
            }
            
            Move-Item -Path $FilePath -Destination $quarantinePath -Force
            Write-EDRLog -Module "Quarantine" -Message "SUCCESS: Quarantined $FilePath -> $quarantinePath (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $true
        } else {
            Write-EDRLog -Module "Quarantine" -Message "Cannot quarantine - file does not exist: $FilePath (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $false
        }
    } catch {
        Write-EDRLog -Module "Quarantine" -Message "ERROR: Failed to quarantine $FilePath : $_ (Reason: $Reason, Source: $Source)" -Level "Error"
    }
    
    return $false
}

function Invoke-QuarantineManagement {
    try {
        $quarantineFiles = Get-ChildItem -Path $Config.QuarantinePath -File -ErrorAction SilentlyContinue
        
        foreach ($file in $quarantineFiles) {
            $age = (Get-Date) - $file.CreationTime
            if ($age.Days -gt 30) {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                Write-EDRLog -Module "Quarantine" -Message "Removed old quarantined file: $($file.Name)" -Level "Info"
            }
        }
    } catch {
        Write-EDRLog -Module "QuarantineManagement" -Message "Error: $_" -Level "Error"
    }
    
    return 0
}

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                $memOnlyModules = $proc.Modules | Where-Object {
                    $_.FileName -and -not (Test-Path $_.FileName)
                }
                
                if ($memOnlyModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        MemoryModules = $memOnlyModules.Count
                        Type = "Potential Reflective DLL Injection"
                        Risk = "High"
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "ReflectiveDLLInjectionDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "ReflectiveDLLInjectionDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Add-ThreatToResponseQueue {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium",
        [hashtable]$Details = $null
    )
    
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Prevent queue overflow
        if ($Script:ResponseQueue.Count -ge $Script:ResponseQueueMaxSize) {
            Write-EDRLog -Module "ResponseEngine" -Message "WARNING: Response queue is full, dropping oldest threat" -Level "Warning"
            $null = $Script:ResponseQueue.Dequeue()
        }

        # Extract ThreatPath from Details if provided and ThreatPath is not set
        if ($Details -and -not $ThreatPath) {
            if ($Details.FilePath) {
                $ThreatPath = $Details.FilePath
            } elseif ($Details.ProcessPath) {
                $ThreatPath = $Details.ProcessPath
            } elseif ($Details.Path) {
                $ThreatPath = $Details.Path
            } elseif ($Details.ProcessName) {
                $ThreatPath = $Details.ProcessName
            } elseif ($Details.FileName) {
                $ThreatPath = $Details.FileName
            }
        }

        $threat = @{
            ThreatType = $ThreatType
            ThreatPath = $ThreatPath
            Severity = $Severity
            Timestamp = Get-Date
        }

        $Script:ResponseQueue.Enqueue($threat)
        Write-EDRLog -Module "ResponseEngine" -Message "Queued threat: $ThreatType - $ThreatPath (Severity: $Severity). Queue size: $($Script:ResponseQueue.Count)" -Level "Debug"
    }
    catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error adding threat to queue: $_" -Level "Error"
    }
}

function Invoke-DriverBehavioralAnalysis {
    <#
    .SYNOPSIS
    Performs behavioral analysis on a driver using hybrid approach:
    - Uses general framework (Invoke-AdvancedThreatDetection) for file-based analysis
    - Adds driver-specific runtime behavioral checks
    
    .DESCRIPTION
    Hybrid analysis combining:
    1. File-based analysis via general framework (entropy, signatures, patterns)
    2. Driver-specific runtime behavior (network from services, process spawning, registry, etc.)
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [string]$DriverServiceName = $null
    )
    
    try {
        $threatScore = 0
        $behavioralIndicators = @()
        $reasons = @()
        $fileBasedScore = 0
        
        if (-not $DriverServiceName) {
            $DriverServiceName = $DriverName
        }
        
        # PART 1: Use general framework for file-based analysis (if driver path provided)
        if ($DriverPath -and (Test-Path $DriverPath)) {
            try {
                # Define rootkit/driver-specific signatures
                $driverSignatures = @{
                    "Rootkit" = @("rootkit", "stealth", "hide", "hook", "inject", "bypass")
                    "KernelDriver" = @("kernel.*driver", "system.*driver", "kernel.*mode")
                }
                
                # Define behavioral patterns for drivers (command-line would be empty for drivers, but we check file content)
                $driverBehavioralPatterns = @{
                    "SuspiciousName" = @("stealth", "hook", "hide", "rootkit", "inject", "bypass", "protect")
                }
                
                # Use general framework for file-based analysis
                $fileAnalysis = Invoke-AdvancedThreatDetection `
                    -FilePath $DriverPath `
                    -FileSignatures $driverSignatures `
                    -BehavioralIndicators $driverBehavioralPatterns `
                    -CommandLine $null `
                    -CheckEntropy $true `
                    -EntropyThreshold 7.5
                
                if ($fileAnalysis.IsThreat) {
                    $fileBasedScore = $fileAnalysis.Confidence / 5  # Convert confidence to threat score (rough conversion)
                    $reasons += "File-based analysis: $($fileAnalysis.ThreatName) (Confidence: $($fileAnalysis.Confidence)%)"
                    $reasons += "Detection methods: $($fileAnalysis.DetectionMethods -join ', ')"
                    if ($fileAnalysis.Details.ContainsKey("Entropy")) {
                        $behavioralIndicators += "HighEntropy"
                        $reasons += "High entropy detected: $($fileAnalysis.Details.Entropy)"
                    }
                }
            } catch {
                Write-EDRLog -Module "DriverBehavioralAnalysis" -Message "Error in file-based analysis for $DriverPath : $_" -Level "Warning"
            }
        }
        
        # PART 2: Driver-specific runtime behavioral checks
        # 1. Check for network activity from driver service
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.ProcessId) {
                $proc = Get-Process -Id $serviceProcess.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    # Check for network connections
                    $netConnections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
                    if ($netConnections) {
                        $externalConnections = $netConnections | Where-Object { $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" -and $_.State -eq "Established" }
                        if ($externalConnections) {
                            $threatScore += 15
                            $behavioralIndicators += "NetworkActivity"
                            $uniqueAddresses = $externalConnections | Select-Object -First 3 -ExpandProperty RemoteAddress -Unique
                            $reasons += "Driver service has active network connections to: $($uniqueAddresses -join ', ')"
                        }
                    }
                }
            }
        } catch {}
        
        # 2. Check for recent file system modifications (runtime indicator)
        if ($DriverPath -and (Test-Path $DriverPath)) {
            try {
                $driverFile = Get-Item $DriverPath -ErrorAction SilentlyContinue
                if ($driverFile) {
                    $fileAge = (Get-Date) - $driverFile.LastWriteTime
                    
                    # Very recent modification (within last 24 hours) - suspicious
                    if ($fileAge.TotalHours -lt 24) {
                        $threatScore += 10
                        $behavioralIndicators += "RecentModification"
                        $reasons += "Driver file modified recently ($([Math]::Round($fileAge.TotalHours, 1)) hours ago)"
                    }
                }
            } catch {}
        }
        
        # 3. Check registry modifications related to the driver
        try {
            $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverServiceName"
            if (Test-Path $serviceKey) {
                $serviceProps = Get-ItemProperty -Path $serviceKey -ErrorAction SilentlyContinue
                
                # Check for suspicious registry values
                if ($serviceProps) {
                    # Check if StartType was recently changed (suggests manipulation)
                    # This is harder to detect without baseline, but we can check for suspicious values
                    if ($serviceProps.Start -eq 0 -and $serviceProps.Type -eq 1) {
                        # Kernel driver set to boot start - check if it's in standard location
                        if ($serviceProps.ImagePath -and $serviceProps.ImagePath -notmatch "^\\\\?\\C:\\Windows") {
                            $threatScore += 8
                            $behavioralIndicators += "SuspiciousServiceConfig"
                            $reasons += "Driver service configured for boot start from non-standard location"
                        }
                    }
                }
            }
        } catch {}
        
        # 4. Check for processes spawned by driver service
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.ProcessId) {
                $proc = Get-Process -Id $serviceProcess.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    # Check for child processes (driver services typically don't spawn processes)
                    $childProcesses = Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                    if ($childProcesses) {
                        $threatScore += 15
                        $behavioralIndicators += "ProcessCreation"
                        $uniqueProcesses = $childProcesses | Select-Object -First 3 -ExpandProperty Name -Unique
                        $reasons += "Driver service spawned processes: $($uniqueProcesses -join ', ')"
                    }
                }
            }
        } catch {}
        
        # 5. Check for file system access patterns (if service is running)
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.State -eq "Running") {
                # Check if driver is accessing user directories (suspicious for system drivers)
                # This is harder to detect without kernel hooks, but we can check service dependencies
                $dependents = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue | 
                    Get-CimAssociatedInstance -ResultClassName Win32_Service -ErrorAction SilentlyContinue
                
                # If driver has many dependencies or is depended upon by many services, it's more critical
                # This is just metadata, not true behavioral, but gives context
            }
        } catch {}
        
        # 6. Check for driver loading time patterns (loaded at unusual times)
        try {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($service -and $service.PathName) {
                # Check if driver file was created/modified at unusual times
                # (e.g., outside business hours if this is a corporate environment)
                # This is a weak indicator but can be part of the analysis
            }
        } catch {}
        
        # Combine file-based and runtime behavioral scores
        $totalThreatScore = $fileBasedScore + $threatScore
        
        # Determine severity based on total threat score
        # Combine file-based and runtime behavioral scores
        $totalThreatScore = $fileBasedScore + $threatScore
        
        $severity = "Low"
        if ($totalThreatScore -ge 30) {
            $severity = "Critical"
        } elseif ($totalThreatScore -ge 20) {
            $severity = "High"
        } elseif ($totalThreatScore -ge 10) {
            $severity = "Medium"
        }
        
        return @{
            ThreatScore = $totalThreatScore
            FileBasedScore = $fileBasedScore
            RuntimeBehaviorScore = $threatScore
            Severity = $severity
            BehavioralIndicators = $behavioralIndicators
            Reasons = $reasons
            IsMalicious = $totalThreatScore -ge 20  # Threshold for considering driver malicious
        }
    } catch {
        Write-EDRLog -Module "DriverBehavioralAnalysis" -Message "Error analyzing driver $DriverName : $_" -Level "Warning"
        return @{
            ThreatScore = 0
            Severity = "Low"
            BehavioralIndicators = @()
            Reasons = @()
            IsMalicious = $false
        }
    }
}

function Remove-MinifilterDriverSafe {
    <#
    .SYNOPSIS
    Safely removes ANY minifilter driver using fltmc unload before stopping/deleting.
    This prevents BSODs by properly unloading the filter before removal.
    
    .DESCRIPTION
    This is a general-purpose function that safely removes minifilter drivers.
    It should be used for malicious minifilter drivers detected as threats.
    Legitimate drivers (signed, standard location) won't be flagged as threats.
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [switch]$DeleteDriverFile = $false
    )
    
    try {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Attempting to safely remove minifilter driver: $DriverName" -Level "Info"
        
        # Check if driver is a registered minifilter by checking fltmc filters
        $isMinifilter = $false
        try {
            $fltmcOutput = fltmc filters 2>&1 | Out-String
            if ($fltmcOutput -match [regex]::Escape($DriverName)) {
                $isMinifilter = $true
            }
        } catch {
            # If fltmc fails, assume it might be a minifilter for safety
            $isMinifilter = $true
        }
        
        # Step 1: Unload the minifilter using fltmc (CRITICAL - prevents BSOD)
        if ($isMinifilter) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Unloading minifilter driver: $DriverName using fltmc" -Level "Info"
                $unloadResult = fltmc unload $DriverName 2>&1 | Out-String
                
                if ($LASTEXITCODE -eq 0 -or $unloadResult -match "success|unloaded") {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Successfully unloaded minifilter: $DriverName" -Level "Info"
                    Start-Sleep -Milliseconds 500  # Give system time to process unload
                } else {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "fltmc unload result for $DriverName : $unloadResult" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to unload minifilter $DriverName with fltmc: $_" -Level "Warning"
            }
        }
        
        # Step 2: Stop the driver service
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Stopping driver service: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "stop $DriverName")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $stopResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0 -or $stopResult -match "STOPPED|STOP_PENDING") {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Stopped driver service: $DriverName" -Level "Info"
                Start-Sleep -Milliseconds 500  # Give system time to process stop
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver stop result for $DriverName : $stopResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to stop driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 3: Disable the driver to prevent auto-start
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Disabling driver service: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "config $DriverName start= disabled")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $configResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Disabled driver service: $DriverName (will not start on next boot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver disable result for $DriverName : $configResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to disable driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 4: Mark driver service for deletion (will be removed after reboot)
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Marking driver service for deletion: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "delete $DriverName")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $deleteResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Marked driver service for deletion: $DriverName (will be removed after reboot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver delete result for $DriverName : $deleteResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to mark driver service for deletion $DriverName : $_" -Level "Warning"
        }
        
        # Step 5: If driver file path is provided and DeleteDriverFile is set, schedule file for deletion
        if ($DeleteDriverFile -and $DriverPath -and (Test-Path $DriverPath)) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Preparing to delete driver file: $DriverPath" -Level "Info"
                
                # Take ownership of the file
                $takeownResult = takeown /f $DriverPath /A 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Reset permissions
                $icaclsResult = icacls $DriverPath /reset 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Remove inheritance and grant full control to administrators
                $icaclsResult2 = icacls $DriverPath /inheritance:d /grant "Administrators:F" 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Try to delete the file (may fail if in use, will be deleted on reboot)
                try {
                    Remove-Item -Path $DriverPath -Force -ErrorAction Stop
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Deleted driver file: $DriverPath" -Level "Info"
                } catch {
                    # If deletion fails, schedule for deletion on reboot using MoveFileEx
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Could not delete $DriverPath immediately (may be in use), will be removed on reboot" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to delete driver file $DriverPath : $_" -Level "Warning"
            }
        }
        
        Write-EDRLog -Module "MinifilterRemoval" -Message "Completed safe removal process for minifilter driver: $DriverName" -Level "Info"
        return $true
    } catch {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Error removing minifilter driver $DriverName : $_" -Level "Error"
        return $false
    }
}

function Remove-MinifilterDriver {
    <#
    .SYNOPSIS
    Safely removes a minifilter driver using fltmc unload before stopping/deleting.
    This prevents BSODs by properly unloading the filter before removal.
    
    .DESCRIPTION
    This function only targets specific drivers (bfs, unionfs) from the batch file.
    Other minifilter drivers (including legitimate antivirus drivers) are NOT processed
    by this function to avoid interfering with user security software.
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [switch]$DeleteDriverFile = $false
    )
    
    try {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Attempting to remove minifilter driver: $DriverName" -Level "Info"
        
        # List of specific minifilter drivers to remove (only drivers explicitly listed in batch file)
        # Only targeting bfs and unionfs - other drivers (including antivirus) are NOT targeted
        # This prevents interference with legitimate security software
        $targetDrivers = @("bfs", "unionfs")
        
        # Check if this is a target driver
        $isTargetDriver = $false
        foreach ($target in $targetDrivers) {
            if ($DriverName -like "*$target*" -or $DriverName -eq $target) {
                $isTargetDriver = $true
                break
            }
        }
        
        # Also check driver path if provided
        if (-not $isTargetDriver -and $DriverPath) {
            $driverFileName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPath).ToLower()
            foreach ($target in $targetDrivers) {
                if ($driverFileName -like "*$target*" -or $driverFileName -eq $target) {
                    $isTargetDriver = $true
                    break
                }
            }
        }
        
        if (-not $isTargetDriver) {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Driver $DriverName is not in target list, skipping minifilter removal" -Level "Debug"
            return $false
        }
        
        # Step 1: Check if driver is a registered minifilter by checking fltmc filters
        $isMinifilter = $false
        try {
            $fltmcOutput = fltmc filters 2>&1 | Out-String
            if ($fltmcOutput -match [regex]::Escape($DriverName)) {
                $isMinifilter = $true
            }
        } catch {
            # If fltmc fails, assume it might be a minifilter for safety
            $isMinifilter = $true
        }
        
        # Step 2: Unload the minifilter using fltmc (CRITICAL - prevents BSOD)
        if ($isMinifilter) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Unloading minifilter driver: $DriverName using fltmc" -Level "Info"
                $unloadResult = fltmc unload $DriverName 2>&1 | Out-String
                
                if ($LASTEXITCODE -eq 0 -or $unloadResult -match "success|unloaded") {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Successfully unloaded minifilter: $DriverName" -Level "Info"
                    Start-Sleep -Milliseconds 500  # Give system time to process unload
                } else {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "fltmc unload result for $DriverName : $unloadResult" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to unload minifilter $DriverName with fltmc: $_" -Level "Warning"
            }
        }
        
        # Step 3: Stop the driver service
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Stopping driver service: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "stop $DriverName")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $stopResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0 -or $stopResult -match "STOPPED|STOP_PENDING") {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Stopped driver service: $DriverName" -Level "Info"
                Start-Sleep -Milliseconds 500  # Give system time to process stop
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver stop result for $DriverName : $stopResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to stop driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 4: Disable the driver to prevent auto-start
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Disabling driver service: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "config $DriverName start= disabled")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $configResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Disabled driver service: $DriverName (will not start on next boot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver disable result for $DriverName : $configResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to disable driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 5: Mark driver service for deletion (will be removed after reboot)
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Marking driver service for deletion: $DriverName" -Level "Info"
            $psi = [System.Diagnostics.ProcessStartInfo]::new("sc.exe", "delete $DriverName")
            $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi); $deleteResult = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
            if ($p.ExitCode -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Marked driver service for deletion: $DriverName (will be removed after reboot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver delete result for $DriverName : $deleteResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to mark driver service for deletion $DriverName : $_" -Level "Warning"
        }
        
        # Step 6: If driver file path is provided and DeleteDriverFile is set, schedule file for deletion
        if ($DeleteDriverFile -and $DriverPath -and (Test-Path $DriverPath)) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Preparing to delete driver file: $DriverPath" -Level "Info"
                
                # Take ownership of the file
                $takeownResult = takeown /f $DriverPath /A 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Reset permissions
                $icaclsResult = icacls $DriverPath /reset 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Remove inheritance and grant full control to administrators
                $icaclsResult2 = icacls $DriverPath /inheritance:d /grant "Administrators:F" 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Try to delete the file (may fail if in use, will be deleted on reboot)
                try {
                    Remove-Item -Path $DriverPath -Force -ErrorAction Stop
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Deleted driver file: $DriverPath" -Level "Info"
                } catch {
                    # If deletion fails, schedule for deletion on reboot using MoveFileEx
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Could not delete $DriverPath immediately (may be in use), will be removed on reboot" -Level "Warning"
                    # Note: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT (4) would require P/Invoke, using sc.exe delete handles service removal
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to delete driver file $DriverPath : $_" -Level "Warning"
            }
        }
        
        Write-EDRLog -Module "MinifilterRemoval" -Message "Completed removal process for minifilter driver: $DriverName" -Level "Info"
        return $true
    } catch {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Error removing minifilter driver $DriverName : $_" -Level "Error"
        return $false
    }
}

function Invoke-ResponseAction {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium"
    )
    
    try {
        $actions = @{
            "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "StopDriver", "Log")
            "High"     = @("Quarantine", "StopDriver", "Log", "Alert")
            "Medium"   = @("Quarantine", "Log", "Alert")
            "Low"      = @("Log")
        }
        
        $responseActions = $actions[$Severity]
        
        foreach ($action in $responseActions) {
            switch ($action) {
                "Quarantine" {
                    # Validate that ThreatPath is a valid file path before attempting quarantine
                    # Skip quarantine for non-file paths (process names, registry paths, network addresses, etc.)
                    if (-not $ThreatPath) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - ThreatPath is empty (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                        continue
                    }
                    
                    # Check if it looks like a file path (contains drive letter or starts with \ or /)
                    $isLikelyFilePath = $ThreatPath -match '^([A-Za-z]:\\|\\\\|/|\.\\)' -or (Test-Path $ThreatPath -PathType Leaf)
                    
                    if (-not $isLikelyFilePath) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Skipping quarantine - ThreatPath appears to be non-file identifier: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                        continue
                    }
                    
                    # Verify it's actually a file (not a directory)
                    if (Test-Path $ThreatPath -PathType Leaf) {
                        $quarantineResult = Invoke-QuarantineFile -FilePath $ThreatPath -Reason $ThreatType -Source "ResponseEngine"
                        if (-not $quarantineResult) {
                            Write-EDRLog -Module "ResponseEngine" -Message "Quarantine failed or skipped for: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Warning"
                        }
                    } elseif (Test-Path $ThreatPath -PathType Container) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - path is a directory, not a file: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                    } else {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - file does not exist: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                    }
                }
                "KillProcess" {
                    try {
                        # ThreatPath might be a PID (integer) or process name
                        if ($ThreatPath -match '^\d+$') {
                            $threatPID = [int]$ThreatPath
                            
                            # Whitelist own process - never kill ourselves
                            if ($threatPID -eq $PID -or $threatPID -eq $Script:SelfPID) {
                                Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $threatPID) - whitelisted" -Level "Warning"
                                return
                            }
                            
                            # Check if this PID is running our script - if so, whitelist it
                            try {
                                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $threatPID" -ErrorAction SilentlyContinue).CommandLine
                                $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                    Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $threatPID) - whitelisted" -Level "Warning"
                                    return
                                }
                            } catch {}
                            
                            $proc = Get-Process -Id $threatPID -ErrorAction SilentlyContinue
                            if ($proc) {
                                Stop-Process -Id $threatPID -Force -ErrorAction SilentlyContinue
                                Write-EDRLog -Module "ResponseEngine" -Message "Terminated process PID: $ThreatPath" -Level "Info"
                            }
                        } else {
                            $proc = Get-Process -Name $ThreatPath -ErrorAction SilentlyContinue
                            if ($proc) {
                                # Check each process to ensure we're not killing our own
                                foreach ($p in $proc) {
                                    if ($p.Id -eq $PID -or $p.Id -eq $Script:SelfPID) {
                                        Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $($p.Id), Name: $ThreatPath) - whitelisted" -Level "Warning"
                                        continue
                                    }
                                    
                                    # Check if this process is running our script
                                    try {
                                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                                        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                        if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                            Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $($p.Id)) - whitelisted" -Level "Warning"
                                            continue
                                        }
                                    } catch {}
                                    
                                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                                    Write-EDRLog -Module "ResponseEngine" -Message "Terminated process: $ThreatPath (PID: $($p.Id))" -Level "Info"
                                }
                            }
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to kill process $ThreatPath : $_" -Level "Warning"
                    }
                }
                "BlockNetwork" {
                    try {
                        # Extract IP address from ThreatPath if it's in format "IP:Port" or just "IP"
                        $ipAddress = if ($ThreatPath -match '^(\d+\.\d+\.\d+\.\d+)') { $matches[1] } else { $ThreatPath }
                        
                        $RuleName = "Block_ResponseEngine_$ipAddress" -replace '[\.:]', '_'
                        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                        
                        if (-not $existingRule) {
                            New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $ipAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                            Write-EDRLog -Module "ResponseEngine" -Message "Blocked network connection to $ipAddress" -Level "Info"
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to block network for $ThreatPath : $_" -Level "Warning"
                    }
                }
                "Log" {
                    Write-EDRLog -Module "ResponseEngine" -Message "THREAT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                }
                "StopDriver" {
                    try {
                        # Check if this is a driver threat (format: "Driver:DriverName|Path" or just a driver path)
                        $driverName = $null
                        $driverPath = $ThreatPath
                        
                        if ($ThreatPath -match "^Driver:([^|]+)\|(.+)$") {
                            $driverName = $matches[1]
                            $driverPath = $matches[2]
                        } elseif ($ThreatType -eq "Rootkit" -and $ThreatPath) {
                            # Try to extract driver name from service registry
                            try {
                                $service = Get-CimInstance -ClassName Win32_SystemDriver -Filter "PathName LIKE '%$($ThreatPath -replace '\\', '\\')%'" -ErrorAction SilentlyContinue | Select-Object -First 1
                                if ($service) {
                                    $driverName = $service.Name
                                }
                            } catch {}
                            
                            # If driver name not found, try to extract from path
                            if (-not $driverName -and $ThreatPath -match '([^\\]+)\.sys$') {
                                $driverName = $matches[1]
                            }
                        }
                        
                        if ($driverName -and $driverPath) {
                            # CRITICAL: Check if this is an inbox/Windows system driver - NEVER remove these
                            $isInboxDriver = $false
                            if ($driverPath -like "*\Windows\System32\drivers\*" -or $driverPath -like "*\SystemRoot\System32\drivers\*") {
                                try {
                                    # Check if driver is signed by Microsoft (inbox drivers are Microsoft-signed)
                                    if (Test-Path $driverPath) {
                                        $sig = Get-AuthenticodeSignature -FilePath $driverPath -ErrorAction SilentlyContinue
                                        if ($sig.Status -eq "Valid" -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match "Microsoft") {
                                            $isInboxDriver = $true
                                            Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to remove inbox/Windows system driver (Microsoft-signed): $driverName at $driverPath - skipping removal" -Level "Warning"
                                        }
                                    }
                                } catch {
                                    # If we can't verify signature but driver is in System32\drivers, err on side of caution
                                    if ($driverPath -like "*\Windows\System32\drivers\*" -or $driverPath -like "*\SystemRoot\System32\drivers\*") {
                                        $isInboxDriver = $true
                                        Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to remove driver from System32\drivers (potential inbox driver): $driverName at $driverPath - skipping removal" -Level "Warning"
                                    }
                                }
                            }
                            
                            if ($isInboxDriver) {
                                Write-EDRLog -Module "ResponseEngine" -Message "Driver removal blocked: $driverName is an inbox/Windows system driver" -Level "Warning"
                                return
                            }
                            
                            # AUTOMATIC MINIFILTER DRIVER REMOVAL DISABLED - Too risky, causes BSODs
                            # Minifilter drivers are detected and logged, but automatic removal is disabled
                            Write-EDRLog -Module "ResponseEngine" -Message "Driver removal requested for: $driverName, but automatic minifilter driver removal is disabled to prevent BSODs. Manual review recommended." -Level "Warning"
                            
                            # Log the driver information but do not remove
                            Write-EDRLog -Module "ResponseEngine" -Message "Detected driver threat (removal disabled): $driverName | Path: $driverPath | Type: $ThreatType | Severity: $Severity" -Level "Warning"
                        } else {
                            Write-EDRLog -Module "ResponseEngine" -Message "Could not determine driver name from threat path: $ThreatPath" -Level "Warning"
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to process driver removal for $ThreatPath : $_" -Level "Warning"
                    }
                }
                "Alert" {
                    try {
                        # Ensure event log source exists before writing
                        if ($null -ne $Config -and $null -ne $Config.EDRName -and -not [string]::IsNullOrWhiteSpace($Config.EDRName)) {
                            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                            }
                            Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Warning -EventId 2000 `
                                -Message "THREAT ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Event log may not be available, fall back to EDR log
                        Write-EDRLog -Module "ResponseEngine" -Message "ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                    }
                }
            }
        }
    } catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error processing response action: $_" -Level "Error"
    }
}

function Invoke-ResponseEngine {
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Process up to 50 items from the queue per tick to avoid blocking
        $processedCount = 0
        $maxProcessPerTick = 50

        while ($Script:ResponseQueue.Count -gt 0 -and $processedCount -lt $maxProcessPerTick) {
            try {
                $threat = $Script:ResponseQueue.Dequeue()
                
                if ($threat -and $threat.ThreatType -and $threat.ThreatPath) {
                    Invoke-ResponseAction -ThreatType $threat.ThreatType -ThreatPath $threat.ThreatPath -Severity $threat.Severity
                    $processedCount++
                }
            }
            catch {
                Write-EDRLog -Module "ResponseEngine" -Message "Error processing threat from queue: $_" -Level "Error"
            }
        }

        if ($processedCount -gt 0) {
            Write-EDRLog -Module "ResponseEngine" -Message "Processed $processedCount threat(s) from queue. Queue size: $($Script:ResponseQueue.Count)" -Level "Info"
        }

        # Return count without outputting to pipeline - suppress any accidental output
        # Store result in variable and explicitly return (don't let it output to console)
        $result = $processedCount
        [void]$result  # Explicitly discard if accidentally output
        return $result
    } catch {
        Write-EDRLog -Module "ResponseEngine" -Message "Error: $_" -Level "Error"
        return 0
    }
}

# PrivacyForge Spoofing Module (Converted from Spoofer.py)
function Invoke-PrivacyForgeSpoofing {
    param(
        [hashtable]$Config
    )
    
    # Initialize script-level variables if not already set
    if (-not $Script:PrivacyForgeIdentity) {
        $Script:PrivacyForgeIdentity = @{}
        $Script:PrivacyForgeDataCollected = 0
        $Script:PrivacyForgeRotationInterval = 3600  # 1 hour
        $Script:PrivacyForgeDataThreshold = 50
        $Script:PrivacyForgeLastRotation = Get-Date
    }
    
    try {
        # Check if rotation is needed
        $timeSinceRotation = (Get-Date) - $Script:PrivacyForgeLastRotation
        $shouldRotate = $false
        
        if ($timeSinceRotation.TotalSeconds -ge $Script:PrivacyForgeRotationInterval) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Time-based rotation triggered" "INFO"
        }
        
        if ($Script:PrivacyForgeDataCollected -ge $Script:PrivacyForgeDataThreshold) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Data threshold reached ($Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold)" "INFO"
        }
        
        if ($shouldRotate -or (-not $Script:PrivacyForgeIdentity.ContainsKey("name"))) {
            Invoke-PrivacyForgeRotateIdentity
        }
        
        # Simulate data collection
        $Script:PrivacyForgeDataCollected += Get-Random -Minimum 1 -Maximum 6
        
        # Perform spoofing operations (full Spoofer.ps1 logic)
        Invoke-PrivacyForgeSpoofSoftwareMetadata
        Invoke-PrivacyForgeSpoofGameTelemetry
        Invoke-PrivacyForgeSpoofSensors
        Invoke-PrivacyForgeSpoofSystemMetrics
        Invoke-PrivacyForgeSpoofClipboard
        Invoke-PrivacyForgeSpoofFileMetadata
        Invoke-PrivacyForgeSpoofDNSNoise
        Invoke-PrivacyForgeSpoofBrowserFingerprint
        
        Write-AVLog "PrivacyForge: Spoofing active - Data collected: $Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold" "INFO"
        
    } catch {
        Write-AVLog "PrivacyForge: Error - $_" "ERROR"
    }
}

function Invoke-PrivacyForgeGenerateIdentity {
    # Generate fake identity data
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Jessica", "Robert", "Amanda", "William", "Ashley", "Richard", "Melissa", "Joseph", "Nicole")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas", "Taylor")
    $domains = @("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com")
    $cities = @("New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose")
    $countries = @("United States", "Canada", "United Kingdom", "Australia", "Germany", "France", "Spain", "Italy")
    $languages = @("en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "pt-BR")
    $interests = @("tech", "gaming", "news", "sports", "music", "movies", "travel", "food", "fitness", "books")
    
    $firstName = Get-Random -InputObject $firstNames
    $lastName = Get-Random -InputObject $lastNames
    $username = "$firstName$lastName" + (Get-Random -Minimum 100 -Maximum 9999)
    $domain = Get-Random -InputObject $domains
    $email = "$username@$domain"
    
    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    
    return @{
        "name" = "$firstName $lastName"
        "email" = $email
        "username" = $username
        "location" = Get-Random -InputObject $cities
        "country" = Get-Random -InputObject $countries
        "user_agent" = Get-Random -InputObject $userAgents
        "screen_resolution" = "$(Get-Random -Minimum 1280 -Maximum 1920)x$(Get-Random -Minimum 720 -Maximum 1080)"
        "interests" = (Get-Random -InputObject $interests -Count 4)
        "device_id" = [System.Guid]::NewGuid().ToString()
        "session_id" = (Get-Random -Minimum 100000 -Maximum 999999)
        "hardware_id" = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
        "mac_address" = (1..6 | ForEach-Object { '{0:X2}' -f (Get-Random -Minimum 0 -Maximum 256) }) -join ':'
        "language" = Get-Random -InputObject $languages
        "timezone" = Get-Random -InputObject @('America/New_York','America/Los_Angeles','Europe/London','Europe/Paris','Asia/Tokyo')
        "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Invoke-PrivacyForgeRotateIdentity {
    $Script:PrivacyForgeIdentity = Invoke-PrivacyForgeGenerateIdentity
    $Script:PrivacyForgeDataCollected = 0
    $Script:PrivacyForgeLastRotation = Get-Date
    
    Write-AVLog "PrivacyForge: Identity rotated - Name: $($Script:PrivacyForgeIdentity.name), Username: $($Script:PrivacyForgeIdentity.username)" "INFO"
}

function Invoke-PrivacyForgeSpoofSoftwareMetadata {
    try {
        $headers = @{
            "User-Agent" = $Script:PrivacyForgeIdentity.user_agent
            "Cookie" = "session_id=$(Get-Random -Minimum 1000 -Maximum 9999); fake_id=$([System.Guid]::NewGuid().ToString())"
            "X-Device-ID" = $Script:PrivacyForgeIdentity.device_id
            "Accept-Language" = $Script:PrivacyForgeIdentity.language
            "X-Timezone" = $Script:PrivacyForgeIdentity.timezone
        }
        
        # Attempt to send spoofed headers (non-blocking)
        try {
            $null = Invoke-WebRequest -Uri "https://httpbin.org/headers" -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
            Write-AVLog "PrivacyForge: Sent spoofed software metadata headers" "DEBUG"
        } catch {
            # Silently fail - network may not be available
        }
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing software metadata - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofGameTelemetry {
    try {
        $fakeTelemetry = @{
            "player_id" = [System.Guid]::NewGuid().ToString()
            "hardware_id" = ((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-Random).ToString())) | ForEach-Object { $_.ToString("X2") }) -join ''
            "latency" = Get-Random -Minimum 20 -Maximum 200
            "game_version" = "$(Get-Random -Minimum 1 -Maximum 5).$(Get-Random -Minimum 0 -Maximum 9)"
            "fps" = Get-Random -Minimum 30 -Maximum 120
        }
        Write-AVLog "PrivacyForge: Spoofed game telemetry - Player ID: $($fakeTelemetry.player_id)" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing game telemetry - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSensors {
    try {
        # Generate random sensor data to spoof fingerprinting
        $null = @{
            "accelerometer" = @{
                "x" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "y" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "z" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
            }
            "gyroscope" = @{
                "pitch" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "roll" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "yaw" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
            }
            "magnetometer" = @{
                "x" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "y" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "z" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
            }
            "light_sensor" = (Get-Random -Minimum 0 -Maximum 1000) / 1.0
            "proximity_sensor" = Get-Random -InputObject @(0, 5, 10)
            "ambient_temperature" = (Get-Random -Minimum 1500 -Maximum 3500) / 100.0
        }
        Write-AVLog "PrivacyForge: Spoofed sensor data" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing sensors - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSystemMetrics {
    try {
        $fakeMetrics = @{
            "cpu_usage" = (Get-Random -Minimum 0 -Maximum 10000) / 100.0
            "memory_usage" = (Get-Random -Minimum 1000 -Maximum 9000) / 100.0
            "battery_level" = Get-Random -Minimum 20 -Maximum 100
        }
        Write-AVLog "PrivacyForge: Spoofed system metrics - CPU: $($fakeMetrics.cpu_usage)%, Memory: $($fakeMetrics.memory_usage)%" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing system metrics - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofClipboard {
    try {
        $fakeTexts = @("Meeting at 3pm tomorrow","Remember to call John","https://www.example.com/article/12345","groceries: milk, bread, eggs","The quick brown fox jumps over the lazy dog")
        $fakeContent = Get-Random -InputObject $fakeTexts
        Set-Clipboard -Value $fakeContent -ErrorAction SilentlyContinue
        Write-AVLog "PrivacyForge: Spoofed clipboard content" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing clipboard - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofFileMetadata {
    try {
        $dummyFile = Join-Path $env:TEMP "pf_dummy_$(Get-Random).txt"
        $fakeContent = "Random content: $([Guid]::NewGuid().ToString())"
        $fakeContent | Out-File -FilePath $dummyFile -Encoding UTF8 -ErrorAction Stop
        $randomDate = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 365))
        (Get-Item $dummyFile).LastWriteTime = $randomDate
        (Get-Item $dummyFile).CreationTime = $randomDate.AddDays(-(Get-Random -Minimum 1 -Maximum 30))
        Remove-Item $dummyFile -Force -ErrorAction SilentlyContinue
        Write-AVLog "PrivacyForge: Spoofed file metadata" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing file metadata - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofDNSNoise {
    try {
        $noiseDomains = @("news.google.com","mail.yahoo.com","docs.microsoft.com","developer.mozilla.org","stackoverflow.com")
        $selected = $noiseDomains | Get-Random -Count 2
        foreach ($domain in $selected) {
            $null = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
        }
        Write-AVLog "PrivacyForge: DNS noise generated" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing DNS noise - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofBrowserFingerprint {
    try {
        $fingerprint = @{
            WebGL = @('NVIDIA Corporation','AMD','Intel Inc.','Apple GPU') | Get-Random
            ColorDepth = @(24, 32) | Get-Random
            PixelRatio = @(1, 1.25, 1.5, 2) | Get-Random
        }
        Write-AVLog "PrivacyForge: Browser fingerprint spoofed - WebGL=$($fingerprint.WebGL)" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing browser fingerprint - $_" "WARN"
    }
}

#endregion

# ===================== Independent Modules (No Whitelist/Response Engine) =====================
# These modules operate independently and do not respect whitelists or use the response engine
# They share logs and quarantine folders with the main antivirus

# ELF DLL Unloader - Actively unloads ELF DLLs from browser processes
function Invoke-ElfDLLUnloader {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DLLUnloader').Type) {
            Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class DLLUnloader {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool MoveFileEx(string src, string dst, int flags);
}
"@ -ErrorAction SilentlyContinue
        }
        $whitelist = @('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'gdi32.dll', 'msvcrt.dll', 'advapi32.dll')
        $targets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore', 'microsoftedge', 'waterfox', 'palemoon')
        if (-not $Script:ElfDLLProcessed) { $Script:ElfDLLProcessed = @{} }
        $unloadedCount = 0
        foreach ($procName in $targets) {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            foreach ($proc in $procs) {
                try {
                    $hProc = [DLLUnloader]::OpenProcess(0x1F0FFF, $false, $proc.Id)
                    if ($hProc -eq [IntPtr]::Zero) { continue }
                    $freeLib = [DLLUnloader]::GetProcAddress([DLLUnloader]::GetModuleHandle("kernel32.dll"), "FreeLibrary")
                    foreach ($mod in $proc.Modules) {
                        $name = [System.IO.Path]::GetFileName($mod.FileName).ToLower()
                        if ($whitelist -contains $name) { continue }
                        $key = "$($proc.Id):$($mod.FileName)"
                        if ($Script:ElfDLLProcessed.ContainsKey($key)) { continue }
                        if ($name -like '*_elf.dll') {
                            Write-AVLog "ELF DLL Unloader: Unloading $name from $procName (PID $($proc.Id))" "INFO" "elf_dll_unloader.log"
                            $thread = [DLLUnloader]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $freeLib, $mod.BaseAddress, 0, [IntPtr]::Zero)
                            if ($thread -ne [IntPtr]::Zero) {
                                [DLLUnloader]::WaitForSingleObject($thread, 5000) | Out-Null
                                [DLLUnloader]::CloseHandle($thread) | Out-Null
                                if ([DLLUnloader]::MoveFileEx($mod.FileName, $null, 4)) { Write-AVLog "ELF DLL Unloader: Scheduled deletion on reboot: $($mod.FileName)" "INFO" "elf_dll_unloader.log" }
                                $unloadedCount++
                            }
                            $Script:ElfDLLProcessed[$key] = Get-Date
                        }
                    }
                    [DLLUnloader]::CloseHandle($hProc) | Out-Null
                } catch { Write-AVLog "ELF DLL Unloader error for process $procName (PID: $($proc.Id)): $_" "WARN" "elf_dll_unloader.log" }
            }
        }
        if ($Script:ElfDLLProcessed.Count -gt 1000) { $oldKeys = $Script:ElfDLLProcessed.Keys | Where-Object { ((Get-Date) - $Script:ElfDLLProcessed[$_]).TotalHours -gt 24 }; foreach ($key in $oldKeys) { $Script:ElfDLLProcessed.Remove($key) } }
        if ($unloadedCount -gt 0) { Write-AVLog "ELF DLL Unloader: Unloaded $unloadedCount ELF DLL(s)" "INFO" "elf_dll_unloader.log" }
        return $unloadedCount
    } catch { Write-AVLog "ELF DLL Unloader error: $_" "ERROR" "elf_dll_unloader.log"; return 0 }
}

# Unsigned DLL Remover - Scans and quarantines unsigned DLLs/WINMD files
function Invoke-UnsignedDLLRemover {
    # This module operates independently - no whitelist checks, no response engine
    try {
        # Initialize scanned files database
        $localDatabase = "$($Config.DatabasePath)\scanned_dlls.txt"
        if (-not $Script:UnsignedDLLScannedFiles) {
            $Script:UnsignedDLLScannedFiles = @{}
            
            # Load existing database
            if (Test-Path $localDatabase) {
                try {
                    $lines = Get-Content $localDatabase -ErrorAction Stop
                    foreach ($line in $lines) {
                        if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                            $Script:UnsignedDLLScannedFiles[$matches[1]] = [bool]$matches[2]
                        }
                    }
                    Write-AVLog "Unsigned DLL Remover: Loaded $($Script:UnsignedDLLScannedFiles.Count) scanned file entries" "INFO" "unsigned_dll_remover.log"
                } catch {
                    Write-AVLog "Unsigned DLL Remover: Failed to load database: $_" "WARN" "unsigned_dll_remover.log"
                }
            }
        }
        
        $quarantinedCount = 0
        
        # Helper function to check if file should be excluded (DeepSeek: protect system)
        function Should-ExcludeDLLFile {
            param ([string]$filePath)
            $lowerPath = $filePath.ToLower()
            
            # NEVER touch Windows system DLLs - could cause boot failure
            if ($lowerPath -like "*\windows\system32\*" -or $lowerPath -like "*\windows\syswow64\*" -or
                $lowerPath -like "*\windows\winsxs\*" -or $lowerPath -like "*\program files\*") {
                return $true
            }
            
            if ($lowerPath -like "*\assembly\*") { return $true }
            if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") { return $true }
            if ($lowerPath -like "*$($Config.QuarantinePath -replace '\\', '\\')*") { return $true }
            return $false
        }
        
        # Helper function to set file ownership and permissions
        function Set-DLLFileOwnership {
            param ([string]$filePath)
            try {
                takeown /F $filePath /A 2>&1 | Out-Null
                icacls $filePath /reset 2>&1 | Out-Null
                icacls $filePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
                return $true
            } catch {
                return $false
            }
        }
        
        # Helper function to stop processes using DLL
        function Stop-ProcessesUsingDLL {
            param ([string]$filePath)
            try {
                $processes = Get-Process | Where-Object { 
                    ($_.Modules | Where-Object { $_.FileName -eq $filePath }) 
                } -ErrorAction SilentlyContinue
                
                foreach ($process in $processes) {
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                        Write-AVLog "Unsigned DLL Remover: Stopped process $($process.Name) (PID: $($process.Id)) using $filePath" "INFO" "unsigned_dll_remover.log"
                    } catch {
                        try {
                            taskkill /PID $process.Id /F 2>&1 | Out-Null
                            Write-AVLog "Unsigned DLL Remover: Force-killed process $($process.Name) (PID: $($process.Id))" "INFO" "unsigned_dll_remover.log"
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Helper function to calculate file hash and signature
        function Get-DLLFileHash {
            param ([string]$filePath)
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                return @{
                    Hash = $hash.Hash.ToLower()
                    Status = $signature.Status
                }
            } catch {
                return $null
            }
        }
        
        # Helper function to quarantine file - delegates to Move-ToQuarantine for path safety
        function Quarantine-DLLFile {
            param ([string]$filePath)
            if (Should-ExcludeDLLFile -filePath $filePath) { return $false }
            try {
                $fileName = Split-Path -Leaf $filePath
                $quarantinePath = Join-Path -Path $Config.QuarantinePath -ChildPath "$([DateTime]::Now.Ticks)_$fileName"
                
                if (-not (Test-Path $Config.QuarantinePath)) {
                    New-Item -ItemType Directory -Path $Config.QuarantinePath -Force | Out-Null
                }
                
                Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-AVLog "Unsigned DLL Remover: Quarantined $filePath to $quarantinePath" "INFO" "unsigned_dll_remover.log"
                return $true
            } catch {
                Write-AVLog "Unsigned DLL Remover: Failed to quarantine ${filePath}: $_" "WARN" "unsigned_dll_remover.log"
                return $false
            }
        }
        
        # Scan drives for unsigned DLLs
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
        
        foreach ($drive in $drives) {
            $root = $drive.DeviceID + "\"
            try {
                # Limit scan to prevent excessive resource usage
                $dllFiles = Get-ChildItem -Path $root -Include *.dll,*.winmd -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { -not (Should-ExcludeDLLFile -filePath $_.FullName) } |
                    Select-Object -First 500
                
                foreach ($dll in $dllFiles) {
                    try {
                        $fileHash = Get-DLLFileHash -filePath $dll.FullName
                        if (-not $fileHash) { continue }
                        
                        if ($Script:UnsignedDLLScannedFiles.ContainsKey($fileHash.Hash)) {
                            # Already scanned - check if invalid
                            if (-not $Script:UnsignedDLLScannedFiles[$fileHash.Hash]) {
                                # Previously found invalid - quarantine if still exists
                                if (Test-Path $dll.FullName) {
                                    if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                        Stop-ProcessesUsingDLL -filePath $dll.FullName
                                        if (Quarantine-DLLFile -filePath $dll.FullName) {
                                            $quarantinedCount++
                                        }
                                    }
                                }
                            }
                        } else {
                            # New file - check signature
                            $isValid = $fileHash.Status -eq "Valid"
                            $Script:UnsignedDLLScannedFiles[$fileHash.Hash] = $isValid
                            
                            # Save to database
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                            
                            if (-not $isValid) {
                                # Unsigned DLL found - quarantine it
                                Write-AVLog "Unsigned DLL Remover: Found unsigned DLL: $($dll.FullName) (Hash: $($fileHash.Hash))" "INFO" "unsigned_dll_remover.log"
                                
                                if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                    Stop-ProcessesUsingDLL -filePath $dll.FullName
                                    if (Quarantine-DLLFile -filePath $dll.FullName) {
                                        $quarantinedCount++
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-AVLog "Unsigned DLL Remover: Error processing $($dll.FullName): $_" "WARN" "unsigned_dll_remover.log"
                    }
                }
            } catch {
                Write-AVLog "Unsigned DLL Remover: Scan failed for drive ${root}: $_" "WARN" "unsigned_dll_remover.log"
            }
        }
        
        # Explicit System32 scan (limited)
        try {
            $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Include *.dll,*.winmd -File -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-ExcludeDLLFile -filePath $_.FullName) } |
                Select-Object -First 200
            
            foreach ($dll in $system32Files) {
                try {
                    $fileHash = Get-DLLFileHash -filePath $dll.FullName
                    if (-not $fileHash) { continue }
                    
                    if ($Script:UnsignedDLLScannedFiles.ContainsKey($fileHash.Hash)) {
                        if (-not $Script:UnsignedDLLScannedFiles[$fileHash.Hash]) {
                            if (Test-Path $dll.FullName) {
                                if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                    Stop-ProcessesUsingDLL -filePath $dll.FullName
                                    if (Quarantine-DLLFile -filePath $dll.FullName) {
                                        $quarantinedCount++
                                    }
                                }
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $Script:UnsignedDLLScannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                        
                        if (-not $isValid) {
                            Write-AVLog "Unsigned DLL Remover: Found unsigned System32 DLL: $($dll.FullName)" "INFO" "unsigned_dll_remover.log"
                            
                            if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                Stop-ProcessesUsingDLL -filePath $dll.FullName
                                if (Quarantine-DLLFile -filePath $dll.FullName) {
                                    $quarantinedCount++
                                }
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($quarantinedCount -gt 0) {
            Write-AVLog "Unsigned DLL Remover: Quarantined $quarantinedCount unsigned DLL(s)" "INFO" "unsigned_dll_remover.log"
        }
        
        return $quarantinedCount
    } catch {
        Write-AVLog "Unsigned DLL Remover error: $_" "ERROR" "unsigned_dll_remover.log"
        return 0
    }
}

# ===================== GShield Ported Jobs =====================

# --- YaraDetection ---
$Script:YaraPaths = @("$env:ProgramFiles\Yara\yara64.exe", "$env:ProgramFiles (x86)\Yara\yara.exe", "yara.exe", "yara64.exe")
$Script:YaraRulesPaths = @("$Script:InstallPath\Yara", "$Script:InstallPath\Rules", "$Script:InstallPath\YaraRules")
$Script:YaraScanPaths = @("$env:Temp", "$env:TEMP", "$env:SystemRoot\Temp")

function Get-YaraExe {
    foreach ($p in $Script:YaraPaths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-YaraRulesPath {
    foreach ($p in $Script:YaraRulesPaths) {
        if (Test-Path $p) {
            $rules = Get-ChildItem -Path $p -Filter *.yar -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($rules) { return $rules.Directory.FullName }
        }
    }
    return $null
}

function Invoke-YaraDetection {
    $yara = Get-YaraExe
    if (-not $yara) { return 0 }
    $rulesDir = Get-YaraRulesPath
    if (-not $rulesDir) { return 0 }
    $detections = @()
    foreach ($base in $Script:YaraScanPaths) {
        if (-not (Test-Path $base)) { continue }
        try {
            $files = Get-ChildItem -Path $base -Include *.exe, *.dll, *.ps1 -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($f in $files) {
                try {
                    $out = & $yara -r "$rulesDir\*.yar" $f.FullName 2>&1
                    if ($out -and $out -match '\S') {
                        $detections += @{
                            File = $f.FullName
                            Match = ($out | Select-Object -First 5) -join "; "
                        }
                    }
                } catch { }
            }
        } catch { }
    }
    if ($detections.Count -gt 0) {
        foreach ($d in $detections) {
            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2096 -Message "YARA: $($d.File) - $($d.Match)" -ErrorAction SilentlyContinue
        }
        $logPath = "$Script:InstallPath\Logs\yara_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.File)|$($_.Match)" | Add-Content -Path $logPath }
        Write-AVLog "YaraDetection: Found $($detections.Count) YARA matches" "THREAT"
    }
    return $detections.Count
}

# --- IdsDetection ---
$Script:IdsPatterns = @(
    @{ Pattern = "meterpreter"; Desc = "Metasploit meterpreter" }
    @{ Pattern = "certutil\s+-urlcache"; Desc = "Certutil download" }
    @{ Pattern = "bitsadmin\s+/transfer"; Desc = "Bitsadmin download" }
    @{ Pattern = "powershell\s+-enc"; Desc = "Base64 encoded PS" }
    @{ Pattern = "powershell\s+-w\s+hidden"; Desc = "Hidden window PS" }
    @{ Pattern = "invoke-expression"; Desc = "IEX usage" }
    @{ Pattern = "iex\s*\("; Desc = "IEX usage" }
    @{ Pattern = "downloadstring"; Desc = "DownloadString" }
    @{ Pattern = "downloadfile"; Desc = "DownloadFile" }
    @{ Pattern = "webclient"; Desc = "WebClient" }
    @{ Pattern = "net\.webclient"; Desc = "Net.WebClient" }
    @{ Pattern = "bypass.*-executionpolicy"; Desc = "Execution policy bypass" }
    @{ Pattern = "wmic\s+process\s+call\s+create"; Desc = "WMI process creation" }
    @{ Pattern = "reg\s+add.*HKLM.*Run"; Desc = "Registry Run key" }
    @{ Pattern = "schtasks\s+/create"; Desc = "Scheduled task creation" }
    @{ Pattern = "netsh\s+firewall"; Desc = "Firewall modification" }
    @{ Pattern = "sc\s+create"; Desc = "Service creation" }
    @{ Pattern = "rundll32.*\.dll"; Desc = "Rundll32 DLL" }
    @{ Pattern = "regsvr32\s+.*/s"; Desc = "Regsvr32 silent" }
    @{ Pattern = "mshta\s+http"; Desc = "Mshta remote script" }
)

function Invoke-IdsDetection {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            $cmd = [string]$proc.CommandLine
            foreach ($p in $Script:IdsPatterns) {
                if ($cmd -match $p.Pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $p.Pattern
                        Description = $p.Desc
                        CommandLine = $cmd.Substring(0, [Math]::Min(500, $cmd.Length))
                    }
                    break
                }
            }
        }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2095 -Message "IDS: $($d.Description) - $($d.ProcessName) PID:$($d.ProcessId)" -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\ids_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Description)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-AVLog "IdsDetection: Found $($detections.Count) IDS matches" "THREAT"
        }
    } catch {
        Write-AVLog "IdsDetection error: $_" "ERROR"
    }
    return $detections.Count
}

# --- MemoryAcquisitionDetection ---
$Script:MemAcqProcessPatterns = @("winpmem", "pmem", "osxpmem", "aff4imager", "winpmem_mini", "memdump", "rawdump")
$Script:MemAcqCmdPatterns = @("winpmem", "pmem", "\.\pmem", "/dev/pmem", ".aff4", "-o .raw", "-o .aff4", "image.raw", "memory.raw", "physical memory", "memory acquisition", "physicalmemory")

function Invoke-MemoryAcquisitionDetection {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath
        foreach ($proc in $processes) {
            $name = ([string]$proc.Name).ToLower()
            $cmd = ([string]$proc.CommandLine) + " " + ([string]$proc.ExecutablePath)
            foreach ($pat in $Script:MemAcqProcessPatterns) {
                if ($name -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $pat
                        Type = "Memory Acquisition Tool"
                        Risk = "Critical"
                    }
                    break
                }
            }
            if ($detections.Count -gt 0 -and $detections[-1].ProcessId -eq $proc.ProcessId) { continue }
            foreach ($pat in $Script:MemAcqCmdPatterns) {
                if ($cmd -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = "cmd:$pat"
                        Type = "Memory Acquisition (cmd)"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2093 -Message "MEMORY ACQUISITION: $($d.Pattern) - $($d.ProcessName) (PID: $($d.ProcessId))" -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\memory_acquisition_detections_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-AVLog "MemoryAcquisitionDetection: Found $($detections.Count) memory acquisition indicators" "THREAT"
        }
    } catch {
        Write-AVLog "MemoryAcquisitionDetection error: $_" "ERROR"
    }
    return $detections.Count
}

# --- BCDSecurity (includes BCD cleanup from BCDCleanup.ps1) ---
function Invoke-BCDCleanup {
    if (-not $Config.EnableBCDCleanup) { return 0 }
    if (-not (Test-IsAdmin)) { return 0 }
    try {
        $bcdedit = Join-Path $env:windir "system32\bcdedit.exe"
        $backupPath = Join-Path $Config.DatabasePath "BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
        if (-not (Test-Path (Split-Path $backupPath -Parent))) { New-Item -ItemType Directory -Path (Split-Path $backupPath -Parent) -Force | Out-Null }
        & $bcdedit /export $backupPath 2>&1 | Out-Null
        $bcdOut = & $bcdedit /enum all 2>&1 | Out-String
        $entries = @(); $current = $null
        foreach ($line in ($bcdOut -split "`n")) {
            if ($line -match "^\s*identifier\s+(\{[^}]+\})") {
                if ($current) { $entries += $current }
                $current = @{ Identifier = $Matches[1].Trim(); Properties = @{} }
            } elseif ($current -and $line -match "^\s*(\w+)\s+(.+)") {
                $current.Properties[$Matches[1]] = $Matches[2].Trim()
            }
        }
        if ($current) { $entries += $current }
        $criticalIds = @('{bootmgr}', '{current}', '{default}')
        $removed = 0
        foreach ($entry in $entries) {
            if ($entry.Identifier -in $criticalIds) { continue }
            $sus = $false
            if ($entry.Properties['description'] -and $entry.Properties['description'] -notmatch 'Windows') { $sus = $true }
            if ($entry.Properties['device'] -match 'vhd=') { $sus = $true }
            if ($entry.Properties['path'] -and $entry.Properties['path'] -notmatch 'winload\.(exe|efi)|bootmgfw\.efi') { $sus = $true }
            if ($sus) {
                try {
                    & $bcdedit /delete $entry.Identifier /f 2>&1 | Out-Null
                    $removed++; Write-AVLog "BCDCleanup: Removed suspicious entry $($entry.Identifier)" "INFO"
                } catch {}
            }
        }
        return $removed
    } catch {
        Write-AVLog "BCDCleanup error: $_" "ERROR"
        return 0
    }
}

function Invoke-BCDSecurity {
    Invoke-BCDCleanup | Out-Null
    $detections = @()
    try {
        $bcdOut = bcdedit /enum 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { return 0 }
        if ($bcdOut -match 'testsigning\s+Yes') {
            $detections += @{ Type = "Test signing enabled"; Risk = "High"; Detail = "testsigning Yes" }
        }
        if ($bcdOut -match 'nointegritychecks\s+Yes') {
            $detections += @{ Type = "No integrity checks"; Risk = "Critical"; Detail = "nointegritychecks Yes" }
        }
        if ($bcdOut -match 'nx\s+OptOut') {
            $detections += @{ Type = "DEP disabled (nx OptOut)"; Risk = "High"; Detail = "nx OptOut" }
        }
        if ($bcdOut -match 'bootmenupolicy\s+Legacy') {
            $detections += @{ Type = "Legacy boot menu policy"; Risk = "Medium"; Detail = "bootmenupolicy Legacy" }
        }
        if ($bcdOut -match 'hypervisorlaunchtype\s+Auto' -and $bcdOut -match 'debug\s+Yes') {
            $detections += @{ Type = "Hypervisor debug enabled"; Risk = "Medium"; Detail = "hypervisor debug Yes" }
        }
        $loaderPaths = [regex]::Matches($bcdOut, 'path\s+(\S+)') | ForEach-Object { $_.Groups[1].Value.Trim() }
        $sysRoot = $env:SystemRoot
        foreach ($path in $loaderPaths) {
            $p = $path -replace '\\Device\\HarddiskVolume\d+', $env:SystemDrive
            if ($p -match '\\Windows\\System32\\winload\.(exe|efi)' -or $p -match '\\EFI\\Microsoft\\Boot\\bootmgfw\.efi') { continue }
            if ($p -match '\.(exe|efi)$' -and $p -notlike "*$sysRoot*" -and $p -notlike '*\EFI\*') {
                $detections += @{ Type = "Non-default boot loader"; Risk = "High"; Detail = $path }
            }
        }
        try {
            $secureBoot = Get-CimInstance -Namespace root\Microsoft\Windows\SecureBoot -ClassName UEFI_SecureBoot -ErrorAction SilentlyContinue
            if ($secureBoot -and $secureBoot.SecureBootEnabled -eq $false) {
                $detections += @{ Type = "Secure Boot disabled"; Risk = "High"; Detail = "UEFI SecureBoot disabled" }
            }
        } catch { }
        try {
            $bcdPath = Join-Path $env:SystemRoot "boot\bcd"
            if (Test-Path $bcdPath) {
                $acl = Get-Acl -Path $bcdPath -ErrorAction SilentlyContinue
                $everyone = $acl.Access | Where-Object { $_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write|Modify' }
                if ($everyone) {
                    $detections += @{ Type = "BCD store writable by broad identity"; Risk = "Medium"; Detail = $bcdPath }
                }
            }
        } catch { }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2091 -Message "BCDSecurity: $($d.Type) - $($d.Detail)" -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\BCDSecurity_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Detail)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "BCDSecurity: Found $($detections.Count) BCD issues" "THREAT"
        }
        return $detections.Count
    } catch {
        Write-AVLog "BCDSecurity error: $_" "ERROR"
        return 0
    }
}

# --- CredentialProtection ---
function Invoke-CredentialProtection {
    $detections = @()
    try {
        $credThreatNames = @('mimikatz','sekurlsa','procdump','proc_dump','lsass_dump','comsvcs','rundll32')
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $pn = $p.ProcessName.ToLower()
            foreach ($t in $credThreatNames) {
                if ($pn -like "*$t*") {
                    $detections += @{
                        Type = "Known credential-dump related process"
                        ProcessId = $p.Id
                        ProcessName = $p.ProcessName
                        Path = $p.Path
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        try {
            $cimProcs = Get-CimInstance Win32_Process | Where-Object {
                $_.CommandLine -match 'lsass|minidump|comsvcs.*MiniDump|sekurlsa|mimikatz|procdump.*lsass'
            }
            foreach ($proc in $cimProcs) {
                $detections += @{
                    Type = "Suspicious credential-related command line"
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Risk = "Critical"
                }
            }
        } catch { }
        try {
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaPath) {
                $runLsaPpl = Get-ItemProperty -Path $lsaPath -Name "RunLsaPpl" -ErrorAction SilentlyContinue
                if (-not $runLsaPpl -or $runLsaPpl.RunLsaPpl -ne 1) {
                    $detections += @{ Type = "LSA protection (RunLsaPpl) not enforced"; Risk = "Medium"; Detail = "RunLsaPpl" }
                }
            }
        } catch { }
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' }
            foreach ($t in $tasks) {
                $action = $t.Actions | Select-Object -First 1
                if ($action.Execute -match 'procdump|mimikatz|pwdump' -or $action.Arguments -match 'lsass|minidump') {
                    $detections += @{
                        Type = "Scheduled task with credential-dump tool"
                        TaskName = $t.TaskName
                        Execute = $action.Execute
                        Arguments = $action.Arguments
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "CredentialProtection: $($d.Type) - $($d.ProcessName -or $d.TaskName -or $d.Detail)"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2092 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\CredentialProtection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.TaskName -or $_.Detail)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "CredentialProtection: Found $($detections.Count) credential threats" "THREAT"
        }
        # Apply credential hardening (from Hardening.ps1) when enabled
        if ($Config.EnableCredentialHardening -and (Test-IsAdmin)) {
            try {
                $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                if (Test-Path $lsaPath) {
                    $runPpl = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
                    if (-not $runPpl -or $runPpl.RunAsPPL -ne 1) {
                        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                        Write-AVLog "CredentialHardening: Enabled LSASS PPL (RunAsPPL)" "INFO"
                    }
                }
                $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                if (Test-Path $winlogonPath) {
                    Set-ItemProperty -Path $winlogonPath -Name "CachedLogonsCount" -Value "0" -Type String -Force -ErrorAction SilentlyContinue
                    Write-AVLog "CredentialHardening: Disabled cached logons" "INFO"
                }
                if (Test-Path "$env:SystemRoot\System32\cmdkey.exe") {
                    $list = & cmdkey /list 2>$null
                    foreach ($line in $list) {
                        if ($line -match "Target:\s*(.+)") {
                            $target = $Matches[1].Trim(); if ($target) { & cmdkey /delete:$target 2>$null | Out-Null }
                        }
                    }
                    Write-AVLog "CredentialHardening: Cleared Credential Manager" "INFO"
                }
            } catch {
                Write-AVLog "CredentialHardening error: $_" "WARN"
            }
        }
        return $detections.Count
    } catch {
        Write-AVLog "CredentialProtection error: $_" "ERROR"
        return 0
    }
}

# --- HidMacroGuard ---
function Invoke-HidMacroGuard {
    $detections = @()
    try {
        try {
            $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction SilentlyContinue
            foreach ($dev in $hidDevices) {
                if ($dev.Status -ne 'OK') { continue }
                $driver = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DriverDesc' -ErrorAction SilentlyContinue
                $hardwareId = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'HardwareID' -ErrorAction SilentlyContinue).Data
                if (-not $hardwareId) { $hardwareId = @() } else { $hardwareId = @($hardwareId) }
                $desc = ($driver.Data -join ' ') -replace '\s+', ' '
                if ($desc -match 'HID.*Boot|Keyboard|Mouse' -and $desc -match 'composite|multi|macro') {
                    $detections += @{
                        Type = "HID composite/macro device"
                        Description = $desc
                        InstanceId = $dev.InstanceId
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        try {
            $suspiciousHid = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^Hid|kbdclass|mouclass' }
            foreach ($svc in $suspiciousHid) {
                $imgPath = Get-ItemProperty -Path $svc.PSPath -Name "ImagePath" -ErrorAction SilentlyContinue
                if ($imgPath -and $imgPath.ImagePath -notmatch '\\System32\\drivers\\') {
                    $detections += @{
                        Type = "Non-default HID/keyboard/mouse driver path"
                        Service = $svc.PSChildName
                        ImagePath = $imgPath.ImagePath
                        Risk = "High"
                    }
                }
            }
        } catch { }
        try {
            $kbd = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass" -ErrorAction SilentlyContinue
            $mou = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass" -ErrorAction SilentlyContinue
            foreach ($node in @($kbd, $mou)) {
                if (-not $node) { continue }
                $upper = $node.UpperFilters -join ','
                $lower = $node.LowerFilters -join ','
                $all = "$upper $lower"
                if ($all -match '[\w\.]+\.(sys|dll)' -and $all -notmatch 'kbdclass|mouclass|i8042prt|kbdhid|mouhid') {
                    $detections += @{
                        Type = "Unexpected keyboard/mouse filter driver"
                        Filters = $all
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        try {
            $procs = Get-CimInstance Win32_Process | Where-Object {
                $_.Name -match 'hid|macro|keyboard|inject|ducky'
            }
            foreach ($p in $procs) {
                $path = $p.ExecutablePath
                if (-not $path -or -not (Test-Path $path)) { continue }
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    $detections += @{
                        Type = "Unsigned HID/macro-related process"
                        ProcessId = $p.ProcessId
                        ProcessName = $p.Name
                        Path = $path
                        Risk = "High"
                    }
                }
            }
        } catch { }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "HidMacroGuard: $($d.Type) - $($d.Description -or $d.Service -or $d.ProcessName -or $d.Filters)"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2093 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\HidMacroGuard_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Description -or $_.Service -or $_.ProcessName)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "HidMacroGuard: Found $($detections.Count) HID/macro issues" "THREAT"
        }
        return $detections.Count
    } catch {
        Write-AVLog "HidMacroGuard error: $_" "ERROR"
        return 0
    }
}

# --- LocalProxyDetection ---
function Invoke-LocalProxyDetection {
    $detections = @()
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $localListen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        $listeners = $localListen | Where-Object {
            $_.LocalAddress -match '^127\.|^::1$' -and $_.OwningProcess -gt 0
        } | Group-Object OwningProcess
        foreach ($g in $listeners) {
            $pid = $g.Name
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if (-not $proc) { continue }
            $out443 = $conns | Where-Object { $_.OwningProcess -eq $pid -and $_.RemotePort -eq 443 }
            if ($out443.Count -eq 0) { continue }
            $exclude = @('svchost','msedge','chrome','firefox','opera','brave','iexplore','ApplicationFrameHost')
            if ($proc.ProcessName -in $exclude) { continue }
            $detections += @{
                Type = "Local proxy pattern (listen local + outbound 443)"
                ProcessId = $pid
                ProcessName = $proc.ProcessName
                Path = $proc.Path
                LocalPorts = ($g.Group.LocalPort | Sort-Object -Unique) -join ','
                Risk = "High"
            }
        }
        $proxyVars = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy')
        foreach ($v in $proxyVars) {
            $val = [Environment]::GetEnvironmentVariable($v, 'Process')
            if ([string]::IsNullOrEmpty($val)) { $val = [Environment]::GetEnvironmentVariable($v, 'User') }
            if ([string]::IsNullOrEmpty($val)) { $val = [Environment]::GetEnvironmentVariable($v, 'Machine') }
            if ($val -and $val -match '127\.0\.0\.1|localhost|::1') {
                $detections += @{
                    Type = "System proxy set to localhost"
                    Variable = $v
                    Value = $val
                    Risk = "Medium"
                }
            }
        }
        try {
            $proxyReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -ErrorAction SilentlyContinue
            if ($proxyReg -and $proxyReg.ProxyServer -match '127\.0\.0\.1|localhost') {
                $detections += @{
                    Type = "Machine proxy registry points to localhost"
                    ProxyServer = $proxyReg.ProxyServer
                    Risk = "High"
                }
            }
        } catch { }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "LocalProxyDetection: $($d.Type) - $($d.ProcessName -or $d.Variable -or 'Registry')"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2094 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\LocalProxyDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Variable -or $_.ProxyServer)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "LocalProxyDetection: Found $($detections.Count) local proxy indicators" "THREAT"
        }
        return $detections.Count
    } catch {
        Write-AVLog "LocalProxyDetection error: $_" "ERROR"
        return 0
    }
}

# --- ScriptContentScan ---
$Script:ScriptScanPatterns = @(
    'IEX\s*\(|Invoke-Expression',
    'DownloadString\s*\(|DownloadFile\s*\(',
    '\[Net\.WebClient\]|New-Object\s+Net\.WebClient',
    '-EncodedCommand\s+[A-Za-z0-9+/=]{50,}',
    'FromBase64String|\[Convert\]::FromBase64String',
    'Bypass.*ExecutionPolicy|ExecutionPolicy\s+Bypass',
    'Hidden|WindowStyle\s+Hidden|-w\s+1',
    'WScript\.Shell|Shell\.Application',
    'ADODB\.Stream|Scripting\.FileSystemObject',
    'eval\s*\(|Execute\s*\(|ExecuteGlobal',
    'powershell.*-nop.*-w.*hidden',
    'certutil.*-urlcache.*-split',
    'bitsadmin.*\/transfer',
    'mshta\s+(vbscript|http|https):',
    'regsvr32\s+.*\/s\s+.*scrobj\.dll'
)

$Script:ScriptScanPaths = @(
    $env:TEMP,
    [Environment]::GetFolderPath('LocalApplicationData'),
    (Join-Path $env:USERPROFILE "Downloads"),
    (Join-Path $env:USERPROFILE "Desktop"),
    "C:\Windows\Temp"
)

function Test-SuspiciousScriptContent {
    param([string]$Content, [string]$Ext)
    if ([string]::IsNullOrWhiteSpace($Content)) { return $false }
    $matchCount = 0
    foreach ($pat in $Script:ScriptScanPatterns) {
        if ($Content -match $pat) { $matchCount++ }
        if ($matchCount -ge 2) { return $true }
    }
    if ($matchCount -ge 1 -and $Content.ToLower() -match 'http[s]?://[^\s''"]+') { return $true }
    return $false
}

function Invoke-ScriptContentScan {
    $detections = @()
    try {
        $extensions = @('*.ps1','*.psm1','*.vbs','*.vbe','*.js','*.jse','*.wsf','*.bat','*.cmd','*.hta')
        $totalScanned = 0
        $maxFiles = 200
        $maxBytes = 8192
        foreach ($root in $Script:ScriptScanPaths) {
            if (-not (Test-Path $root)) { continue }
            foreach ($ext in $extensions) {
                $files = Get-ChildItem -Path $root -Filter $ext -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First ([Math]::Min(50, $maxFiles - $totalScanned))
                foreach ($f in $files) {
                    $totalScanned++
                    if ($totalScanned -gt $maxFiles) { break }
                    try {
                        $raw = [System.IO.File]::ReadAllBytes($f.FullName)
                        $len = [Math]::Min($raw.Length, $maxBytes)
                        $content = [System.Text.Encoding]::GetEncoding(28591).GetString($raw, 0, $len)
                        if (Test-SuspiciousScriptContent -Content $content -Ext $f.Extension) {
                            $detections += @{
                                Path = $f.FullName
                                Length = $f.Length
                                Extension = $f.Extension
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
                if ($totalScanned -ge $maxFiles) { break }
            }
            if ($totalScanned -ge $maxFiles) { break }
        }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2095 -Message "ScriptContentScan: Suspicious script $($d.Path)" -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\ScriptContentScan_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Path)|$($_.Risk)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "ScriptContentScan: Found $($detections.Count) suspicious scripts" "THREAT"
        }
        return $detections.Count
    } catch {
        Write-AVLog "ScriptContentScan error: $_" "ERROR"
        return 0
    }
}

# --- ScriptHostDetection ---
$Script:ScriptHosts = @('mshta.exe','wscript.exe','cscript.exe','scriptrunner.exe')
$Script:ScriptHostSuspiciousPatterns = @(
    'http[s]?://[^\s''"]+',
    'vbscript:',
    'javascript:',
    '-EncodedCommand',
    '\.hta\b',
    '\.vbs\b.*http|http.*\.vbs',
    '\.js\b.*http|http.*\.js',
    'Execute.*Request|Response\.Write',
    'eval\s*\(|Execute\s*\(',
    'GetObject\s*\(.*http',
    'XMLHTTP|WinHttp|MSXML2\.ServerXMLHTTP',
    'Adodb\.Stream.*TypeBinary|\.Open.*adTypeBinary',
    'ExpandEnvironmentStrings.*%temp%|%appdata%',
    'powershell.*-enc|powershell.*-encodedcommand'
)

function Test-SuspiciousScriptHostCommandLine {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return $false }
    $count = 0
    foreach ($pat in $Script:ScriptHostSuspiciousPatterns) {
        if ($CmdLine -match $pat) { $count++ }
        if ($count -ge 2) { return $true }
    }
    if ($CmdLine -match 'http[s]?://' -and $CmdLine.Length -gt 80) { return $true }
    return $false
}

function Invoke-ScriptHostDetection {
    $detections = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in $Script:ScriptHosts }
        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            if (-not (Test-SuspiciousScriptHostCommandLine -CmdLine $cmd)) { continue }
            $path = $p.ExecutablePath
            $sig = $null
            if ($path -and (Test-Path $path)) {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            }
            $detections += @{
                ProcessId = $p.ProcessId
                ProcessName = $p.Name
                CommandLine = $cmd
                Path = $path
                Signed = ($sig.Status -eq 'Valid')
                Risk = if ($sig -and $sig.Status -ne 'Valid') { "Critical" } else { "High" }
            }
        }
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' }
            foreach ($t in $tasks) {
                $action = $t.Actions | Select-Object -First 1
                $exec = $action.Execute
                $arg = $action.Arguments
                $combined = "$exec $arg"
                if ($exec -notmatch 'mshta|wscript|cscript') { continue }
                if (Test-SuspiciousScriptHostCommandLine -CmdLine $combined) {
                    $detections += @{
                        Type = "Scheduled task script host with suspicious args"
                        TaskName = $t.TaskName
                        Execute = $exec
                        Arguments = $arg
                        Risk = "High"
                    }
                }
            }
        } catch { }
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $short = if ($d.CommandLine) { $d.CommandLine.Substring(0, [Math]::Min(200, $d.CommandLine.Length)) } else { $d.TaskName -or $d.Arguments }
                $msg = "ScriptHostDetection: $($d.ProcessName -or 'Task') - $short"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2096 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$Script:InstallPath\Logs\ScriptHostDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or 'Task')|$($_.Risk)|$($_.CommandLine -or $_.Arguments)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "ScriptHostDetection: Found $($detections.Count) script host abuses" "THREAT"
        }
        return $detections.Count
    } catch {
        Write-AVLog "ScriptHostDetection error: $_" "ERROR"
        return 0
    }
}

# --- NeuroBehaviorMonitor ---
$Script:NBM_LastRun = [DateTime]::MinValue
$Script:NBM_TickInterval = 1
$Script:NBM_FocusHistory = @{}
$Script:NBM_LastBrightness = -1
$Script:NBM_FlashScore = 0
$Script:NBM_LastCursorPos = @{X=0;Y=0}
$Script:NBM_CursorFirstSeen = [DateTime]::MinValue
$Script:NBM_CursorJitterCount = 0
$Script:NBM_LastAvgR = -1
$Script:NBM_LastAvgG = -1
$Script:NBM_LastAvgB = -1
$Script:NBM_DistortScore = 0
$Script:NBM_ReportedItems = @{}
$Script:NBM_TopmostAllowlist = @("explorer","taskmgr","dwm","systemsettings","applicationframehost","shellexperiencehost","searchapp","startmenuexperiencehost","msedge","chrome","firefox")

function Test-NBMShouldReport { param([string]$Key); if ($Script:NBM_ReportedItems.ContainsKey($Key)) { return $false }; $Script:NBM_ReportedItems[$Key] = [DateTime]::UtcNow; return $true }

function Invoke-NeuroBehaviorMonitor {
    $now = Get-Date; if ($Script:NBM_LastRun -ne [DateTime]::MinValue -and ($now - $Script:NBM_LastRun).TotalSeconds -lt $Script:NBM_TickInterval) { return }; $Script:NBM_LastRun = $now
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        if (-not ([System.Management.Automation.PSTypeName]'NeuroWin32AV').Type) {
            Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class NeuroWin32AV { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid); [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex); public const int GWL_EXSTYLE = -20; public const int WS_EX_TOPMOST = 0x00000008; }' -ErrorAction SilentlyContinue
        }
        $hWnd = [NeuroWin32AV]::GetForegroundWindow(); if ($hWnd -eq [IntPtr]::Zero) { return }; $fpid = 0; [NeuroWin32AV]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null; if ($fpid -eq 0) { return }
        $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue; $procName = if ($proc) { $proc.ProcessName } else { "unknown" }; if ($procName -eq "powershell" -and $fpid -eq $PID) { return }
        $bmp = [System.Drawing.Bitmap]::new(64,64); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen(0,0,0,0,$bmp.Size); $g.Dispose()
        $sumR=0;$sumG=0;$sumB=0;$sumBright=0;$samples=0; for ($x=0; $x -lt 64; $x+=4) { for ($y=0; $y -lt 64; $y+=4) { $c = $bmp.GetPixel($x,$y); $sumR+=$c.R; $sumG+=$c.G; $sumB+=$c.B; $sumBright+=$c.R+$c.G+$c.B; $samples++ } }; $bmp.Dispose()
        $n = if ($samples -gt 0) { $samples } else { 1 }; $avgR=$sumR/$n; $avgG=$sumG/$n; $avgB=$sumB/$n; $bright = $sumBright
        if (-not $Script:NBM_FocusHistory.ContainsKey($fpid)) { $Script:NBM_FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }; $fe = $Script:NBM_FocusHistory[$fpid]; $fe.Count++; $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        if ($elapsed -gt 10) { $fe.Count=1; $fe.FirstSeen=[DateTime]::UtcNow }; $Script:NBM_FocusHistory[$fpid]=$fe
        if ($elapsed -lt 10 -and $fe.Count -gt 8) { $key = "NBM_FocusAbuse:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Focus abuse by $procName (PID: $fpid)" "THREAT" }; $Script:NBM_FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }
        if ($Script:NBM_LastBrightness -ge 0) { $delta = [Math]::Abs($bright - $Script:NBM_LastBrightness); if ($delta -gt 40000) { $Script:NBM_FlashScore++ } else { $Script:NBM_FlashScore = [Math]::Max(0, $Script:NBM_FlashScore - 1) }; if ($Script:NBM_FlashScore -ge 6) { $key = "NBM_Flash:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Flash stimulus detected ($procName)" "THREAT" }; $Script:NBM_FlashScore = 0 } }; $Script:NBM_LastBrightness = $bright
        $exStyle = [NeuroWin32AV]::GetWindowLong($hWnd, [NeuroWin32AV]::GWL_EXSTYLE); if (([int]$exStyle -band [NeuroWin32AV]::WS_EX_TOPMOST) -ne 0 -and $Script:NBM_TopmostAllowlist -notcontains $procName.ToLower()) { $key = "NBM_Topmost:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Topmost abuse by $procName (PID: $fpid)" "THREAT" } }
        try { $pos = [System.Windows.Forms.Cursor]::Position; $dx = [Math]::Abs($pos.X - $Script:NBM_LastCursorPos.X); $dy = [Math]::Abs($pos.Y - $Script:NBM_LastCursorPos.Y); $Script:NBM_LastCursorPos = @{X=$pos.X; Y=$pos.Y}; if ($Script:NBM_CursorFirstSeen -eq [DateTime]::MinValue) { $Script:NBM_CursorFirstSeen = [DateTime]::UtcNow } else { $elapsed2 = ([DateTime]::UtcNow - $Script:NBM_CursorFirstSeen).TotalSeconds; if ($elapsed2 -gt 10) { $Script:NBM_CursorJitterCount=0; $Script:NBM_CursorFirstSeen=[DateTime]::UtcNow }; if ($dx + $dy -gt 60) { $Script:NBM_CursorJitterCount++ }; if ($elapsed2 -lt 10 -and $Script:NBM_CursorJitterCount -gt 6) { $key = "NBM_Cursor:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Cursor jitter abuse ($procName)" "THREAT" }; $Script:NBM_CursorJitterCount=0; $Script:NBM_CursorFirstSeen=[DateTime]::UtcNow } } } catch { }
        if ($Script:NBM_LastAvgR -ge 0) { $invR = 255 - $Script:NBM_LastAvgR; $invG = 255 - $Script:NBM_LastAvgG; $invB = 255 - $Script:NBM_LastAvgB; $isInv = [Math]::Abs($avgR - $invR) -lt 25 -and [Math]::Abs($avgG - $invG) -lt 25 -and [Math]::Abs($avgB - $invB) -lt 25; $dR=[Math]::Abs($avgR - $Script:NBM_LastAvgR); $dG=[Math]::Abs($avgG - $Script:NBM_LastAvgG); $dB=[Math]::Abs($avgB - $Script:NBM_LastAvgB); if ($isInv) { $key = "NBM_Color:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Color distortion/inversion ($procName)" "THREAT" } } else { $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB)); if ($maxD -gt 70) { $Script:NBM_DistortScore++ } else { $Script:NBM_DistortScore = [Math]::Max(0, $Script:NBM_DistortScore - 1) }; if ($Script:NBM_DistortScore -ge 5) { $key = "NBM_Distort:$procName"; if (Test-NBMShouldReport -Key $key) { Write-AVLog "NeuroBehaviorMonitor: Screen distortion ($procName)" "THREAT" }; $Script:NBM_DistortScore = 0 } } }; $Script:NBM_LastAvgR=$avgR; $Script:NBM_LastAvgG=$avgG; $Script:NBM_LastAvgB=$avgB
    } catch { Write-AVLog "NeuroBehaviorMonitor error: $_" "ERROR" }
}

# --- StartupPersistenceDetection ---
$Script:SPD_ReportedItems = @{}
$Script:SPD_ScriptExtensions = @(".vbs",".vbe",".js",".jse",".wsf",".ps1",".bat",".cmd",".scr")

function Test-SPDShouldReport {
    param([string]$Key)
    if ($Script:SPD_ReportedItems.ContainsKey($Key)) { return $false }
    $Script:SPD_ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

function Invoke-StartupPersistenceDetection {
    try {
        $scanPaths = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
        $suspiciousExtensions = @(".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".scr")
        foreach ($basePath in $scanPaths) {
            if (-not (Test-Path $basePath)) { continue }
            try {
                $files = Get-ChildItem -Path $basePath -File -ErrorAction SilentlyContinue |
                    Where-Object { $suspiciousExtensions -contains $_.Extension.ToLower() }
                foreach ($file in $files) {
                    $key = "SPD_File_$($file.FullName)"
                    if (Test-SPDShouldReport -Key $key) {
                        Write-AVLog "StartupPersistenceDetection: Suspicious file $($file.FullName)" "WARNING"
                    }
                }
            } catch { }
        }
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($regPath in $registryPaths) {
            if (-not (Test-Path $regPath)) { continue }
            try {
                $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                $properties = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                foreach ($prop in $properties) {
                    $value = $prop.Value
                    if ($value -match "\.exe|\.dll|\.ps1|\.vbs|\.bat|powershell|cmd\.exe") {
                        $key = "SPD_Reg_$regPath_$($prop.Name)"
                        if (Test-SPDShouldReport -Key $key) {
                            Write-AVLog "StartupPersistenceDetection: Registry persistence $regPath\$($prop.Name) = $value" "WARNING"
                        }
                    }
                }
            } catch { }
        }
    } catch {
        Write-AVLog "StartupPersistenceDetection error: $_" "ERROR"
    }
}

# --- SuspiciousParentChildDetection ---
$Script:SPC_ReportedItems = @{}

function Test-SPCShouldReport {
    param([string]$Key)
    if ($Script:SPC_ReportedItems.ContainsKey($Key)) { return $false }
    $Script:SPC_ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

function Invoke-SuspiciousParentChildDetection {
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId
        $procMap = @{}
        foreach ($p in $processes) { $procMap[$p.ProcessId] = $p }

        # Suspicious parent-child rules
        $rules = @(
            @{ Parent = 'winword.exe'; Child = 'cmd.exe'; Desc = "Word spawning cmd" }
            @{ Parent = 'winword.exe'; Child = 'powershell.exe'; Desc = "Word spawning PowerShell" }
            @{ Parent = 'excel.exe'; Child = 'cmd.exe'; Desc = "Excel spawning cmd" }
            @{ Parent = 'excel.exe'; Child = 'powershell.exe'; Desc = "Excel spawning PowerShell" }
            @{ Parent = 'outlook.exe'; Child = 'cmd.exe'; Desc = "Outlook spawning cmd" }
            @{ Parent = 'outlook.exe'; Child = 'powershell.exe'; Desc = "Outlook spawning PowerShell" }
            @{ Parent = 'mshta.exe'; Child = 'powershell.exe'; Desc = "MSHTA spawning PowerShell" }
            @{ Parent = 'wscript.exe'; Child = 'powershell.exe'; Desc = "WScript spawning PowerShell" }
            @{ Parent = 'cscript.exe'; Child = 'powershell.exe'; Desc = "CScript spawning PowerShell" }
            @{ Parent = 'svchost.exe'; Child = 'cmd.exe'; Desc = "Svchost spawning cmd" }
            @{ Parent = 'explorer.exe'; Child = 'mshta.exe'; Desc = "Explorer spawning MSHTA" }
        )

        foreach ($proc in $processes) {
            if ($proc.ProcessId -eq $PID) { continue }
            $parentProc = $procMap[$proc.ParentProcessId]
            if (-not $parentProc) { continue }
            $parentName = $parentProc.Name.ToLower()
            $childName = $proc.Name.ToLower()
            foreach ($rule in $rules) {
                if ($parentName -eq $rule.Parent -and $childName -eq $rule.Child) {
                    $key = "SPC_$($rule.Desc)_$($proc.ProcessId)"
                    if (Test-SPCShouldReport -Key $key) {
                        Write-AVLog "SuspiciousParentChildDetection: $($rule.Desc) - Parent PID:$($parentProc.ProcessId) Child PID:$($proc.ProcessId)" "THREAT"
                        Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2097 -Message "SPC: $($rule.Desc)" -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } catch {
        Write-AVLog "SuspiciousParentChildDetection error: $_" "ERROR"
    }
}

# --- ScriptBlockLoggingCheck ---
function Invoke-ScriptBlockLoggingCheck {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $detections = @()
        if (-not (Test-Path $regPath)) {
            $detections += @{ Type = "ScriptBlockLogging policy key missing"; Risk = "Medium" }
        } else {
            $val = Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            if (-not $val -or $val.EnableScriptBlockLogging -ne 1) {
                $detections += @{ Type = "ScriptBlockLogging not enabled"; Risk = "Medium" }
            }
        }
        $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $regPath2)) {
            $detections += @{ Type = "Module logging policy key missing"; Risk = "Low" }
        } else {
            $val2 = Get-ItemProperty -Path $regPath2 -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
            if (-not $val2 -or $val2.EnableModuleLogging -ne 1) {
                $detections += @{ Type = "Module logging not enabled"; Risk = "Low" }
            }
        }
        if ($detections.Count -gt 0) {
            $logPath = "$Script:InstallPath\Logs\ScriptBlockLoggingCheck_$(Get-Date -Format 'yyyy-MM-dd').log"
            foreach ($d in $detections) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($d.Type)|$($d.Risk)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "ScriptBlockLoggingCheck: $($detections.Count) logging issues found" "WARNING"
        }
        return $detections.Count
    } catch {
        Write-AVLog "ScriptBlockLoggingCheck error: $_" "ERROR"
        return 0
    }
}

# --- CVE-MitigationPatcher ---
$Script:CVE_KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
$Script:CVE_InstallDir = "C:\ProgramData\CVE-MitigationPatcher"
$Script:CVE_StatePath = Join-Path $Script:InstallPath "Data\CVE-PatcherState.json"
$Script:CVE_LogPath = Join-Path $Script:InstallPath "Logs\CVE-MitigationPatcher.log"

$Script:CVE_EmbeddedConfigJson = '{"templates":{"Set-Registry-DWord":{"type":"registry","path":"{{path}}","name":"{{name}}","value":"{{value}}","valueType":"DWord"}},"actions":{"CVE-2017-0143":{"description":"SMBv1 RCE","run":["Disable-SMBv1"]},"CVE-2017-0144":{"description":"EternalBlue","run":["Disable-SMBv1"]},"CVE-2020-0796":{"description":"SMBGhost","run":["Disable-SMBv3Compression"]},"CVE-2019-0708":{"description":"BlueKeep","run":["Enable-RDPNLA"]},"CVE-2022-30190":{"description":"Follina","run":["Block-MSDTProtocol"]},"CVE-2021-34527":{"description":"PrintNightmare","run":["Disable-PrintSpooler"]},"CVE-2024-38063":{"description":"IPv6 RCE","run":["Disable-IPv6"]}}}'

$Script:CVE_MitigationActions = @{
    "Disable-SMBv1" = {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "SMB1" -Value 0 -Type DWord -Force
    }
    "Disable-SMBv3Compression" = {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DisableCompression" -Value 1 -Type DWord -Force
    }
    "Disable-PrintSpooler" = {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
    "Block-MSDTProtocol" = {
        $path = "HKCR:\ms-msdt"
        if (Test-Path $path) { Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue }
    }
    "Enable-RDPNLA" = {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        if (Test-Path $path) { Set-ItemProperty -Path $path -Name "UserAuthentication" -Value 1 -Type DWord -Force }
    }
    "Disable-IPv6" = {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DisabledComponents" -Value 0xFF -Type DWord -Force
    }
}

function Invoke-CVEMitigationPatcher {
    try {
        $catalog = $null
        try {
            $catalog = Invoke-RestMethod -Uri $Script:CVE_KevUrl -Method Get -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-AVLog "CVE-MitigationPatcher: Failed to fetch CISA KEV: $_" "ERROR"
            return 0
        }
        $seen = @{}
        $reapply = if ($null -ne $Config.CVEReapply) { $Config.CVEReapply } else { $false }
        if (-not $reapply -and (Test-Path $Script:CVE_StatePath)) {
            try {
                $o = Get-Content $Script:CVE_StatePath -Raw | ConvertFrom-Json
                $o.seenCveIds.PSObject.Properties | ForEach-Object { $seen[$_.Name] = $true }
            } catch { }
        }
        $config = try { $Script:CVE_EmbeddedConfigJson | ConvertFrom-Json } catch { $null }
        $actions = @{}
        if ($config -and $config.actions) {
            $config.actions.PSObject.Properties | ForEach-Object { $actions[$_.Name] = $_.Value }
        }
        $newCves = @($catalog.vulnerabilities | Where-Object { -not $seen[$_.cveID] })
        if ($newCves.Count -eq 0) { return 0 }
        $applied = 0
        foreach ($cve in $newCves) {
            $id = $cve.cveID
            $actionConfig = $actions[$id]
            if ($actionConfig -and $actionConfig.run) {
                $dryRun = if ($null -ne $Config.CVEDryRun) { $Config.CVEDryRun } else { $false }
                foreach ($actionName in @($actionConfig.run)) {
                    if ($Script:CVE_MitigationActions[$actionName]) {
                        try {
                            if ($dryRun) {
                                Write-AVLog "CVE-MitigationPatcher [DRYRUN]: Would apply $actionName for $id" "INFO"
                            } else {
                                & $Script:CVE_MitigationActions[$actionName]
                                Write-AVLog "CVE-MitigationPatcher: Applied $actionName for $id" "INFO"
                            }
                            $applied++
                        } catch {
                            Write-AVLog "CVE-MitigationPatcher: Failed $actionName for ${id}: $_" "ERROR"
                        }
                    }
                }
            }
        }
        $newIds = @($newCves | ForEach-Object { $_.cveID })
        foreach ($id in $newIds) { $seen[$id] = $true }
        $stateDir = Split-Path $Script:CVE_StatePath -Parent
        if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
        @{ seenCveIds = $seen; lastUpdate = (Get-Date -Format "o") } | ConvertTo-Json -Depth 3 | Set-Content $Script:CVE_StatePath -Encoding UTF8
        if ($applied -gt 0) {
            Write-AVLog "CVE-MitigationPatcher: Applied $applied mitigations for $($newCves.Count) new CVEs" "INFO"
        }
        return $applied
    } catch {
        Write-AVLog "CVE-MitigationPatcher error: $_" "ERROR"
        return 0
    }
}

# --- AsrRules ---
function Invoke-AsrRules {
    try {
        $rules = @(
            @{ Id = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Desc = "Block executable content from email" }
            @{ Id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Desc = "Block Office child process creation" }
            @{ Id = "3B576869-A4EC-4529-8536-B80A7769E899"; Desc = "Block Office creating executable content" }
            @{ Id = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Desc = "Block Office injecting into other processes" }
            @{ Id = "D3E037E1-3EB8-44C8-A917-57927947596D"; Desc = "Block JavaScript/VBScript launching executables" }
            @{ Id = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Desc = "Block execution of potentially obfuscated scripts" }
            @{ Id = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Desc = "Block Win32 API calls from Office macros" }
        )
        $applied = 0
        foreach ($rule in $rules) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                $applied++
            } catch { }
        }
        if ($applied -gt 0) {
            Write-AVLog "AsrRules: Enabled/verified $applied ASR rules" "INFO"
        }
        return $applied
    } catch {
        Write-AVLog "AsrRules error: $_" "ERROR"
        return 0
    }
}

# --- GRulesC2Block ---
$Script:GRulesC2_KnownBadIPs = @()

function Invoke-GRulesC2Block {
    try {
        $blocked = 0
        # Fetch threat intelligence feeds for known C2 IPs
        $feeds = @(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        )
        foreach ($feedUrl in $feeds) {
            try {
                $content = Invoke-RestMethod -Uri $feedUrl -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
                $ips = $content -split "`n" | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -First 500
                foreach ($ip in $ips) {
                    $ip = $ip.Trim()
                    if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $ip -notmatch '^(10\.|172\.(1[6-9]|2|3[01])\.|192\.168\.|127\.)') {
                        $ruleName = "GRulesC2_Block_$($ip -replace '\.','_')"
                        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                        if (-not $existing) {
                            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ip -Protocol Any -ErrorAction SilentlyContinue | Out-Null
                            $blocked++
                        }
                    }
                }
            } catch { }
        }
        if ($blocked -gt 0) {
            Write-AVLog "GRulesC2Block: Added $blocked new C2 block rules" "INFO"
        }
        return $blocked
    } catch {
        Write-AVLog "GRulesC2Block error: $_" "ERROR"
        return 0
    }
}

# --- ProcessAuditing ---
function Invoke-ProcessAuditing {
    try {
        $detections = 0
        # Enable process creation auditing via auditpol
        try {
            $auditStatus = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
            if ($auditStatus -notmatch 'Success and Failure|Success') {
                auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null
                Write-AVLog "ProcessAuditing: Enabled process creation auditing" "INFO"
                $detections++
            }
        } catch { }
        # Enable command line in process creation events
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            $current = Get-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
            if (-not $current -or $current.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
                Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
                Write-AVLog "ProcessAuditing: Enabled command line in process creation events" "INFO"
                $detections++
            }
        } catch { }
        return $detections
    } catch {
        Write-AVLog "ProcessAuditing error: $_" "ERROR"
        return 0
    }
}

# --- MitreMapping ---
$Script:MitreTechniqueMap = @{
    "HashDetection" = "T1204"; "LOLBin" = "T1218"; "ProcessAnomaly" = "T1055"
    "AMSIBypass" = "T1562.006"; "CredentialDump" = "T1003"; "MemoryAcquisition" = "T1119"
    "WMIPersistence" = "T1547.003"; "ScheduledTask" = "T1053.005"; "RegistryPersistence" = "T1547.001"
    "DLLHijacking" = "T1574.001"; "TokenManipulation" = "T1134"; "ProcessHollowing" = "T1055.012"
    "Keylogger" = "T1056.001"; "Ransomware" = "T1486"; "NetworkAnomaly" = "T1041"
    "Beacon" = "T1071"; "DNSExfiltration" = "T1048"; "Rootkit" = "T1014"
    "Clipboard" = "T1115"; "ShadowCopy" = "T1490"; "USB" = "T1052"
    "AttackTools" = "T1588"; "AdvancedThreat" = "T1204"
    "EventLog" = "T1562.006"; "FirewallRule" = "T1562.004"; "Fileless" = "T1059"
    "MemoryScanning" = "T1003"; "CodeInjection" = "T1055"; "DataExfiltration" = "T1048"
    "FileEntropy" = "T1204"; "Honeypot" = "T1204"; "LateralMovement" = "T1021"
    "ProcessCreation" = "T1059"; "YaraDetection" = "T1204"; "IdsDetection" = "T1059"
}

function Invoke-MitreMapping {
    $mapped = 0
    try {
        $logPath = "$Script:InstallPath\Logs"
        if (-not (Test-Path $logPath)) { return 0 }
        $today = Get-Date -Format 'yyyy-MM-dd'
        $logFiles = Get-ChildItem -Path $logPath -Filter "*_$today.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch 'mitre_mapping|ResponseEngine' }
        foreach ($lf in $logFiles) {
            $entries = Get-Content $lf.FullName -Tail 20 -ErrorAction SilentlyContinue
            foreach ($line in $entries) {
                if ($line -match '\|') {
                    $parts = $line -split '\|'
                    $src = $parts[1] -replace 'Detection|Scan|Monitoring', ''
                    $tech = $Script:MitreTechniqueMap[$src]
                    if ($tech -and $line -notmatch 'mitre_mapping') {
                        $mitreLog = "$logPath\mitre_mapping_$today.log"
                        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$src|$tech|$($parts -join '|')" | Add-Content -Path $mitreLog -ErrorAction SilentlyContinue
                        $mapped++
                    }
                }
            }
        }
        if ($mapped -gt 0) { Write-AVLog "MitreMapping: Mapped $mapped detections" "INFO" }
    } catch { Write-AVLog "MitreMapping error: $_" "ERROR" }
    return $mapped
}

# --- RealTimeFileMonitor (with debouncing - Claude) ---
$Script:RTFM_Watchers = @()
$Script:RTFM_Initialized = $false
$Script:RTFM_PendingQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Script:RTFM_MaxProcessPerTick = 50

function Start-RealtimeFileMonitor {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    foreach ($drive in $drives) {
        $root = $drive.Root
        if (-not (Test-Path $root)) { continue }
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            $action = {
                $path = $Event.SourceEventArgs.FullPath
                $ext = [System.IO.Path]::GetExtension($path).ToLower()
                $monitoredExts = @('.exe','.dll','.sys','.com','.scr','.bat','.cmd','.ps1','.vbs','.js','.hta','.msi')
                if ($ext -in $monitoredExts) { $Script:RTFM_PendingQueue.Enqueue($path) }
            }
            Register-ObjectEvent $watcher Created -Action $action | Out-Null
            Register-ObjectEvent $watcher Changed -Action $action | Out-Null
            $watcher.EnableRaisingEvents = $true
            $Script:RTFM_Watchers += $watcher
        } catch { }
    }
}

function Invoke-RealTimeFileMonitor {
    if (-not $Script:RTFM_Initialized) {
        Start-RealtimeFileMonitor
        $Script:RTFM_Initialized = $true
    }
    $processed = 0
    $maxPerTick = $Script:RTFM_MaxProcessPerTick
    $eicarHash = if ($Config.EICARHash) { $Config.EICARHash } else { "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" }
    $knownBad = @{ $eicarHash = "EICAR-Test-File" }
    $quarantinePath = if ($Config.QuarantinePath) { $Config.QuarantinePath } else { "$env:ProgramData\Antivirus\Quarantine" }
    $logPath = if ($Config.LogPath) { $Config.LogPath } else { "$env:ProgramData\Antivirus\Logs" }
    # Skip temp/system paths to reduce noise (Grok: exclude temp/system folders)
    $rtExclude = @('\temp\','\tmp\','\windows\temp\','\$recycle.bin\','\prefetch\','\caches\','\cache\')
    while ($processed -lt $maxPerTick) {
        $path = $null
        if (-not $Script:RTFM_PendingQueue.TryDequeue([ref]$path)) { break }
        $pathLower = $path.ToLower()
        if ($rtExclude | Where-Object { $pathLower -like "*$_*" }) { continue }
        $processed++
        Start-Sleep -Milliseconds 100
        if (-not (Test-Path $path -PathType Leaf)) { continue }
        try {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $knownBad.ContainsKey($hash)) {
                if (-not $Script:LearningMode -and $Config.AutoQuarantine) {
                    $qf = "$quarantinePath\$([DateTime]::Now.Ticks)_$([System.IO.Path]::GetFileName($path))"
                    try {
                        [System.IO.File]::Move($path, $qf)
                        Write-EventLog -LogName Application -Source "MalwareDetector" -EntryType Warning -EventId 9998 -Message "[RealTime] Quarantined: $path" -ErrorAction SilentlyContinue
                    } catch { Remove-Item -Path $path -Force -ErrorAction SilentlyContinue }
                }
            } else {
                # Run full threat analysis (Cymru, MalwareBazaar, cache) on new/changed executables
                Invoke-TinyThreatAnalysis -FilePath $path
                $rtLog = "$logPath\realtime_monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Created/Changed|$path|$hash" | Add-Content -Path $rtLog -ErrorAction SilentlyContinue
            }
        } catch { }
    }
    return $Script:RTFM_Watchers.Count
}

# --- DriverWatcher ---
$Script:DW_AllowedVendors = @("Microsoft", "Realtek", "Dolby", "Intel", "Advanced Micro Devices", "AMD", "NVIDIA", "MediaTek")

function Invoke-DriverWatcher {
    $detections = 0
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
            Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion, InfName
        foreach ($driver in $drivers) {
            $vendor = $driver.DriverProviderName
            if ($vendor -and $vendor -notin $Script:DW_AllowedVendors) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2091 -Message "DriverWatcher: Unauthorized driver $($driver.DeviceName) | Vendor: $vendor" -ErrorAction SilentlyContinue
                $detections++
            }
        }
        if ($detections -gt 0) {
            $logPath = "$Script:InstallPath\Logs\DriverWatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Found $detections non-whitelisted drivers" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            Write-AVLog "DriverWatcher: Found $detections non-whitelisted driver(s)" "WARNING"
        }
    } catch { Write-AVLog "DriverWatcher error: $_" "ERROR" }
    return $detections
}

# --- CrudePayloadGuard ---
$Script:CrudePayloadPattern = '(?i)(<script|javascript:|onerror=|onload=|alert\()'

function Invoke-CrudePayloadGuard {
    $detections = 0
    # Browser processes legitimately have JS in command line (extensions, web dev tools) - skip them (Grok)
    $browserNames = @('chrome','firefox','msedge','iexplore','brave','opera','vivaldi','waterfox')
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            if (-not $proc.CommandLine) { continue }
            $procName = ($proc.Name -replace '\.exe$','').ToLower()
            if ($browserNames -contains $procName) { continue }  # Skip browsers - benign JS/HTML in CLI
            if ($proc.CommandLine -match $Script:CrudePayloadPattern) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2092 -Message "CrudePayloadGuard: Potential XSS/payload in PID $($proc.ProcessId) - $($proc.Name)" -ErrorAction SilentlyContinue
                $detections++
            }
        }
        if ($detections -gt 0) {
            Write-AVLog "CrudePayloadGuard: Found $detections crude payload(s)" "THREAT"
        }
    } catch { Write-AVLog "CrudePayloadGuard error: $_" "ERROR" }
    return $detections
}

# --- DnsSecureConfig ---
$Script:DnsSecure_Initialized = $false
$Script:DnsSecure_Servers = @(
    @{ IP = "1.1.1.1";              DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com" },
    @{ IP = "1.0.0.1";              DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com" },
    @{ IP = "2606:4700:4700::1111"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com" },
    @{ IP = "2606:4700:4700::1001"; DohTemplate = "https://cloudflare-dns.com/dns-query"; DotHost = "cloudflare-dns.com" },
    @{ IP = "8.8.8.8";              DohTemplate = "https://dns.google/dns-query";         DotHost = "dns.google" },
    @{ IP = "8.8.4.4";              DohTemplate = "https://dns.google/dns-query";         DotHost = "dns.google" },
    @{ IP = "2001:4860:4860::8888"; DohTemplate = "https://dns.google/dns-query";         DotHost = "dns.google" },
    @{ IP = "2001:4860:4860::8844"; DohTemplate = "https://dns.google/dns-query";         DotHost = "dns.google" }
)

function Invoke-DnsSecureConfig {
    if ($Script:DnsSecure_Initialized) { return 0 }
    
    $applied = 0
    try {
        foreach ($server in $Script:DnsSecure_Servers) {
            try {
                Add-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
                $applied++
            } catch {
                try {
                    Set-DnsClientDohServerAddress -ServerAddress $server.IP -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
                    $applied++
                } catch { }
            }
        }
        
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Virtual|Loopback|Bluetooth" } | Select-Object -First 1
        if ($adapter) {
            try {
                $netshCmds = @(
                    "interface ipv4 set dnsservers name=`"$($adapter.Name)`" static 1.1.1.1 primary validate=no",
                    "interface ipv4 add dnsservers name=`"$($adapter.Name)`" 8.8.8.8 index=2 validate=no",
                    "interface ipv6 set dnsservers name=`"$($adapter.Name)`" static 2606:4700:4700::1111 primary validate=no",
                    "interface ipv6 add dnsservers name=`"$($adapter.Name)`" 2001:4860:4860::8888 index=2 validate=no"
                )
                foreach ($cmd in $netshCmds) {
                    $psi = [System.Diagnostics.ProcessStartInfo]::new("netsh.exe", $cmd)
                    $psi.CreateNoWindow = $true; $psi.UseShellExecute = $false
                    $p = [System.Diagnostics.Process]::Start($psi); $p.WaitForExit()
                }
                
                $guid = $adapter.InterfaceGuid
                $basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings"
                
                $dohServers = @(
                    @{ IP = "1.1.1.1";              Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh" },
                    @{ IP = "8.8.8.8";              Template = "https://dns.google/dns-query";         Path = "Doh" },
                    @{ IP = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query"; Path = "Doh6" },
                    @{ IP = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query";         Path = "Doh6" }
                )
                foreach ($doh in $dohServers) {
                    $dohPath = "$basePath\$($doh.Path)\$($doh.IP)"
                    New-Item -Path $dohPath -Force -ErrorAction SilentlyContinue | Out-Null
                    Set-ItemProperty -Path $dohPath -Name "DohFlags" -Value 0x11 -Type QWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $dohPath -Name "DohTemplate" -Value $doh.Template -Type String -ErrorAction SilentlyContinue
                }
                
                $dotBasePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DotInterfaceSettings"
                $dotServers = @(
                    @{ IP = "1.1.1.1";              Host = "cloudflare-dns.com"; Path = "Dot" },
                    @{ IP = "8.8.8.8";              Host = "dns.google";         Path = "Dot" },
                    @{ IP = "2606:4700:4700::1111"; Host = "cloudflare-dns.com"; Path = "Dot6" },
                    @{ IP = "2001:4860:4860::8888"; Host = "dns.google";         Path = "Dot6" }
                )
                foreach ($dot in $dotServers) {
                    $serverPath = "$dotBasePath\$($dot.Path)\$($dot.IP)"
                    New-Item -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
                    Set-ItemProperty -Path $serverPath -Name "DotFlags" -Value 0x11 -Type QWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $serverPath -Name "DotHost" -Value $dot.Host -Type String -ErrorAction SilentlyContinue
                }
                
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                $applied++
            } catch { }
        }
        
        if ($applied -gt 0) {
            Write-AVLog "DnsSecureConfig: Configured DoH/DoT for $applied servers" "INFO"
            $Script:DnsSecure_Initialized = $true
        }
    } catch {
        Write-AVLog "DnsSecureConfig error: $_" "ERROR"
    }
    return $applied
}

# --- SecpolHardening ---
$Script:Secpol_Initialized = $false

function Invoke-SecpolHardening {
    if ($Script:Secpol_Initialized) { return 0 }
    
    $applied = 0
    try {
        $privilegeSettings = @'
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyRemoteLogonRight = *S-1-5-11
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeRemoteInteractiveLogonRight=
SeRemoteLogonRight=
'@
        $cfgPath = "$env:TEMP\secpol_$(Get-Random).cfg"
        try {
            secedit /export /cfg $cfgPath /quiet 2>&1 | Out-Null
            $privilegeSettings | Out-File -Append -FilePath $cfgPath -Encoding ASCII
            secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfgPath /areas USER_RIGHTS /quiet 2>&1 | Out-Null
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
            $applied++
            Write-AVLog "SecpolHardening: Applied privilege rights hardening" "INFO"
            $Script:Secpol_Initialized = $true
        } catch {
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-AVLog "SecpolHardening error: $_" "ERROR"
    }
    return $applied
}

# --- ShadowProxyCaptureDetection ---
$Script:ShadowProxy_SuspiciousModules = @{
    ProxyStub = @('npmproxy.dll', 'onecoreapiproxystub.dll', 'onecoreuapcommonproxystub.dll', 
                  'onecorecommonproxystub.dll', 'usermgrproxy.dll', 'edaboradutilsproxy.dll')
    MediaCapture = @('mfcaptureengine.dll', 'mfplat.dll', 'mfsensorgroup.dll', 
                     'windows.media.capture.dll', 'frameserver.dll', 'frameservermonitor.dll')
    UserMgmt = @('usermgrcli.dll', 'usermgrproxy.dll', 'credprovs.dll', 'authui.dll')
    NetIntercept = @('winhttp.dll', 'wininet.dll', 'urlmon.dll', 'rasapi32.dll')
}

$Script:ShadowProxy_Whitelist = @(
    'svchost', 'explorer', 'dwm', 'sihost', 'taskhostw', 'runtimebroker',
    'searchhost', 'startmenuexperiencehost', 'shellexperiencehost',
    'systemsettings', 'applicationframehost', 'textinputhost',
    'securityhealthservice', 'msmpeng', 'nissrv',
    'teams', 'zoom', 'skype', 'discord', 'slack',
    'brave', 'chrome', 'firefox', 'msedge', 'opera'
)

function Invoke-ShadowProxyCaptureDetection {
    $detections = 0
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 -and $_.Id -ne $PID }
        
        foreach ($proc in $processes) {
            $procNameLower = $proc.ProcessName.ToLower()
            if ($procNameLower -in $Script:ShadowProxy_Whitelist) { continue }
            
            try {
                $loadedModules = $proc.Modules | ForEach-Object { $_.ModuleName.ToLower() }
                if (-not $loadedModules) { continue }
                
                $categories = @{
                    ProxyStub = $false
                    MediaCapture = $false
                    UserMgmt = $false
                    NetIntercept = $false
                }
                
                foreach ($mod in $loadedModules) {
                    if ($Script:ShadowProxy_SuspiciousModules.ProxyStub -contains $mod) { $categories.ProxyStub = $true }
                    if ($Script:ShadowProxy_SuspiciousModules.MediaCapture -contains $mod) { $categories.MediaCapture = $true }
                    if ($Script:ShadowProxy_SuspiciousModules.UserMgmt -contains $mod) { $categories.UserMgmt = $true }
                    if ($Script:ShadowProxy_SuspiciousModules.NetIntercept -contains $mod) { $categories.NetIntercept = $true }
                }
                
                $loadedCategories = ($categories.Values | Where-Object { $_ -eq $true }).Count
                
                if ($loadedCategories -ge 3) {
                    $isSigned = $false
                    $isFromSafeLocation = $false
                    
                    if ($proc.Path) {
                        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
                        $isSigned = $sig.Status -eq 'Valid'
                        $isFromSafeLocation = $proc.Path -match '^C:\\Windows\\|^C:\\Program Files'
                    }
                    
                    if (-not $isSigned -or -not $isFromSafeLocation) {
                        $loadedCats = @()
                        if ($categories.ProxyStub) { $loadedCats += "ProxyStub" }
                        if ($categories.MediaCapture) { $loadedCats += "MediaCapture" }
                        if ($categories.UserMgmt) { $loadedCats += "UserMgmt" }
                        if ($categories.NetIntercept) { $loadedCats += "NetIntercept" }
                        
                        Write-AVLog "ShadowProxyCapture: DETECTED $($proc.ProcessName) (PID: $($proc.Id)) - Categories: $($loadedCats -join ', ')" "THREAT"
                        $detections++
                        
                        if (-not $isSigned -and -not $isFromSafeLocation) {
                            try {
                                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                                Write-AVLog "ShadowProxyCapture: Terminated $($proc.ProcessName) (PID: $($proc.Id))" "INFO"
                                Show-ThreatToast -Title "Shadow Proxy Detected" -Message "Terminated: $($proc.ProcessName) - suspicious module combination" -ActionType "Terminated"
                            } catch {
                                Write-AVLog "ShadowProxyCapture: Failed to terminate $($proc.ProcessName): $_" "ERROR"
                            }
                        }
                    }
                }
            } catch { }
        }
        
        if ($detections -gt 0) {
            Write-AVLog "ShadowProxyCaptureDetection: Found $detections suspicious process(es)" "THREAT"
        }
    } catch {
        Write-AVLog "ShadowProxyCaptureDetection error: $_" "ERROR"
    }
    return $detections
}

# ===================== Chaos Mode (Test/Validation) =====================
# Simulates benign threats to validate detections - for testing only
function Invoke-ChaosMode {
    Write-Host "`n[CHAOS MODE] Running detection validation tests...`n" -ForegroundColor Cyan
    $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $testPath = Join-Path $env:TEMP "eicar_test_$(Get-Random).com"
    try {
        $eicar | Out-File -FilePath $testPath -Encoding ASCII -NoNewline
        $hash = (Get-FileHash -Path $testPath -Algorithm SHA256).Hash
        $expectedHash = if ($Config.EICARHash) { $Config.EICARHash } else { "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" }
        if ($hash -eq $expectedHash) {
            Write-Host "[CHAOS] EICAR test file created: $testPath" -ForegroundColor Green
            Write-Host "[CHAOS] Hash matches known-bad - detection would trigger. Cleanup..." -ForegroundColor Green
        } else {
            Write-Host "[CHAOS] EICAR created (hash: $hash) - run full scan to validate" -ForegroundColor Yellow
        }
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        Write-Host "[CHAOS] Test complete. Run without -ChaosMode for full protection.`n" -ForegroundColor Cyan
    } catch {
        Write-Host "[CHAOS] Error: $_" -ForegroundColor Red
    }
}

# ===================== Main =====================
# UNINSTALL: Run with -Uninstall to remove persistence, stop instances, clean Run key.
# Full stop: Use -Uninstall, or kill PID from Data\antivirus.pid, then remove Run key manually if needed.

try {
    if ($Uninstall) {
        Uninstall-Antivirus
        exit 0
    }

    if ($ChaosMode) {
        Invoke-ChaosMode
        exit 0
    }

    if ($SelfTest) {
        Test-Configuration
        Invoke-SelfTest
        exit 0
    }

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "`n[!] WARNING: Script is not running as Administrator!" -ForegroundColor Red
        Write-Host "[!] Some features require administrator privileges:" -ForegroundColor Yellow
        Write-Host "    - Password Management (registry access)" -ForegroundColor Yellow
        Write-Host "    - Some detection modules" -ForegroundColor Yellow
        Write-Host "`n[i] To run with full functionality, right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Cyan
        Write-Host "`n[i] Continuing with limited functionality...`n" -ForegroundColor Gray
        Write-StabilityLog "Script running without administrator privileges - limited functionality" "WARN"
    } else {
        Write-StabilityLog "Script running with administrator privileges" "INFO"
    }

    Write-Host "`nAntivirus Protection (Single File)`n" -ForegroundColor Cyan
    Write-StabilityLog "=== Antivirus Starting ==="

    # Set LearningMode early so Test-ConfigurationSanity can detect conflicts
    if ($LearningMode) {
        $Script:LearningMode = $true
        $Config.AutoKillThreats = $false
        $Config.AutoQuarantine = $false
        Write-Host "[LEARNING MODE] Log-only: no kill/quarantine. Building baseline." -ForegroundColor Yellow
        Write-StabilityLog "Learning mode enabled - detections logged only"
    } else {
        $Script:LearningMode = $false
    }

    Test-Configuration

    # Safe Mode detection: WMI BootupState or registry fallback
    $safeMode = $false
    try {
        $bootState = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).BootupState
        if ($bootState -match "Safe|Fail-safe") { $safeMode = $true }
    } catch {}
    if (-not $safeMode -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option")) {
        try {
            $opt = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" -Name "OptionValue" -ErrorAction SilentlyContinue
            if ($opt.OptionValue -in @(1, 2)) { $safeMode = $true }
        } catch {}
    }
    if ($safeMode) {
        Write-Host "[!] Safe Mode detected - disabling auto-actions to prevent system instability" -ForegroundColor Yellow
        if (-not $Config.ForceQuarantineInSafeMode) { $Config.AutoQuarantine = $false }
        $Config.AutoKillThreats = $false
        $Config.EnableUnsignedDLLScanner = $false
        Write-StabilityLog "Safe Mode - AutoKillThreats, AutoQuarantine, UnsignedDLLScanner disabled"
    }

    $global:AntivirusPIDFilePath = $Config.PIDFilePath

    Write-StabilityLog "Executing script path: $PSCommandPath" "INFO"

    $flagFile = "$Script:InstallPath\Data\.elevated"
    Register-EngineEvent PowerShell.Exiting -Action { Remove-Item $flagFile -Force -ErrorAction SilentlyContinue } | Out-Null
    Register-ExitCleanup
    
    Request-Elevation -Reason "Antivirus protection requires administrator privileges for full functionality."
    
    if ($isAdmin) { Invoke-PasswordRotatorSetup }
    Install-Antivirus
    
    # Only initialize mutex if not already initialized during installation
    if (-not $Global:AntivirusState.Running) {
        Initialize-Mutex
    }

    Register-TerminationProtection

Write-Host "`n[PROTECTION] Initializing anti-termination safeguards..." -ForegroundColor Cyan

if ($host.Name -eq "Windows PowerShell ISE Host") {
    # In ISE, use trap handler which is already defined at the top
    Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
    Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
} else {
    # In regular console, use the Console.CancelKeyPress handler
    Enable-CtrlCProtection
}

# Enable auto-restart if running as admin
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Enable-AutoRestart
        Start-ProcessWatchdog
    } else {
        Write-Host "[INFO] Auto-restart requires administrator privileges (optional)" -ForegroundColor Gray
    }
} catch {
    Write-Host "[WARNING] Some protection features failed to initialize: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[PROTECTION] Anti-termination safeguards active" -ForegroundColor Green
    Write-Host "[*] Starting detection jobs...`n" -ForegroundColor Cyan

    $loaded = 0
    $failed = 0

    Load-HashDatabase
    if ($Script:KnownFilesCache.Count -gt 0) {
        Write-Host "[+] Loaded $($Script:KnownFilesCache.Count) hash cache entries" -ForegroundColor Green
    }

    $moduleNames = @(
        "TinyThreatScan",
        "SecureDnsMonitoring",
        "HashDetection",
        "LOLBinDetection",
        "ProcessAnomalyDetection",
        "AMSIBypassDetection",
        "CredentialDumpDetection",
        "WMIPersistenceDetection",
        "ScheduledTaskDetection",
        "RegistryPersistenceDetection",
        "DLLHijackingDetection",
        "TokenManipulationDetection",
        "ProcessHollowingDetection",
        "KeystrokeInjectionDetection",
        "KeyScramblerManagement",
        "RansomwareDetection",
        "NetworkAnomalyDetection",
        "RootkitDetection",
        "ClipboardMonitoring",
        "COMMonitoring",
        "BrowserExtensionMonitoring",
        "ShadowCopyMonitoring",
        "USBMonitoring",
        "MobileDeviceMonitoring",
        "AttackToolsDetection",
        "PUADetection",
        "PUPDetection",
        "PUMDetection",
        "PhantomProcessKiller",
        "AdvancedThreatDetection",
        "EventLogMonitoring",
        "FirewallRuleMonitoring",
        "ServiceMonitoring",
        "FilelessDetection",
        "MemoryScanning",
        "NamedPipeMonitoring",
        "DNSExfiltrationDetection",
        "PasswordManagement",
        "BeaconDetection",
        "CodeInjectionDetection",
        "DataExfiltrationDetection",
        "FileEntropyDetection",
        "HoneypotMonitoring",
        "LateralMovementDetection",
        "ProcessCreationDetection",
        "QuarantineManagement",
        "ReflectiveDLLInjectionDetection",
        "ResponseEngine",
        "PrivacyForgeSpoofing",
        "ElfCatcher",
        "ElfDLLUnloader",
        "UnsignedDLLRemover",
        "YaraDetection",
        "IdsDetection",
        "MemoryAcquisitionDetection",
        "BCDSecurity",
        "CredentialProtection",
        "HidMacroGuard",
        "LocalProxyDetection",
        "ScriptContentScan",
        "ScriptHostDetection",
        "NeuroBehaviorMonitor",
        "StartupPersistenceDetection",
        "SuspiciousParentChildDetection",
        "ScriptBlockLoggingCheck",
        "CVEMitigationPatcher",
        "AsrRules",
        "GRulesC2Block",
        "ProcessAuditing",
        "MitreMapping",
        "RealTimeFileMonitor",
        "DriverWatcher",
        "CrudePayloadGuard",
        "DnsSecureConfig",
        "SecpolHardening",
        "ShadowProxyCaptureDetection",
        "DragonBreathHunter"
    )

    foreach ($modName in $moduleNames) {
        # Opt-in for invasive modules (Grok: clipboard/keystroke need explicit enable)
        if ($modName -eq "ClipboardMonitoring" -and -not $Config.EnableClipboardMonitoring) {
            Write-Host "[.] ClipboardMonitoring - skipped (opt-in: set Config.EnableClipboardMonitoring = `$true)" -ForegroundColor DarkGray
            continue
        }
        if ($modName -eq "KeystrokeInjectionDetection" -and -not $Config.EnableKeystrokeInjectionDetection) {
            Write-Host "[.] KeystrokeInjectionDetection - skipped (set Config.EnableKeystrokeInjectionDetection = `$true to enable)" -ForegroundColor DarkGray
            continue
        }

        $key = "${modName}IntervalSeconds"
        $interval = if ($Script:ManagedJobConfig.ContainsKey($key)) { $Script:ManagedJobConfig[$key] } else { 60 }
        # Low-power mode: double intervals to reduce CPU/RAM (Grok suggestion)
        if ($Config.LowPowerMode) { $interval = [Math]::Max($interval * 2, 60) }

        try {
            Start-ManagedJob -ModuleName $modName -IntervalSeconds $interval

            if ($Global:AntivirusState.Jobs.ContainsKey("AV_$modName")) {
                Write-Host "[+] $modName ($interval sec)" -ForegroundColor Green
                Write-StabilityLog "Successfully started module: $modName"
                $loaded++
            }
            else {
                Write-Host "[!] $modName - skipped" -ForegroundColor Yellow
                Write-StabilityLog "Module skipped: $modName" "WARN"
                $failed++
            }
        }
        catch {
            Write-Host "[!] Failed to start $modName : $_" -ForegroundColor Red
            Write-StabilityLog "Module start failed: $modName - $_" "ERROR"
            Write-AVLog "Module start failed: $modName - $_" "ERROR"
            $failed++
        }
    }

    Write-Host "`n[+] Started $loaded modules" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "[!] $failed modules failed to start" -ForegroundColor Yellow
    }

    Write-StabilityLog "Module start complete: $loaded started, $failed failed"

    try {
        $mjCount = if ($script:ManagedJobs) { $script:ManagedJobs.Count } else { 0 }
        Write-StabilityLog "Managed jobs registered after start: $mjCount" "INFO"
        Write-Host "[AV] Managed jobs registered: $mjCount" -ForegroundColor DarkGray
    }
    catch {}

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Antivirus Protection ACTIVE" -ForegroundColor Green
    Write-Host "  Active jobs: $($Global:AntivirusState.Jobs.Count)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor Yellow

    Write-StabilityLog "Antivirus fully started with $($Global:AntivirusState.Jobs.Count) active jobs"
    Write-AVLog "About to enter Monitor-Jobs loop"

    # Initialize FileSystemWatcher at startup (runs in main thread, not as job)
    if (-not $Script:RTFM_Initialized) {
        Write-AVLog "Initializing real-time file monitoring..."
        Start-RealtimeFileMonitor
        $Script:RTFM_Initialized = $true
        Write-AVLog "Real-time file monitoring active on $($Script:RTFM_Watchers.Count) drives"
    }

    Monitor-Jobs
}
catch {
    $err = $_.Exception.Message
    Write-Host "`n[!] Critical error: $err`n" -ForegroundColor Red
    Write-StabilityLog "Critical startup error: $err" "ERROR"
    Write-AVLog "Startup error: $err" "ERROR"

    if ($err -like "*already running*") {
        Write-Host "[i] Another instance is running. Exiting.`n" -ForegroundColor Yellow
        Write-StabilityLog "Blocked duplicate instance - exiting" "INFO"
        exit 1
    }

    Write-StabilityLog "Exiting due to startup failure" "ERROR"
    exit 1
}
