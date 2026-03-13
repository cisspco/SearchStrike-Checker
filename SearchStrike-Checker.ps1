#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$Script:LogPath        = Join-Path $PSScriptRoot "SearchStrike_Check_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Script:Findings       = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:StartTime      = Get-Date
$Script:CurrentSection = 'Init'

$IOC_Hashes = @{
    'd6acbd0cf0c99c76c3f09f68792eabb843fd539ae42573ecdfeda63fa695dcd2' = 'Tftpd64 (2026-02-17)'
    '3ddfcc93aefab5a671edb4c643a810b7a2a7b35629c27f3f68849cf390a26025' = 'Postman (2026-02-17)'
    'c3910810dc87e1a5993d4e4234fd3f94fa7ecf66735fd0396be73b2379aafabd' = 'Tftpd64 (2026-02-23)'
    '3abe9aa1b6a9f2f779f875773e077e0129e770e98fcbee60c0137f656f4fe82e' = 'Tftpd64 (2026-03-09)'
    'ece54f2a68530222604014dd5b23520bb1729efe7ea15a822c1ea16556ed8257' = 'Tftpd64 (2026-03-10)'
    'ab79d9ef9fddb880bbfc5e2587566884da9510988005f2737493cfc25437b8ba' = 'WinDbg (2026-03-10)'
    'c03e9aade86079a2d4007b58e3b419dfe821bf64366fd3a9c3d04dd63b5e7779' = 'PsExec (2026-03-10)'
    'eb2a4c6e88adc5b56dcb6a39bf749564d5b72fbb5ba2dc3c603ba183a99bccb4' = 'USMT (2026-03-10)'
    'fc9da1e9c12930f1c324b4dee5918033a644d090a96f69ff3669711d4219158b' = 'IntuneWinAppUtil (2026-03-10)'
    'e3df11e259647e00de5f6119fce20c07f551b4bb5b3c4da3fb07956c0c3d69ff' = 'BgInfo (2026-03-10)'
    'f88532089976d65463869a1ab5e8f050d8f3ee49501a5fa7883f80ac86b20a84' = 'RDCMan (2026-03-10)'
}

$IOC_C2Domains = @(
    'jariosos.com', 'hayesmed.com', 'regancontrols.com', 'salinasrent.com',
    'justtalken.com', 'mebeliotmasiv.com', 'euclidrent.com',
    'o-parana.com', 'palshona.com', 'aurineuroth.com'
)

$ETH_RPC_Hosts = @(
    'rpc.mevblock.io', 'mainnet.blockpi.network', 'rpc.payload.de',
    'hereusers.allsettled.net', 'rpc.drpc.io', 'rpc.flashbots.net',
    'eth.llamarpc.com', 'rpc.lokichain.io', 'rpc.blastapi.io'
)

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$ts] $Msg" | Out-File -FilePath $Script:LogPath -Append -Encoding UTF8
}

function Write-Section {
    param([string]$Title)
    $line = '=' * 62
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Log "=== $Title ==="
}

function Write-Check {
    param([string]$Item)
    Write-Host "  [*] $Item" -ForegroundColor Gray
    Write-Log "[CHECK] $Item"
}

function Write-Hit {
    param([string]$Msg, [string]$Detail = '')
    Write-Host "  [!] DETECTED : $Msg" -ForegroundColor Red
    if ($Detail) { Write-Host "      >> $Detail" -ForegroundColor Yellow }
    Write-Log "[DETECTED] $Msg | $Detail"
    $Script:Findings.Add([PSCustomObject]@{
        Severity = 'HIGH'; Category = $Script:CurrentSection
        Message  = $Msg;   Detail   = $Detail
    })
}

function Write-Warn {
    param([string]$Msg, [string]$Detail = '')
    Write-Host "  [?] SUSPECT  : $Msg" -ForegroundColor Yellow
    if ($Detail) { Write-Host "      >> $Detail" -ForegroundColor DarkYellow }
    Write-Log "[SUSPECT] $Msg | $Detail"
    $Script:Findings.Add([PSCustomObject]@{
        Severity = 'MEDIUM'; Category = $Script:CurrentSection
        Message  = $Msg;     Detail   = $Detail
    })
}

function Write-Clean {
    param([string]$Msg)
    Write-Host "  [+] CLEAN    : $Msg" -ForegroundColor Green
    Write-Log "[CLEAN] $Msg"
}

function Get-FileEntropy {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -lt 64) { return 0.0 }
        $freq = @{}
        foreach ($b in $bytes) {
            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
        }
        $entropy = 0.0
        $total   = $bytes.Length
        foreach ($count in $freq.Values) {
            $p = $count / $total
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($entropy, 4)
    } catch { return 0.0 }
}

function Test-LooksHex {
    param([string]$Val)
    if ($Val.Length -lt 6) { return $false }
    $hexCount = ($Val.ToCharArray() | Where-Object { $_ -match '[0-9a-fA-F]' }).Count
    return ($hexCount / $Val.Length) -ge 0.8
}

function Test-LooksRandom {
    param([string]$Val)
    if ($Val.Length -lt 4 -or $Val.Length -gt 16) { return $false }
    return ($Val -match '[a-zA-Z]') -and ($Val -match '[0-9]') -and ($Val -match '^[a-zA-Z0-9]+$')
}

# --------------------------------------------------
# Section 1: Filesystem Check
# --------------------------------------------------
function Invoke-FilesystemCheck {
    $Script:CurrentSection = 'Filesystem'
    Write-Section '[1/5] Filesystem Check'
    $localApp = $env:LOCALAPPDATA

    Write-Check 'node.exe inside random 6-char dirs under %LOCALAPPDATA%'
    $suspDirs = Get-ChildItem -Path $localApp -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[a-zA-Z0-9]{6}$' }
    $nodeFound = $false
    foreach ($dir in $suspDirs) {
        $nodeFiles = Get-ChildItem -Path $dir.FullName -Filter 'node.exe' -File -Recurse `
                         -ErrorAction SilentlyContinue
        foreach ($n in $nodeFiles) {
            Write-Hit 'node.exe found inside random 6-char directory' $n.FullName
            $nodeFound = $true
        }
    }
    if (-not $nodeFound) { Write-Clean 'No node.exe found inside random 6-char directories' }

    Write-Check 'High-entropy files (.xml/.bak/.cfg/.bin/.ini) in AppData/Temp'
    $exts = @('*.xml','*.bak','*.cfg','*.bin','*.ini')
    $hiEntFound = $false
    foreach ($sp in @($localApp, $env:APPDATA, $env:TEMP)) {
        foreach ($ext in $exts) {
            $files = Get-ChildItem -Path $sp -Filter $ext -File -Recurse -Depth 3 `
                         -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 512 }
            foreach ($f in $files) {
                # Exclude known legitimate Windows/system high-entropy files
                $knownSafe = $f.FullName -like '*\Packages\*' -or
                             $f.FullName -like '*\Microsoft\*' -or
                             $f.FullName -like '*\WindowsApps\*'
                if ($knownSafe) { continue }
                $ent = Get-FileEntropy -FilePath $f.FullName
                if ($ent -ge 7.2) {
                    $sha256 = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
                    Write-Warn 'High-entropy file (possible encrypted payload)' "$($f.FullName) [Entropy=$ent]"
                    Write-Log "[HASH] $($f.FullName) | Entropy=$ent | SHA256=$sha256"
                    $hiEntFound = $true
                }
            }
        }
    }
    if (-not $hiEntFound) { Write-Clean 'No high-entropy suspicious files' }

    Write-Check 'Random-named .cmd scripts in %LOCALAPPDATA%\Temp'
    $cmdFiles = Get-ChildItem -Path "$localApp\Temp" -Filter '*.cmd' -File -ErrorAction SilentlyContinue |
                Where-Object { Test-LooksRandom $_.BaseName }
    if ($cmdFiles) {
        foreach ($f in $cmdFiles) { Write-Warn 'Random .cmd file (MSI install artifact)' $f.FullName }
    } else { Write-Clean 'No random .cmd files in Temp' }

}

# --------------------------------------------------
# Section 2: Registry Check
# --------------------------------------------------
function Invoke-RegistryCheck {
    $Script:CurrentSection = 'Registry'
    Write-Section '[2/5] Registry Check'

    Write-Check 'HKCU Run key - node.exe entries'
    $entries  = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    $runFound = $false
    if ($entries) {
        $entries.PSObject.Properties |
            Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notlike 'PS*' } |
            ForEach-Object {
                $n = $_.Name; $v = $_.Value
                if ($v -match 'node\.exe') {
                    Write-Hit 'node.exe in HKCU Run key' "Key=$n | Value=$v"
                    $runFound = $true
                } elseif ((Test-LooksHex $n) -and ($v -match '\.(cfg|ini|bin|bak)' -or $v -match 'LOCALAPPDATA')) {
                    Write-Warn 'Hex-named Run key with suspicious value' "Key=$n | Value=$v"
                    $runFound = $true
                }
            }
    }
    if (-not $runFound) { Write-Clean 'No suspicious entries in HKCU Run key' }

    Write-Check 'HKLM Run key - node.exe entries'
    $entriesLM = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    $lmFound   = $false
    if ($entriesLM) {
        $entriesLM.PSObject.Properties |
            Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notlike 'PS*' } |
            ForEach-Object {
                if ($_.Value -match 'node\.exe') {
                    Write-Hit 'node.exe in HKLM Run key' "Key=$($_.Name) | Value=$($_.Value)"
                    $lmFound = $true
                }
            }
    }
    if (-not $lmFound) { Write-Clean 'No suspicious entries in HKLM Run key' }

    Write-Check 'HKCU\Software - random string subkeys (MSI artifact)'
    # Exclude known legitimate keys that look random
    $knownLegitKeys = @('Wow6432Node','AppEvents','Classes','Console','Control Panel',
                        'Environment','EUDC','Keyboard Layout','Network','Printers',
                        'SessionInformation','Volatile Environment')
    $suspKeys = Get-ChildItem -Path 'HKCU:\Software' -ErrorAction SilentlyContinue |
                Where-Object {
                    (Test-LooksRandom $_.PSChildName) -and
                    $_.PSChildName.Length -ge 6 -and
                    $_.PSChildName -notin $knownLegitKeys
                }
    if ($suspKeys) {
        foreach ($sk in $suspKeys) { Write-Warn 'Random subkey under HKCU\Software' $sk.PSPath }
    } else { Write-Clean 'No random-string subkeys under HKCU\Software' }
}

# --------------------------------------------------
# Section 3: Process Check
# --------------------------------------------------
function Invoke-ProcessCheck {
    $Script:CurrentSection = 'Process'
    Write-Section '[3/5] Process Check'

    $procs   = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
    $procMap = @{}
    foreach ($p in $procs) { $procMap[$p.ProcessId] = $p }

    Write-Check 'node.exe running from LOCALAPPDATA (abnormal)'
    $abnNode = $procs | Where-Object {
        $_.Name -eq 'node.exe' -and $_.ExecutablePath -and
        $_.ExecutablePath -match 'LOCALAPPDATA' -and
        $_.ExecutablePath -notmatch '\\nodejs\\'
    }
    if ($abnNode) {
        foreach ($n in $abnNode) {
            Write-Hit 'node.exe from abnormal LOCALAPPDATA path' "PID=$($n.ProcessId) | Path=$($n.ExecutablePath)"
        }
    } else { Write-Clean 'No node.exe running from abnormal paths' }

    Write-Check 'Process chain: msiexec->cmd->node or explorer->node'
    $chainFound = $false
    foreach ($p in ($procs | Where-Object { $_.Name -eq 'node.exe' })) {
        $parentId = $p.ParentProcessId
        if (-not $procMap.ContainsKey($parentId)) { continue }
        $parent = $procMap[$parentId]
        if ($parent.Name -eq 'cmd.exe' -and $procMap.ContainsKey($parent.ParentProcessId)) {
            if ($procMap[$parent.ParentProcessId].Name -eq 'msiexec.exe') {
                Write-Hit 'Chain: msiexec -> cmd -> node' "node PID=$($p.ProcessId)"
                $chainFound = $true
            }
        }
        if ($parent.Name -eq 'explorer.exe' -and $p.ExecutablePath -match 'LOCALAPPDATA') {
            Write-Hit 'Chain: explorer -> node (Run key persistence)' "node PID=$($p.ProcessId) | Path=$($p.ExecutablePath)"
            $chainFound = $true
        }
    }
    if (-not $chainFound) { Write-Clean 'No suspicious process chains' }

    Write-Check 'node.exe with config payload args (.cfg/.ini/.bin)'
    $hiddenNode = $procs | Where-Object {
        $_.Name -eq 'node.exe' -and $_.CommandLine -and
        $_.CommandLine -match '\.(cfg|ini|bin|bak)' -and
        $_.ExecutablePath -match 'LOCALAPPDATA'
    }
    if ($hiddenNode) {
        foreach ($h in $hiddenNode) {
            Write-Hit 'node.exe hidden execution with config payload' "PID=$($h.ProcessId) | CMD=$($h.CommandLine)"
        }
    } else { Write-Clean 'No hidden node.exe execution patterns' }
}

# --------------------------------------------------
# Section 4: Network Check
# --------------------------------------------------
function Invoke-NetworkCheck {
    $Script:CurrentSection = 'Network'
    Write-Section '[4/5] Network Check'

    $tcpConns  = Get-NetTCPConnection -State Established,TimeWait,CloseWait -ErrorAction SilentlyContinue
    $remoteIPs = $tcpConns | Select-Object -ExpandProperty RemoteAddress -Unique

    # NOTE: DNS cache must be captured BEFORE any DNS resolution calls below
    $dnsCache  = Get-DnsClientCache -ErrorAction SilentlyContinue

    # 4-1. DNS cache check first (before any resolution that would pollute the cache)
    Write-Check 'DNS cache traces of C2 domains'
    $dnsCacheFound = $false
    foreach ($domain in $IOC_C2Domains) {
        $hit = $dnsCache | Where-Object { $_.Entry -like "*$domain*" }
        if ($hit) {
            Write-Hit "C2 domain in DNS cache: $domain" "TTL=$($hit[0].TimeToLive)"
            $dnsCacheFound = $true
        }
    }
    if (-not $dnsCacheFound) { Write-Clean 'No C2 domain traces in DNS cache' }

    Write-Check 'Ethereum RPC endpoint DNS cache traces (blockchain C2)'
    $ethDnsFound = $false
    foreach ($h in $ETH_RPC_Hosts) {
        $dnsHit = $dnsCache | Where-Object { $_.Entry -like "*$h*" }
        if ($dnsHit) {
            Write-Hit "Ethereum RPC in DNS cache: $h" 'Abnormal traffic in business environment'
            $ethDnsFound = $true
        }
    }
    if (-not $ethDnsFound) { Write-Clean 'No Ethereum RPC DNS cache traces' }

    # 4-2. Active TCP connection checks using cached IPs only (no fresh DNS resolution)
    Write-Check 'Active TCP connections to C2 domains (using cached IPs only)'
    $c2ConnFound = $false
    foreach ($domain in $IOC_C2Domains) {
        # Use only already-cached IPs to avoid polluting DNS cache ourselves
        $cachedEntries = $dnsCache | Where-Object { $_.Entry -like "*$domain*" -and $_.RecordData }
        foreach ($entry in $cachedEntries) {
            $cachedIP = $entry.RecordData.IPv4Address.IPAddressToString
            if ($cachedIP -and $cachedIP -in $remoteIPs) {
                Write-Hit "Active TCP connection to C2 (cached IP): $domain" "IP=$cachedIP"
                $c2ConnFound = $true
            }
        }
    }
    if (-not $c2ConnFound) { Write-Clean 'No active TCP connections to C2 IPs' }

    Write-Check 'Active TCP connections to Ethereum RPC (using cached IPs only)'
    $ethConnFound = $false
    foreach ($h in $ETH_RPC_Hosts) {
        $cachedEntries = $dnsCache | Where-Object { $_.Entry -like "*$h*" -and $_.RecordData }
        foreach ($entry in $cachedEntries) {
            $cachedIP = $entry.RecordData.IPv4Address.IPAddressToString
            if ($cachedIP -and $cachedIP -in $remoteIPs) {
                Write-Hit "Active TCP connection to Ethereum RPC (cached IP): $h" "IP=$cachedIP"
                $ethConnFound = $true
            }
        }
    }
    if (-not $ethConnFound) { Write-Clean 'No active TCP connections to Ethereum RPC IPs' }

    Write-Check 'Outbound connections by node.exe processes'
    $nodePids  = (Get-Process -Name 'node' -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty Id
    $nodeConns = $tcpConns | Where-Object {
        $_.OwningProcess -in $nodePids -and
        $_.RemoteAddress -notin @('0.0.0.0','127.0.0.1','::1','::')
    }
    if ($nodeConns) {
        foreach ($nc in $nodeConns) {
            Write-Warn 'node.exe outbound connection detected' `
                "PID=$($nc.OwningProcess) | $($nc.LocalAddress):$($nc.LocalPort) -> $($nc.RemoteAddress):$($nc.RemotePort)"
        }
    } else { Write-Clean 'No outbound connections from node.exe' }

    Write-Check 'hosts file tampering check'
    $hostsLines    = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    $hostsModified = $false
    foreach ($domain in $IOC_C2Domains) {
        if ($hostsLines -match $domain) {
            Write-Warn "C2 domain entry in hosts file: $domain"
            $hostsModified = $true
        }
    }
    if (-not $hostsModified) { Write-Clean 'hosts file not tampered' }
}

# --------------------------------------------------
# Section 5: IOC Hash Check
# --------------------------------------------------
function Invoke-HashCheck {
    $Script:CurrentSection = 'IOC Hash'
    Write-Section '[5/5] IOC Hash Check (SHA256)'

    $scanPaths = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        $env:TEMP,
        $env:LOCALAPPDATA,
        $env:APPDATA
    )
    Write-Check 'Scan paths: Downloads, Desktop, Temp, LocalAppData, AppData'
    Write-Host '  (Scanning files - please wait...)' -ForegroundColor DarkGray

    $hashFound = $false
    foreach ($sp in $scanPaths) {
        if (-not (Test-Path $sp)) { continue }
        $files = Get-ChildItem -Path $sp -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
                 Where-Object {
                     $_.Extension -in @('.msi','.exe','.cmd','.bat','.ps1','.js','.vbs') -and
                     $_.Length -gt 1KB
                 }
        foreach ($f in $files) {
            try {
                $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
                if ($IOC_Hashes.ContainsKey($hash)) {
                    Write-Hit 'IOC hash match - malicious file found!' "File=$($f.FullName) | ID=$($IOC_Hashes[$hash])"
                    $hashFound = $true
                }
            } catch {}
        }
    }
    if (-not $hashFound) { Write-Clean 'No known IOC hashes found' }
}

# --------------------------------------------------
# Summary
# --------------------------------------------------
function Show-Summary {
    $elapsed = (Get-Date) - $Script:StartTime
    $highCnt = ($Script:Findings | Where-Object { $_.Severity -eq 'HIGH'   }).Count
    $medCnt  = ($Script:Findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $border  = '=' * 62

    Write-Host ""
    Write-Host $border -ForegroundColor Cyan
    Write-Host '  SCAN SUMMARY' -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "  Duration  : $([math]::Round($elapsed.TotalSeconds,1)) sec"
    Write-Host ""

    if ($highCnt -gt 0) { Write-Host "  [!!] HIGH   : $highCnt finding(s)" -ForegroundColor Red }
    if ($medCnt  -gt 0) { Write-Host "  [?]  MEDIUM : $medCnt finding(s)"  -ForegroundColor Yellow }
    if ($highCnt -eq 0 -and $medCnt -eq 0) {
        Write-Host '  [+]  No threats detected' -ForegroundColor Green
    }

    if ($Script:Findings.Count -gt 0) {
        Write-Host ""
        Write-Host '  --- Findings ---' -ForegroundColor White
        $i = 1
        foreach ($f in $Script:Findings) {
            $col = if ($f.Severity -eq 'HIGH') { 'Red' } else { 'Yellow' }
            Write-Host "  $i. [$($f.Severity)] [$($f.Category)] $($f.Message)" -ForegroundColor $col
            if ($f.Detail) { Write-Host "     $($f.Detail)" -ForegroundColor DarkGray }
            $i++
        }
        Write-Host ""
        Write-Host '  !! HIGH detected: isolate from network immediately !!' -ForegroundColor Red
        Write-Host '     Report to KISA: https://boho.or.kr' -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  Log : $Script:LogPath" -ForegroundColor Gray
    Write-Host $border -ForegroundColor Cyan
    Write-Log "=== SUMMARY: HIGH=$highCnt, MEDIUM=$medCnt, Duration=$([math]::Round($elapsed.TotalSeconds,1))s ==="
}

# --------------------------------------------------
# Main
# --------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host "   Operation SearchStrike - Malware Infection Checker" -ForegroundColor Cyan
Write-Host "   KISA Hunting Guide (2026-03-11) | Severity: Critical" -ForegroundColor Cyan
Write-Host "   [!] DETECTED (RED)"  -ForegroundColor Red
Write-Host "   [?] SUSPECT (YELLOW)" -ForegroundColor Yellow
Write-Host "   [+] CLEAN (GREEN)" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host "  Host    : $env:COMPUTERNAME | User: $env:USERNAME" -ForegroundColor Gray
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "  Privilege: Administrator (full scan)" -ForegroundColor Green
} else {
    Write-Host "  Privilege: Standard user (some checks may be limited)" -ForegroundColor Yellow
}
# Initialize log file explicitly
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] === Operation SearchStrike Checker Log ===" |
    Out-File -FilePath $Script:LogPath -Encoding UTF8 -Force
Write-Log "Scan started | User=$env:USERNAME | Host=$env:COMPUTERNAME | Admin=$isAdmin"

Invoke-FilesystemCheck
Invoke-RegistryCheck
Invoke-ProcessCheck
Invoke-NetworkCheck
Invoke-HashCheck
Show-Summary
