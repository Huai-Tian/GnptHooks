<#
=====================================================================
 GNPT 加速测试自动化脚本 v4  accel_test.ps1
 用途: 高频 idle<->活跃切换放大 C-state 竞态触发率 (加速轮A/对照轮C)
 用法(管理员 PowerShell):
   powershell -ExecutionPolicy Bypass -File .\accel_test.ps1
   .\accel_test.ps1 -Minutes 60                 # 加速轮A加长
   .\accel_test.ps1 -Mode C                     # 对照轮C(核钉C0)
   .\accel_test.ps1 -Mode Full                  # A + C 连跑
 v4 变更:
   - 日志根多候选自动定位: 提权会话API桌面≠logger桌面——依次探测
     Public Desktop→用户桌面→兜底, 修复"全程盯错目录"的假超时
 v3 变更:
   - 服务名默认 Test(按目标机实际)
   - 日志读取改 FileStream共享模式(ReadWrite|Delete)——驱动运行时
     logger 持独占锁, Get-Content 会全部失败(v2 的超时根因)
   - 版本门禁降级: 服务运行40s即开跑(日志不可读时警告), sc stop后
     文件解锁再验版本, 不符则标记本轮无效
   - 超时前自动输出诊断(服务状态/桌面文件清单)
 已知缺陷(待v5): 同boot二跑 WRONGVER 假警报——上轮日志仍在桌面,
   Get-GnptLogs 时间窗(-3min)可捞到旧文件复核出"版本不符"。
   数据有效, 忽略该标签即可。
 崩溃后: 重启完直接再跑本脚本 = 自动收集上轮现场
 产物: Desktop\gnpt_accel_<标签>_<时间戳>\ 文件夹
=====================================================================
#>
param(
    [int]$Minutes = 30,
    [int]$Togglers = 12,
    [ValidateSet('A','C','Full')]
    [string]$Mode = 'A',
    [string]$ExpectTag = 'v0.9y',
    [string]$SvcName = 'Test'
)

$ErrorActionPreference = 'Stop'
# 日志根: 多候选自动定位(实测目标机=Public Desktop; 提权会话的API桌面
# 可能不同)——取"存在gnpt_log.txt或L*.txt的目录", 兜底=API桌面
$LogRoots = @("$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop",
              'C:\Users\Public\Desktop', 'C:\Users\User\Desktop',
              [Environment]::GetFolderPath('Desktop')) | Select-Object -Unique
$Desk = $null
foreach ($r in $LogRoots) {
    if ($r -and (Test-Path (Join-Path $r 'gnpt_log.txt') -ErrorAction SilentlyContinue)) { $Desk = $r; break }
}
if (-not $Desk) { $Desk = [Environment]::GetFolderPath('Desktop') }
$OutDesk = [Environment]::GetFolderPath('Desktop')   # 产物输出仍用会话桌面
$StateF = Join-Path $OutDesk 'gnpt_accel_state.json'
$ProgF  = Join-Path $OutDesk 'gnpt_accel_progress.log'

# ---------- 基础工具 ----------
function Log([string]$m) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $ProgF -Value $line -Encoding UTF8
}

function Save-State([datetime]$start, [string]$mode, [bool]$done) {
    @{ TestStart = $start.ToString('o'); Mode = $mode; Completed = $done } |
        ConvertTo-Json | Set-Content -Path $StateF -Encoding UTF8
}

# 共享模式读(logger持锁也能读); 失败返回 $null
function Read-HeadText([string]$path, [int]$lines) {
    try {
        $fs = [IO.File]::Open($path, 'Open', 'Read', ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sr = New-Object IO.StreamReader($fs)
        $out = @()
        for ($i = 0; $i -lt $lines -and -not $sr.EndOfStream; $i++) { $out += $sr.ReadLine() }
        $sr.Close(); $fs.Close()
        return ($out -join ' ')
    } catch { return $null }
}

function Read-TailText([string]$path, [int]$lines) {
    try {
        $fs = [IO.File]::Open($path, 'Open', 'Read', ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sr = New-Object IO.StreamReader($fs)
        $q = New-Object System.Collections.Generic.Queue[string]
        while (-not $sr.EndOfStream) {
            $q.Enqueue($sr.ReadLine())
            if ($q.Count -gt $lines) { $q.Dequeue() | Out-Null }
        }
        $sr.Close(); $fs.Close()
        return ($q.ToArray() -join "`n")
    } catch { return $null }
}

# gnpt 日志识别: gnpt_log.txt(T2镜像, 首行[Entry]) 或 "^L<行号> "形态 或 头部含GNPT/[Entry]/T2:
function Get-GnptLogs([datetime]$since) {
    Get-ChildItem $Desk -Filter *.txt -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $since.AddMinutes(-3) } |
        Where-Object {
            if ($_.Name -eq 'gnpt_log.txt') { return $true }
            if ($_.Name -match '^L\d+ ') { return $true }
            $h = Read-HeadText $_.FullName 8
            return ($null -ne $h -and $h -match 'GNPT|\[Entry\]|T2:')
        } |
        Sort-Object LastWriteTime
}

function Get-HexIndexes([string]$setting) {
    try {
        $out = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR $setting 2>$null) -join ' '
        if (-not $out) { return $null }
        $m = [regex]::Matches($out, '0x[0-9A-Fa-f]+')
        if ($m.Count -lt 2) { return $null }
        return @([Convert]::ToInt32($m[0].Value, 16), [Convert]::ToInt32($m[1].Value, 16))
    } catch { return $null }
}

function Set-Power([int]$demote, [int]$disable) {
    if ($demote -ge 0) {
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDEMOTE $demote | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDEMOTE $demote | Out-Null
    }
    if ($disable -ge 0) {
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE $disable | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE $disable | Out-Null
    }
    powercfg /setactive SCHEME_CURRENT | Out-Null
}

function Dump-Diagnostics {
    try { Log ('诊断: 服务状态 = {0} | 日志根 = {1}' -f (Get-Service $SvcName -ErrorAction SilentlyContinue).Status, $Desk) } catch {}
    Get-ChildItem $Desk -Filter *.txt -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 6 | ForEach-Object {
            Log ('诊断: {0} | {1}B | {2}' -f $_.Name, $_.Length, $_.LastWriteTime.ToString('HH:mm:ss'))
        }
}

function Collect-Artifacts([datetime]$since, [string]$tag, [string]$note) {
    $dir = Join-Path $OutDesk ('gnpt_accel_{0}_{1}' -f $tag, (Get-Date -Format 'MMdd_HHmmss'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $logs = @(Get-GnptLogs $since)
    foreach ($l in $logs) {
        try { Copy-Item $l.FullName $dir -Force } catch { Log ('复制失败(锁): ' + $l.Name) }
    }
    $dmps = @(Get-ChildItem C:\Windows\Minidump -Filter *.dmp -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $since })
    if ($dmps.Count -gt 0) { $dmps | ForEach-Object { Copy-Item $_.FullName $dir -Force } }

    $evLines = @()
    try {
        $evLines = @(Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -match 'Kernel-Power|WHEA|BugCheck|EventLog' -and $_.Id -in 41,1001,6008,18,19,1,12,13 } |
            ForEach-Object { '{0} | {1} | ID={2}' -f $_.TimeCreated, $_.ProviderName, $_.Id })
    } catch {}
    if ($evLines.Count -gt 0) { $evLines | Set-Content (Join-Path $dir 'events.txt') -Encoding UTF8 }
    if (Test-Path $ProgF) { Copy-Item $ProgF $dir -Force }

    $lastHb = ''
    $newest = $logs | Select-Object -Last 1
    if ($newest) {
        $tail = Read-TailText $newest.FullName 30
        if ($tail) { $lastHb = ($tail -split "`n" | Where-Object { $_ -match '\[HB' } | Select-Object -Last 1) }
    }
    $sum = @(
        '==== GNPT 加速测试摘要 ===='
        '备注      : ' + $note
        '开始时间  : ' + $since.ToString('yyyy-MM-dd HH:mm:ss')
        '收集时间  : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        '轮次标签  : ' + $tag
        ('日志文件  : {0} 个' -f $logs.Count)
        ('Minidump  : {0} 个{1}' -f $dmps.Count, $(if ($dmps) { ' ' + ($dmps.Name -join ', ') }))
        ('关键事件  : {0} 条' -f $evLines.Count)
        '最后HB行  : ' + $lastHb
    )
    $sum | Set-Content (Join-Path $dir 'summary.txt') -Encoding UTF8
    Write-Host ''
    Write-Host ('现场已打包: {0}' -f $dir) -ForegroundColor Green
    $sum | ForEach-Object { Write-Host $_ }
    return $dir
}

# ---------- 一轮测试 ----------
function Invoke-Round([string]$roundMode, [int]$minutes) {
    $testStart = Get-Date
    Save-State $testStart $roundMode $false
    Set-Content -Path $ProgF -Value ('==== 加速轮{0} 开始 {1} (预期横幅 {2}) ====' -f $roundMode, $testStart, $ExpectTag) -Encoding UTF8

    $savedDemote  = Get-HexIndexes 'IDLEDEMOTE'
    $savedDisable = Get-HexIndexes 'IDLEDISABLE'
    if ($savedDemote)  { Log ('记录: IDLEDEMOTE 当前 AC={0} DC={1}' -f $savedDemote[0],  $savedDemote[1]) }
    if ($savedDisable) { Log ('记录: IDLEDISABLE 当前 AC={0} DC={1}' -f $savedDisable[0], $savedDisable[1]) }

    $procs = @()
    $roundErr = $null

    try {
        if ($roundMode -eq 'A') {
            Log '电源: IDLEDEMOTE=0 (空闲立即降最深C-state, 放大转换频率)'
            Set-Power -demote 0 -disable -1
        } else {
            Log '电源: IDLEDISABLE=1 (核钉C0, idle竞态对照轮)'
            Set-Power -demote -1 -disable 1
        }

        # 驱动: 干净重启
        if ((Get-Service $SvcName -ErrorAction SilentlyContinue).Status -eq 'Running') {
            Log '驱动已在运行——先停止再重启(干净状态)'
            sc.exe stop $SvcName | Out-Null
            try { (Get-Service $SvcName).WaitForStatus('Stopped', '00:00:30') } catch {}
            Start-Sleep -Seconds 3
        }
        Log ('启动驱动 {0} ...' -f $SvcName)
        sc.exe start $SvcName | Out-Null

        # 就绪门禁: 优先日志版本确认; 日志被锁时以"服务持续运行40s"放行
        # (版本最终在 sc stop 后文件解锁时复核, 不符则本轮标记无效)
        $deadline = (Get-Date).AddSeconds(90)
        $runSecs = 0; $ok = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
            if ((Get-Service $SvcName -ErrorAction SilentlyContinue).Status -ne 'Running') { continue }
            $runSecs += 2
            $f = Get-GnptLogs $testStart | Select-Object -Last 1
            if ($f) {
                $head = Read-HeadText $f.FullName 8
                if ($null -ne $head) {
                    if ($head -match [regex]::Escape($ExpectTag)) { $ok = $true; Log ('驱动OK, 横幅含 {0}' -f $ExpectTag); break }
                    if ($head -match 'GNPT|\[Entry\]') {
                        Dump-Diagnostics
                        throw ('日志版本不符: 期望 {0}, 头部: {1}' -f $ExpectTag, $head.Substring(0, [Math]::Min(120, $head.Length)))
                    }
                }
            }
            if ($runSecs -ge 40) {
                $ok = $true
                Log '警告: 日志不可读(锁定)——以服务运行40s为准放行, 版本将在停止后复核'
                break
            }
        }
        if (-not $ok) { Dump-Diagnostics; throw '驱动启动失败(90s超时, 见诊断)' }

        # 切换器负载
        $toggle = 'while($true){$e=[DateTime]::UtcNow.AddMilliseconds(80);while([DateTime]::UtcNow -lt $e){};Start-Sleep -Milliseconds 250}'
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($toggle))
        for ($i = 0; $i -lt $Togglers; $i++) {
            $procs += Start-Process powershell -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + $enc) -PassThru
        }
        Log ('切换器 x{0} 已启动 (80ms烧核/250ms深idle)' -f $Togglers)

        # 监控循环
        $end = (Get-Date).AddMinutes($minutes)
        $lastUp = $null; $stall = 0
        while ((Get-Date) -lt $end) {
            Start-Sleep -Seconds 60
            $alive = @($procs | Where-Object { -not $_.HasExited }).Count
            $hb = ''
            $f = Get-GnptLogs $testStart | Select-Object -Last 1
            if ($f) {
                $tail = Read-TailText $f.FullName 10
                if ($tail) { $hb = ($tail -split "`n" | Where-Object { $_ -match '\[HB' } | Select-Object -Last 1) }
            }
            $up = if ($hb -match 'up=(\d+)s') { [int]$Matches[1] } else { $null }
            Log ('剩余{0,3}分钟 | 切换器{1}/{2} | {3}' -f [int](($end - (Get-Date)).TotalMinutes), $alive, $Togglers, $hb)
            if ($null -ne $up) {
                if ($null -ne $lastUp -and $up -eq $lastUp) {
                    $stall++
                    Log ('警告: HB up值连续{0}分钟未增长——引擎疑似楔死(系统仍活)' -f $stall)
                } else { $stall = 0 }
                $lastUp = $up
            }
        }
        Log ('定时窗口 {0} 分钟走完, 系统存活' -f $minutes)
    }
    catch {
        $roundErr = $_.Exception.Message
        Log ('异常: ' + $roundErr)
        throw
    }
    finally {
        Log '清理: 停切换器...'
        $procs | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {} }
        Log '清理: 停驱动...'
        if ((Get-Service $SvcName -ErrorAction SilentlyContinue).Status -eq 'Running') {
            sc.exe stop $SvcName | Out-Null
            try { (Get-Service $SvcName).WaitForStatus('Stopped', '00:00:30') } catch {}
            Start-Sleep -Seconds 5
        }
        Log '清理: 还原电源设置...'
        if ($savedDemote)  { Set-Power -demote $savedDemote[0]  -disable -1 }
        if ($savedDisable) { Set-Power -demote -1 -disable $savedDisable[0] }
        powercfg /setactive SCHEME_CURRENT | Out-Null
        Save-State $testStart $roundMode $true

        # 版本复核(文件已解锁)
        $verBad = $false
        $newest = Get-GnptLogs $testStart | Select-Object -Last 1
        if ($newest) {
            $h = Read-HeadText $newest.FullName 8
            if ($null -ne $h -and $h -notmatch [regex]::Escape($ExpectTag)) { $verBad = $true }
        }
        $tag = if ($verBad) { 'WRONGVER_' + $roundMode }
               elseif ($roundErr) { 'ERR_' + $roundMode }
               else { 'OK_' + $roundMode }
        $note = if ($verBad) { '!!版本不符(期望{0})——本轮数据无效' -f $ExpectTag }
                elseif ($roundErr) { ('轮次{0}异常终止: {1}' -f $roundMode, $roundErr) }
                else { ('轮次{0}定时完成, 系统存活' -f $roundMode) }
        Collect-Artifacts $testStart $tag $note | Out-Null
    }
}

# ---------- 主流程 ----------
$prin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '必须以管理员身份运行'
}

if (Test-Path $StateF) {
    $prev = $null
    try { $prev = Get-Content $StateF -Raw | ConvertFrom-Json } catch {}
    if ($prev -and -not $prev.Completed) {
        Write-Host '检测到上轮测试未完成(崩溃或中断) —— 收集现场...' -ForegroundColor Yellow
        Collect-Artifacts ([datetime]$prev.TestStart) ('CRASH_' + $prev.Mode) ('上轮{0}未完成 = 崩溃或中断' -f $prev.Mode) | Out-Null
        Remove-Item $StateF -Force
        Write-Host '现场收集完毕: 打包 Desktop 下 gnpt_accel_CRASH_* 文件夹上传; 再次运行本脚本开始新测试。'
        return
    }
    Remove-Item $StateF -Force
}

if (-not (Get-Service $SvcName -ErrorAction SilentlyContinue)) {
    throw ('服务 {0} 不存在——请先部署驱动' -f $SvcName)
}

if ($Mode -eq 'Full') {
    Invoke-Round 'A' $Minutes
    Start-Sleep -Seconds 10
    Invoke-Round 'C' $Minutes
} else {
    Invoke-Round $Mode $Minutes
}

Write-Host ''
Write-Host '全部完成。产物在 Desktop\gnpt_accel_* 文件夹, 打包上传即可。' -ForegroundColor Green
