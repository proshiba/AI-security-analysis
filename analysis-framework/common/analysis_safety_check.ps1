[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "end")]
    [string]$Phase,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Pattern
)

# Read-only host safety gate for malware-analysis work. The script intentionally
# supports stdout only: do not redirect its output into the repository.
$ErrorActionPreference = "SilentlyContinue"
$escaped = @($Pattern | Where-Object { $_ } | ForEach-Object { [regex]::Escape($_) })
$matcher = if ($escaped.Count) { $escaped -join "|" } else { "(?!)" }

$processes = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessId -ne $PID -and
            (([string]$_.ExecutablePath -match $matcher) -or ([string]$_.CommandLine -match $matcher))
        } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
)

$services = @(
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            ([string]$_.Name -match $matcher) -or
            ([string]$_.DisplayName -match $matcher) -or
            ([string]$_.PathName -match $matcher)
        } |
        Select-Object Name, DisplayName, State, StartMode, PathName
)

$tasks = @(
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $task = $_
            ([string]$task.TaskName -match $matcher) -or
            (@($task.Actions | ForEach-Object { "$(($_.Execute)) $(($_.Arguments)) $(($_.WorkingDirectory))" }) -join " " -match $matcher)
        } |
        Select-Object TaskPath, TaskName, State
)

$runKeys = [System.Collections.Generic.List[object]]::new()
@(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
) | ForEach-Object {
    $path = $_
    $item = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
    if ($null -ne $item) {
        $item.PSObject.Properties |
            Where-Object {
                $_.Name -notmatch "^PS" -and
                (([string]$_.Name -match $matcher) -or ([string]$_.Value -match $matcher))
            } |
            ForEach-Object {
                $runKeys.Add([pscustomobject]@{ Path = $path; Name = $_.Name; Value = [string]$_.Value })
            }
    }
}

$matchedPids = @($processes | ForEach-Object { [int]$_.ProcessId })
$connections = @(
    if ($matchedPids.Count) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $matchedPids -contains $_.OwningProcess } |
            Select-Object OwningProcess, State, LocalAddress, LocalPort, RemoteAddress, RemotePort
    }
)

$defenderThreats = @()
if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
    $defenderThreats = @(
        Get-MpThreat -ErrorAction SilentlyContinue |
            Where-Object { $_.IsActive -eq $true } |
            Select-Object ThreatID, ThreatName, SeverityID, CategoryID, IsActive
    )
}

$evidenceCount = @($processes).Count + @($services).Count + @($tasks).Count +
    $runKeys.Count + @($connections).Count + @($defenderThreats).Count
$result = [ordered]@{
    schema_version = 1
    phase = $Phase
    checked_at_utc = [DateTime]::UtcNow.ToString("o")
    patterns = @($Pattern)
    clean = ($evidenceCount -eq 0)
    evidence_count = $evidenceCount
    processes = @($processes)
    services = @($services)
    scheduled_tasks = @($tasks)
    run_keys = @($runKeys)
    tcp_connections = @($connections)
    active_defender_threats = @($defenderThreats)
    retention = "stdout_only_do_not_commit"
}

$result | ConvertTo-Json -Depth 7
if ($evidenceCount -gt 0) { exit 2 }
