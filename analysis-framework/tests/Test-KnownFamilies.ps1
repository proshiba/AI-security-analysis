[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentTeslaRoot,
    [Parameter(Mandatory)][string]$RemcosRoot,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$framework = Split-Path -Parent $PSScriptRoot
$registry = Join-Path $framework 'registry\malware_types.json'
$classifier = Join-Path $framework 'classifiers\classify_sample.py'
$sets = @(
    @{Family='agenttesla'; Root=$AgentTeslaRoot; Count=10},
    @{Family='remcosrat'; Root=$RemcosRoot; Count=10}
)
$tested = 0
foreach ($set in $sets) {
    $dirs = Get-ChildItem -LiteralPath $set.Root -Directory
    if ($dirs.Count -ne $set.Count) { throw "Expected $($set.Count) $($set.Family) cases, got $($dirs.Count)" }
    foreach ($dir in $dirs) {
        $zip = Join-Path $dir.FullName ($dir.Name + '.zip')
        $temp = Join-Path $env:TEMP ($dir.Name + '-classification.json')
        & $Python $classifier --sample $zip --registry $registry --output $temp | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Classifier failed: $($dir.Name)" }
        $result = Get-Content $temp -Raw | ConvertFrom-Json
        if ($result.malware_type -ne $set.Family) { throw "Family mismatch $($dir.Name): $($result.malware_type)" }
        if ($result.campaign_type -eq 'unknown') { throw "Campaign unresolved: $($dir.Name)" }
        if ($result.observations.type_detector.inner_sha256 -ne $dir.Name) { throw "Inner hash mismatch: $($dir.Name)" }
        $tested++
    }
}
Write-Host "PASS: $tested/20 known submissions classified with verified inner SHA-256 and a campaign handler."
