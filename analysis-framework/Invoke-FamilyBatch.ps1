[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('agenttesla','remcosrat')][string]$Family,
    [Parameter(Mandatory)][string]$SampleRoot,
    [string]$Python = 'python',
    [string]$Password = 'infected'
)

$ErrorActionPreference = 'Stop'
$framework = Split-Path -Parent $PSScriptRoot
$registry = Join-Path $framework 'registry\malware_types.json'
$analyzer = Join-Path $framework 'common\analyze_family_sample.py'
$layers = Join-Path $framework 'common\analyze_script_layers.py'
$classifier = Join-Path $framework 'classifiers\classify_sample.py'

Get-ChildItem -LiteralPath $SampleRoot -Directory | Sort-Object Name | ForEach-Object {
    $hash = $_.Name
    $zip = Join-Path $_.FullName ($hash + '.zip')
    if (-not (Test-Path -LiteralPath $zip)) {
        Write-Warning "Skip $hash: expected ZIP not found"
        return
    }
    $out = Join-Path $_.FullName 'analysis-output'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    & $Python $analyzer --outer-zip $zip --output-dir $out --password $Password
    if ($LASTEXITCODE -ne 0) { throw "generic analysis failed: $hash" }
    & $Python $classifier --sample $zip --registry $registry --output (Join-Path $out 'classification.json')
    if ($LASTEXITCODE -ne 0) { throw "classification failed: $hash" }

    $triage = Get-Content (Join-Path $out 'family-triage.json') -Raw | ConvertFrom-Json
    $member = $triage.members | Select-Object -First 1
    if ($member.type -eq 'script') {
        & $Python $layers --outer-zip $zip --output (Join-Path $out 'script-layers.json') --password $Password
        if ($LASTEXITCODE -ne 0) { Write-Warning "script-layer analysis needs manual review: $hash" }
    }
}

Write-Host "Completed safe static batch analysis for $Family. No sample was executed and no C2 was contacted."
