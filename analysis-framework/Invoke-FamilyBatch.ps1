[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('agenttesla','remcosrat')][string]$Family,
    [Parameter(Mandatory)][string]$SampleRoot,
    [string]$Python = 'python',
    [string]$Password = 'infected'
)

$ErrorActionPreference = 'Stop'
$framework = $PSScriptRoot
$registry = Join-Path $framework 'registry\malware_types.json'
$tools = @{
    Triage = Join-Path $framework 'common\analyze_family_sample.py'
    Layers = Join-Path $framework 'common\analyze_script_layers.py'
    Logic = Join-Path $framework 'common\extract_script_logic.py'
    Encoded = Join-Path $framework 'common\extract_encoded_text.py'
    Marker = Join-Path $framework 'common\strip_unicode_marker.py'
    VbsTrace = Join-Path $framework 'common\trace_vbs_variables.py'
    Iso = Join-Path $framework 'common\analyze_iso9660.py'
    AgentTeslaRecover = Join-Path $framework 'malware\agenttesla\agenttesla_recover.py'
    Classifier = Join-Path $framework 'classifiers\classify_sample.py'
}

function Invoke-PythonStage {
    param([string]$Name, [string[]]$Arguments, [System.Collections.Generic.List[string]]$Completed)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
    $Completed.Add($Name)
}

$cases = Get-ChildItem -LiteralPath $SampleRoot -Directory | Sort-Object Name
$batch = [System.Collections.Generic.List[object]]::new()
foreach ($case in $cases) {
    $hash = $case.Name
    $zip = Join-Path $case.FullName ($hash + '.zip')
    if (-not (Test-Path -LiteralPath $zip)) {
        Write-Warning "Skip ${hash}: expected ZIP not found"
        continue
    }
    $out = Join-Path $case.FullName 'analysis-output'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $completed = [System.Collections.Generic.List[string]]::new()
    Invoke-PythonStage 'triage' @($tools.Triage,'--outer-zip',$zip,'--output-dir',$out,'--password',$Password) $completed
    Invoke-PythonStage 'classification' @($tools.Classifier,'--sample',$zip,'--registry',$registry,'--output',(Join-Path $out 'classification.json')) $completed

    $triage = Get-Content (Join-Path $out 'family-triage.json') -Raw | ConvertFrom-Json
    $classification = Get-Content (Join-Path $out 'classification.json') -Raw | ConvertFrom-Json
    $member = $triage.members | Select-Object -First 1
    $extension = [IO.Path]::GetExtension($member.name).ToLowerInvariant()
    if ($member.type -eq 'script') {
        Invoke-PythonStage 'script-layers' @($tools.Layers,'--outer-zip',$zip,'--output',(Join-Path $out 'script-layers.json'),'--password',$Password) $completed
        Invoke-PythonStage 'script-logic' @($tools.Logic,'--outer-zip',$zip,'--output',(Join-Path $out 'script-logic.json'),'--password',$Password) $completed
        Invoke-PythonStage 'encoded-text' @($tools.Encoded,'--outer-zip',$zip,'--output-dir',(Join-Path $out 'encoded-text'),'--password',$Password) $completed
        if ($extension -in @('.vbs','.vbe')) {
            Invoke-PythonStage 'vbs-variable-trace' @($tools.VbsTrace,'--outer-zip',$zip,'--output',(Join-Path $out 'vbs-variable-trace.json'),'--password',$Password) $completed
        }
        if ($classification.campaign_type -match 'unicode_marker|png_stage') {
            Invoke-PythonStage 'unicode-marker' @($tools.Marker,'--outer-zip',$zip,'--output-dir',(Join-Path $out 'deobfuscated'),'--password',$Password) $completed
        }
    }
    if ($Family -eq 'agenttesla') {
        Invoke-PythonStage 'agenttesla-static-recovery' @($tools.AgentTeslaRecover,'--outer-zip',$zip,'--output-dir',(Join-Path $out 'agenttesla-static-recovery'),'--password',$Password) $completed
    }
    if ($extension -in @('.iso','.img')) {
        Invoke-PythonStage 'iso9660' @($tools.Iso,'--outer-zip',$zip,'--output',(Join-Path $out 'iso9660.json'),'--password',$Password) $completed
    }
    $summary = [ordered]@{
        schema_version = 2
        family = $Family
        sample_sha256 = $hash
        member_sha256 = $member.sha256
        member_type = $member.type
        campaign_type = $classification.campaign_type
        completed_stages = @($completed)
        executed = $false
        network_contacted = $false
    }
    $summaryPath = Join-Path $out 'batch-run-summary.json'
    [IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $batch.Add($summary)
}

Write-Host "Completed $($batch.Count) safe static cases for $Family. No sample was executed and no C2 was contacted."
