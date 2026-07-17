[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Sample,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $ProfilePath,
    [string] $NetworkEvidence,
    [string] $MalwareType,
    [string] $VirusTotalApiKey = $env:VT_API_KEY,
    [switch] $AllowLiveC2Check,
    [switch] $CollectJarm,
    [string] $Python = 'C:\Users\Administrator\Tools\GhidraMCP\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$classification = Join-Path $OutputDirectory 'classification.json'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments)] [string[]] $Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python failed: $($Arguments -join ' ')" }
}

$classifyArgs = @(
    (Join-Path $root 'classifiers\classify_sample.py'),
    '--sample', $Sample,
    '--registry', (Join-Path $root 'registry\malware_types.json'),
    '--output', $classification
)
if ($MalwareType) { $classifyArgs += @('--malware-type', $MalwareType) }
Invoke-Python @classifyArgs

$selected = Get-Content -Raw -Encoding UTF8 $classification | ConvertFrom-Json
$vtSandboxEvidence = $null
if ($VirusTotalApiKey) {
    $vtSandboxEvidence = Join-Path $OutputDirectory 'virustotal-sandbox.json'
    $sampleHash = $selected.observations.sha256
    Invoke-Python (Join-Path $root 'common\vt_sandbox.py') '--sha256' $sampleHash '--api-key' $VirusTotalApiKey '--output' $vtSandboxEvidence
}

if ($selected.malware_type -ne 'valleyrat') {
    throw "No malware handler is registered for: $($selected.malware_type)"
}
if ($ProfilePath) {
    $validateArgs = @(
        (Join-Path $root 'malware\valleyrat\common\validate_profile.py'),
        '--sample', $Sample, '--profile', $ProfilePath
    )
    Invoke-Python @validateArgs
}

switch ($selected.campaign_type) {
    'dll_sideload_vvas_bundle' {
        if (-not $ProfilePath) { throw 'This handler requires -ProfilePath.' }
        $caseProfile = Get-Content -Raw -Encoding UTF8 $ProfilePath | ConvertFrom-Json
        if (-not $caseProfile.vvas) { throw 'Profile has no vvas configuration.' }
        $payload = Join-Path $OutputDirectory 'payload'
        Invoke-Python (Join-Path $root 'common\safe_extract_zip.py') '--archive' $Sample '--output' $payload
        $plain = Join-Path $OutputDirectory 'decrypted\vvaS.xor.bin'
        $decryptArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\dll_sideload_vvas_bundle\decrypt_vvas.py'),
            (Join-Path $payload $caseProfile.vvas.input), $plain, '--key', ([string]$caseProfile.vvas.xor_key),
            '--expected-sha256', $caseProfile.vvas.expected_plain_sha256
        )
        Invoke-Python @decryptArgs
        $decodeArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\dll_sideload_vvas_bundle\analyze_vvas.py'),
            $plain, '--output-dir', (Join-Path $OutputDirectory 'decoded-analysis'), '--marker', $caseProfile.vvas.marker
        )
        Invoke-Python @decodeArgs
    }
    'msi_embedded_cab_custom_actions' {
        $msiMember = $selected.candidates[0].msi_member
        if (-not $msiMember) { throw 'Classifier did not return the MSI member.' }
        $msiArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\msi_embedded_cab_custom_actions\analyze_msi.py'),
            '--inner-zip', $Sample, '--member', $msiMember, '--output', (Join-Path $OutputDirectory 'msi-analysis.json')
        )
        Invoke-Python @msiArgs
        $chainArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\msi_embedded_cab_custom_actions\analyze_chain_c2.py'),
            '--inner-zip', $Sample, '--msi-member', $msiMember,
            '--output', (Join-Path $OutputDirectory 'msi-chain-c2-analysis.json')
        )
        if ($NetworkEvidence) { $chainArgs += @('--network-evidence', $NetworkEvidence) }
        Invoke-Python @chainArgs
    }
    default { throw "No campaign handler is registered for: $($selected.campaign_type)" }
}

$liveResults = @()
if ($AllowLiveC2Check) {
    if (-not $ProfilePath) { throw '-AllowLiveC2Check requires a reviewed -ProfilePath with live_c2_targets.' }
    if (-not $caseProfile) { $caseProfile = Get-Content -Raw -Encoding UTF8 $ProfilePath | ConvertFrom-Json }
    $targets = @($caseProfile.live_c2_targets)
    if ($targets.Count -eq 0) { throw 'Profile contains no reviewed live_c2_targets.' }
    $liveDirectory = Join-Path $OutputDirectory 'c2-live'
    New-Item -ItemType Directory -Force -Path $liveDirectory | Out-Null
    for ($index = 0; $index -lt $targets.Count; $index++) {
        $target = $targets[$index]
        $liveOutput = Join-Path $liveDirectory ("{0:D2}-{1}-{2}.json" -f ($index + 1), $target.host, $target.port)
        $liveArgs = @(
            (Join-Path $root 'common\c2_detector.py'), $target.host, ([string]$target.port),
            '--protocol', $target.protocol, '--timeout', '8', '--allow-network', '--output', $liveOutput
        )
        if ($target.send_hex) { $liveArgs += @('--send-hex', $target.send_hex) }
        if ($target.expected_stage_size) { $liveArgs += @('--expected-stage-size', ([string]$target.expected_stage_size)) }
        if ($target.http_host) { $liveArgs += @('--http-host', $target.http_host) }
        if ($target.sni) { $liveArgs += @('--sni', $target.sni) }
        if ($CollectJarm -and $target.protocol -in @('https','tls','n520')) { $liveArgs += '--collect-jarm' }
        & $Python @liveArgs
        $probeExit = $LASTEXITCODE
        if ($probeExit -notin @(0,1)) { throw "C2 probe failed unexpectedly: $liveOutput" }
        $liveResults += Get-Content -Raw -Encoding UTF8 $liveOutput | ConvertFrom-Json
    }
}

[ordered]@{
    malware_type = $selected.malware_type
    campaign_type = $selected.campaign_type
    output_directory = $OutputDirectory
    executed = $false
    network_contacted = [bool]($AllowLiveC2Check -or $VirusTotalApiKey)
    vt_sandbox_evidence = $vtSandboxEvidence
    live_c2_results = $liveResults
} | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory 'run-summary.json')

Write-Host "Analysis completed without sample execution: $OutputDirectory" -ForegroundColor Green

