[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Sample,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [string] $ProfilePath,
    [string] $NetworkEvidence,
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
Invoke-Python @classifyArgs

$selected = Get-Content -Raw -Encoding UTF8 $classification | ConvertFrom-Json
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
        $profile = Get-Content -Raw -Encoding UTF8 $ProfilePath | ConvertFrom-Json
        if (-not $profile.vvas) { throw 'Profile has no vvas configuration.' }
        $payload = Join-Path $OutputDirectory 'payload'
        Invoke-Python (Join-Path $root 'common\safe_extract_zip.py') '--archive' $Sample '--output' $payload
        $plain = Join-Path $OutputDirectory 'decrypted\vvaS.xor.bin'
        $decryptArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\dll_sideload_vvas_bundle\decrypt_vvas.py'),
            (Join-Path $payload $profile.vvas.input), $plain, '--key', ([string]$profile.vvas.xor_key),
            '--expected-sha256', $profile.vvas.expected_plain_sha256
        )
        Invoke-Python @decryptArgs
        $decodeArgs = @(
            (Join-Path $root 'malware\valleyrat\campaigns\dll_sideload_vvas_bundle\analyze_vvas.py'),
            $plain, '--output-dir', (Join-Path $OutputDirectory 'decoded-analysis'), '--marker', $profile.vvas.marker
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

[ordered]@{
    malware_type = $selected.malware_type
    campaign_type = $selected.campaign_type
    output_directory = $OutputDirectory
    executed = $false
    network_contacted = $false
} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory 'run-summary.json')

Write-Host "Analysis completed without sample execution: $OutputDirectory" -ForegroundColor Green



