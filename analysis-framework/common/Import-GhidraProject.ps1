[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PayloadDirectory,
    [Parameter(Mandatory)] [string] $ProjectDirectory,
    [Parameter(Mandatory)] [string] $ProjectName,
    [Parameter(Mandatory)] [string[]] $Targets,
    [string] $AnalyzeHeadless = 'C:\Users\Administrator\Tools\Ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $AnalyzeHeadless)) {
    throw "analyzeHeadless.bat not found: $AnalyzeHeadless"
}
New-Item -ItemType Directory -Force -Path $ProjectDirectory | Out-Null
$arguments = @($ProjectDirectory, $ProjectName)
foreach ($target in $Targets) {
    $path = Join-Path $PayloadDirectory $target
    if (-not (Test-Path -LiteralPath $path)) { throw "Ghidra target not found: $path" }
    $arguments += @('-import', $path)
}
$arguments += @('-analysisTimeoutPerFile', '600', '-overwrite')
& $AnalyzeHeadless @arguments
if ($LASTEXITCODE -ne 0) { throw "Ghidra analysis failed with exit code $LASTEXITCODE" }
[pscustomobject]@{
    Project = Join-Path $ProjectDirectory "$ProjectName.gpr"
    Targets = $Targets
    ExecutedSample = $false
} | ConvertTo-Json -Depth 4

