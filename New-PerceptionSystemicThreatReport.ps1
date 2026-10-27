[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Perception-Systemic-Threat-Signals.html'),
    [string]$JsonOutputPath = (Join-Path $PSScriptRoot 'Perception-Systemic-Threat-Signals.json'),
    [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow,
    [switch]$UseModel,
    [string]$CouncilRoot = '',
    [string]$ConfigurationPath = '',
    [ValidateRange(1, 2147483647)][int]$MaxModelInputCharacters = 180000,
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionSnapshotInsights.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionSystemicSignals.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')
$configuration = Get-PerceptionConfiguration -Path $ConfigurationPath

$inputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
$htmlFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$jsonFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JsonOutputPath)
if (@($inputFile, $htmlFile, $jsonFile | Sort-Object -Unique).Count -ne 3) {
    throw 'Input, HTML and JSON output paths must all be different.'
}
if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
    throw "Session snapshot not found: $inputFile. Generate it with Show-PerceptionLiveEnvironment.ps1 first."
}
foreach ($file in @($htmlFile, $jsonFile)) {
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($file)) -PathType Container)) {
        throw "Output directory does not exist: $([IO.Path]::GetDirectoryName($file))"
    }
}
$snapshot = [IO.File]::ReadAllText($inputFile) | ConvertFrom-Json -Depth 50 -ErrorAction Stop
$insights = Get-PerceptionSnapshotInsights -Snapshot $snapshot -AsOf $AsOf
$signals = Get-PerceptionSystemicSignals -Insights $insights
$modelSynthesis = [pscustomobject]@{ status = 'not-requested' }
if ($UseModel) {
    $node = (Get-Command node -CommandType Application -ErrorAction Stop).Source
    $temporaryInput = Join-Path ([IO.Path]::GetTempPath()) "perception-systemic-$([Guid]::NewGuid()).input.json"
    $temporaryOutput = Join-Path ([IO.Path]::GetTempPath()) "perception-systemic-$([Guid]::NewGuid()).output.json"
    $previousToken = [Environment]::GetEnvironmentVariable('PERCEPTION_MODEL_ACCESS_TOKEN', 'Process')
    try {
        $legacyRoot = if ($CouncilRoot) { $CouncilRoot } else { '-' }
        if (-not $CouncilRoot) {
            if (-not $configuration.model.endpoint -or -not $configuration.model.deployment) {
                throw 'Configure your Azure model endpoint and deployment in perception.config.json before using -UseModel. CouncilRoot is an explicit legacy option, not a dependency.'
            }
            $tenant = if ($configuration.model.tenantId) { $configuration.model.tenantId } else { $configuration.tenantId }
            $env:PERCEPTION_MODEL_ACCESS_TOKEN = Get-PerceptionCliToken -Resource $configuration.model.tokenResource -TenantId $tenant
        }
        $requestInput = [pscustomobject]@{ insights = $insights; modelConfiguration = $configuration.model }
        [IO.File]::WriteAllText($temporaryInput, ($requestInput | ConvertTo-Json -Depth 50 -Compress), [Text.UTF8Encoding]::new($false))
        & $node (Join-Path $PSScriptRoot 'Invoke-PerceptionSystemicSynthesis.cjs') $legacyRoot $temporaryInput $temporaryOutput $MaxModelInputCharacters
        if ($LASTEXITCODE -ne 0) { throw 'Model synthesis failed. No new report was written; review the explicit model error above.' }
        $modelSynthesis = [IO.File]::ReadAllText($temporaryOutput) | ConvertFrom-Json -Depth 50 -ErrorAction Stop
    }
    finally {
        [Environment]::SetEnvironmentVariable('PERCEPTION_MODEL_ACCESS_TOKEN', $previousToken, 'Process')
        foreach ($temporaryFile in @($temporaryInput, $temporaryOutput)) {
            if (Test-Path -LiteralPath $temporaryFile -PathType Leaf) { Remove-Item -LiteralPath $temporaryFile -ErrorAction Stop }
        }
    }
}
$signals | Add-Member modelSynthesis $modelSynthesis
$report = [pscustomobject]@{
    schemaVersion = 1; generatedAt = $AsOf.ToString('o'); sourceSnapshot = $inputFile
    snapshotInsights = $insights; systemicSignals = $signals
}
$payload = [pscustomobject]@{ report = $report; experience = 'systemic' } | ConvertTo-Json -Depth 50 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$html = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Snapshot-Insights.template.html')).Replace('__SNAPSHOT_PAYLOAD__', $encoded)
. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$html = Set-PerceptionReportPresentation -Html $html
[IO.File]::WriteAllText($jsonFile, ($report | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($htmlFile, $html, [Text.UTF8Encoding]::new($false))
Write-Host "Report: $htmlFile"
$modelHypothesisCount = if ($modelSynthesis.status -eq 'completed') { @($modelSynthesis.hypotheses).Count } else { 0 }
Write-Host "Systemic Threat Signals: $($signals.correlations.Count) correlations; $($signals.hypotheses.Count) rule hypotheses; $modelHypothesisCount model hypotheses (all unverified)."
[pscustomobject]@{
    HtmlPath = $htmlFile; JsonPath = $jsonFile; SessionCount = $insights.sessionCount
    CorrelationCount = $signals.correlations.Count; HypothesisCount = $signals.hypotheses.Count + $modelHypothesisCount
    RuleHypothesisCount = $signals.hypotheses.Count; ModelHypothesisCount = $modelHypothesisCount
}
if (-not $NoOpen) { Start-Process $htmlFile }
