[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Perception-Operational-Loops.html'),
    [string]$JsonOutputPath = (Join-Path $PSScriptRoot 'Perception-Operational-Loops.json'),
    [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow,
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionOperationalLoops.ps1')
. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$inputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
$htmlFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$jsonFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JsonOutputPath)
if (@($inputFile, $htmlFile, $jsonFile | Sort-Object -Unique).Count -ne 3) {
    throw 'Input, HTML and JSON output paths must all be different.'
}
if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) { throw "Session snapshot not found: $inputFile" }
foreach ($file in @($htmlFile, $jsonFile)) {
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($file)) -PathType Container)) {
        throw "Output directory does not exist: $([IO.Path]::GetDirectoryName($file))"
    }
}
$snapshot = [IO.File]::ReadAllText($inputFile) | ConvertFrom-Json -Depth 50 -ErrorAction Stop
$insights = Get-PerceptionSnapshotInsights -Snapshot $snapshot -AsOf $AsOf
$loops = Get-PerceptionOperationalLoops -Snapshot $snapshot -Insights $insights
$report = [pscustomobject]@{
    schemaVersion = 1; generatedAt = $AsOf.ToString('o'); sourceSnapshot = $inputFile
    snapshotInsights = $insights; operationalLoops = $loops
}
$payload = [pscustomobject]@{ report = $report; experience = 'loops' } | ConvertTo-Json -Depth 50 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$html = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Snapshot-Insights.template.html')).Replace('__SNAPSHOT_PAYLOAD__', $encoded)
$html = Set-PerceptionReportPresentation -Html $html
[IO.File]::WriteAllText($jsonFile, ($report | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($htmlFile, $html, [Text.UTF8Encoding]::new($false))
Write-Host "Report: $htmlFile"
Write-Host "Operational Loops: $($loops.counts.groups) evidence groups; $($loops.counts.explicitLoopIds) explicit loop IDs. Outcome metrics are not calculated."
[pscustomobject]@{ HtmlPath = $htmlFile; JsonPath = $jsonFile; GroupCount = $loops.counts.groups; SessionCount = $insights.sessionCount }
if (-not $NoOpen) { Start-Process $htmlFile }
