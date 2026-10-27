[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.json'),
    [string]$RegisterPath = (Join-Path $PSScriptRoot 'Perception-Threat-Protection-Register.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Perception-Threat-Protection.html'),
    [string]$JsonOutputPath = (Join-Path $PSScriptRoot 'Perception-Threat-Protection.json'),
    [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow,
    [switch]$RegisterView,
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionThreatProtection.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionSnapshotInsights.ps1')

$inputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
$registerFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RegisterPath)
$htmlFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$jsonFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JsonOutputPath)
if (@($inputFile, $registerFile, $htmlFile, $jsonFile | Sort-Object -Unique).Count -ne 4) {
    throw 'Input, register, HTML and JSON output paths must all be different.'
}
if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
    throw "Session snapshot not found: $inputFile. Generate it with Show-PerceptionLiveEnvironment.ps1 first."
}
$snapshot = [IO.File]::ReadAllText($inputFile) | ConvertFrom-Json -Depth 50 -ErrorAction Stop
$insights = Get-PerceptionSnapshotInsights -Snapshot $snapshot -AsOf $AsOf
if ($RegisterView) {
    if (-not (Test-Path -LiteralPath $registerFile -PathType Leaf)) {
        $register = [pscustomobject]@{ schemaVersion = 1; threats = @() }
        [IO.File]::WriteAllText($registerFile, ($register | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        Write-Warning "Created an empty protection register at '$registerFile'. No threat relevance or protection is inferred from session activity."
    }
    else {
        $register = [IO.File]::ReadAllText($registerFile) | ConvertFrom-Json -Depth 50 -ErrorAction Stop
    }
    $report = Get-PerceptionThreatProtection -Snapshot $snapshot -Register $register -AsOf $AsOf
    $report | Add-Member sourceSnapshot $inputFile
    $report | Add-Member registerPath $registerFile
}
else {
    $register = $null
    $report = [pscustomobject]@{ schemaVersion = 1; generatedAt = $AsOf.ToString('o'); sourceSnapshot = $inputFile }
}
$report | Add-Member snapshotInsights $insights
$payload = [pscustomobject]@{ report = $report; register = $register; experience = 'briefing' } | ConvertTo-Json -Depth 50 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$templateName = if ($RegisterView) { 'Threat-Protection.template.html' } else { 'Snapshot-Insights.template.html' }
$marker = if ($RegisterView) { '__PROTECTION_PAYLOAD__' } else { '__SNAPSHOT_PAYLOAD__' }
$html = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $templateName)).Replace($marker, $encoded)
. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$html = Set-PerceptionReportPresentation -Html $html
foreach ($file in @($htmlFile, $jsonFile)) {
    $directory = [IO.Path]::GetDirectoryName($file)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Output directory does not exist: $directory" }
}
[IO.File]::WriteAllText($jsonFile, ($report | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($htmlFile, $html, [Text.UTF8Encoding]::new($false))
Write-Host "Report: $htmlFile"
Write-Host "Operational Briefing: $($insights.sessionCount) sessions, $($insights.groups.Count) workflow/input groups, $($insights.reportCount) collected intelligence reports."
if (-not $NoOpen) { Start-Process $htmlFile }
$result = [pscustomobject]@{
    HtmlPath = $htmlFile; JsonPath = $jsonFile
    SessionCount = $insights.sessionCount; ReportCount = $insights.reportCount; CampaignCount = $insights.campaigns.Count
}
if ($RegisterView) {
    $result | Add-Member RegisterPath $registerFile
    $result | Add-Member ThreatCount $report.threatCount
    $result | Add-Member Summary $report.summary
}
$result
