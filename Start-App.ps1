[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,

    [ValidateRange(1, 500)]
    [int]$SessionLimit = 500,

    [ValidateRange(1, 500)]
    [int]$MessagePageSize = 100,

    [ValidateRange(1, 20)]
    [int]$MaximumMessagePagesPerRun = 5,

    [ValidateRange(1024, 10485760)]
    [int]$MaximumMarkdownOutputBytes = 1048576,

    [switch]$Refresh,

    [Alias('RunQuality')][switch]$AssuranceFreshness,

    [Alias('ThreatBriefing')][switch]$ThreatProtection,

    [switch]$OperationalLoops,

    [switch]$SystemicThreatSignals,

    [Alias('AgentBehavior')][switch]$AgentBehaviorAnalysis,

    [switch]$ModelSynthesis,

    [ValidateRange(1, 2147483647)]
    [int]$MaxModelInputCharacters = 180000,

    [switch]$AnalyzeAgentBehavior,

    [switch]$IncludeDefender,

    [switch]$DefenderInvestigations,

    [string]$ConfigurationPath = '',

    [string]$GraphTokenPath = '',

    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (@($AssuranceFreshness, $ThreatProtection, $OperationalLoops, $SystemicThreatSignals, $AgentBehaviorAnalysis, $DefenderInvestigations | Where-Object { $_ }).Count -gt 1) {
    throw 'Choose only one initial report: -AssuranceFreshness, -ThreatProtection, -OperationalLoops, -SystemicThreatSignals, -AgentBehaviorAnalysis or -DefenderInvestigations.'
}

$dashboardPath = Join-Path $PSScriptRoot 'Perception-Live-Environment.html'
$generatorPath = Join-Path $PSScriptRoot 'Show-PerceptionLiveEnvironment.ps1'
$runnerPath = Join-Path $PSScriptRoot 'Start-PerceptionLiveEnvironment.ps1'

if ($Refresh) {
    Write-Host 'Generating a fresh dashboard from the signed-in Production environment...'
    & $generatorPath `
        -OutputPath $dashboardPath `
        -SessionLimit $SessionLimit `
        -MessagePageSize $MessagePageSize `
        -MaximumMessagePagesPerRun $MaximumMessagePagesPerRun `
        -MaximumMarkdownOutputBytes $MaximumMarkdownOutputBytes `
        -ConfigurationPath $ConfigurationPath `
        -NoOpen
}
else {
    Write-Host 'Opening the unified workspace. Run with -Refresh to explicitly collect current API data.'
}

$snapshotAvailable = Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Perception-Live-Environment.json') -PathType Leaf
if (-not $snapshotAvailable -and ($ModelSynthesis -or $AnalyzeAgentBehavior)) {
    throw 'No saved snapshot exists. Sign in with Azure CLI and run Start-App.ps1 -Refresh before requesting model analysis.'
}
if ($snapshotAvailable) {
    & (Join-Path $PSScriptRoot 'New-PerceptionAssuranceFreshnessReport.ps1') -NoOpen | Out-Null
    & (Join-Path $PSScriptRoot 'New-PerceptionThreatProtectionReport.ps1') -NoOpen | Out-Null
    & (Join-Path $PSScriptRoot 'New-PerceptionOperationalLoopsReport.ps1') -NoOpen | Out-Null
}
if ($snapshotAvailable -and ($ModelSynthesis -or $Refresh -or -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Perception-Systemic-Threat-Signals.html') -PathType Leaf))) {
    if ($Refresh -and -not $ModelSynthesis) { Write-Warning 'Refreshing systemic signals without model synthesis. Add -ModelSynthesis for a new configured-model assessment.' }
    & (Join-Path $PSScriptRoot 'New-PerceptionSystemicThreatReport.ps1') -UseModel:$ModelSynthesis -MaxModelInputCharacters $MaxModelInputCharacters -ConfigurationPath $ConfigurationPath -NoOpen | Out-Null
}
if ($AnalyzeAgentBehavior) {
    & (Join-Path $PSScriptRoot 'New-PerceptionAgentBehaviorReport.ps1') -ConfigurationPath $ConfigurationPath -NoOpen | Out-Null
}
if ($IncludeDefender) {
    & (Join-Path $PSScriptRoot 'New-PerceptionDefenderInvestigationReport.ps1') -ConfigurationPath $ConfigurationPath -GraphTokenPath $GraphTokenPath -NoOpen | Out-Null
}
elseif ($GraphTokenPath) {
    throw 'GraphTokenPath is a last-resort override for -IncludeDefender only. It is never selected automatically.'
}

& $runnerPath `
    -Port $Port `
    -DashboardPath $dashboardPath `
    -AssuranceFreshness:$AssuranceFreshness `
    -ThreatProtection:$ThreatProtection `
    -OperationalLoops:$OperationalLoops `
    -SystemicThreatSignals:$SystemicThreatSignals `
    -AgentBehaviorAnalysis:$AgentBehaviorAnalysis `
    -DefenderInvestigations:$DefenderInvestigations `
    -ConfigurationPath $ConfigurationPath `
    -NoOpen:$NoOpen
