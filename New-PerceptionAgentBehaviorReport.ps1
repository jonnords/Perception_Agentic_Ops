[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.json'),

    [string]$OutputPath = (Join-Path $PSScriptRoot 'Perception-Agent-Behavior-Analysis.html'),

    [string]$JsonOutputPath = (Join-Path $PSScriptRoot 'Perception-Agent-Behavior-Analysis.json'),

    [string]$AnalysisEndpoint = '',

    [string]$AnalysisModel = '',

    [ValidateSet('AzureFoundryGrok', 'AzureOpenAIResponses')]
    [string]$AnalysisProvider = 'AzureOpenAIResponses',

    [ValidateSet('EntraId', 'ApiKey')]
    [string]$AnalysisAuthentication = 'EntraId',

    [string]$AnalysisApiKeyEnvironmentVariable = '',

    [string]$AnalysisTenantId = '',

    [string]$ConfigurationPath = '',

    [string]$AnalysisSubscriptionId = '',

    [ValidateRange(1, 20)]
    [int]$AnalysisBatchSize = 8,

    [ValidateRange(1000, 20000)]
    [int]$AnalysisEvidenceCharactersPerRun = 6000,

    [ValidateRange(3, 100)]
    [int]$AgentBaselineWindow = 20,

    [ValidateRange(3, 20)]
    [int]$MinimumAgentBaselineRuns = 5,

    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
$configuration = Get-PerceptionConfiguration -Path $ConfigurationPath

function ConvertTo-BehaviorHtmlText {
    param([AllowNull()][object]$Value)

    [Net.WebUtility]::HtmlEncode([string]$Value)
}

$resolvedInputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
if (-not (Test-Path -LiteralPath $resolvedInputPath -PathType Leaf)) {
    $legacyInputPath = Join-Path $PSScriptRoot 'Perception-Live-Environment.html'
    if ([IO.Path]::GetFileName($resolvedInputPath) -eq 'Perception-Live-Environment.json' -and
        (Test-Path -LiteralPath $legacyInputPath -PathType Leaf)) {
        $resolvedInputPath = $legacyInputPath
        Write-Warning 'Reusable session JSON was not found; reading the embedded data from the legacy HTML snapshot.'
    }
    else {
        throw "The live-environment session data was not found: $resolvedInputPath"
    }
}

$analysisScript = Join-Path $PSScriptRoot 'Get-PerceptionAgentBehaviorAnalysis.ps1'
if (-not (Test-Path -LiteralPath $analysisScript -PathType Leaf)) {
    throw "The agent behavior analysis engine was not found: $analysisScript"
}
. $analysisScript

try {
    $sessionJson = if ([IO.Path]::GetExtension($resolvedInputPath) -ieq '.json') {
        [IO.File]::ReadAllText($resolvedInputPath)
    }
    else {
        $snapshotHtml = [IO.File]::ReadAllText($resolvedInputPath)
        $sessionDataMatch = [regex]::Match(
            $snapshotHtml,
            "const encodedSessionData = '([^']+)';",
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $sessionDataMatch.Success) {
            throw "The snapshot does not contain embedded session data: $resolvedInputPath"
        }
        [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($sessionDataMatch.Groups[1].Value)
        )
    }
    $parsedSessionData = $sessionJson | ConvertFrom-Json -Depth 30 -ErrorAction Stop
    $sessionsProperty = $parsedSessionData.PSObject.Properties['sessions']
    $sessions = @(
        if ($null -ne $sessionsProperty) { $sessionsProperty.Value }
        else { $parsedSessionData }
    )
    if ($sessions.Count -gt 0 -and
        $null -eq $sessions[0].PSObject.Properties['runs']) {
        throw 'The JSON root must be the reusable live-environment session array.'
    }
}
catch {
    throw "The live-environment session data is invalid: $($_.Exception.Message)"
}

$resolvedAnalysisEndpoint = if (-not [string]::IsNullOrWhiteSpace($AnalysisEndpoint)) {
    $AnalysisEndpoint
}
elseif ($AnalysisProvider -eq 'AzureFoundryGrok' -and
    -not [string]::IsNullOrWhiteSpace($env:AZURE_GROK_ENDPOINT)) {
    $env:AZURE_GROK_ENDPOINT
}
elseif (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_REPORTING_ENDPOINT)) {
    $env:AZURE_OPENAI_REPORTING_ENDPOINT
}
else {
    $configuration.model.endpoint
}
if ([string]::IsNullOrWhiteSpace($resolvedAnalysisEndpoint)) {
    throw 'Configure your own Azure model endpoint and deployment in perception.config.json, or explicitly supply AnalysisEndpoint and AnalysisModel. No built-in customer or developer resource is used.'
}
Assert-PerceptionModelEndpoint $resolvedAnalysisEndpoint
if (-not $PSBoundParameters.ContainsKey('AnalysisProvider')) {
    $AnalysisProvider = if ($resolvedAnalysisEndpoint.Contains('/chat/completions')) { 'AzureFoundryGrok' } else { 'AzureOpenAIResponses' }
}
if (($AnalysisProvider -eq 'AzureOpenAIResponses') -ne $resolvedAnalysisEndpoint.EndsWith('/responses')) {
    throw 'AnalysisProvider does not match the configured endpoint API format. Choose AzureOpenAIResponses for /responses or AzureFoundryGrok for /chat/completions.'
}
$resolvedAnalysisModel = if (-not [string]::IsNullOrWhiteSpace($AnalysisModel)) {
    $AnalysisModel
}
elseif ($AnalysisProvider -eq 'AzureFoundryGrok' -and
    -not [string]::IsNullOrWhiteSpace($env:AZURE_GROK_MODEL)) {
    $env:AZURE_GROK_MODEL
}
elseif (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_REPORTING_MODEL)) {
    $env:AZURE_OPENAI_REPORTING_MODEL
}
else {
    $configuration.model.deployment
}
if ([string]::IsNullOrWhiteSpace($resolvedAnalysisModel)) { throw 'Configure model.deployment or explicitly supply AnalysisModel.' }
if (-not $AnalysisTenantId) {
    $AnalysisTenantId = if ($configuration.model.tenantId) { $configuration.model.tenantId } else { $configuration.tenantId }
}
$analysisAccessToken = ''
$resolvedKeyEnvironmentVariable = ''
if ($AnalysisAuthentication -eq 'EntraId') {
    $resolvedSubscriptionId = if (-not [string]::IsNullOrWhiteSpace($AnalysisSubscriptionId)) {
        $AnalysisSubscriptionId
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:AZURE_SUBSCRIPTION_ID)) {
        $env:AZURE_SUBSCRIPTION_ID
    }
    else {
        ''
    }

    $analysisAccessToken = Get-PerceptionCliToken -Resource $configuration.model.tokenResource `
        -TenantId $AnalysisTenantId -SubscriptionId $resolvedSubscriptionId
}
else {
    $resolvedKeyEnvironmentVariable = if (-not [string]::IsNullOrWhiteSpace(
        $AnalysisApiKeyEnvironmentVariable
    )) {
        $AnalysisApiKeyEnvironmentVariable
    }
    else {
        $keyCandidates = if ($AnalysisProvider -eq 'AzureFoundryGrok') {
            @('AZURE_GROK_API_KEY', 'AZURE_FOUNDRY_API_KEY')
        }
        else {
            @(
                'AZURE_OPENAI_REPORTING_KEY',
                'AZURE_OPENAI_API_KEY2',
                'AZURE_OPENAI_API_KEY'
            )
        }
        $keyCandidates |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_))
            } |
            Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace($resolvedKeyEnvironmentVariable)) {
        throw 'API-key authentication was selected, but no configured key environment variable was found.'
    }
}

$sourceRunCount = @($sessions | ForEach-Object { @($_.runs) }).Count
Write-Host "Analyzing $sourceRunCount agent runs from $resolvedInputPath..."
$analysisSummary = Add-PerceptionAgentBehaviorAnalysis `
    -Sessions $sessions `
    -Provider $AnalysisProvider `
    -Endpoint $resolvedAnalysisEndpoint `
    -Model $resolvedAnalysisModel `
    -ApiKeyEnvironmentVariable $resolvedKeyEnvironmentVariable `
    -AccessToken $analysisAccessToken `
    -BatchSize $AnalysisBatchSize `
    -MaximumEvidenceCharacters $AnalysisEvidenceCharactersPerRun `
    -BaselineWindow $AgentBaselineWindow `
    -MinimumBaselineRuns $MinimumAgentBaselineRuns `
    -SkipDriftExplanations

$reportRuns = @(
    foreach ($session in $sessions) {
        foreach ($run in @($session.runs)) {
            $agentDefinitionName = [string](Get-AnalysisPropertyValue `
                -InputObject $run.agent `
                -Name 'agentDefinitionName')
            $agentDisplayName = [string](Get-AnalysisPropertyValue `
                -InputObject $run.agent `
                -Name 'displayName')
            $agentName = if (-not [string]::IsNullOrWhiteSpace($agentDefinitionName)) {
                $agentDefinitionName
            }
            elseif (-not [string]::IsNullOrWhiteSpace($agentDisplayName)) {
                $agentDisplayName
            }
            else {
                '<unknown>'
            }

            [pscustomobject]@{
                runId = [string]$run.id
                sessionId = [string]$session.id
                sessionDisplayName = [string]$session.displayName
                sessionState = [string]$session.state
                agent = $agentName
                agentDisplayName = $agentDisplayName
                runState = [string]$run.state
                createdAt = [string]$run.createdAt
                durationMs = Get-AnalysisPropertyValue -InputObject $run -Name 'durationMs'
                messageCount = @($run.messages).Count
                messagePagesRead = Get-AnalysisPropertyValue -InputObject $run -Name 'messagePagesRead'
                messagesTruncated = [bool](Get-AnalysisPropertyValue `
                    -InputObject $run `
                    -Name 'messagesTruncated')
                markdownOutputCount = @($session.markdownOutputs).Count
                analysis = $run.analysis
            }
        }
    }
)

$analysisApiKey = if (-not [string]::IsNullOrWhiteSpace($resolvedKeyEnvironmentVariable)) {
    [Environment]::GetEnvironmentVariable($resolvedKeyEnvironmentVariable)
}
else {
    ''
}
$agentThematicProfiles = @(
    Add-AgentConversationThemes `
        -Runs $reportRuns `
        -Provider $AnalysisProvider `
        -Endpoint $resolvedAnalysisEndpoint `
        -Model $resolvedAnalysisModel `
        -ApiKey $analysisApiKey `
        -AccessToken $analysisAccessToken
)
Update-AgentConversationDriftScores `
    -Runs $reportRuns `
    -BaselineWindow $AgentBaselineWindow `
    -MinimumBaselineRuns $MinimumAgentBaselineRuns
Add-ConversationDriftExplanations `
    -Runs $reportRuns `
    -Provider $AnalysisProvider `
    -Endpoint $resolvedAnalysisEndpoint `
    -Model $resolvedAnalysisModel `
    -ApiKey $analysisApiKey `
    -AccessToken $analysisAccessToken `
    -BatchSize $AnalysisBatchSize

$agentSummaries = @(
    foreach ($group in @($reportRuns | Group-Object agent | Sort-Object Name)) {
        $runs = @($group.Group)
        $scoredRuns = @($runs | Where-Object { $null -ne $_.analysis.driftScore })
        $flaggedRuns = @(
            $runs |
                Where-Object { $_.analysis.driftStatus -in @('review', 'high-deviation') }
        )
        $averageScore = if ($scoredRuns.Count -gt 0) {
            [Math]::Round(
                ($scoredRuns.analysis.driftScore | Measure-Object -Average).Average,
                1
            )
        }
        else {
            $null
        }
        $topThemes = @(
            $runs.analysis.topicTheme |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Group-Object |
                Sort-Object Count -Descending |
                Select-Object -First 3 |
                ForEach-Object {
                    [pscustomobject]@{ theme = $_.Name; count = $_.Count }
                }
        )

        [pscustomobject]@{
            agent = $group.Name
            runCount = $runs.Count
            scoredRunCount = $scoredRuns.Count
            flaggedRunCount = $flaggedRuns.Count
            highDeviationRunCount = @(
                $runs |
                    Where-Object { $_.analysis.driftStatus -eq 'high-deviation' }
            ).Count
            incompleteRunCount = @($runs | Where-Object messagesTruncated).Count
            averageDriftScore = $averageScore
            topThemes = $topThemes
            thematicProfile = @(
                $agentThematicProfiles |
                    Where-Object { $_.agent -eq $group.Name }
            )[0]
        }
    }
)
$finalFlaggedRunCount = @(
    $reportRuns |
        Where-Object { $_.analysis.driftStatus -in @('review', 'high-deviation') }
).Count

$generatedAt = [DateTimeOffset]::Now
$report = [ordered]@{
    generatedAt = $generatedAt.ToString('o')
    sourceSnapshot = $resolvedInputPath
    provider = $analysisSummary.Provider
    model = $analysisSummary.Model
    baselineWindow = $analysisSummary.BaselineWindow
    minimumBaselineRuns = $analysisSummary.MinimumBaselineRuns
    artifactAttribution = $analysisSummary.ArtifactAttribution
    sessionCount = $sessions.Count
    runCount = $reportRuns.Count
    flaggedRunCount = $finalFlaggedRunCount
    incompleteRunCount = @($reportRuns | Where-Object messagesTruncated).Count
    agents = $agentSummaries
    runs = $reportRuns
}
$reportJson = $report | ConvertTo-Json -Depth 30
$reportJsonBytes = [Text.Encoding]::UTF8.GetBytes($reportJson)
$reportDataBase64 = [Convert]::ToBase64String($reportJsonBytes)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Perception Agent Behavior Analysis</title>
<style>
  .report-nav { display: flex; flex-wrap: wrap; gap: 10px 20px; padding: 16px 24px; background: #fff; border-bottom: 1px solid #d8e0e9; }
  .report-nav a { color: #123b66; text-decoration: none; }
  .report-nav a:hover { text-decoration: underline; }
  .report-nav a[aria-current="page"] { font-weight: 700; }
  :root {
    color-scheme: light;
    --ink: #172033;
    --muted: #617086;
    --navy: #123b66;
    --blue: #2b78c5;
    --line: #d8e0e9;
    --panel: #fff;
    --canvas: #f3f6f9;
    --good: #237a43;
    --watch: #a86608;
    --bad: #ad3434;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--canvas); color: var(--ink); font-family: Aptos, "Segoe UI", Arial, sans-serif; }
  header { padding: 30px clamp(20px, 5vw, 70px); background: linear-gradient(130deg, #071f38, #0d4f80 70%, #1472aa); color: white; }
  header div, main { max-width: 1380px; margin: 0 auto; }
  h1 { margin: 0; font-size: clamp(29px, 4vw, 44px); }
  header p { max-width: 850px; margin: 10px 0 0; color: #dbeeff; }
  main { padding: 25px 22px 40px; }
  .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 13px; }
  .card, section { border: 1px solid var(--line); border-radius: 13px; background: var(--panel); box-shadow: 0 9px 26px rgba(20,45,70,.07); }
  .card { padding: 18px; }
  .card span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
  .card strong { display: block; margin-top: 4px; color: var(--navy); font-size: 29px; }
  section { margin-top: 19px; padding: 22px; }
  h2 { margin: 0 0 6px; color: var(--navy); }
  .intro, .muted { color: var(--muted); }
  .controls { display: flex; flex-wrap: wrap; gap: 9px; margin: 16px 0; }
  input, select { min-height: 40px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 7px; background: white; color: var(--ink); }
  input { flex: 1 1 300px; }
  select { flex: 0 1 220px; }
  code { color: #712b68; overflow-wrap: anywhere; }
  .advisory { margin-top: 19px; padding: 13px 16px; border: 1px solid #e2c679; border-radius: 9px; background: #fffaf0; color: #66531d; }
  .sankey-wrap { margin-top: 15px; overflow-x: auto; border: 1px solid var(--line); border-radius: 9px; background: #fbfdff; }
  .sankey { display: block; width: 100%; min-width: 1100px; height: auto; }
  .sankey .column-label { fill: var(--muted); font-size: 11px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
  .sankey .node-label { fill: var(--ink); font-size: 10px; }
  .sankey .node-label.strong { font-size: 11px; font-weight: 750; }
  .sankey .flow { fill: none; stroke-opacity: .27; transition: stroke-opacity .15s ease; cursor: pointer; }
  .sankey .flow.outlier { stroke-opacity: .58; }
  .sankey .flow:hover, .sankey .flow:focus { stroke-opacity: .9; outline: none; }
  .sankey .node { stroke: #fff; stroke-width: 1; rx: 3px; }
  .sankey-legend { display: flex; flex-wrap: wrap; gap: 13px; margin-top: 10px; color: var(--muted); font-size: 11px; }
  .legend-item { display: inline-flex; align-items: center; gap: 5px; }
  .legend-dot { width: 9px; height: 9px; border-radius: 50%; }
  .agent-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-top: 16px; }
  .agent-card { min-width: 0; border: 1px solid var(--line); border-radius: 11px; background: #fff; box-shadow: 0 4px 14px rgba(20,45,70,.08); overflow: hidden; }
  .agent-head { display: flex; justify-content: space-between; gap: 12px; padding: 15px 16px 12px; border-bottom: 1px solid var(--line); }
  .agent-head h3 { margin: 0; color: var(--ink); font-size: 16px; overflow-wrap: anywhere; }
  .agent-id { color: var(--muted); font: 11px Consolas, monospace; text-align: right; overflow-wrap: anywhere; }
  .agent-body { padding: 14px 16px 16px; }
  .agent-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; }
  .agent-stat { padding: 9px; border: 1px solid var(--line); border-radius: 6px; background: #f8fafc; }
  .agent-stat strong { display: block; color: var(--ink); font-size: 18px; }
  .agent-stat span { color: var(--muted); font-size: 9px; font-weight: 700; text-transform: uppercase; }
  .score-row { display: flex; justify-content: space-between; gap: 12px; margin-top: 12px; color: var(--muted); font-size: 11px; }
  .score-track { height: 6px; margin-top: 6px; border-radius: 999px; background: #e5e9ef; overflow: hidden; }
  .score-fill { height: 100%; background: linear-gradient(90deg, var(--good), #e5c263 65%, var(--bad)); }
  .label { margin-top: 14px; color: var(--muted); font-size: 10px; font-weight: 800; text-transform: uppercase; }
  .chips { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
  .chip { padding: 3px 7px; border: 1px solid #9fc8f2; border-radius: 999px; color: #236aaf; background: #f7fbff; font-size: 10px; }
  .chip.flag { border-color: #e2b56f; color: #8b5200; background: #fff8e9; }
  .theme-list { display: grid; gap: 7px; margin-top: 7px; }
  .theme-item { padding: 9px; border: 1px solid var(--line); border-radius: 7px; background: #f8fbfe; }
  .theme-title { display: flex; justify-content: space-between; gap: 8px; color: var(--navy); font-size: 12px; font-weight: 750; }
  .theme-description { margin-top: 3px; color: var(--muted); font-size: 11px; line-height: 1.35; }
  .agent-summary { min-height: 58px; margin: 12px 0 0; color: #4c5868; font-size: 12px; line-height: 1.45; }
  .agent-runs { margin-top: 13px; border-top: 1px solid var(--line); padding-top: 10px; }
  .agent-runs > summary { cursor: pointer; color: var(--navy); font-size: 12px; font-weight: 750; }
  .agent-runs-list { max-height: 560px; margin-top: 8px; overflow-y: auto; }
  .run { margin: 10px 0; border: 1px solid var(--line); border-left: 5px solid #6c7180; border-radius: 9px; background: #fff; }
  .run[data-status="expected"] { border-left-color: var(--good); }
  .run[data-status="review"] { border-left-color: var(--watch); }
  .run[data-status="high-deviation"] { border-left-color: var(--bad); }
  .run summary { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; padding: 13px; cursor: pointer; }
  .run-body { padding: 0 14px 14px; }
  .pill { padding: 3px 8px; border-radius: 999px; background: #6c7180; color: white; font-size: 12px; font-weight: 700; }
  .pill.expected { background: var(--good); }
  .pill.review { background: var(--watch); }
  .pill.high-deviation { background: var(--bad); }
  .run-tag { padding: 2px 6px; border: 1px solid #9fc8f2; border-radius: 999px; color: #236aaf; background: #f7fbff; font-size: 10px; }
  .run-tag.flag { border-color: #e2b56f; color: #8b5200; background: #fff8e9; }
  .session-link { margin-left: auto; padding: 3px 8px; border: 1px solid #2b78c5; border-radius: 999px; color: #1e659d; background: #f7fbff; font-size: 10px; font-weight: 750; text-decoration: none; }
  .session-link:hover { background: #e8f3fd; }
  .facts { display: flex; flex-wrap: wrap; gap: 12px; color: var(--muted); font-size: 12px; }
  .theme { margin: 12px 0 4px; color: var(--navy); font-size: 18px; font-weight: 750; }
  .warning { margin: 10px 0; padding: 9px; border: 1px solid #dc8f8f; border-radius: 7px; background: #fff1f1; color: #7b2323; }
  .hidden { display: none !important; }
  footer { padding: 20px; color: var(--muted); text-align: center; font-size: 12px; }
  @media (max-width: 1050px) { .agent-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 760px) { .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } .agent-grid { grid-template-columns: 1fr; } }
  @media (max-width: 480px) { .cards { grid-template-columns: 1fr; } main { padding-inline: 12px; } .agent-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
</head>
<body>
<header>
  <div>
    <h1>Perception Agent Behavior Analysis</h1>
    <p>Separate analytical view of agent-run themes, key aspects, and rolling per-agent deviation. The live-environment dashboard remains unchanged.</p>
  </div>
</header>
<nav class="report-nav" aria-label="Evidence views">
  <a href="/threat-protection" data-file="Perception-Threat-Protection.html">Operational Briefing</a>
  <a href="/assurance-freshness" data-file="Perception-Assurance-Freshness.html">Freshness &amp; Run Quality</a>
  <a href="/systemic-threat-signals" data-file="Perception-Systemic-Threat-Signals.html">Systemic Threat Signals</a>
  <a href="/agent-behavior" data-file="Perception-Agent-Behavior-Analysis.html" aria-current="page">Agent Behavior Analysis</a>
  <a href="/" data-file="Perception-Live-Environment.html">Environment explorer</a>
</nav>
<main>
  <div class="cards">
    <div class="card"><span>Agents</span><strong>$($agentSummaries.Count)</strong></div>
    <div class="card"><span>Runs analyzed</span><strong>$($reportRuns.Count)</strong></div>
    <div class="card"><span>Flagged for review</span><strong>$finalFlaggedRunCount</strong></div>
    <div class="card"><span>Incomplete transcripts</span><strong>$(@($reportRuns | Where-Object messagesTruncated).Count)</strong></div>
  </div>

  <div class="advisory"><strong>Advisory only:</strong> these are descriptive behavior patterns for each agent across its own run history. Deviation is not a correctness or quality score. A specialized agent can legitimately vary when its assigned task changes.</div>

  <section>
    <h2>Agent-theme outlier flow</h2>
    <p class="intro">Each conversation flows from its agent through its primary thematic cluster to its final status. Wider paths represent more conversations; orange and red branches isolate themes producing review or high-deviation outliers. Select a flow to open a conversation behind it.</p>
    <div class="sankey-legend">
      <span class="legend-item"><span class="legend-dot" style="background:#7a8798"></span>Baseline building</span>
      <span class="legend-item"><span class="legend-dot" style="background:#237a43"></span>Expected</span>
      <span class="legend-item"><span class="legend-dot" style="background:#d18a16"></span>Review</span>
      <span class="legend-item"><span class="legend-dot" style="background:#ad3434"></span>High deviation</span>
    </div>
    <div class="sankey-wrap"><svg id="behaviorSankey" class="sankey" role="img" aria-label="Flow from agents through conversation themes to behavioral outcomes"></svg></div>
  </section>

  <section>
    <h2>Agent behavior profiles</h2>
    <p class="intro">One profile per agent. Each agent is compared only with its own previous $AgentBaselineWindow runs, with at least $MinimumAgentBaselineRuns required. Expand a card to inspect its individual runs.</p>
    <div class="controls">
      <input id="search" type="search" placeholder="Search agent, recurring theme, aspect, session, or run ID">
      <select id="status"><option value="">All agent profiles</option><option value="high-deviation">Has high deviation</option><option value="review">Has review runs</option><option value="expected">Has expected runs</option><option value="baseline-building">Still building baseline</option></select>
    </div>
    <div id="agentCards" class="agent-grid"></div>
  </section>
</main>
<footer>
  Generated $($generatedAt.ToString('u')) using $(ConvertTo-BehaviorHtmlText $analysisSummary.Model).
  This report contains tenant-derived analytical data and should be handled like the source snapshot.
</footer>
<script>
  if (location.protocol === 'file:') {
    document.querySelectorAll('.report-nav a[data-file]').forEach(function (link) {
      link.href = link.dataset.file;
    });
  }
  const encodedReport = '$(ConvertTo-BehaviorHtmlText $reportDataBase64)';
  const binaryReport = atob(encodedReport);
  const reportBytes = Uint8Array.from(binaryReport, function (character) {
    return character.charCodeAt(0);
  });
  const report = JSON.parse(new TextDecoder().decode(reportBytes));
  const root = document.getElementById('agentCards');
  const search = document.getElementById('search');
  const status = document.getElementById('status');

  function element(tag, className, text) {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== undefined && text !== null) value.textContent = String(text);
    return value;
  }

  function renderRun(run) {
    const analysis = run.analysis || {};
    const details = element('details', 'run');
    details.dataset.status = analysis.driftStatus || '';
    details.dataset.agent = run.agent || '';
    details.dataset.runId = run.runId || '';
    details.dataset.search = [
      run.agent, run.agentDisplayName, run.runId, run.sessionId, run.sessionDisplayName,
      analysis.topicTheme, (analysis.keyAspects || []).join(' '),
      (analysis.driftSignals || []).join(' ')
    ].join(' ').toLowerCase();

    const summary = element('summary');
    summary.append(element('strong', null, run.agentDisplayName || run.agent));
    summary.append(element('span', 'pill ' + (analysis.driftStatus || ''), String(analysis.driftStatus || 'unknown').replaceAll('-', ' ')));
    if (analysis.driftScore !== undefined && analysis.driftScore !== null) {
      summary.append(element('span', 'muted', 'drift ' + analysis.driftScore + '/100'));
    }
    (analysis.themeTags || []).forEach(function (tag) {
      summary.append(element('span', 'run-tag', tag));
    });
    (analysis.flagTags || []).forEach(function (tag) {
      summary.append(element('span', 'run-tag flag', tag));
    });
    summary.append(element('code', null, run.runId));
    const sessionLink = element('a', 'session-link', 'Open full session \u2197');
    sessionLink.href = 'Perception-Live-Environment.html#session=' +
      encodeURIComponent(run.sessionId || '') + '&run=' + encodeURIComponent(run.runId || '');
    sessionLink.target = '_blank';
    sessionLink.rel = 'noopener noreferrer';
    sessionLink.addEventListener('click', function (event) { event.stopPropagation(); });
    summary.append(sessionLink);
    details.append(summary);

    const body = element('div', 'run-body');
    const facts = element('div', 'facts');
    facts.append(element('span', null, run.createdAt || ''));
    facts.append(element('span', null, run.messageCount + ' messages'));
    facts.append(element('span', null, Number(run.durationMs || 0).toLocaleString() + ' ms'));
    facts.append(element('span', null, analysis.baselineRunCount + ' baseline runs'));
    facts.append(element('span', null, run.markdownOutputCount + ' session Markdown outputs'));
    body.append(facts);
    body.append(element('div', 'theme', analysis.topicTheme || 'No topic theme'));

    const aspects = element('ul');
    (analysis.keyAspects || []).forEach(function (item) {
      aspects.append(element('li', null, item));
    });
    body.append(aspects);

    const signals = element('ul', 'muted');
    (analysis.driftSignals || []).forEach(function (item) {
      signals.append(element('li', null, item));
    });
    body.append(signals);
    if (analysis.driftExplanation) {
      const explanation = element('p');
      explanation.append(element('strong', null, 'AI explanation: '));
      explanation.append(document.createTextNode(analysis.driftExplanation));
      body.append(explanation);
    }
    if (run.messagesTruncated) {
      body.append(element('div', 'warning', 'Transcript collection reached the configured page limit; this run has incomplete evidence.'));
    }
    body.append(element('div', 'muted', 'Session: ' + (run.sessionDisplayName || run.sessionId)));
    details.append(body);
    return details;
  }

  function svgElement(tag, attributes, text) {
    const value = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attributes || {}).forEach(function (entry) {
      value.setAttribute(entry[0], entry[1]);
    });
    if (text !== undefined) value.textContent = text;
    return value;
  }

  function openConversation(run) {
    const card = Array.from(document.querySelectorAll('.agent-card'))
      .find(function (candidate) { return candidate.dataset.agent === run.agent; });
    if (!card) return;
    card.classList.remove('hidden');
    const history = card.querySelector('.agent-runs');
    if (history) history.open = true;
    const conversation = Array.from(card.querySelectorAll('.run'))
      .find(function (candidate) { return candidate.dataset.runId === run.runId; });
    if (conversation) {
      conversation.open = true;
      conversation.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  function renderSankey() {
    const svg = document.getElementById('behaviorSankey');
    const statuses = ['baseline-building', 'expected', 'review', 'high-deviation'];
    const statusLabels = {
      'baseline-building': 'Baseline building',
      expected: 'Expected',
      review: 'Review',
      'high-deviation': 'High deviation'
    };
    const statusColors = {
      'baseline-building': '#7a8798',
      expected: '#237a43',
      review: '#d18a16',
      'high-deviation': '#ad3434'
    };
    const agentColors = ['#356fa8', '#6f5aa8', '#23858c', '#9b6b2f', '#3e7f52', '#8b4f77', '#536b8f'];
    const agentNames = report.agents.map(function (item) { return item.agent; });
    const records = report.runs.map(function (run) {
      const analysis = run.analysis || {};
      return {
        run: run,
        agent: run.agent,
        theme: (analysis.themeTags || [])[0] || analysis.topicTheme || 'Unclassified',
        status: analysis.driftStatus || 'baseline-building'
      };
    });
    if (!records.length) return;

    const agentNodes = agentNames.map(function (name, index) {
      return { key: name, label: shortAgentName(name), value: records.filter(function (item) { return item.agent === name; }).length, color: agentColors[index % agentColors.length] };
    });
    const themeMap = new Map();
    records.forEach(function (item) {
      const key = item.agent + '\u241f' + item.theme;
      if (!themeMap.has(key)) themeMap.set(key, { key: key, agent: item.agent, label: item.theme, value: 0, color: agentColors[agentNames.indexOf(item.agent) % agentColors.length] });
      themeMap.get(key).value += 1;
    });
    const themeNodes = Array.from(themeMap.values()).sort(function (left, right) {
      return agentNames.indexOf(left.agent) - agentNames.indexOf(right.agent) || right.value - left.value || left.label.localeCompare(right.label);
    });
    const statusNodes = statuses.map(function (status) {
      return { key: status, label: statusLabels[status], value: records.filter(function (item) { return item.status === status; }).length, color: statusColors[status] };
    });

    const width = 1280;
    const top = 42;
    const bottom = 24;
    const height = Math.max(720, (themeNodes.length * 24) + top + bottom);
    const available = height - top - bottom;
    const paddings = { agents: 18, themes: 7, statuses: 28 };
    const scale = Math.min(
      (available - (paddings.agents * (agentNodes.length - 1))) / records.length,
      (available - (paddings.themes * (themeNodes.length - 1))) / records.length,
      (available - (paddings.statuses * (statusNodes.length - 1))) / records.length
    );
    function layout(nodes, x, padding) {
      const total = nodes.reduce(function (sum, node) { return sum + (node.value * scale); }, 0) + (padding * (nodes.length - 1));
      let y = top + ((available - total) / 2);
      nodes.forEach(function (node) {
        node.x0 = x;
        node.x1 = x + 16;
        node.y0 = y;
        node.y1 = y + (node.value * scale);
        node.inOffset = 0;
        node.outOffset = 0;
        y = node.y1 + padding;
      });
    }
    layout(agentNodes, 185, paddings.agents);
    layout(themeNodes, 650, paddings.themes);
    layout(statusNodes, 1085, paddings.statuses);
    const agentByKey = new Map(agentNodes.map(function (node) { return [node.key, node]; }));
    const themeByKey = new Map(themeNodes.map(function (node) { return [node.key, node]; }));
    const statusByKey = new Map(statusNodes.map(function (node) { return [node.key, node]; }));

    function aggregateLinks(sourceKey, targetKey) {
      const links = new Map();
      records.forEach(function (record) {
        const source = sourceKey(record);
        const target = targetKey(record);
        const key = source + '\u241f' + target;
        if (!links.has(key)) links.set(key, { sourceKey: source, targetKey: target, value: 0, runs: [] });
        const link = links.get(key);
        link.value += 1;
        link.runs.push(record.run);
      });
      return Array.from(links.values());
    }
    const leftLinks = aggregateLinks(
      function (record) { return record.agent; },
      function (record) { return record.agent + '\u241f' + record.theme; }
    );
    const rightLinks = aggregateLinks(
      function (record) { return record.agent + '\u241f' + record.theme; },
      function (record) { return record.status; }
    );
    leftLinks.sort(function (left, right) { return themeByKey.get(left.targetKey).y0 - themeByKey.get(right.targetKey).y0; });
    rightLinks.sort(function (left, right) {
      const leftOutlier = left.targetKey === 'review' || left.targetKey === 'high-deviation' ? 1 : 0;
      const rightOutlier = right.targetKey === 'review' || right.targetKey === 'high-deviation' ? 1 : 0;
      return leftOutlier - rightOutlier ||
        statusByKey.get(left.targetKey).y0 - statusByKey.get(right.targetKey).y0 ||
        themeByKey.get(left.sourceKey).y0 - themeByKey.get(right.sourceKey).y0;
    });

    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    svg.append(svgElement('text', { x: 185, y: 20, class: 'column-label' }, 'Agents'));
    svg.append(svgElement('text', { x: 650, y: 20, class: 'column-label' }, 'Conversation themes'));
    svg.append(svgElement('text', { x: 1085, y: 20, class: 'column-label' }, 'Outcome / outliers'));

    function drawLinks(links, sourceMap, targetMap, colorFor, outlierFor) {
      links.forEach(function (link) {
        const source = sourceMap.get(link.sourceKey);
        const target = targetMap.get(link.targetKey);
        const thickness = Math.max(1.5, link.value * scale);
        const sy = source.y0 + source.outOffset + (thickness / 2);
        const ty = target.y0 + target.inOffset + (thickness / 2);
        source.outOffset += thickness;
        target.inOffset += thickness;
        const middle = (source.x1 + target.x0) / 2;
        const path = svgElement('path', {
          d: 'M ' + source.x1 + ' ' + sy + ' C ' + middle + ' ' + sy + ', ' + middle + ' ' + ty + ', ' + target.x0 + ' ' + ty,
          stroke: colorFor(link, source, target),
          'stroke-width': thickness,
          class: 'flow' + (outlierFor(link) ? ' outlier' : ''),
          tabindex: '0',
          role: 'button'
        });
        path.append(svgElement('title', {}, source.label + ' \u2192 ' + target.label + ': ' + link.value + ' conversation' + (link.value === 1 ? '' : 's')));
        function activate() { if (link.runs.length) openConversation(link.runs[0]); }
        path.addEventListener('click', activate);
        path.addEventListener('keydown', function (event) {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            activate();
          }
        });
        svg.append(path);
      });
    }
    drawLinks(leftLinks, agentByKey, themeByKey, function (link, source) { return source.color; }, function () { return false; });
    themeNodes.forEach(function (node) { node.outOffset = 0; });
    statusNodes.forEach(function (node) { node.inOffset = 0; });
    drawLinks(rightLinks, themeByKey, statusByKey, function (link, source, target) { return target.color; }, function (link) { return link.targetKey === 'review' || link.targetKey === 'high-deviation'; });

    function drawNodes(nodes, labelSide, strong) {
      nodes.forEach(function (node) {
        svg.append(svgElement('rect', { x: node.x0, y: node.y0, width: node.x1 - node.x0, height: Math.max(2, node.y1 - node.y0), fill: node.color, class: 'node' }));
        const label = node.label.length > 42 ? node.label.slice(0, 39) + '\u2026' : node.label;
        const x = labelSide === 'left' ? node.x0 - 8 : node.x1 + 8;
        svg.append(svgElement('text', { x: x, y: ((node.y0 + node.y1) / 2) + 3, 'text-anchor': labelSide === 'left' ? 'end' : 'start', class: 'node-label' + (strong ? ' strong' : '') }, label + ' (' + node.value + ')'));
      });
    }
    drawNodes(agentNodes, 'left', true);
    drawNodes(themeNodes, 'right', false);
    drawNodes(statusNodes, 'right', true);
  }

  function shortAgentName(name) {
    return String(name || 'Unknown agent')
      .replace(/^Global\.Microsoft\.Defender\./, '')
      .replace(/Agent$/, '')
      .replace(/([a-z])([A-Z])/g, '`$1 `$2');
  }

  function renderAgent(summary) {
    const profile = summary.thematicProfile || { overview: '', themes: [] };
    const runs = report.runs
      .filter(function (run) { return run.agent === summary.agent; })
      .sort(function (left, right) { return String(right.createdAt).localeCompare(String(left.createdAt)); });
    const flagTagCounts = {};
    runs.forEach(function (run) {
      ((run.analysis && run.analysis.flagTags) || []).forEach(function (tag) {
        flagTagCounts[tag] = (flagTagCounts[tag] || 0) + 1;
      });
    });
    const statuses = Array.from(new Set(runs.map(function (run) {
      return (run.analysis && run.analysis.driftStatus) || '';
    })));
    const card = element('article', 'agent-card');
    card.dataset.agent = summary.agent;
    card.dataset.statuses = statuses.join(' ');
    card.dataset.search = [
      summary.agent,
      profile.overview,
      profile.themes.map(function (item) { return item.name + ' ' + item.description; }).join(' '),
      Object.keys(flagTagCounts).join(' '),
      runs.map(function (run) {
        return [
          run.runId, run.sessionId, run.sessionDisplayName,
          run.analysis && run.analysis.topicTheme,
          ((run.analysis && run.analysis.themeTags) || []).join(' '),
          ((run.analysis && run.analysis.flagTags) || []).join(' ')
        ].join(' ');
      }).join(' ')
    ].join(' ').toLowerCase();

    const head = element('div', 'agent-head');
    head.append(element('h3', null, shortAgentName(summary.agent)));
    head.append(element('div', 'agent-id', summary.agent));
    card.append(head);

    const body = element('div', 'agent-body');
    const stats = element('div', 'agent-stats');
    [
      [summary.runCount, 'runs'],
      [summary.scoredRunCount, 'scored'],
      [summary.flaggedRunCount, 'flagged'],
      [summary.highDeviationRunCount, 'high']
    ].forEach(function (item) {
      const stat = element('div', 'agent-stat');
      stat.append(element('strong', null, item[0]));
      stat.append(element('span', null, item[1]));
      stats.append(stat);
    });
    body.append(stats);

    const score = summary.averageDriftScore;
    const scoreRow = element('div', 'score-row');
    scoreRow.append(element('span', null, 'Average deviation (descriptive)'));
    scoreRow.append(element('strong', null, score === null ? 'Building baseline' : score + ' / 100'));
    body.append(scoreRow);
    const track = element('div', 'score-track');
    const fill = element('div', 'score-fill');
    fill.style.width = (score === null ? 0 : Math.max(0, Math.min(100, score))) + '%';
    track.append(fill);
    body.append(track);

    body.append(element('div', 'label', 'Conversation themes'));
    const themeList = element('div', 'theme-list');
    profile.themes.forEach(function (item) {
      const theme = element('div', 'theme-item');
      const title = element('div', 'theme-title');
      title.append(element('span', null, item.name));
      title.append(element('span', 'muted', item.runCount + ' conversations'));
      theme.append(title);
      theme.append(element('div', 'theme-description', item.description));
      themeList.append(theme);
    });
    body.append(themeList);

    body.append(element('div', 'label', 'Flagged conversation tags'));
    const flagChips = element('div', 'chips');
    Object.entries(flagTagCounts)
      .sort(function (left, right) { return right[1] - left[1] || left[0].localeCompare(right[0]); })
      .forEach(function (item) {
        flagChips.append(element('span', 'chip flag', item[0] + ' (' + item[1] + ')'));
      });
    if (!Object.keys(flagTagCounts).length) {
      flagChips.append(element('span', 'muted', 'No conversations currently flagged.'));
    }
    body.append(flagChips);

    body.append(element('p', 'agent-summary', profile.overview ||
      ('This agent has ' + summary.runCount + ' recorded runs and is still building its thematic profile.')));

    const runDetails = element('details', 'agent-runs');
    runDetails.append(element('summary', null, 'View ' + runs.length + ' runs'));
    const runList = element('div', 'agent-runs-list');
    runs.forEach(function (run) { runList.append(renderRun(run)); });
    runDetails.append(runList);
    body.append(runDetails);
    card.append(body);
    return card;
  }

  report.agents.forEach(function (summary) { root.append(renderAgent(summary)); });
  renderSankey();

  function applyFilters() {
    const term = search.value.trim().toLowerCase();
    root.querySelectorAll('.agent-card').forEach(function (card) {
      const visible = (!term || card.dataset.search.includes(term)) &&
        (!status.value || card.dataset.statuses.split(' ').includes(status.value));
      card.classList.toggle('hidden', !visible);
    });
  }
  search.addEventListener('input', applyFilters);
  status.addEventListener('change', applyFilters);
</script>
</body>
</html>
"@

. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$html = Set-PerceptionReportPresentation -Html $html
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$resolvedJsonOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
    $JsonOutputPath
)
foreach ($directory in @(
    (Split-Path -Parent $resolvedOutputPath),
    (Split-Path -Parent $resolvedJsonOutputPath)
) | Sort-Object -Unique) {
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory
    }
}

[IO.File]::WriteAllText(
    $resolvedJsonOutputPath,
    $reportJson,
    [Text.UTF8Encoding]::new($false)
)
[IO.File]::WriteAllText(
    $resolvedOutputPath,
    $html,
    [Text.UTF8Encoding]::new($false)
)
Write-Host "Behavior analysis JSON written to $resolvedJsonOutputPath"
Write-Host "Behavior analysis report written to $resolvedOutputPath"

if (-not $NoOpen) {
    Start-Process $resolvedOutputPath
}

[pscustomobject]@{
    GeneratedAt = $generatedAt
    SourceSnapshot = $resolvedInputPath
    SessionCount = $sessions.Count
    AgentRunCount = $reportRuns.Count
    AgentCount = $agentSummaries.Count
    FlaggedRunCount = $finalFlaggedRunCount
    IncompleteRunCount = @($reportRuns | Where-Object messagesTruncated).Count
    Model = $analysisSummary.Model
    Provider = $analysisSummary.Provider
    JsonOutputPath = $resolvedJsonOutputPath
    OutputPath = $resolvedOutputPath
}
