Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionSnapshotInsights.ps1')

function Get-PerceptionLoopAgentCatalog {
    param([Parameter(Mandatory)][object]$Snapshot)

    $catalog = Get-AssuranceValue $Snapshot 'catalog'
    if ($null -eq $catalog) {
        return [pscustomobject]@{
            status = 'not-collected'; capturedAt = $null; agents = @(); playbooks = @()
            issues = @('This snapshot does not retain the agent catalog. Refresh collection to map available agents; observed runs alone do not establish availability.')
        }
    }
    if ((Get-AssuranceValue $catalog 'agents') -isnot [array] -or (Get-AssuranceValue $catalog 'playbooks') -isnot [array]) {
        throw 'Snapshot catalog must contain agents and playbooks arrays.'
    }
    $issues = [Collections.Generic.List[string]]::new()
    $agents = @(
        foreach ($agent in $catalog.agents) {
            $id = [string](Get-AssuranceValue $agent 'id')
            $definition = [string](Get-AssuranceValue $agent 'agentDefinitionName')
            if (-not $id -or -not $definition) { $issues.Add('A registry agent is missing its ID or definition name and was not mapped.'); continue }
            $enabled = Get-AssuranceValue $agent 'enabled'
            [pscustomobject]@{
                id = $id; definitionName = $definition
                displayName = [string](Get-AssuranceValue $agent 'displayName' $definition)
                enabled = if ($enabled -is [bool]) { $enabled } else { $null }
            }
        }
    )
    $playbooks = @(
        foreach ($playbook in $catalog.playbooks) {
            $id = [string](Get-AssuranceValue $playbook 'id')
            if (-not $id) { $issues.Add('A catalog playbook is missing its ID and was not mapped.'); continue }
            $declaredAgents = Get-AssuranceValue $playbook 'agents' @()
            $inputTypes = Get-AssuranceValue $playbook 'acceptedInputTypes' @()
            $definitions = @(
                [string](Get-AssuranceValue $playbook 'startAgent')
                foreach ($agent in $declaredAgents) { [string](Get-AssuranceValue $agent 'id') }
            ) | Where-Object { $_ } | Sort-Object -Unique -CaseSensitive
            [pscustomobject]@{
                id = $id; displayName = [string](Get-AssuranceValue $playbook 'displayName' $id)
                agentDefinitions = @($definitions)
                acceptedInputTypes = @($inputTypes)
            }
        }
    )
    [pscustomobject]@{
        status = 'collected'; capturedAt = Get-AssuranceValue $catalog 'capturedAt'
        agents = $agents; playbooks = $playbooks; issues = $issues.ToArray()
    }
}

function Get-PerceptionOperationalLoops {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Insights
    )

    $stages = @(
        @{ id = 'sense'; title = 'Sense'; requirement = 'A relevant trigger or triage observation.' }
        @{ id = 'understand'; title = 'Understand'; requirement = 'Investigation or assessment evidence for the same scope.' }
        @{ id = 'decide'; title = 'Decide'; requirement = 'An explicit, attributable human decision or approval.' }
        @{ id = 'engineer'; title = 'Engineer'; requirement = 'A detection, hunt or remediation design; not proof of deployment.' }
        @{ id = 'act'; title = 'Act'; requirement = 'An accountable execution or change record, not a recommendation.' }
        @{ id = 'verify'; title = 'Verify'; requirement = 'A linked reassessment of the same scope demonstrating resolution of the original finding.' }
        @{ id = 'learn'; title = 'Learn'; requirement = 'Evidence that feedback or findings were incorporated into subsequent work; retained logs alone are insufficient.' }
    ) | ForEach-Object { [pscustomobject]$_ }
    $flows = @('alert-led','threat-led','exposure-led','hunt-led','validation-led')
    $mappings = @{
        'triage-security-copilot' = @{ flow = 'alert-led'; stages = @('sense','understand') }
        'investigate-incident' = @{ flow = 'alert-led'; stages = @('understand') }
        'analyze-article' = @{ flow = 'threat-led'; stages = @('sense','understand') }
        'prioritize-posture' = @{ flow = 'exposure-led'; stages = @('engineer') }
        'run-reconnaissance' = @{ flow = 'exposure-led'; stages = @('understand') }
        'assess-identity-risk' = @{ flow = 'exposure-led'; stages = @('understand') }
    }
    $context = Get-PerceptionSnapshotEvidence $Snapshot
    $members = @(
        foreach ($session in $Insights.sessions) {
            $sourceSession = $context.sessionIndex[$session.id]
            if ($null -eq $sourceSession) { throw "Loop evidence references an absent session: $($session.id)" }
            $tags = @((Get-AssuranceValue $sourceSession 'tags' @()) | Where-Object { $_ -is [string] })
            $ids = @($tags | Where-Object { $_ -cmatch '^loopId=' })
            $flowTags = @($tags | Where-Object { $_ -cmatch '^loopFlow=' })
            $incidents = @($session.inputTags | Where-Object { $_ -cmatch '^input:(incident|defenderIncidentId)=' })
            $issues = [Collections.Generic.List[string]]::new()
            $basis = 'session-only'
            $label = if ($session.title) { $session.title } else { $session.id }
            $key = @('session', $session.id)
            if ($ids.Count -eq 1 -and $ids[0] -cmatch '^loopId=([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\z') {
                $id = $Matches[1]
                $basis = 'explicit-loop-id'; $label = $id; $key = @('loop', $id)
            }
            elseif ($ids.Count -gt 0) {
                $issues.Add('Ambiguous or invalid loopId tags. This session has not been joined to another session.')
            }
            elseif ($incidents.Count -eq 1 -and $incidents[0] -cmatch '^input:(?:incident|defenderIncidentId)=([0-9]{1,32})\z') {
                $id = $Matches[1]
                $basis = 'shared-incident-input'; $label = "Incident $id"; $key = @('incident', $id)
            }
            elseif ($incidents.Count -gt 0) {
                $issues.Add('Incident input is ambiguous or is not a supported numeric incident identifier. This session remains separate.')
            }
            $explicitFlow = ''
            if ($flowTags.Count -eq 1 -and $flowTags[0].Substring('loopFlow='.Length) -cin $flows) {
                $explicitFlow = $flowTags[0].Substring('loopFlow='.Length)
            }
            elseif ($flowTags.Count -gt 0) { $issues.Add('Ambiguous or unsupported loopFlow tags. Entry flow is not established.') }
            [pscustomobject]@{
                key = ConvertTo-Json -InputObject $key -Compress
                basis = $basis; label = $label; session = $session
                explicitFlow = $explicitFlow; invalidFlow = $flowTags.Count -gt 0 -and -not $explicitFlow
                issues = $issues.ToArray()
            }
        }
    )
    $groups = @(
        foreach ($bucket in @($members | Group-Object key -CaseSensitive)) {
            $items = @($bucket.Group)
            $sessions = @($items.session | Sort-Object { [DateTimeOffset]$_.startedAt }, id)
            $issues = @($items | ForEach-Object issues | Sort-Object -Unique)
            $explicitFlows = @($items.explicitFlow | Where-Object { $_ } | Sort-Object -Unique -CaseSensitive)
            $suggestedFlows = @(
                foreach ($session in $sessions) {
                    if ($mappings.ContainsKey($session.workflow)) { $mappings[$session.workflow].flow }
                    else { 'unclassified' }
                }
            ) | Sort-Object -Unique
            $flow = 'unclassified'; $flowBasis = 'not-established'
            if (@($items | Where-Object invalidFlow).Count -gt 0 -or $explicitFlows.Count -gt 1) {
                $issues += 'Entry-flow tags conflict or are invalid. No single entry flow has been assigned.'
            }
            elseif ($explicitFlows.Count -eq 1) { $flow = $explicitFlows[0]; $flowBasis = 'explicit-tag' }
            elseif (@($suggestedFlows).Count -eq 1) { $flow = @($suggestedFlows)[0]; $flowBasis = 'workflow-derived' }
            elseif (@($suggestedFlows).Count -gt 1) { $flow = 'mixed'; $flowBasis = 'workflow-derived' }
            $references = @(
                foreach ($session in $sessions) {
                    $ambiguousPaths = @($session.artifacts | Group-Object path -CaseSensitive | Where-Object Count -GT 1 | ForEach-Object Name)
                    foreach ($path in $ambiguousPaths) { $issues += "Ambiguous source path in session $($session.id): $path. It has not been used as stage evidence." }
                    foreach ($artifact in $session.artifacts) {
                        if ($artifact.path -cin $ambiguousPaths) { continue }
                        if ($null -ne $artifact.error -or [string]::IsNullOrWhiteSpace($artifact.content)) { continue }
                        [pscustomobject]@{
                            sessionId = $session.id; path = $artifact.path; kind = $artifact.kind
                            workflow = $session.workflow; line = 1
                            stageIds = @(
                                if ($artifact.kind -eq 'artifact' -and
                                    $session.classification -notin @('source-unavailable','output-missing') -and
                                    $mappings.ContainsKey($session.workflow)) { $mappings[$session.workflow].stages }
                            )
                        }
                    }
                }
            )
            $coverage = @(
                foreach ($stage in $stages) {
                    $evidence = @($references | Where-Object { $_.stageIds -contains $stage.id })
                    $status = if ($evidence.Count -gt 0) { 'evidence-to-review' }
                        elseif ($stage.id -in @('decide','act','verify','learn')) { 'not-assessed' }
                        else { 'not-observed' }
                    [pscustomobject]@{
                        stageId = $stage.id; status = $status
                        sources = $evidence
                        completed = $null
                    }
                }
            )
            $collectionIssues = @($sessions | ForEach-Object collectionIssues | Sort-Object -Unique)
            [pscustomobject]@{
                id = $bucket.Name; title = $items[0].label; correlationBasis = $items[0].basis
                flow = $flow; flowBasis = $flowBasis
                sessionIds = @($sessions.id); sessionCount = $sessions.Count
                agentRunCount = ($sessions | Measure-Object runCount -Sum).Sum
                workflows = @($sessions.workflow | Sort-Object -Unique)
                inputTags = @($sessions | ForEach-Object inputTags | Sort-Object -Unique -CaseSensitive)
                latestRunStartedAt = $sessions[-1].startedAt
                coverage = $coverage; sources = $references
                issues = $issues; collectionIssues = $collectionIssues
                owner = $null; verifiedOutcome = $null
            }
        }
    ) | Sort-Object { [DateTimeOffset]$_.latestRunStartedAt }, id -Descending
    [pscustomobject]@{
        schemaVersion = 1
        mappingVersion = 1
        stages = $stages; flows = $flows
        agentCatalog = Get-PerceptionLoopAgentCatalog -Snapshot $Snapshot
        groups = @($groups)
        counts = [pscustomobject]@{
            groups = @($groups).Count
            explicitLoopIds = @($groups | Where-Object correlationBasis -EQ 'explicit-loop-id').Count
            incidentCandidates = @($groups | Where-Object correlationBasis -EQ 'shared-incident-input').Count
            sessionScoped = @($groups | Where-Object correlationBasis -EQ 'session-only').Count
            withMappedEvidence = @($groups | Where-Object { @($_.coverage | Where-Object status -EQ 'evidence-to-review').Count -gt 0 }).Count
            withCollectionIssues = @($groups | Where-Object { $_.collectionIssues.Count -gt 0 }).Count
        }
        unavailableMetrics = [pscustomobject]@{
            verifiedRiskReductions = $null; closureRate = $null; handoffDwell = $null
            reason = 'Reliable linked decisions, execution, verification and handoff records are not collected by this view. These metrics are not calculated, not zero.'
        }
        limitations = @(
            'Coverage is limited to this retained snapshot. No cross-tenant or cross-snapshot joins are performed.'
            'Workflow-stage mappings identify readable artifacts to review, not successful completion of a stage. Session-shared artifacts are not attributed to individual agent runs.'
            'Entry flows are possible workflow-derived interpretations unless explicitly tagged. A repeat run is not automatically a validation-led flow.'
            'Only explicit loopId tags establish a declared link. Shared numeric incident inputs form candidates, not confirmed end-to-end loops. Other inputs remain session-scoped.'
            'Agent transcripts are contextual sources only. Human messages, recommendations, successful runs and retained logs do not establish approval, execution, verification or learning.'
            'Not observed means absent from retained evidence, not proof that work did not occur. No stalled-loop, SLA, ownership or verified-risk-reduction claim is inferred.'
        )
    }
}
