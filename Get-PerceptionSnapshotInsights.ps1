Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionReportEvidence.ps1')

function ConvertTo-InsightText {
    param([AllowNull()][string]$Text)

    ([regex]::Replace([string]$Text, '\[([^\]]+)\]\([^)]+\)', '$1') -replace '[`*]', '').Trim()
}

function Get-InsightCell {
    param([object]$Row, [string[]]$Names)

    foreach ($name in $Names) {
        if ($Row.cells.Contains($name)) { return [string]$Row.cells[$name] }
    }
    ''
}

function Read-PerceptionIntelligenceReport {
    param([object]$Session, [object]$Output)

    $lines = ([string]$Output.content) -split '\r?\n'
    $sections = [Collections.Generic.List[object]]::new()
    $tables = [Collections.Generic.List[object]]::new()
    $section = $null
    $headers = @()
    $sourceLine = ''
    $title = ''
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ($line -match '^#\s+(.+)') {
            $title = ConvertTo-InsightText ($Matches[1] -replace '^Threat Intelligence Report:\s*', '')
        }
        if ($line -match '(?i)^\*\*Source Reports?:') { $sourceLine = $line }
        if ($line -match '^##\s+(?:\d+[.)]\s*)?(.+?)\s*$') {
            $section = [pscustomobject]@{ name = $Matches[1].Trim(); lines = [Collections.Generic.List[object]]::new() }
            $sections.Add($section)
            $headers = @()
            continue
        }
        if ($null -ne $section) { $section.lines.Add([pscustomobject]@{ text = $line; line = $index + 1 }) }
        if ($line -match '^\s*\|.*\|\s*$') {
            $cells = @([regex]::Split($line.Trim().Trim('|'), '(?<!\\)\|') | ForEach-Object { ConvertTo-InsightText ($_ -replace '\\\|', '|') })
            if ($cells.Count -gt 0 -and @($cells | Where-Object { $_ -notmatch '^:?-{2,}:?$' }).Count -eq 0) { continue }
            if ($headers.Count -eq 0) {
                $headers = @($cells | ForEach-Object { ($_ -replace '[^a-zA-Z0-9]', '').ToLowerInvariant() })
                continue
            }
            $values = [ordered]@{}
            for ($column = 0; $column -lt [Math]::Min($headers.Count, $cells.Count); $column++) {
                $values[$headers[$column]] = $cells[$column]
            }
            $tables.Add([pscustomobject]@{
                section = if ($null -ne $section) { $section.name } else { '' }
                cells = $values; line = $index + 1; excerpt = $line
            })
        }
        else { $headers = @() }
    }
    $behaviours = @(
        foreach ($row in @($tables | Where-Object section -match '^(TTPs|Techniques|Tactics.*)$')) {
            $action = Get-InsightCell $row @('action', 'behavior', 'behaviour', 'description')
            $mapping = (Get-InsightCell $row @('technique')) + ' ' + (Get-InsightCell $row @('subtechnique'))
            $identifiers = @([regex]::Matches($mapping, '\bT\d{4}(?:\.\d{3})?\b') |
                ForEach-Object Value | Sort-Object -Unique)
            if ($identifiers.Count -eq 0 -or [string]::IsNullOrWhiteSpace($action)) { continue }
            [pscustomobject]@{
                tactic = Get-InsightCell $row @('tactic')
                technique = Get-InsightCell $row @('technique')
                subTechnique = Get-InsightCell $row @('subtechnique')
                techniqueIds = $identifiers
                action = $action
                impact = Get-InsightCell $row @('impact', 'severity')
                opportunity = Get-InsightCell $row @('detectionopportunity', 'detection')
                telemetry = Get-InsightCell $row @('telemetry', 'datasources')
                line = $row.line; excerpt = $row.excerpt
            }
        }
    )
    $indicators = @(
        foreach ($row in @($tables | Where-Object section -match '^(Indicators|Indicators of Compromise|IOCs)$')) {
            $value = Get-InsightCell $row @('value', 'indicator')
            if ([string]::IsNullOrWhiteSpace($value) -or $value -match '(?i)^no (data|indicators)') { continue }
            $tipRows = @($tables | Where-Object {
                $_.section -match '^TIP' -and (Get-InsightCell $_ @('indicator', 'value')) -ceq $value
            })
            $tip = if ($tipRows.Count -eq 1) { $tipRows[0] } else { $null }
            $tipStatus = if ($null -ne $tip) { Get-InsightCell $tip @('currenttipstatus', 'tipstatus', 'status') } else { '' }
            $tipCategory = if ($tipStatus -match '(?i)expired') { 'expired' }
            elseif ($tipStatus -match '(?i)missing|not (in|found)') { 'missing' }
            elseif ($tipStatus -match '(?i)\bactive\b') { 'active' } else { 'unknown' }
            [pscustomobject]@{
                type = Get-InsightCell $row @('type')
                value = $value
                context = Get-InsightCell $row @('context', 'description')
                tipStatus = $tipStatus
                tipCategory = $tipCategory
                recommendation = if ($null -ne $tip) { Get-InsightCell $tip @('recommendation') } else { '' }
                line = $row.line
                tipLine = if ($null -ne $tip) { $tip.line } else { $null }
            }
        }
    )
    $actions = @(
        foreach ($part in @($sections | Where-Object name -match '^Recommended Actions$')) {
            foreach ($entry in $part.lines) {
                if ($entry.text -notmatch '^\s*\d+[.)]\s+(.+)') { continue }
                $text = ConvertTo-InsightText $Matches[1]
                $priority = if ($text -match '^\[(Critical|High|Medium|Low)\]') { $Matches[1] } else { 'Unspecified' }
                [pscustomobject]@{ text = $text; priority = $priority; line = $entry.line }
            }
        }
    )
    $summaryParts = @($sections | Where-Object name -match '^Threat Summary$')
    $summary = if ($summaryParts.Count -gt 0) {
        ConvertTo-InsightText ((@($summaryParts[0].lines | Where-Object { $_.text -notmatch '^\s*(---|\|)' } | ForEach-Object text) -join "`n").Trim())
    } else { '' }
    $actors = @($tables | Where-Object section -match '^Threat Actors$' |
        ForEach-Object { Get-InsightCell $_ @('actor', 'name') } |
        Where-Object { $_ -and $_ -notmatch '(?i)^no (data|actors)' } | Sort-Object -Unique)
    $packages = @([regex]::Matches($summary, '\b[a-zA-Z][a-zA-Z0-9_-]*@\d+\.\d+\.\d+\b') |
        ForEach-Object Value | Sort-Object -Unique)
    $hunting = @($sections | Where-Object name -match '^Hunting Queries$')
    $huntingText = if ($hunting.Count -gt 0) { (@($hunting[0].lines | ForEach-Object text) -join "`n").Trim() } else { '' }
    $sourceUpdates = @([regex]::Matches($sourceLine, '(?i)updated:\s*(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2}))') |
        ForEach-Object { (Get-AssuranceTimestamp $_.Groups[1].Value 'Reported source update').ToString('o') } | Sort-Object)
    [pscustomobject]@{
        sessionId = $Session.id
        path = $Output.path
        title = $title
        summary = $summary
        actors = $actors
        packages = $packages
        behaviours = $behaviours
        techniqueIds = @($behaviours | ForEach-Object techniqueIds | Sort-Object -Unique)
        indicators = $indicators
        actions = $actions
        sourceMetadata = ConvertTo-InsightText $sourceLine
        sourceUpdatedAt = if ($sourceUpdates.Count -gt 0) { $sourceUpdates[-1] } else { $null }
        huntingText = $huntingText
        huntingQueriesProvided = $huntingText -match '```' -and $huntingText -notmatch '(?i)no hunting quer|no quer.*provided'
        content = [string]$Output.content
    }
}

function Read-PerceptionOperationalEvidence {
    param([object]$Output)

    $lines = ([string]$Output.content) -split '\r?\n'
    $heading = 'Collected evidence'
    $start = 0
    $inCode = $false
    for ($index = 0; $index -le $lines.Count; $index++) {
        $isHeading = $index -lt $lines.Count -and -not $inCode -and
            $lines[$index] -match '^#{1,6}\s+(.+?)\s*#*\s*$'
        $nextHeading = if ($isHeading) { $Matches[1] } else { '' }
        if ($isHeading -or $index -eq $lines.Count) {
            $first = $start
            while ($first -lt $index -and [string]::IsNullOrWhiteSpace($lines[$first])) { $first++ }
            if ($first -lt $index) {
                $text = ($lines[$first..($index - 1)] -join "`n").TrimEnd()
                $category = if ($heading -match '(?i)verdict|classification|disposition|determination') { 'verdict' }
                elseif ($heading -match '(?i)recommend|next steps|actions?|remediat') { 'actions' }
                elseif ($heading -match '(?i)entities|affected (assets|users|devices)|scope') { 'entities' }
                elseif ($heading -match '(?i)findings|observations|evidence|reasoning') { 'findings' }
                elseif ($heading -match '(?i)summary|conclusion') { 'summary' }
                else { 'context' }
                [pscustomobject]@{
                    heading = $heading; category = $category; text = $text
                    path = $Output.path; line = $first + 1
                }
            }
            $heading = $nextHeading
            $start = $index + 1
        }
        if ($index -lt $lines.Count -and $lines[$index] -match '^\s*(```|~~~)') { $inCode = -not $inCode }
    }
}

function Get-PerceptionOperationalContext {
    param([object]$Session, [string[]]$Tags, [bool]$IsIntelligence)

    $playbooks = @($Tags | Where-Object { $_ -cmatch '^playbookId=.+$' } | Sort-Object -Unique -CaseSensitive)
    $workflow = 'other'
    $workflowSource = 'unclassified'
    if ($playbooks.Count -eq 1) {
        $workflow = $playbooks[0].Substring('playbookId='.Length)
        $workflowSource = 'playbook tag'
    }
    elseif ($IsIntelligence) {
        $workflow = 'threat-intelligence'
        $workflowSource = 'intelligence input, agent or report'
    }
    elseif ([string](Get-AssuranceValue $Session 'displayName') -match '^(investigate-incident|triage-security-copilot)\b') {
        $workflow = $Matches[1]
        $workflowSource = 'session title prefix'
    }
    $inputs = @($Tags | Where-Object { $_ -cmatch '^input:[^=]+=.+$' } | Sort-Object -Unique -CaseSensitive)
    $keys = @($inputs | ForEach-Object { ($_ -split '=', 2)[0] })
    $unambiguous = $inputs.Count -gt 0 -and
        @($keys | Sort-Object -Unique -CaseSensitive).Count -eq $keys.Count -and $playbooks.Count -le 1
    $groupId = if ($unambiguous) {
        ConvertTo-Json -InputObject @($workflow, $inputs) -Compress -Depth 4
    } else { "session:$($Session.id)" }
    [pscustomobject]@{
        workflow = $workflow; workflowSource = $workflowSource
        inputTags = $inputs; groupId = $groupId; explicitCorrelation = $unambiguous
    }
}

function Get-PerceptionSnapshotInsights {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow
    )

    $context = Get-PerceptionSnapshotEvidence $Snapshot
    $rows = @(
        foreach ($session in $context.sessions) {
            $tags = Get-AssuranceValue $session 'tags' @()
            if ($null -eq $tags) { $tags = @() }
            $runs = Get-AssuranceValue $session 'runs' @()
            if ($null -eq $runs) { $runs = @() }
            $inputs = @($tags | Where-Object { $_ -is [string] -and $_ -cmatch '^input:threat-intelligence=.+$' })
            if ($inputs.Count -gt 1) { throw "Session '$($session.id)' has ambiguous threat-intelligence input tags." }
            $agents = @($runs |
                ForEach-Object { [string](Get-AssuranceValue (Get-AssuranceValue $_ 'agent') 'agentDefinitionName') } |
                Where-Object { $_ } | Sort-Object -Unique)
            $isIntelligence = $inputs.Count -eq 1 -or @($agents | Where-Object { $_ -match '\.ThreatIntelligenceAgent$' }).Count -gt 0
            $reports = @(
                foreach ($output in $session.markdownOutputs) {
                    if ($null -ne (Get-AssuranceValue $output 'error') -or [string]::IsNullOrWhiteSpace([string]$output.content)) { continue }
                    if ($output.path -notmatch '(?i)(?:^|/)summary\.md$' -and
                        ($output.path -match '(?i)threat_intelligence_report' -or
                        $output.content -match '(?im)^##\s+(?:\d+[.)]\s*)?Threat Summary\s*$')) {
                        Read-PerceptionIntelligenceReport $session $output
                    }
                }
            )
            $isIntelligence = $isIntelligence -or $reports.Count -gt 0
            $tagStrings = @($tags | Where-Object { $_ -is [string] })
            $operationalContext = Get-PerceptionOperationalContext $session $tagStrings $isIntelligence
            $collectionIssues = [Collections.Generic.List[string]]::new()
            foreach ($field in @('error', 'outputsError')) {
                if ($null -ne (Get-AssuranceValue $session $field)) { $collectionIssues.Add("Session $field is present.") }
            }
            $artifacts = [Collections.Generic.List[object]]::new()
            $evidence = @(
                foreach ($output in $session.markdownOutputs) {
                    $outputError = Get-AssuranceValue $output 'error'
                    $artifacts.Add([pscustomobject]@{
                        path = $output.path; content = [string](Get-AssuranceValue $output 'content')
                        error = $outputError; kind = 'artifact'
                    })
                    if ($null -ne $outputError) { $collectionIssues.Add("Artifact collection failed: $($output.path)") }
                    elseif (-not [string]::IsNullOrWhiteSpace([string](Get-AssuranceValue $output 'content'))) {
                        Read-PerceptionOperationalEvidence $output
                    }
                }
            )
            $runIndex = 0
            $agentRuns = @(
                foreach ($run in $runs) {
                    $runIndex++
                    $agent = Get-AssuranceValue $run 'agent'
                    $name = [string](Get-AssuranceValue $agent 'agentDefinitionName')
                    if (-not $name) { $name = [string](Get-AssuranceValue $agent 'displayName') }
                    if (-not $name) { $name = 'Unlabelled agent' }
                    $runId = [string](Get-AssuranceValue $run 'id')
                    $messageValue = Get-AssuranceValue $run 'messages' @()
                    $messages = @($messageValue | Where-Object { $null -ne $_ })
                    $truncated = (Get-AssuranceValue $run 'messagesTruncated' $false) -eq $true
                    $runError = Get-AssuranceValue $run 'error'
                    if ($null -ne $runError) { $collectionIssues.Add("Agent message collection failed: $name / $runId") }
                    if ($truncated) { $collectionIssues.Add("Agent messages are truncated: $name / $runId") }
                    $transcriptPath = $null
                    if ($messages.Count -gt 0) {
                        $transcriptPath = "agent-runs/$runIndex/$runId/messages"
                        $transcript = @(
                            foreach ($message in $messages) {
                                $content = Get-AssuranceValue $message 'content'
                                if ($null -eq $content) { continue }
                                $text = if ($content -is [string]) { $content } else { ConvertTo-Json -InputObject $content -Depth 30 }
                                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                                "## Message $([string](Get-AssuranceValue $message 'messageId'))"
                                "Role: $([string](Get-AssuranceValue $message 'role')) / Type: $([string](Get-AssuranceValue $message 'type'))"
                                "Timestamp: $([string](Get-AssuranceValue $message 'timestamp'))"
                                $text
                            }
                        ) -join "`n`n"
                        if (-not [string]::IsNullOrWhiteSpace($transcript)) {
                            $artifacts.Add([pscustomobject]@{
                                path = $transcriptPath; content = $transcript; error = $null; kind = 'agent-transcript'
                            })
                        }
                        else { $transcriptPath = $null }
                    }
                    [pscustomobject]@{
                        id = $runId; agent = $name
                        agentId = [string](Get-AssuranceValue $agent 'id')
                        agentDefinitionName = [string](Get-AssuranceValue $agent 'agentDefinitionName')
                        state = [string](Get-AssuranceValue $run 'state' (Get-AssuranceValue $run 'status'))
                        durationMs = Get-AssuranceValue $run 'durationMs'
                        messageCount = $messages.Count; messagesTruncated = $truncated
                        error = $runError; transcriptPath = $transcriptPath
                    }
                }
            )
            $summaryOutputs = @($session.markdownOutputs | Where-Object {
                $_.path -match '(?i)(?:^|/)summary\.md$' -and $null -eq (Get-AssuranceValue $_ 'error')
            })
            $summary = (@($summaryOutputs | ForEach-Object content) -join "`n").Trim()
            $state = [string](Get-AssuranceValue $session 'state')
            $reason = ''
            $classification = if ($reports.Count -gt 0) { 'report' }
            elseif ($summary -match '(?i)no (?:matching )?article content|article could not be retrieved|could not retrieve content|source content was unavailable|catalog did not return matching content') {
                $reason = 'The collected summary reports that source content could not be retrieved.'
                'source-unavailable'
            }
            elseif ($summary -match '(?i)(?:expected|detailed|threat.intelligence) report (?:content )?(?:was )?not available|report.*not available (?:for|in)|expected report content was not available') {
                $reason = 'The summary refers to a detailed report that is absent from collected outputs.'
                'output-missing'
            }
            elseif ($collectionIssues.Count -gt 0) {
                $reason = 'Snapshot collection includes an explicit session or output error.'
                'collection-issue'
            }
            elseif ($state -match '^(notStarted|pending|queued|running|inProgress)$') { 'pending' }
            elseif ($state -match '^(failed|cancelled|canceled)$') { 'failed' }
            elseif ($summaryOutputs.Count -gt 0) { 'summary-only' }
            elseif (@($session.markdownOutputs | Where-Object { $null -eq (Get-AssuranceValue $_ 'error') -and $_.content }).Count -gt 0) { 'other-output' }
            elseif (@($artifacts | Where-Object { -not [string]::IsNullOrWhiteSpace($_.content) }).Count -gt 0) { 'messages-only' }
            else { 'no-output' }
            $created = Get-AssuranceTimestamp (Get-AssuranceValue $session 'createdAt') 'Session createdAt'
            $durations = @($runs |
                ForEach-Object { Get-AssuranceValue $_ 'durationMs' } | Where-Object { $null -ne $_ })
            [pscustomobject]@{
                id = $session.id
                title = [string](Get-AssuranceValue $session 'displayName')
                startedAt = $created.ToString('o')
                apiState = $state
                classification = $classification
                reason = $reason
                workflow = $operationalContext.workflow
                workflowSource = $operationalContext.workflowSource
                inputTags = $operationalContext.inputTags
                evidence = $evidence
                agentRuns = $agentRuns
                collectionIssues = $collectionIssues.ToArray()
                hasEvidence = @($artifacts | Where-Object {
                    $null -eq $_.error -and -not [string]::IsNullOrWhiteSpace($_.content)
                }).Count -gt 0
                ageDays = [Math]::Round(($AsOf - $created).TotalDays, 2)
                summary = $summary
                agents = @($agentRuns | ForEach-Object agent | Sort-Object -Unique)
                isIntelligence = $isIntelligence
                groupId = $operationalContext.groupId
                explicitCorrelation = $operationalContext.explicitCorrelation
                reports = $reports
                reportCount = $reports.Count
                artifactCount = @($session.markdownOutputs).Count
                runCount = @($runs).Count
                collectedAgentDurationMs = if ($durations.Count -gt 0) { ($durations | Measure-Object -Sum).Sum } else { $null }
                artifacts = $artifacts.ToArray()
            }
        }
    )
    $campaigns = @(
        foreach ($group in @($rows | Where-Object isIntelligence | Group-Object groupId -CaseSensitive)) {
            $ordered = @($group.Group | Sort-Object { [DateTimeOffset]$_.startedAt })
            $reportRuns = @($ordered | Where-Object reportCount -gt 0)
            $latest = if ($reportRuns.Count -gt 0) { $reportRuns[-1].reports[0] } else { $null }
            $reportColumns = @(
                foreach ($run in $reportRuns) {
                    foreach ($report in $run.reports) {
                        [pscustomobject]@{
                            sessionId = $run.id; startedAt = $run.startedAt; path = $report.path
                            behaviourCount = $report.behaviours.Count; techniqueIds = @($report.techniqueIds)
                            indicatorCount = $report.indicators.Count
                            indicators = @($report.indicators | ForEach-Object value | Sort-Object -Unique)
                        }
                    }
                }
            )
            $allTechniques = @($reportColumns | ForEach-Object techniqueIds | Sort-Object -Unique)
            $presence = @(
                foreach ($technique in $allTechniques) {
                    $hits = @($reportColumns | Where-Object { $technique -cin $_.techniqueIds }).Count
                    [pscustomobject]@{ id = $technique; reports = $hits; totalReports = $reportColumns.Count }
                }
            )
            $title = if ($null -ne $latest -and $latest.title) { $latest.title }
            else { $ordered[-1].title -replace '^Extract threat intelligence\s*-\s*', '' }
            [pscustomobject]@{
                id = $group.Name
                explicitCorrelation = $ordered[0].explicitCorrelation
                title = $title
                sessionIds = @($ordered | ForEach-Object id)
                firstStartedAt = $ordered[0].startedAt
                lastStartedAt = $ordered[-1].startedAt
                sessionCount = $ordered.Count
                reportRunCount = $reportRuns.Count
                latestReport = $latest
                reportColumns = $reportColumns
                techniquePresence = @($presence | Sort-Object reports -Descending)
                behaviourRange = if ($reportColumns.Count -gt 0) {
                    [pscustomobject]@{ min = ($reportColumns | Measure-Object behaviourCount -Minimum).Minimum; max = ($reportColumns | Measure-Object behaviourCount -Maximum).Maximum }
                } else { $null }
            }
        }
    )
    $counts = [ordered]@{}
    foreach ($state in @('report', 'source-unavailable', 'output-missing', 'pending', 'failed', 'collection-issue', 'summary-only', 'other-output', 'messages-only', 'no-output')) {
        $counts[$state] = @($rows | Where-Object classification -eq $state).Count
    }
    $succeeded = @($rows | Where-Object apiState -match '^(succeeded|completed)$')
    [pscustomobject]@{
        schemaVersion = 1
        asOf = $AsOf.ToString('o')
        snapshotGeneratedAt = Get-AssuranceValue $Snapshot 'generatedAt'
        sessions = @($rows | Sort-Object { [DateTimeOffset]$_.startedAt } -Descending)
        campaigns = @($campaigns | Sort-Object lastStartedAt -Descending)
        groups = @(
            foreach ($group in @($rows | Group-Object groupId -CaseSensitive)) {
                $ordered = @($group.Group | Sort-Object { [DateTimeOffset]$_.startedAt }, id)
                $withEvidence = @($ordered | Where-Object hasEvidence)
                [pscustomobject]@{
                    id = $group.Name; workflow = $ordered[-1].workflow
                    title = $ordered[-1].title; inputTags = $ordered[-1].inputTags
                    explicitCorrelation = $ordered[-1].explicitCorrelation
                    sessionIds = @($ordered | ForEach-Object id)
                    latestSessionId = $ordered[-1].id
                    latestEvidenceSessionId = if ($withEvidence.Count) { $withEvidence[-1].id } else { $null }
                }
            }
        )
        sessionCount = $rows.Count
        artifactCount = $context.inventory.Count
        reportCount = @($rows | ForEach-Object reports).Count
        counts = [pscustomobject]$counts
        apiSucceededCount = $succeeded.Count
        succeededWithoutFullReport = @($succeeded | Where-Object { $_.isIntelligence -and $_.reportCount -eq 0 }).Count
        scopeNote = 'All workflows in the retained snapshot are analysed, not all historical tenant activity. Findings, verdicts and actions are attributed to agent outputs, not independently verified. Evidence age uses session start time, not the time activity occurred. Missing downstream activity here does not establish that no work occurred elsewhere.'
    }
}
