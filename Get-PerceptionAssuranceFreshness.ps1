Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionReportEvidence.ps1')

function Assert-AssurancePolicy {
    param([object]$Window, [object]$Warning)

    if ($Window -isnot [int] -and $Window -isnot [long]) { throw 'freshnessDays must be an integer.' }
    if ($Warning -isnot [int] -and $Warning -isnot [long]) { throw 'dueSoonDays must be an integer.' }
    if ($Window -lt 1 -or $Window -gt 3650 -or $Warning -lt 0 -or $Warning -ge $Window) {
        throw 'Policy requires 1-3650 freshnessDays and 0 <= dueSoonDays < freshnessDays.'
    }
}

function Get-PerceptionAssuranceFreshness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Register,
        [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow
    )

    if ((Get-AssuranceValue $Register 'schemaVersion') -ne 1) {
        throw 'The assurance register must have schemaVersion 1.'
    }
    foreach ($field in @('objectives', 'changes')) {
        if ((Get-AssuranceValue $Register $field) -isnot [array]) {
            throw "The assurance register must contain a $field array."
        }
    }
    $defaults = Get-AssuranceValue $Register 'defaults'
    $freshnessDays = Get-AssuranceValue $defaults 'freshnessDays' 7
    $dueSoonDays = Get-AssuranceValue $defaults 'dueSoonDays' 2
    Assert-AssurancePolicy $freshnessDays $dueSoonDays
    $snapshotEvidence = Get-PerceptionSnapshotEvidence $Snapshot
    $sessions = $snapshotEvidence.sessions
    $sessionIndex = $snapshotEvidence.sessionIndex

    $changeIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $changes = @(
        foreach ($change in $Register.changes) {
            foreach ($field in @('id', 'title', 'impact')) {
                Assert-AssuranceText (Get-AssuranceValue $change $field) "Change $field"
            }
            if (-not $changeIds.Add($change.id)) { throw "Duplicate change id: $($change.id)" }
            Assert-AssuranceScopes (Get-AssuranceValue $change 'scopeIds') "Change '$($change.id)' scopeIds"
            if ($change.impact -cnotin @('material', 'uncertain', 'informational')) {
                throw "Change '$($change.id)' impact must be material, uncertain or informational."
            }
            $occurredAt = Get-AssuranceTimestamp (Get-AssuranceValue $change 'occurredAt') "Change '$($change.id)' occurredAt"
            [pscustomobject]@{
                id = $change.id
                title = $change.title
                occurredAt = $occurredAt.ToString('o')
                scopeIds = @($change.scopeIds)
                impact = $change.impact
            }
        }
    )
    $objectiveIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rows = @(
        foreach ($objective in $Register.objectives) {
            foreach ($field in @('id', 'title', 'service', 'owner')) {
                Assert-AssuranceText (Get-AssuranceValue $objective $field) "Objective $field"
            }
            if (-not $objectiveIds.Add($objective.id)) { throw "Duplicate objective id: $($objective.id)" }
            Assert-AssuranceScopes (Get-AssuranceValue $objective 'scopeIds') "Objective '$($objective.id)' scopeIds"
            $window = Get-AssuranceValue $objective 'freshnessDays' $freshnessDays
            $warning = Get-AssuranceValue $objective 'dueSoonDays' $dueSoonDays
            Assert-AssurancePolicy $window $warning
            $issues = [Collections.Generic.List[string]]::new()
            $evidence = [Collections.Generic.List[object]]::new()
            $verification = Get-AssuranceValue $objective 'verification'
            $verifiedAt = $null
            $expiresAt = $null
            $age = $null
            $outcome = ''
            if ($null -eq $verification) {
                $issues.Add('No explicit verification has been registered.')
            }
            else {
                foreach ($field in @('reviewer', 'conclusion', 'outcome')) {
                    Assert-AssuranceText (Get-AssuranceValue $verification $field) "Objective '$($objective.id)' verification.$field"
                }
                $outcome = $verification.outcome
                if ($outcome -cnotin @('supported', 'refuted', 'inconclusive')) {
                    throw "Objective '$($objective.id)' verification.outcome must be supported, refuted or inconclusive."
                }
                $verifiedAt = Get-AssuranceTimestamp (Get-AssuranceValue $verification 'verifiedAt') "Objective '$($objective.id)' verifiedAt"
                $expiresAt = $verifiedAt.AddDays($window)
                $age = [Math]::Round(($AsOf - $verifiedAt).TotalDays, 2)
                if ($verifiedAt -gt $AsOf) { $issues.Add('Verification is in the future relative to this report.') }
                $sources = Get-AssuranceValue $verification 'sources'
                if ($sources -isnot [array] -or $sources.Count -eq 0) {
                    $issues.Add('Verification has no explicit artifact evidence references.')
                }
                else {
                    foreach ($source in $sources) {
                        $resolved = Resolve-PerceptionArtifactEvidence -Source $source -SessionIndex $sessionIndex `
                            -RecordedAt $verifiedAt -Field "Objective '$($objective.id)'"
                        foreach ($issue in $resolved.issues) {
                            $issues.Add("$($source.sessionId) / $($source.outputPath): $issue")
                        }
                        $evidence.Add($resolved)
                    }
                }
            }
            $relevantChanges = @($changes | Where-Object {
                $change = $_
                ([DateTimeOffset]$change.occurredAt) -le $AsOf -and
                ($null -eq $verifiedAt -or ([DateTimeOffset]$change.occurredAt) -gt $verifiedAt) -and
                @($change.scopeIds | Where-Object { $_ -cin $objective.scopeIds }).Count -gt 0
            } | Sort-Object occurredAt -Descending)
            $material = @($relevantChanges | Where-Object impact -eq 'material')
            $uncertain = @($relevantChanges | Where-Object impact -eq 'uncertain')
            $status = 'unknown'
            $reason = $issues -join ' '
            $nextAction = 'Register an explicit verification with a reviewer and exact artifact evidence.'
            if ($issues.Count -eq 0) {
                if ($outcome -eq 'refuted') {
                    $status = 'contradicted'
                    $reason = 'The latest registered verification refutes this assurance.'
                    $nextAction = 'Investigate the failed assurance, remediate and independently re-verify.'
                }
                elseif ($material.Count -gt 0) {
                    $status = 'changed'
                    $reason = 'A material change affects the registered scope after verification.'
                    $nextAction = 'Reassess the changed scope and its explicitly registered dependencies.'
                }
                elseif ($outcome -eq 'inconclusive') {
                    $reason = 'The registered verification was inconclusive.'
                    $nextAction = 'Resolve the evidence gaps before asserting this assurance.'
                }
                elseif ($AsOf -ge $expiresAt) {
                    $status = 'stale'
                    $reason = 'The verification freshness window has expired.'
                    $nextAction = 'Run an approved reassessment and register its verification evidence.'
                }
                elseif ($uncertain.Count -gt 0) {
                    $status = 'review'
                    $reason = 'A scope-matched change has uncertain impact.'
                    $nextAction = 'Review the change impact; re-verify if the conclusion may no longer apply.'
                }
                elseif ($AsOf -ge $expiresAt.AddDays(-$warning)) {
                    $status = 'due-soon'
                    $reason = 'Verification is within its warning window.'
                    $nextAction = 'Schedule reassessment before the evidence freshness window expires.'
                }
                else {
                    $status = 'fresh'
                    $reason = 'Supported evidence is within policy; no later material change is registered for this scope.'
                    $nextAction = 'Maintain change monitoring and reassess on material change or expiry.'
                }
            }
            [pscustomobject]@{
                id = $objective.id
                title = $objective.title
                service = $objective.service
                owner = $objective.owner
                scopeIds = @($objective.scopeIds)
                freshnessDays = $window
                dueSoonDays = $warning
                status = $status
                reason = $reason
                nextAction = $nextAction
                verifiedAt = if ($null -ne $verifiedAt) { $verifiedAt.ToString('o') } else { $null }
                expiresAt = if ($null -ne $expiresAt) { $expiresAt.ToString('o') } else { $null }
                ageDays = $age
                reviewer = [string](Get-AssuranceValue $verification 'reviewer')
                conclusion = [string](Get-AssuranceValue $verification 'conclusion')
                outcome = $outcome
                evidenceIssues = $issues.ToArray()
                evidence = $evidence.ToArray()
                changes = $relevantChanges
            }
        }
    )
    $counts = [ordered]@{}
    foreach ($state in @('fresh', 'due-soon', 'stale', 'changed', 'review', 'contradicted', 'unknown')) {
        $counts[$state] = @($rows | Where-Object status -eq $state).Count
    }
    $inventory = $snapshotEvidence.inventory
    [pscustomobject]@{
        schemaVersion = 1
        asOf = $AsOf.ToString('o')
        snapshotGeneratedAt = Get-AssuranceValue $Snapshot 'generatedAt'
        sessionCount = $sessions.Count
        objectiveCount = $rows.Count
        counts = [pscustomobject]$counts
        objectives = $rows
        evidenceInventory = $inventory
        changeCount = @($changes | Where-Object { ([DateTimeOffset]$_.occurredAt) -le $AsOf }).Count
        futureChangeCount = @($changes | Where-Object { ([DateTimeOffset]$_.occurredAt) -gt $AsOf }).Count
        limitations = @(
            'Fresh means registered supporting evidence is within policy, not that the environment is unchanged or safe.',
            'Changes are manually registered, not collected from a live change feed. Missing changes cannot be detected.',
            'Scope matching is exact and case-sensitive. Register dependency identifiers explicitly on each objective.',
            'Evidence references and exact excerpts are checked; their security meaning is attested by the named reviewer, not automatically proven.',
            'Session completion, agent activity and behavioral drift are not verification evidence.'
        )
    }
}
