Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionReportEvidence.ps1')

function Add-ProtectionIssue {
    param([object]$Milestone, [string]$Message)

    $Milestone.state = 'unknown'
    $Milestone.issues = @($Milestone.issues) + $Message
}

function Get-ProtectionMilestone {
    param(
        [AllowNull()][object]$Value,
        [string]$Field,
        [Collections.Generic.Dictionary[string, object]]$SessionIndex,
        [DateTimeOffset]$AsOf,
        [AllowNull()][object]$NotBefore = $null
    )

    $result = [pscustomobject]@{
        state = 'missing'; at = $null; reviewer = ''; summary = ''
        issues = @(); evidence = @()
    }
    if ($null -eq $Value) { return $result }
    foreach ($name in @('reviewer', 'summary')) {
        Assert-AssuranceText (Get-AssuranceValue $Value $name) "$Field.$name"
    }
    $at = Get-AssuranceTimestamp (Get-AssuranceValue $Value 'at') "$Field.at"
    $result.state = 'complete'
    $result.at = $at.ToString('o')
    $result.reviewer = $Value.reviewer
    $result.summary = $Value.summary
    if ($at -gt $AsOf) { Add-ProtectionIssue $result 'Milestone is after the report cutoff.' }
    if ($null -ne $NotBefore -and $at -lt [DateTimeOffset]$NotBefore) {
        Add-ProtectionIssue $result 'Milestone precedes its prerequisite or intelligence arrival.'
    }
    $sources = Get-AssuranceValue $Value 'sources'
    if ($sources -isnot [array] -or $sources.Count -eq 0) {
        Add-ProtectionIssue $result 'No explicit artifact evidence references.'
    }
    else {
        foreach ($source in $sources) {
            $resolved = Resolve-PerceptionArtifactEvidence -Source $source -SessionIndex $SessionIndex -RecordedAt $at -Field $Field
            $result.evidence += $resolved
            foreach ($issue in $resolved.issues) {
                Add-ProtectionIssue $result "$($resolved.sessionId) / $($resolved.outputPath): $issue"
            }
        }
    }
    $result
}

function Assert-ProtectionReferences {
    param([object]$Values, [string[]]$Allowed, [string]$Field)

    Assert-AssuranceScopes $Values $Field
    if (@($Values | Sort-Object -Unique -CaseSensitive).Count -ne $Values.Count) {
        throw "$Field contains duplicate identifiers."
    }
    foreach ($value in $Values) {
        if ($value -cnotin $Allowed) { throw "$Field references an unregistered identifier: $value" }
    }
}

function Get-ProtectionScopedMilestone {
    param(
        [AllowNull()][object]$Value, [string]$Field,
        [Collections.Generic.Dictionary[string, object]]$SessionIndex,
        [DateTimeOffset]$AsOf, [object]$NotBefore,
        [string[]]$RequiredAssets, [switch]$EstablishAssets
    )

    $result = Get-ProtectionMilestone $Value $Field $SessionIndex $AsOf $NotBefore
    $assetIds = @()
    if ($null -ne $Value) {
        $assetIds = Get-AssuranceValue $Value 'assetIds'
        Assert-AssuranceScopes (Get-AssuranceValue $Value 'assetIds') "$Field.assetIds"
        if (@($assetIds | Sort-Object -Unique -CaseSensitive).Count -ne $assetIds.Count) {
            throw "$Field.assetIds contains duplicate identifiers."
        }
        if (-not $EstablishAssets -and $result.state -eq 'complete') {
            if ($RequiredAssets.Count -eq 0) {
                Add-ProtectionIssue $result 'Relevant asset scope has not been established.'
            }
            elseif (@($RequiredAssets | Where-Object { $_ -cnotin $assetIds }).Count -gt 0) {
                $result.state = 'partial'
                $result.issues += 'Evidence does not cover every registered relevant asset.'
            }
        }
    }
    $result | Add-Member assetIds $assetIds
    $result
}

function Get-PerceptionThreatProtection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Register,
        [DateTimeOffset]$AsOf = [DateTimeOffset]::UtcNow
    )

    if ((Get-AssuranceValue $Register 'schemaVersion') -ne 1 -or
        (Get-AssuranceValue $Register 'threats') -isnot [array]) {
        throw 'The protection register requires schemaVersion 1 and a threats array.'
    }
    $snapshotEvidence = Get-PerceptionSnapshotEvidence $Snapshot
    $sessions = $snapshotEvidence.sessions
    $index = $snapshotEvidence.sessionIndex
    $threatIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rows = @(
        foreach ($threat in $Register.threats) {
            foreach ($name in @('id', 'title', 'owner', 'source', 'relevance')) {
                Assert-AssuranceText (Get-AssuranceValue $threat $name) "Threat $name"
            }
            if (-not $threatIds.Add($threat.id)) { throw "Duplicate threat id: $($threat.id)" }
            if ($threat.relevance -cnotin @('relevant', 'unknown', 'not-relevant')) {
                throw "Threat '$($threat.id)' relevance must be relevant, unknown or not-relevant."
            }
            foreach ($name in @('behaviours', 'detections')) {
                if ((Get-AssuranceValue $threat $name) -isnot [array]) { throw "Threat '$($threat.id)' requires a $name array." }
            }
            $received = Get-AssuranceTimestamp (Get-AssuranceValue $threat 'receivedAt') "Threat '$($threat.id)' receivedAt"
            $assets = Get-ProtectionScopedMilestone (Get-AssuranceValue $threat 'assets') 'assets' $index $AsOf $received @() -EstablishAssets
            $assetIds = @($assets.assetIds)
            $assessmentStart = if ($assets.at) { $assets.at } else { $received }
            $assessmentRaw = Get-AssuranceValue $threat 'assessment'
            $assessment = Get-ProtectionScopedMilestone $assessmentRaw 'assessment' $index $AsOf $assessmentStart $assetIds
            if ($null -ne $assessmentRaw -and (Get-AssuranceValue $assessmentRaw 'kind') -cnotin @('investigation', 'recon', 'both')) {
                throw 'assessment.kind must be investigation, recon or both.'
            }
            $decisionStart = if ($assessment.at) { $assessment.at } else { $assessmentStart }
            $decisionRaw = Get-AssuranceValue $threat 'exposureDecision'
            $decision = Get-ProtectionScopedMilestone $decisionRaw 'exposureDecision' $index $AsOf $decisionStart $assetIds
            if ($null -ne $decisionRaw -and (Get-AssuranceValue $decisionRaw 'decision') -cnotin @('remediate', 'accepted-risk', 'no-exposure')) {
                throw 'exposureDecision.decision must be remediate, accepted-risk or no-exposure.'
            }
            $behaviourIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $behaviours = @(
                foreach ($behaviour in $threat.behaviours) {
                    foreach ($name in @('id', 'title')) {
                        Assert-AssuranceText (Get-AssuranceValue $behaviour $name) "Behaviour $name"
                    }
                    if (-not $behaviourIds.Add($behaviour.id)) { throw "Duplicate behaviour id: $($behaviour.id)" }
                    [pscustomobject]@{
                        id = $behaviour.id
                        title = $behaviour.title
                        observation = Get-ProtectionMilestone (Get-AssuranceValue $behaviour 'observation') 'observation' $index $AsOf $received
                        candidateAssetIds = @()
                        coveredAssetIds = @()
                        uncoveredAssetIds = @()
                        covered = $false
                        verifiedAt = $null
                    }
                }
            )
            $detectionIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $detections = @(
                foreach ($detection in $threat.detections) {
                    foreach ($name in @('id', 'title')) {
                        Assert-AssuranceText (Get-AssuranceValue $detection $name) "Detection $name"
                    }
                    if (-not $detectionIds.Add($detection.id)) { throw "Duplicate detection id: $($detection.id)" }
                    Assert-ProtectionReferences (Get-AssuranceValue $detection 'behaviourIds') @($behaviours | ForEach-Object id) 'Detection behaviourIds'
                    Assert-AssuranceScopes (Get-AssuranceValue $detection 'assetIds') 'Detection assetIds'
                    if ($assetIds.Count -gt 0) { Assert-ProtectionReferences $detection.assetIds $assetIds 'Detection assetIds' }
                    $candidate = Get-ProtectionMilestone (Get-AssuranceValue $detection 'candidate') 'candidate' $index $AsOf
                    $reviewRaw = Get-AssuranceValue $detection 'review'
                    $review = Get-ProtectionMilestone $reviewRaw 'review' $index $AsOf $candidate.at
                    if ($null -ne $reviewRaw) {
                        if ((Get-AssuranceValue $reviewRaw 'outcome') -cnotin @('approved', 'rejected')) { throw 'review.outcome must be approved or rejected.' }
                        if ($candidate.state -ne 'complete') { Add-ProtectionIssue $review 'Candidate evidence is not complete.' }
                        elseif ($review.state -eq 'complete' -and $reviewRaw.outcome -eq 'rejected') { $review.state = 'failed' }
                    }
                    $deploymentRaw = Get-AssuranceValue $detection 'deployment'
                    $deployment = Get-ProtectionMilestone $deploymentRaw 'deployment' $index $AsOf $review.at
                    if ($null -ne $deploymentRaw) {
                        Assert-AssuranceText (Get-AssuranceValue $deploymentRaw 'ruleId') 'deployment.ruleId'
                        if ($review.state -ne 'complete') { Add-ProtectionIssue $deployment 'Deployment has no evidenced approved review.' }
                    }
                    $validationRaw = Get-AssuranceValue $detection 'validation'
                    $validationStart = $received
                    foreach ($time in @($deployment.at, $decision.at)) {
                        if ($null -ne $time -and [DateTimeOffset]$time -gt $validationStart) { $validationStart = [DateTimeOffset]$time }
                    }
                    $validation = Get-ProtectionMilestone $validationRaw 'validation' $index $AsOf $validationStart
                    $validatedAssets = @()
                    $validatedBehaviours = @()
                    if ($null -ne $validationRaw) {
                        if ((Get-AssuranceValue $validationRaw 'outcome') -cnotin @('passed', 'failed', 'inconclusive')) {
                            throw 'validation.outcome must be passed, failed or inconclusive.'
                        }
                        Assert-ProtectionReferences (Get-AssuranceValue $validationRaw 'assetIds') $detection.assetIds 'Validation assetIds'
                        Assert-ProtectionReferences (Get-AssuranceValue $validationRaw 'behaviourIds') $detection.behaviourIds 'Validation behaviourIds'
                        $validatedAssets = @($validationRaw.assetIds)
                        $validatedBehaviours = @($validationRaw.behaviourIds)
                        if ($deployment.state -ne 'complete') { Add-ProtectionIssue $validation 'Validation has no evidenced approved and deployed detection.' }
                        elseif ($validation.state -eq 'complete' -and $validationRaw.outcome -eq 'failed') { $validation.state = 'failed' }
                        elseif ($validationRaw.outcome -eq 'inconclusive') { Add-ProtectionIssue $validation 'Validation outcome is inconclusive.' }
                    }
                    $queue = if ($review.state -eq 'failed') { 'rejected' }
                    elseif ($validation.state -eq 'failed') { 'failed-validation' }
                    elseif ($candidate.state -ne 'complete') { 'evidence-gap' }
                    elseif ($review.state -eq 'missing') { 'awaiting-review' }
                    elseif ($review.state -ne 'complete') { 'evidence-gap' }
                    elseif ($deployment.state -eq 'missing') { 'awaiting-deployment' }
                    elseif ($deployment.state -ne 'complete') { 'evidence-gap' }
                    elseif ($validation.state -eq 'missing') { 'awaiting-validation' }
                    elseif ($validation.state -ne 'complete') { 'evidence-gap' }
                    else { 'validated' }
                    [pscustomobject]@{
                        id = $detection.id; title = $detection.title
                        behaviourIds = @($detection.behaviourIds); assetIds = @($detection.assetIds)
                        candidate = $candidate; review = $review; deployment = $deployment; validation = $validation
                        validatedAssetIds = $validatedAssets; validatedBehaviourIds = $validatedBehaviours
                        queue = $queue
                    }
                }
            )
            foreach ($behaviour in $behaviours) {
                $pairTimes = [Collections.Generic.List[DateTimeOffset]]::new()
                foreach ($asset in $assetIds) {
                    $candidates = @($detections | Where-Object {
                        $behaviour.id -cin $_.behaviourIds -and $asset -cin $_.assetIds -and $_.candidate.state -eq 'complete'
                    })
                    if ($candidates.Count -gt 0) { $behaviour.candidateAssetIds += $asset }
                    $covering = @($detections | Where-Object {
                        $_.validation.state -eq 'complete' -and $behaviour.id -cin $_.validatedBehaviourIds -and $asset -cin $_.validatedAssetIds
                    } | Sort-Object { [DateTimeOffset]$_.validation.at })
                    if ($covering.Count -gt 0) {
                        $behaviour.coveredAssetIds += $asset
                        $pairTimes.Add([DateTimeOffset]$covering[0].validation.at)
                    }
                    else { $behaviour.uncoveredAssetIds += $asset }
                }
                $behaviour.covered = $assets.state -eq 'complete' -and $assetIds.Count -gt 0 -and $behaviour.uncoveredAssetIds.Count -eq 0
                if ($behaviour.covered) { $behaviour.verifiedAt = ($pairTimes | Sort-Object | Select-Object -Last 1).ToString('o') }
            }
            $candidateCount = @($behaviours | Where-Object {
                $assetIds.Count -gt 0 -and $_.candidateAssetIds.Count -eq $assetIds.Count
            }).Count
            $coveredCount = @($behaviours | Where-Object covered).Count
            $detectionState = if ($behaviours.Count -gt 0 -and $candidateCount -eq $behaviours.Count) { 'complete' }
            elseif ($candidateCount -gt 0 -or $detections.Count -gt 0) { 'partial' } else { 'missing' }
            $validationState = if ($behaviours.Count -gt 0 -and $coveredCount -eq $behaviours.Count) { 'complete' }
            elseif (@($detections | Where-Object { $_.validation.state -eq 'failed' }).Count -gt 0) { 'failed' }
            elseif ($coveredCount -gt 0) { 'partial' } else { 'missing' }
            $inScope = $threat.relevance -eq 'relevant' -and $received -le $AsOf
            $verified = $inScope -and $assets.state -eq 'complete' -and $assessment.state -eq 'complete' -and
                $decision.state -eq 'complete' -and $validationState -eq 'complete'
            $protectedAt = $null
            $leadHours = $null
            if ($verified) {
                $times = @($received, [DateTimeOffset]$assets.at, [DateTimeOffset]$assessment.at, [DateTimeOffset]$decision.at) +
                    @($behaviours | ForEach-Object { [DateTimeOffset]$_.verifiedAt })
                $protectedAt = ($times | Sort-Object | Select-Object -Last 1).ToString('o')
                $leadHours = [Math]::Round(([DateTimeOffset]$protectedAt - $received).TotalHours, 3)
            }
            $gaps = [Collections.Generic.List[string]]::new()
            if ($received -gt $AsOf) { $gaps.Add('Intelligence has not arrived at the report cutoff.') }
            if ($threat.relevance -eq 'unknown') { $gaps.Add('Threat relevance needs review.') }
            if ($assets.state -ne 'complete') { $gaps.Add('Relevant assets need evidenced scoping.') }
            if ($assessment.state -ne 'complete') { $gaps.Add('Environmental assessment is missing, partial or unevidenced.') }
            if ($decision.state -ne 'complete') { $gaps.Add('Exposure decision is missing, partial or unevidenced.') }
            if ($behaviours.Count -eq 0) { $gaps.Add('No in-scope behaviours have been registered.') }
            if ($coveredCount -lt $behaviours.Count) { $gaps.Add('Not every in-scope behaviour has validated detection coverage across all relevant assets.') }
            $status = if ($received -gt $AsOf) { 'not-arrived' }
            elseif ($threat.relevance -eq 'not-relevant') { 'not-relevant' }
            elseif ($threat.relevance -eq 'unknown') { 'needs-relevance' }
            elseif ($verified) { 'verified' }
            elseif ($assessment.state -ne 'complete') { 'assessment-gap' }
            elseif ($coveredCount -lt $behaviours.Count -or $behaviours.Count -eq 0) { 'coverage-gap' }
            else { 'pipeline-gap' }
            [pscustomobject]@{
                id = $threat.id; title = $threat.title; owner = $threat.owner
                source = $threat.source; relevance = $threat.relevance
                receivedAt = $received.ToString('o'); status = $status
                ageHours = if ($received -le $AsOf) { [Math]::Round(($AsOf - $received).TotalHours, 2) } else { $null }
                verified = $verified; protectedAt = $protectedAt; leadTimeHours = $leadHours
                stages = [pscustomobject]@{
                    intelligence = [pscustomobject]@{ state = if ($received -le $AsOf) { 'complete' } else { 'unknown' }; at = $received.ToString('o') }
                    assets = $assets; assessment = $assessment; decision = $decision
                    detection = [pscustomobject]@{ state = $detectionState; summary = "$candidateCount / $($behaviours.Count) behaviours have candidates across relevant assets." }
                    validation = [pscustomobject]@{ state = $validationState; summary = "$coveredCount / $($behaviours.Count) behaviours have validated coverage across relevant assets." }
                }
                behaviours = $behaviours; detections = $detections; gaps = $gaps.ToArray()
                needsAssessment = $inScope -and $assessment.state -ne 'complete'
                observedCoverageGaps = @($behaviours | Where-Object { $_.observation.state -eq 'complete' -and -not $_.covered }).Count
            }
        }
    )
    $relevant = @($rows | Where-Object { $_.relevance -eq 'relevant' -and $_.status -ne 'not-arrived' })
    $verifiedRows = @($relevant | Where-Object verified)
    $observedGapCount = 0
    foreach ($row in $relevant) { $observedGapCount += $row.observedCoverageGaps }
    $leadTimes = @($verifiedRows | ForEach-Object leadTimeHours | Sort-Object)
    $median = $null
    if ($leadTimes.Count -gt 0) {
        $middle = [int][Math]::Floor($leadTimes.Count / 2)
        $median = if ($leadTimes.Count % 2 -eq 0) { ($leadTimes[$middle - 1] + $leadTimes[$middle]) / 2 } else { $leadTimes[$middle] }
    }
    $inventory = $snapshotEvidence.inventory
    [pscustomobject]@{
        schemaVersion = 1; asOf = $AsOf.ToString('o')
        snapshotGeneratedAt = Get-AssuranceValue $Snapshot 'generatedAt'
        sessionCount = $sessions.Count; threatCount = $rows.Count
        summary = [pscustomobject]@{
            relevantThreats = $relevant.Count
            noAssessment = @($relevant | Where-Object needsAssessment).Count
            observedCoverageGaps = $observedGapCount
            awaitingReview = @($relevant | ForEach-Object detections | Where-Object queue -eq 'awaiting-review').Count
            awaitingDeployment = @($relevant | ForEach-Object detections | Where-Object queue -eq 'awaiting-deployment').Count
            verifiedThreats = $verifiedRows.Count
            waitingThreats = $relevant.Count - $verifiedRows.Count
            medianLeadTimeHours = $median
        }
        threats = $rows; evidenceInventory = $inventory
        limitations = @(
            'This is an explicit local register, not an automatic threat-intelligence feed or a live deployment inventory.',
            'Every registered in-scope behaviour must have passed validation on every relevant asset, with evidenced scoping, assessment and exposure decision, before a threat counts as protected.',
            'References and exact excerpts are checked. Named reviewers attest relevance, security meaning and coverage; text matching does not prove control effectiveness.',
            'Lead time uses the earliest registered passing validation per behaviour/asset pair, then the latest required milestone. Missing protection is never reported as zero lead time.',
            'Previously deployed controls can count only after evidenced review/deployment and validation after intelligence arrival and the exposure decision.',
            'Risk acceptance and no-exposure decisions do not bypass detection coverage. Snapshot contents and current register records are not a historical event store.'
            'Protection here means evidenced detection readiness for the registered scope, not proof that exposures were remediated or an adversary was evicted.'
        )
    }
}
