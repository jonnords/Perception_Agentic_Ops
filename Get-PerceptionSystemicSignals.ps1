Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionReportEvidence.ps1')

function Get-SystemicHash {
    param([string]$Text)

    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function Get-SystemicEntities {
    param([string]$Text)

    $entities = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $patterns = @(
        @{ type = 'identity'; pattern = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b' },
        @{ type = 'ip'; pattern = '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])' }
    )
    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($Text, $pattern.pattern)) {
            $value = $match.Value.ToLowerInvariant()
            if ($pattern.type -eq 'ip') {
                $address = $null
                if (-not [Net.IPAddress]::TryParse($value, [ref]$address)) { continue }
                $value = $address.ToString()
            }
            $key = "$($pattern.type):$value"
            $entities[$key] = [pscustomobject]@{ key = $key; type = $pattern.type; value = $value }
        }
    }
    $labels = '(?i)\b(domain|hostname|host|device|server|user|account|identity|service principal|appId|application id|objectId|object id|ip(?: address)?)\s*[:=]\s*[`"'' ]*([^\s|,;`"''<>]+)'
    foreach ($match in [regex]::Matches($Text, $labels)) {
        $label = $match.Groups[1].Value.ToLowerInvariant()
        $value = $match.Groups[2].Value.TrimEnd('.', ')', ']').ToLowerInvariant()
        if ($value -in @('unknown', 'none', 'n/a', 'not', 'unavailable', '-')) { continue }
        $type = switch -Regex ($label) {
            '^ip' { 'ip'; break }
            '^(user|account|identity|service principal)$' { 'identity'; break }
            '^(app|object)' { 'directory-id'; break }
            '^domain$' { 'domain'; break }
            default { 'host' }
        }
        if ($type -eq 'ip') {
            $address = $null
            if (-not [Net.IPAddress]::TryParse($value, [ref]$address)) { continue }
            $value = $address.ToString()
        }
        if ($type -eq 'directory-id') {
            $guid = [Guid]::Empty
            if (-not [Guid]::TryParse($value, [ref]$guid)) { continue }
            $value = $guid.ToString()
        }
        $key = "${type}:$value"
        $entities[$key] = [pscustomobject]@{ key = $key; type = $type; value = $value }
    }
    @($entities.Values | Sort-Object key -CaseSensitive)
}

function Get-PerceptionSystemicSignals {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Insights)

    if ((Get-AssuranceValue $Insights 'sessions') -isnot [array]) {
        throw 'Systemic signals require snapshot insights with a sessions array.'
    }
    $rules = @(
        @{ id = 'identity-risk'; title = 'Identity compromise indicators'; pattern = '(?i)\b(?:suspicious|anomalous|unusual)\s+(?:sign[- ]?in|authentication)|\b(?:password spray|impossible travel|credential theft|compromised (?:account|identity|credentials|service principal))\b' },
        @{ id = 'execution'; title = 'Suspicious execution'; pattern = '(?i)\b(?:suspicious|malicious|encoded)\s+(?:process|command|script|powershell|execution)|\bcredential dumping\b' },
        @{ id = 'movement'; title = 'Movement or data loss'; pattern = '(?i)\b(?:lateral movement|exfiltration|ransomware)\b' },
        @{ id = 'privilege-gap'; title = 'Excessive privileges'; pattern = '(?i)\b(?:excessive|overly broad)\s+(?:privileges|permissions)|\boverprivileged\b'; weakness = $true },
        @{ id = 'mfa-gap'; title = 'Missing MFA'; pattern = '(?i)\b(?:missing|disabled)\s+(?:mfa|multi[- ]factor authentication)|\bmfa (?:is )?(?:missing|disabled|not enforced)\b'; weakness = $true },
        @{ id = 'public-exposure'; title = 'Public exposure'; pattern = '(?i)\b(?:publicly exposed|public exposure|unrestricted public access)\b'; weakness = $true }
    )
    $facts = [Collections.Generic.List[object]]::new()
    foreach ($session in $Insights.sessions) {
        $tenantTags = @($session.inputTags | Where-Object { $_ -cmatch '^input:tenant(?:-id)?=' } | Sort-Object -CaseSensitive)
        $tenant = if ($tenantTags.Count) { $tenantTags -join '|' } else { 'snapshot-tenant-unspecified' }
        $eventTags = @($session.inputTags | Where-Object { $_ -cmatch '^input:incident=' })
        if (-not $eventTags.Count) { $eventTags = @($session.inputTags | Where-Object { $_ -cmatch '^input:alert=' }) }
        $scope = if ($eventTags.Count -eq 1) { "$tenant|$($eventTags[0])" } else { "unresolved:$($session.id)" }
        $sourceKind = if ($session.isIntelligence) { 'intelligence-context' } else { 'operational-report' }
        foreach ($artifact in @($session.artifacts | Where-Object {
            $_.kind -eq 'artifact' -and $null -eq $_.error -and -not [string]::IsNullOrWhiteSpace($_.content)
        })) {
            $bodyHash = Get-SystemicHash ([regex]::Replace($artifact.content, '\s+', ' ').Trim().ToLowerInvariant())
            $sections = @($session.evidence | Where-Object {
                $_.path -ceq $artifact.path -and $_.category -in @('summary', 'findings', 'verdict', 'entities')
            })
            foreach ($section in $sections) {
                $inCode = $false
                $lines = $section.text -split '\r?\n'
                for ($index = 0; $index -lt $lines.Count; $index++) {
                    $line = $lines[$index]
                    if ($line -match '^\s*(```|~~~)') { $inCode = -not $inCode; continue }
                    if ($inCode -or [string]::IsNullOrWhiteSpace($line) -or
                        $line -match '(?i)\b(?:hypothetical|illustrative|for example|recommend(?:ed|ation)?|should|could|may indicate)\b') { continue }
                    $counter = $line -match '(?i)\b(?:no evidence of|no suspicious|no malicious|not observed|not detected|not malicious|not suspicious|benign|false positive|expected activity|legitimate activity|ruled out)\b'
                    $uncertain = $line -match '(?i)\b(?:inconclusive|insufficient evidence|cannot confirm|unconfirmed|potential|possible)\b'
                    $themes = @(
                        if (-not $counter -and -not $uncertain) {
                            foreach ($rule in $rules) { if ($line -match $rule.pattern) { $rule.id } }
                        }
                    )
                    $entities = @(Get-SystemicEntities $line)
                    if (-not $entities.Count -and -not $themes.Count -and -not $counter) { continue }
                    $facts.Add([pscustomobject]@{
                        sessionId = $session.id; path = $artifact.path; line = $section.line + $index
                        excerpt = $line; workflow = $session.workflow; startedAt = $session.startedAt
                        sourceKind = $sourceKind; tenantScope = $tenant; inputScope = $scope
                        knownEventScope = $eventTags.Count -eq 1; contentHash = $bodyHash
                        entities = $entities; themes = $themes
                        stance = if ($counter) { 'potential-counterevidence' } elseif ($uncertain) { 'uncertain' }
                            elseif ($themes.Count) { 'reported-risk' } else { 'mention' }
                    })
                }
            }
        }
    }
    $correlations = [Collections.Generic.List[object]]::new()
    $hypotheses = [Collections.Generic.List[object]]::new()
    $entityIndex = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($fact in $facts) {
        foreach ($entity in $fact.entities) {
            $key = "$($fact.tenantScope)|$($entity.key)"
            if (-not $entityIndex.ContainsKey($key)) {
                $entityIndex[$key] = [pscustomobject]@{ entity = $entity; facts = [Collections.Generic.List[object]]::new() }
            }
            $entityIndex[$key].facts.Add($fact)
        }
    }
    foreach ($key in @($entityIndex.Keys | Sort-Object -CaseSensitive)) {
        $entry = $entityIndex[$key]
        $operational = @($entry.facts | Where-Object sourceKind -eq 'operational-report')
        $sessionIds = @($operational | ForEach-Object sessionId | Sort-Object -Unique -CaseSensitive)
        if ($sessionIds.Count -lt 2) { continue }
        $support = @($operational | Where-Object stance -eq 'reported-risk')
        $counter = @($operational | Where-Object stance -eq 'potential-counterevidence')
        $context = @($entry.facts | Where-Object sourceKind -eq 'intelligence-context')
        $hashes = @($operational | ForEach-Object contentHash | Sort-Object -Unique)
        $scopeCount = @($operational | Where-Object knownEventScope | ForEach-Object inputScope | Sort-Object -Unique -CaseSensitive).Count
        $id = (Get-SystemicHash $key).Substring(0, 20)
        $correlations.Add([pscustomobject]@{
            id = $id; entity = $entry.entity; sessionIds = $sessionIds
            inputScopeCount = $scopeCount; distinctContentCount = $hashes.Count
            evidence = $operational; intelligenceContext = $context
            explanation = 'Exact normalised entity mentions in multiple operational sessions. This is a factual text correlation, not proof of common activity or independent corroboration.'
        })
        $supportSessions = @($support | ForEach-Object sessionId | Sort-Object -Unique -CaseSensitive)
        $supportHashes = @($support | ForEach-Object contentHash | Sort-Object -Unique)
        $themes = @($support | ForEach-Object themes | Sort-Object -Unique)
        if ($supportSessions.Count -ge 2 -and $supportHashes.Count -ge 2 -and $themes.Count -ge 2) {
            $hypotheses.Add([pscustomobject]@{
                id = "entity-$id"; kind = 'cross-run-risk'; title = "Related risk signals involving $($entry.entity.value)"
                correlationId = $id; status = 'Unverified hypothesis'; rule = 'shared-entity-complementary-risk'
                explanation = 'Different risk themes are reported for the same exact entity across multiple non-identical operational outputs. They may describe a connected issue, but no causal or attack-chain relationship has been established.'
                evidence = $support; counterevidence = $counter; intelligenceContext = $context
                themes = $themes; inputScopeCount = $scopeCount; distinctContentCount = $supportHashes.Count
                alternatives = @('Unrelated events involving a common identity, host or shared infrastructure.', 'Repeated or paraphrased analysis of the same underlying telemetry.')
                missingEvidence = @('Verify entity ownership, tenant and event-time overlap in the original telemetry.', 'Establish whether the reports rely on independent underlying observations.', 'Resolve uncertain and conflicting conclusions; agent awareness of the combined pattern has not been assessed.')
                nextChecks = @('Pivot on the exact entity in the cited investigations and compare original event timestamps, identifiers and provenance.', 'Ask an investigator to test a common-cause explanation against routine activity and the cited counterevidence.')
            })
        }
    }
    foreach ($rule in @($rules | Where-Object { $_.ContainsKey('weakness') })) {
        $byTenant = @($facts | Where-Object {
            $_.sourceKind -eq 'operational-report' -and $rule.id -in $_.themes
        } | Group-Object tenantScope -CaseSensitive)
        foreach ($group in $byTenant) {
            $support = @($group.Group)
            $scopes = @($support | Where-Object knownEventScope | ForEach-Object inputScope | Sort-Object -Unique -CaseSensitive)
            $hashes = @($support | ForEach-Object contentHash | Sort-Object -Unique)
            if ($scopes.Count -lt 2 -or $hashes.Count -lt 2) { continue }
            $counter = @($facts | Where-Object {
                $_.tenantScope -ceq $group.Name -and $_.sourceKind -eq 'operational-report' -and
                $_.stance -eq 'potential-counterevidence' -and $_.excerpt -match $rule.pattern
            })
            $hypotheses.Add([pscustomobject]@{
                id = "weakness-$($rule.id)-$((Get-SystemicHash $group.Name).Substring(0, 12))"
                kind = 'recurring-control-gap'; title = "Recurring reported weakness: $($rule.title)"
                correlationId = $null; status = 'Unverified hypothesis'; rule = $rule.id
                explanation = 'The same explicit control-gap wording appears in non-identical operational outputs for multiple incident/alert input scopes. A common control weakness is possible; actual prevalence and independent corroboration remain unverified.'
                evidence = $support; counterevidence = $counter; intelligenceContext = @()
                themes = @($rule.id); inputScopeCount = $scopes.Count; distinctContentCount = $hashes.Count
                alternatives = @('A small or biased incident sample rather than an organisation-wide weakness.', 'A common template or reused evidence rather than separate observed failures.')
                missingEvidence = @('Confirm the reported gap against current configuration and original telemetry.', 'Determine the affected population, exceptions and whether the inputs represent independent events.')
                nextChecks = @("Review the cited $($rule.title.ToLowerInvariant()) findings with the control owner.", 'Test representative affected and unaffected assets before making an organisation-wide claim.')
            })
        }
    }
    [pscustomobject]@{
        schemaVersion = 1; asOf = $Insights.asOf; method = 'Local deterministic correlation and explicit wording rules; no model calls.'
        correlations = $correlations.ToArray(); hypotheses = $hypotheses.ToArray()
        sessionCount = $Insights.sessionCount; extractedFactCount = $facts.Count
        limitations = @(
            'This view cannot establish whether an agent already recognised the combined pattern, or whether a real systemic threat exists.',
            'Only retained, readable artifact sections are analysed. Recommendations, fenced code and agent transcripts are not treated as observations.',
            'Entity matches use exact normalised identifiers, not fuzzy names or inferred aliases. Tenant-tagged and unspecified-tenant evidence are not merged.',
            'Input scopes and non-identical report text do not establish independent underlying telemetry. Repeated runs are not independent confirmation.',
            'Intelligence reports are context only and cannot create an operational correlation or support a threat hypothesis.',
            'Quoted risk wording is not verified activity. Negation and uncertainty handling is conservative and not a full natural-language understanding system.',
            'Session start times are provenance, not event times. No temporal, causal, campaign or remediation conclusion is inferred.',
            'An empty result means no supported rule match in this snapshot, not an absence of systemic threats.'
        )
    }
}
