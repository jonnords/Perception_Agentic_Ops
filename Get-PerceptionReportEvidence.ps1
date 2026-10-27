Set-StrictMode -Version Latest

function Get-AssuranceValue {
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Name, [object]$Default = $null)

    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties[$Name]) {
        return ,$Value.PSObject.Properties[$Name].Value
    }
    return $Default
}

function Get-AssuranceTimestamp {
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Field)

    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [DateTime] -and $Value.Kind -ne [DateTimeKind]::Unspecified) {
        return [DateTimeOffset]$Value
    }
    $parsed = [DateTimeOffset]::MinValue
    if ($Value -isnot [string] -or $Value -notmatch '(Z|[+-]\d{2}:\d{2})$' -or
        -not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw "$Field must be an ISO 8601 timestamp with a timezone."
    }
    $parsed
}

function Assert-AssuranceText {
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Field)

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
        throw "$Field must be a non-empty string."
    }
}

function Assert-AssuranceScopes {
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Field)

    if ($Value -isnot [array] -or $Value.Count -eq 0) {
        throw "$Field must be a non-empty array of explicit scope identifiers."
    }
    foreach ($scope in $Value) { Assert-AssuranceText $scope $Field }
}

function Get-PerceptionSnapshotEvidence {
    param([Parameter(Mandatory)][object]$Snapshot)

    $sessionValue = Get-AssuranceValue $Snapshot 'sessions'
    $sessions = @(if ($null -ne $sessionValue) { $sessionValue } else { $Snapshot })
    $index = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($session in $sessions) {
        Assert-AssuranceText (Get-AssuranceValue $session 'id') 'Snapshot session id'
        if (-not $index.TryAdd($session.id, $session)) { throw "Duplicate snapshot session id: $($session.id)" }
        if ((Get-AssuranceValue $session 'markdownOutputs') -isnot [array]) {
            throw "Snapshot session '$($session.id)' must contain a markdownOutputs array."
        }
    }
    $inventory = @(
        foreach ($session in $sessions) {
            foreach ($output in $session.markdownOutputs) {
                $content = [string](Get-AssuranceValue $output 'content')
                [pscustomobject]@{
                    sessionId = $session.id
                    sessionName = [string](Get-AssuranceValue $session 'displayName')
                    createdAt = Get-AssuranceValue $session 'createdAt'
                    outputPath = [string](Get-AssuranceValue $output 'path')
                    available = $null -eq (Get-AssuranceValue $output 'error') -and
                        -not [string]::IsNullOrWhiteSpace($content)
                    content = $content
                    error = Get-AssuranceValue $output 'error'
                }
            }
        }
    )
    [pscustomobject]@{ sessions = $sessions; sessionIndex = $index; inventory = $inventory }
}

function Resolve-PerceptionArtifactEvidence {
    param(
        [Parameter(Mandatory)][object]$Source,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.Dictionary[string, object]]$SessionIndex,
        [Parameter(Mandatory)][DateTimeOffset]$RecordedAt,
        [string]$Field = 'Evidence'
    )

    foreach ($name in @('sessionId', 'outputPath', 'excerpt')) {
        Assert-AssuranceText (Get-AssuranceValue $Source $name) "$Field source.$name"
    }
    $issues = [Collections.Generic.List[string]]::new()
    $session = $null
    if (-not $SessionIndex.TryGetValue($Source.sessionId, [ref]$session)) {
        $issues.Add('Referenced session is absent from the snapshot.')
    }
    else {
        $outputs = @($session.markdownOutputs | Where-Object {
            [string](Get-AssuranceValue $_ 'path') -ceq $Source.outputPath
        })
        if ($outputs.Count -ne 1) {
            $issues.Add('Referenced artifact is missing or ambiguous.')
        }
        else {
            $content = [string](Get-AssuranceValue $outputs[0] 'content')
            if ($null -ne (Get-AssuranceValue $outputs[0] 'error') -or [string]::IsNullOrWhiteSpace($content)) {
                $issues.Add('Referenced artifact could not be collected or has no content.')
            }
            elseif (-not $content.Contains($Source.excerpt, [StringComparison]::Ordinal)) {
                $issues.Add('The exact evidence excerpt is absent from the referenced artifact.')
            }
        }
        $created = Get-AssuranceValue $session 'createdAt'
        if ($null -ne $created -and (Get-AssuranceTimestamp $created 'Session createdAt') -gt $RecordedAt) {
            $issues.Add('Referenced session was created after the registered verification.')
        }
    }
    [pscustomobject]@{
        sessionId = $Source.sessionId
        sessionName = [string](Get-AssuranceValue $session 'displayName')
        outputPath = $Source.outputPath
        excerpt = $Source.excerpt
        valid = $issues.Count -eq 0
        issues = $issues.ToArray()
    }
}
