#requires -Version 7.0

<#
.SYNOPSIS
Creates a standalone comparison report for Perception incident investigations and Defender incidents.

.DESCRIPTION
Enumerates Perception sessions across all supported states, follows usable continuation links,
selects sessions tagged with playbookId=investigate-incident, and joins each session to the exact
Microsoft Defender incident identified by its input:incident tag.

The script writes an interactive HTML view, JSON, and CSV. Individual session, run, or Defender
lookup failures are retained in the report instead of stopping the complete collection.

.EXAMPLE
.\New-PerceptionDefenderInvestigationReport.ps1

.EXAMPLE
.\New-PerceptionDefenderInvestigationReport.ps1 `
    -GraphTokenPath .\graph-token.txt `
    -MaxSessionPagesPerState 20

.EXAMPLE
.\New-PerceptionDefenderInvestigationReport.ps1 -SessionId 'known-session-id' -NoOpen
#>

[CmdletBinding()]
param(
    [string]$GraphTokenPath = '',

    [string]$ConfigurationPath = '',

    [ValidatePattern('^https://')]
    [string]$PerceptionApiBaseUrl = 'https://perception.microsoft.com/api/v1.0',

    [string]$PerceptionTokenScope = 'https://api.securitycopilot.microsoft.com/Perception.Operate.All',

    [ValidateRange(1, 500)]
    [int]$SessionPageSize = 500,

    [ValidateRange(1, 100)]
    [int]$MaxSessionPagesPerState = 100,

    [ValidateRange(10, 300)]
    [int]$RequestTimeoutSeconds = 90,

    [ValidateRange(0, 10)]
    [int]$RetryCount = 3,

    [ValidateRange(1, 500)]
    [int]$MessagePageSize = 500,

    [ValidateRange(1, 50)]
    [int]$MessagePageLimit = 20,

    [ValidatePattern('^\d{1,32}$')]
    [string]$IncidentIdFilter,

    [ValidateNotNullOrEmpty()]
    [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
    [string[]]$SessionId = @(),

    [string]$OutputPath,

    [string]$JsonOutputPath,

    [string]$CsvOutputPath,

    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
$configuration = Get-PerceptionConfiguration -Path $ConfigurationPath

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptRoot 'Perception-Defender-Investigations.html'
}
if ([string]::IsNullOrWhiteSpace($JsonOutputPath)) {
    $JsonOutputPath = Join-Path $scriptRoot 'Perception-Defender-Investigations.json'
}
if ([string]::IsNullOrWhiteSpace($CsvOutputPath)) {
    $CsvOutputPath = Join-Path $scriptRoot 'Perception-Defender-Investigations.csv'
}

$script:requestCount = 0
$script:retryAttemptCount = 0
$script:supportsSkipHttpErrorCheck = (Get-Command Invoke-WebRequest).Parameters.ContainsKey('SkipHttpErrorCheck')
$collectionStopwatch = [Diagnostics.Stopwatch]::StartNew()
$sessionStates = @('queued', 'running', 'pendingInput', 'completed', 'failed', 'canceled')
$incidentFields = 'id,displayName,status,severity,classification,determination,createdDateTime,lastUpdateDateTime,incidentWebUrl'

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)

    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-PerceptionPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    $property.Value
}

function Get-PerceptionLifecycleState {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        return ''
    }

    $stateProperty = $InputObject.PSObject.Properties['state']
    if ($null -ne $stateProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$stateProperty.Value)) {
        return [string]$stateProperty.Value
    }

    $statusProperty = $InputObject.PSObject.Properties['status']
    if ($null -ne $statusProperty) {
        return [string]$statusProperty.Value
    }

    ''
}

function Get-JwtClaims {
    param([Parameter(Mandatory)][string]$Token)

    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) {
        throw 'The supplied Microsoft Graph token is not a JWT.'
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        1 { throw 'The Microsoft Graph token has invalid Base64Url encoding.' }
    }

    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    $json | ConvertFrom-Json -ErrorAction Stop
}

function Get-GraphTokenFromFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Microsoft Graph token file was not found: $Path"
    }

    $raw = (Get-Content -Raw -LiteralPath $Path).Trim()
    $token = $raw
    if ($raw.StartsWith('{')) {
        $tokenObject = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $tokenObject.PSObject.Properties['accessToken']) {
            $token = [string]$tokenObject.accessToken
        }
        elseif ($null -ne $tokenObject.PSObject.Properties['access_token']) {
            $token = [string]$tokenObject.access_token
        }
        else {
            throw 'Token JSON contains neither accessToken nor access_token.'
        }
    }

    if ($token.StartsWith('Bearer ', [StringComparison]::OrdinalIgnoreCase)) {
        $token = $token.Substring(7).Trim()
    }

    Assert-GraphToken -Token $token
}

function Assert-GraphToken {
    param([Parameter(Mandatory)][string]$Token)

    $claims = Get-JwtClaims -Token $Token
    if ("$($claims.aud)" -notin @('https://graph.microsoft.com', '00000003-0000-0000-c000-000000000000')) {
        throw "The token audience is not Microsoft Graph: $($claims.aud)"
    }

    $expiry = [DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)
    if ($expiry -le [DateTimeOffset]::UtcNow) {
        throw "The Microsoft Graph token expired at $($expiry.UtcDateTime.ToString('u'))."
    }

    $scopeProperty = $claims.PSObject.Properties['scp']
    $scopes = if ($null -ne $scopeProperty) { [string]$scopeProperty.Value } else { '' }
    $roles = if ($null -ne $claims.PSObject.Properties['roles']) { @($claims.roles) } else { @() }
    if ($scopes -notmatch '(^| )SecurityIncident\.(Read|ReadWrite)(\.All)?( |$)' -and
        @($roles | Where-Object { $_ -in @('SecurityIncident.Read.All','SecurityIncident.ReadWrite.All') }).Count -eq 0) {
        throw 'The Microsoft Graph token lacks incident-read permission. Obtain tenant admin consent for SecurityIncident.Read.All, then sign in with the intended Graph scope. GraphTokenPath is an explicit last-resort override only.'
    }

    $token
}

function Get-PerceptionToken {
    Get-PerceptionCliToken -Scope $PerceptionTokenScope -TenantId $configuration.tenantId
}

function Assert-SameOrigin {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][Uri]$ExpectedOrigin
    )

    $candidate = [Uri]$Uri
    if ($candidate.Scheme -ne $ExpectedOrigin.Scheme -or
        $candidate.Host -ne $ExpectedOrigin.Host -or
        $candidate.Port -ne $ExpectedOrigin.Port) {
        throw "Refusing to follow an API link outside $($ExpectedOrigin.GetLeftPart([UriPartial]::Authority)): $Uri"
    }
}

function Invoke-ApiWebRequest {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    if ($script:supportsSkipHttpErrorCheck) {
        return Invoke-WebRequest `
            -Method Get `
            -Uri $Uri `
            -Headers $Headers `
            -SkipHttpErrorCheck `
            -TimeoutSec $RequestTimeoutSeconds
    }

    try {
        return Invoke-WebRequest `
            -UseBasicParsing `
            -Method Get `
            -Uri $Uri `
            -Headers $Headers `
            -TimeoutSec $RequestTimeoutSeconds
    }
    catch {
        $legacyResponse = $_.Exception.Response
        if ($null -eq $legacyResponse) {
            throw
        }

        $content = ''
        $responseStream = $legacyResponse.GetResponseStream()
        if ($null -ne $responseStream) {
            $reader = [IO.StreamReader]::new($responseStream)
            try {
                $content = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
                $responseStream.Dispose()
            }
        }

        [pscustomobject]@{
            StatusCode = [int]$legacyResponse.StatusCode
            Content = $content
            Headers = $legacyResponse.Headers
        }
    }
}

function Convert-WebResponseContentToText {
    param([Parameter(Mandatory)][object]$Response)

    $contentProperty = $Response.PSObject.Properties['Content']
    $rawStreamProperty = $Response.PSObject.Properties['RawContentStream']
    if ($null -ne $contentProperty -and $contentProperty.Value -is [byte[]]) {
        return [Text.Encoding]::UTF8.GetString([byte[]]$contentProperty.Value)
    }
    if ($null -ne $rawStreamProperty -and $null -ne $rawStreamProperty.Value) {
        $memory = [IO.MemoryStream]::new()
        try {
            $rawStreamProperty.Value.CopyTo($memory)
            return [Text.Encoding]::UTF8.GetString($memory.ToArray())
        }
        finally {
            $memory.Dispose()
        }
    }
    if ($null -eq $contentProperty) {
        return ''
    }
    [string]$contentProperty.Value
}

function Invoke-JsonGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    for ($attempt = 0; $attempt -le $RetryCount; $attempt++) {
        $script:requestCount++
        try {
            $response = Invoke-ApiWebRequest -Uri $Uri -Headers $Headers
        }
        catch {
            if ($attempt -ge $RetryCount) {
                return [pscustomobject]@{
                    Succeeded   = $false
                    StatusCode  = $null
                    Body        = $null
                    Code        = 'requestFailed'
                    Message     = $_.Exception.Message
                    RequestId   = $null
                }
            }

            $script:retryAttemptCount++
            Start-Sleep -Seconds ([Math]::Min(8, [Math]::Pow(2, $attempt)))
            continue
        }

        $body = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$response.Content)) {
            try {
                $body = $response.Content | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                if ([int]$response.StatusCode -lt 400) {
                    return [pscustomobject]@{
                        Succeeded   = $false
                        StatusCode  = [int]$response.StatusCode
                        Body        = $null
                        Code        = 'invalidJson'
                        Message     = $_.Exception.Message
                        RequestId   = [string]$response.Headers['request-id']
                    }
                }
            }
        }

        if ([int]$response.StatusCode -lt 400) {
            return [pscustomobject]@{
                Succeeded   = $true
                StatusCode  = [int]$response.StatusCode
                Body        = $body
                Code        = $null
                Message     = $null
                RequestId   = [string]$response.Headers['request-id']
            }
        }

        $errorProperty = if ($null -ne $body) { $body.PSObject.Properties['error'] } else { $null }
        $errorObject = if ($null -ne $errorProperty) { $errorProperty.Value } else { $null }
        $codeProperty = if ($null -ne $errorObject) { $errorObject.PSObject.Properties['code'] } else { $null }
        $messageProperty = if ($null -ne $errorObject) { $errorObject.PSObject.Properties['message'] } else { $null }
        $errorCode = if ($null -ne $codeProperty) {
            [string]$codeProperty.Value
        }
        else {
            "http$([int]$response.StatusCode)"
        }
        $errorMessage = if ($null -ne $messageProperty -and
            -not [string]::IsNullOrWhiteSpace([string]$messageProperty.Value)) {
            [string]$messageProperty.Value
        }
        else {
            "HTTP $([int]$response.StatusCode) returned a non-standard error response."
        }
        $isRetryable = [int]$response.StatusCode -eq 429 -or [int]$response.StatusCode -ge 500
        if (-not $isRetryable -or $attempt -ge $RetryCount) {
            return [pscustomobject]@{
                Succeeded   = $false
                StatusCode  = [int]$response.StatusCode
                Body        = $body
                Code        = $errorCode
                Message     = $errorMessage
                RequestId   = [string]$response.Headers['request-id']
            }
        }

        $script:retryAttemptCount++
        $retryAfter = 0
        [void][int]::TryParse([string]$response.Headers['Retry-After'], [ref]$retryAfter)
        $delay = if ($retryAfter -gt 0) {
            [Math]::Min(60, $retryAfter)
        }
        else {
            [Math]::Min(8, [Math]::Pow(2, $attempt))
        }
        Start-Sleep -Seconds $delay
    }
}

function Invoke-TextGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    for ($attempt = 0; $attempt -le $RetryCount; $attempt++) {
        $script:requestCount++
        try {
            $response = Invoke-ApiWebRequest -Uri $Uri -Headers $Headers
        }
        catch {
            if ($attempt -ge $RetryCount) {
                return [pscustomobject]@{
                    Succeeded = $false
                    StatusCode = $null
                    Content = $null
                    Code = 'requestFailed'
                    Message = $_.Exception.Message
                    RequestId = $null
                }
            }
            $script:retryAttemptCount++
            Start-Sleep -Seconds ([Math]::Min(8, [Math]::Pow(2, $attempt)))
            continue
        }

        if ([int]$response.StatusCode -lt 400) {
            return [pscustomobject]@{
                Succeeded = $true
                StatusCode = [int]$response.StatusCode
                Content = Convert-WebResponseContentToText -Response $response
                Code = $null
                Message = $null
                RequestId = [string]$response.Headers['request-id']
            }
        }

        $isRetryable = [int]$response.StatusCode -eq 429 -or [int]$response.StatusCode -ge 500
        if (-not $isRetryable -or $attempt -ge $RetryCount) {
            return [pscustomobject]@{
                Succeeded = $false
                StatusCode = [int]$response.StatusCode
                Content = $null
                Code = "http$([int]$response.StatusCode)"
                Message = "HTTP $([int]$response.StatusCode) failed while downloading AI evidence."
                RequestId = [string]$response.Headers['request-id']
            }
        }

        $script:retryAttemptCount++
        Start-Sleep -Seconds ([Math]::Min(8, [Math]::Pow(2, $attempt)))
    }
}

function Get-IncidentIdFromSession {
    param([Parameter(Mandatory)][object]$Session)

    $candidates = [Collections.Generic.HashSet[string]]::new()
    foreach ($tag in @((Get-PerceptionPropertyValue -InputObject $Session -Name 'tags'))) {
        $tagText = [string]$tag
        if ($tagText -notmatch '(?i)^input:(?:incident|incidentId|incident-id)=(.+)$') {
            continue
        }

        $inputValue = $Matches[1]
        if ($inputValue -match '^\d{1,32}$') {
            [void]$candidates.Add($inputValue)
        }
        elseif ($inputValue -match '(?i)/incident2/(\d{1,32})(?:/|$)') {
            [void]$candidates.Add($Matches[1])
        }
    }

    if ($candidates.Count -eq 0 -and
        [string](Get-PerceptionPropertyValue -InputObject $Session -Name 'displayName') -match '(?i)\bIncident:\s*(?:https://\S*/incident2/)?(\d{1,32})\b') {
        [void]$candidates.Add($Matches[1])
    }

    if ($candidates.Count -ne 1) {
        return $null
    }

    @($candidates)[0]
}

function New-ApiError {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][object]$Result,
        [AllowNull()][string]$SessionId,
        [AllowNull()][string]$IncidentId
    )

    [pscustomobject]@{
        Area       = $Area
        SessionId  = $SessionId
        IncidentId = $IncidentId
        StatusCode = $Result.StatusCode
        Code       = $Result.Code
        Message    = $Result.Message
        RequestId  = $Result.RequestId
    }
}

function ConvertTo-NormalizedClassification {
    param([Parameter(Mandatory)][string]$Value)

    switch -Regex ($Value.Trim()) {
        '^(?i:true[\s_-]*positive|tp)$' { 'truePositive'; break }
        '^(?i:false[\s_-]*positive|fp)$' { 'falsePositive'; break }
        '^(?i:benign[\s_-]*positive|bp)$' { 'benignPositive'; break }
        '^(?i:unknown)$' { 'unknown'; break }
        default { $null }
    }
}

function ConvertTo-NormalizedDetermination {
    param([Parameter(Mandatory)][string]$Value)

    $normalized = $Value.Trim() -replace '[\s_-]+', ''
    switch -Regex ($normalized) {
        '^(?i:notmalicious|benign)$' { 'notMalicious'; break }
        '^(?i:malware)$' { 'malware'; break }
        '^(?i:phishing)$' { 'phishing'; break }
        '^(?i:compromisedaccount)$' { 'compromisedAccount'; break }
        '^(?i:securitytesting|penetrationtest(?:ing)?)$' { 'securityTesting'; break }
        '^(?i:unwantedsoftware)$' { 'unwantedSoftware'; break }
        '^(?i:apt|advancedpersistentthreat)$' { 'apt'; break }
        '^(?i:malicioususeractivity)$' { 'maliciousUserActivity'; break }
        '^(?i:lineofbusinessapplication|lobapplication)$' { 'lineOfBusinessApplication'; break }
        '^(?i:multistagedattack)$' { 'multiStagedAttack'; break }
        '^(?i:notenoughdatatovalidate)$' { 'notEnoughDataToValidate'; break }
        '^(?i:securitypersonnel)$' { 'securityPersonnel'; break }
        '^(?i:other)$' { 'other'; break }
        '^(?i:unknown)$' { 'unknown'; break }
        default { $null }
    }
}

function Add-AiSignalMatches {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Classifications,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Determinations,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Severities,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$Evidence
    )

    $classificationPatterns = @(
        '(?im)(?:Incident\s+Classification|Accepted\s+Classification|Final\s+Classification)\**\s*:\s*\**\s*(True[\s_-]*Positive|False[\s_-]*Positive|Benign[\s_-]*Positive|Unknown)\b',
        '(?im)(?:accepted|final|preliminary\s+and\s+final)\s+verdict\s*(?:is|:)\s*\**\s*(True[\s_-]*Positive|False[\s_-]*Positive|Benign[\s_-]*Positive|TP|FP)\b',
        '(?im)\bclassified\s+(?:it|the\s+incident)\s+as\s+(?:a\s+)?(?:high-confidence\s+)?(True[\s_-]*Positive|False[\s_-]*Positive|Benign[\s_-]*Positive)\b'
    )
    $determinationPatterns = @(
        '(?im)(?:Incident\s+Determination|Accepted\s+Determination|Final\s+Determination)\**\s*:\s*\**\s*([A-Za-z][A-Za-z -]{2,60})(?:\**\s*(?:[,.;\r\n]|$))',
        '(?im)(?:accepted|final|preliminary\s+and\s+final)\s+verdict\s*(?:is|:)\s*\**\s*(?:True[\s_-]*Positive|False[\s_-]*Positive|Benign[\s_-]*Positive|TP|FP)\s*/\s*([A-Za-z][A-Za-z -]{2,60})(?:\**\s*(?:[,.;\r\n]|$))'
    )
    $severityPatterns = @(
        '(?im)(?:Incident\s+Severity|Final\s+Severity|Severity)\**\s*:\s*`?\**\s*(Informational|Low|Medium|High)\b'
    )

    foreach ($pattern in $classificationPatterns) {
        foreach ($match in [regex]::Matches($Content, $pattern)) {
            $value = ConvertTo-NormalizedClassification -Value $match.Groups[1].Value
            if ($null -ne $value) {
                [void]$Classifications.Add($value)
                if ($Evidence.Count -lt 8) {
                    $Evidence.Add("AI classification: $value")
                }
            }
        }
    }

    foreach ($pattern in $determinationPatterns) {
        foreach ($match in [regex]::Matches($Content, $pattern)) {
            $value = ConvertTo-NormalizedDetermination -Value $match.Groups[1].Value
            if ($null -ne $value) {
                [void]$Determinations.Add($value)
                if ($Evidence.Count -lt 8) {
                    $Evidence.Add("AI determination: $value")
                }
            }
        }
    }

    foreach ($pattern in $severityPatterns) {
        foreach ($match in [regex]::Matches($Content, $pattern)) {
            $value = $match.Groups[1].Value.ToLowerInvariant()
            [void]$Severities.Add($value)
            if ($Evidence.Count -lt 8) {
                $Evidence.Add("AI severity: $value")
            }
        }
    }
}

function Compare-NormalizedSignal {
    param(
        [AllowNull()][string]$AiValue,
        [AllowNull()][string]$DefenderValue
    )

    $aiMissing = [string]::IsNullOrWhiteSpace($AiValue) -or $AiValue -eq 'unknown'
    $defenderMissing = [string]::IsNullOrWhiteSpace($DefenderValue) -or $DefenderValue -eq 'unknown'
    if ($aiMissing -and $defenderMissing) { return 'BothUnknown' }
    if ($aiMissing) { return 'AiMissing' }
    if ($defenderMissing) { return 'DefenderMissing' }
    if ($AiValue -eq $DefenderValue) { return 'Match' }
    'Conflict'
}

function Get-SingleSignal {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Signals
    )

    $known = @($Signals | Where-Object { $_ -ne 'unknown' } | Sort-Object)
    if ($known.Count -eq 1) { return $known[0] }
    if ($known.Count -gt 1) { return "ambiguous:$($known -join '|')" }
    if ($Signals.Contains('unknown')) { return 'unknown' }
    $null
}

function Read-PerceptionSessionPages {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][int]$PageLimit,
        [string]$SessionStatus = ''
    )

    $nextUri = $Uri
    $pagesRead = 0
    $httpStatus = $null
    $seenLinks = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $statusLabel = if ($SessionStatus) { " for status '$SessionStatus'" } else { '' }
    while (-not [string]::IsNullOrWhiteSpace($nextUri) -and $pagesRead -lt $PageLimit) {
        Assert-SameOrigin -Uri $nextUri -ExpectedOrigin $perceptionOrigin
        if (-not $seenLinks.Add($nextUri)) {
            $errors.Add([pscustomobject]@{
                Area = 'PerceptionSessionList'; SessionId = $null; IncidentId = $null
                StatusCode = $null; Code = 'continuationLoop'; RequestId = $null
                SessionStatus = $SessionStatus
                Message = "A repeated session-list continuation link was returned$statusLabel."
            })
            break
        }

        $result = Invoke-JsonGet -Uri $nextUri -Headers $perceptionHeaders
        $httpStatus = $result.StatusCode
        if (-not $result.Succeeded) {
            $listError = New-ApiError -Area 'PerceptionSessionList' -Result $result
            $listError | Add-Member -NotePropertyName RequestUriLength -NotePropertyValue $nextUri.Length
            $listError | Add-Member -NotePropertyName SessionStatus -NotePropertyValue $SessionStatus
            if ($result.StatusCode -eq 414) {
                $listError.Message = "HTTP 414 (URI Too Long) while listing sessions$statusLabel. Request URL length: $($nextUri.Length) characters; pages retrieved: $pagesRead. Session discovery is incomplete. Use -SessionId for known investigations while the API continuation issue is unresolved."
            }
            elseif ($SessionStatus) {
                $listError.Message = "Session listing$statusLabel failed: $($listError.Message)"
            }
            $errors.Add($listError)
            break
        }

        $pagesRead++
        foreach ($session in @($result.Body.value)) {
            $sessionsById[[string]$session.id] = $session
        }
        $nextProperty = $result.Body.PSObject.Properties['@odata.nextLink']
        $nextUri = if ($null -ne $nextProperty) { [string]$nextProperty.Value } else { '' }
    }

    if (-not [string]::IsNullOrWhiteSpace($nextUri) -and $pagesRead -ge $PageLimit) {
        $errors.Add([pscustomobject]@{
            Area = 'PerceptionSessionList'; SessionId = $null; IncidentId = $null
            StatusCode = $null; Code = 'pageLimitReached'; RequestId = $null
            SessionStatus = $SessionStatus
            Message = "Session listing$statusLabel reached its page limit of $PageLimit."
        })
    }

    [pscustomobject]@{
        PagesRead = $pagesRead
        Complete = [string]::IsNullOrWhiteSpace($nextUri)
        HttpStatus = $httpStatus
    }
}

$graphToken = if ($GraphTokenPath) {
    Write-Warning 'Using the explicitly supplied Graph token file. Prefer Azure CLI authentication; token files must never be included in shared packages.'
    Get-GraphTokenFromFile -Path $GraphTokenPath
}
else {
    Assert-GraphToken -Token (Get-PerceptionCliToken -Scope 'https://graph.microsoft.com/SecurityIncident.Read.All' -TenantId $configuration.tenantId)
}
$perceptionToken = Get-PerceptionToken
$graphHeaders = @{ Authorization = ('Bearer {0}' -f $graphToken); Accept = 'application/json' }
$perceptionHeaders = @{ Authorization = ('Bearer {0}' -f $perceptionToken); Accept = 'application/json' }
$perceptionOrigin = [Uri]$PerceptionApiBaseUrl
$graphOrigin = [Uri]'https://graph.microsoft.com'
$sessionsById = @{}
$errors = [Collections.Generic.List[object]]::new()
$pagesReadByState = [ordered]@{ all = 0 }
$maximumSessionPages = $MaxSessionPagesPerState * $sessionStates.Count
$sessionsUri = "$($PerceptionApiBaseUrl.TrimEnd('/'))/sessions?`$orderby=createdAt%20desc&`$top=$SessionPageSize"
$sessionDiscoveryComplete = $false
$fallbackStatuses = [Collections.Generic.List[string]]::new()
$fallbackAdditionalSessions = 0

if ($SessionId.Count -gt 0) {
    foreach ($requestedSessionId in @($SessionId | Sort-Object -Unique)) {
        $encodedId = [Uri]::EscapeDataString($requestedSessionId)
        $result = Invoke-JsonGet `
            -Uri "$($PerceptionApiBaseUrl.TrimEnd('/'))/sessions/$encodedId" `
            -Headers $perceptionHeaders
        if (-not $result.Succeeded) {
            $errors.Add((New-ApiError -Area 'PerceptionSessionLookup' -Result $result -SessionId $requestedSessionId))
            continue
        }
        $sessionsById[[string]$result.Body.id] = $result.Body
    }
}

else {
    $listing = Read-PerceptionSessionPages -Uri $sessionsUri -PageLimit $maximumSessionPages
    $pagesReadByState['all'] = $listing.PagesRead
    $sessionDiscoveryComplete = $listing.Complete
    if ($listing.HttpStatus -eq 414) {
        $observedStatuses = @(
            $sessionsById.Values |
                ForEach-Object { Get-PerceptionPropertyValue -InputObject $_ -Name 'status' } |
                Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )
        $initialSessionCount = $sessionsById.Count
        $totalPagesRead = $listing.PagesRead
        if ($observedStatuses.Count -gt 0) {
            Write-Warning 'Session pagination returned HTTP 414. Trying separate queries for observed API statuses; recovered results will still be marked incomplete.'
        }
        foreach ($status in $observedStatuses) {
            $remainingPages = $maximumSessionPages - $totalPagesRead
            if ($remainingPages -le 0) {
                $errors.Add([pscustomobject]@{
                    Area = 'PerceptionSessionList'; SessionId = $null; IncidentId = $null
                    StatusCode = $null; Code = 'pageLimitReached'; RequestId = $null
                    Message = "Status-filtered recovery stopped at the shared page limit of $maximumSessionPages; remaining statuses were not queried."
                })
                break
            }
            $fallbackStatuses.Add($status)
            $filter = [Uri]::EscapeDataString("status eq '$($status.Replace("'", "''"))'")
            $statusListing = Read-PerceptionSessionPages `
                -Uri "$sessionsUri&`$filter=$filter" `
                -SessionStatus $status `
                -PageLimit ([Math]::Min($MaxSessionPagesPerState, $remainingPages))
            $pagesReadByState[$status] = $statusListing.PagesRead
            $totalPagesRead += $statusListing.PagesRead
        }
        $fallbackAdditionalSessions = $sessionsById.Count - $initialSessionCount
    }
}

if ($sessionsById.Count -eq 0) {
    $failureSummary = @(
        $errors |
            Where-Object { $_.Area -like 'PerceptionSession*' } |
            ForEach-Object { "$($_.Area): $($_.Code) - $($_.Message)" }
    ) -join [Environment]::NewLine
    throw "No Perception sessions were retrieved. Existing report files were not replaced.$([Environment]::NewLine)$failureSummary"
}

$investigationSessions = @(
    $sessionsById.Values |
        Where-Object {
            @((Get-PerceptionPropertyValue -InputObject $_ -Name 'tags')) -contains 'playbookId=investigate-incident' -or
            [string](Get-PerceptionPropertyValue -InputObject $_ -Name 'displayName') -like 'investigate-incident*'
        } |
        Where-Object {
            [string]::IsNullOrWhiteSpace($IncidentIdFilter) -or
            (Get-IncidentIdFromSession -Session $_) -eq $IncidentIdFilter
        } |
        Sort-Object { [DateTimeOffset]$_.createdAt } -Descending
)

$sessionRecords = [Collections.Generic.List[object]]::new()
foreach ($session in $investigationSessions) {
    $incidentId = Get-IncidentIdFromSession -Session $session
    $encodedSessionId = [Uri]::EscapeDataString([string]$session.id)
    $runsResult = Invoke-JsonGet `
        -Uri "$($PerceptionApiBaseUrl.TrimEnd('/'))/sessions/$encodedSessionId/agentRuns" `
        -Headers $perceptionHeaders

    $runs = @()
    $runError = $null
    if ($runsResult.Succeeded) {
        $runs = @($runsResult.Body.value)
    }
    else {
        $runError = New-ApiError `
            -Area 'PerceptionAgentRuns' `
            -Result $runsResult `
            -SessionId ([string]$session.id) `
            -IncidentId $incidentId
        $errors.Add($runError)
    }

    $runStates = @(
        $runs |
            Group-Object state |
            Sort-Object Name |
            ForEach-Object { "$($_.Name):$($_.Count)" }
    )
    $agents = @(
        $runs |
            ForEach-Object {
                $agent = Get-PerceptionPropertyValue -InputObject $_ -Name 'agent'
                $agentDisplayName = [string](Get-PerceptionPropertyValue -InputObject $agent -Name 'displayName')
                $agentDefinitionName = [string](Get-PerceptionPropertyValue -InputObject $agent -Name 'agentDefinitionName')
                if (-not [string]::IsNullOrWhiteSpace($agentDisplayName)) {
                    $agentDisplayName
                }
                elseif (-not [string]::IsNullOrWhiteSpace($agentDefinitionName)) {
                    $agentDefinitionName
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    $classificationSignals = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $determinationSignals = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $severitySignals = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $signalEvidence = [Collections.Generic.List[string]]::new()
    $messagesScanned = 0
    $messagePagesRead = 0
    $artifactsScanned = [Collections.Generic.List[string]]::new()

    foreach ($run in $runs) {
        $encodedRunId = [Uri]::EscapeDataString([string]$run.id)
        $messageUri = "$($PerceptionApiBaseUrl.TrimEnd('/'))/sessions/$encodedSessionId/agentRuns/$encodedRunId/messages?`$top=$MessagePageSize"
        $runPageCount = 0

        while (-not [string]::IsNullOrWhiteSpace($messageUri) -and $runPageCount -lt $MessagePageLimit) {
            Assert-SameOrigin -Uri $messageUri -ExpectedOrigin $perceptionOrigin
            $messageResult = Invoke-JsonGet -Uri $messageUri -Headers $perceptionHeaders
            if (-not $messageResult.Succeeded) {
                $messageError = New-ApiError `
                    -Area 'PerceptionMessages' `
                    -Result $messageResult `
                    -SessionId ([string]$session.id) `
                    -IncidentId $incidentId
                $errors.Add($messageError)
                break
            }

            $runPageCount++
            $messagePagesRead++
            foreach ($message in @($messageResult.Body.value)) {
                if ([string]$message.type -ne 'agentMessage') {
                    continue
                }

                $messagesScanned++
                $content = if ($message.content -is [string]) {
                    [string]$message.content
                }
                else {
                    $message.content | ConvertTo-Json -Depth 20 -Compress
                }
                Add-AiSignalMatches `
                    -Content $content `
                    -Classifications $classificationSignals `
                    -Determinations $determinationSignals `
                    -Severities $severitySignals `
                    -Evidence $signalEvidence
            }

            $nextProperty = $messageResult.Body.PSObject.Properties['@odata.nextLink']
            $messageUri = if ($null -ne $nextProperty) { [string]$nextProperty.Value } else { '' }
        }

        if (-not [string]::IsNullOrWhiteSpace($messageUri) -and $runPageCount -ge $MessagePageLimit) {
            $errors.Add([pscustomobject]@{
                Area = 'PerceptionMessages'
                SessionId = [string]$session.id
                IncidentId = $incidentId
                StatusCode = $null
                Code = 'pageLimitReached'
                Message = "Run $($run.id) reached the configured message page limit of $MessagePageLimit."
                RequestId = $null
            })
        }
    }

    $outputsResult = Invoke-JsonGet `
        -Uri "$($PerceptionApiBaseUrl.TrimEnd('/'))/sessions/$encodedSessionId/outputs" `
        -Headers $perceptionHeaders
    if (-not $outputsResult.Succeeded) {
        $errors.Add((New-ApiError `
            -Area 'PerceptionOutputs' `
            -Result $outputsResult `
            -SessionId ([string]$session.id) `
            -IncidentId $incidentId))
    }
    else {
        $evidenceOutputs = @(
            $outputsResult.Body.value |
                Where-Object {
                    [string]$_.path -match '(?i)^shared/outputs/.+\.md$' -and
                    [long]$_.size -le 1048576 -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.downloadUrl)
                } |
                Sort-Object {
                    switch -Regex ([string]$_.path) {
                        '(?i)/summary\.md$' { 0; break }
                        '(?i)/report\.md$' { 1; break }
                        default { 2 }
                    }
                }
        )

        foreach ($output in $evidenceOutputs) {
            $downloadUri = [Uri]::new([Uri]$PerceptionApiBaseUrl, [string]$output.downloadUrl).AbsoluteUri
            Assert-SameOrigin -Uri $downloadUri -ExpectedOrigin $perceptionOrigin
            $downloadResult = Invoke-TextGet -Uri $downloadUri -Headers $perceptionHeaders
            if (-not $downloadResult.Succeeded) {
                $errors.Add((New-ApiError `
                    -Area 'PerceptionOutputDownload' `
                    -Result $downloadResult `
                    -SessionId ([string]$session.id) `
                    -IncidentId $incidentId))
                continue
            }

            $artifactsScanned.Add([string]$output.path)
            Add-AiSignalMatches `
                -Content $downloadResult.Content `
                -Classifications $classificationSignals `
                -Determinations $determinationSignals `
                -Severities $severitySignals `
                -Evidence $signalEvidence
        }
    }

    $sessionRecords.Add([pscustomobject]@{
        SessionId       = [string]$session.id
        IncidentId      = $incidentId
        State           = Get-PerceptionLifecycleState -InputObject $session
        CreatedAt       = $session.createdAt
        UpdatedAt       = Get-PerceptionPropertyValue -InputObject $session -Name 'updatedAt'
        DisplayName     = [string](Get-PerceptionPropertyValue -InputObject $session -Name 'displayName')
        WebUrl          = [string](Get-PerceptionPropertyValue -InputObject $session -Name 'webUrl')
        RunCount        = $runs.Count
        RunStates       = $runStates
        Agents          = $agents
        RunLookupError  = $runError
        AiClassification = Get-SingleSignal -Signals $classificationSignals
        AiDetermination  = Get-SingleSignal -Signals $determinationSignals
        AiSeverity       = Get-SingleSignal -Signals $severitySignals
        AiEvidence       = @($signalEvidence | Sort-Object -Unique)
        MessagesScanned  = $messagesScanned
        MessagePagesRead = $messagePagesRead
        ArtifactsScanned = $artifactsScanned.ToArray()
    })
}

$incidentsById = @{}
$incidentIds = @(
    $sessionRecords |
        ForEach-Object { $_.IncidentId } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

foreach ($incidentId in $incidentIds) {
    $encodedIncidentId = [Uri]::EscapeDataString($incidentId)
    $incidentUri = "https://graph.microsoft.com/v1.0/security/incidents/${encodedIncidentId}?`$select=$incidentFields"
    Assert-SameOrigin -Uri $incidentUri -ExpectedOrigin $graphOrigin
    $incidentResult = Invoke-JsonGet -Uri $incidentUri -Headers $graphHeaders
    if ($incidentResult.Succeeded) {
        $incidentsById[$incidentId] = $incidentResult.Body
    }
    else {
        $errorRecord = New-ApiError `
            -Area 'DefenderIncident' `
            -Result $incidentResult `
            -IncidentId $incidentId
        $errors.Add($errorRecord)
        $incidentsById[$incidentId] = $errorRecord
    }
}

$investigationCounts = @{}
foreach ($record in $sessionRecords) {
    $key = if ([string]::IsNullOrWhiteSpace($record.IncidentId)) { '(unresolved)' } else { $record.IncidentId }
    if (-not $investigationCounts.ContainsKey($key)) {
        $investigationCounts[$key] = 0
    }
    $investigationCounts[$key]++
}

$comparisons = [Collections.Generic.List[object]]::new()
foreach ($record in $sessionRecords) {
    $incident = if (-not [string]::IsNullOrWhiteSpace($record.IncidentId)) {
        $incidentsById[$record.IncidentId]
    }
    else {
        $null
    }

    $isDefenderIncident = $null -ne $incident -and $null -ne $incident.PSObject.Properties['displayName']
    $defenderError = if ($null -ne $incident -and -not $isDefenderIncident) { $incident } else { $null }
    $joinStatus = if ([string]::IsNullOrWhiteSpace($record.IncidentId)) {
        'IncidentIdMissing'
    }
    elseif ($isDefenderIncident) {
        'Matched'
    }
    else {
        'DefenderLookupFailed'
    }

    $lifecycle = if (-not $isDefenderIncident) {
        'NotComparable'
    }
    elseif ($record.State -eq 'completed' -and $incident.status -eq 'resolved') {
        'CompletedAndResolved'
    }
    elseif ($record.State -eq 'completed' -and $incident.status -eq 'active') {
        'PerceptionCompletedDefenderActive'
    }
    elseif ($record.State -in @('queued', 'running', 'pendingInput') -and $incident.status -eq 'resolved') {
        'DefenderResolvedPerceptionNotCompleted'
    }
    else {
        'NoSimpleLifecycleConclusion'
    }

    $defenderClassification = if ($isDefenderIncident) { [string]$incident.classification } else { $null }
    $defenderDetermination = if ($isDefenderIncident) { [string]$incident.determination } else { $null }
    $defenderSeverity = if ($isDefenderIncident) { [string]$incident.severity } else { $null }
    $classificationComparison = Compare-NormalizedSignal `
        -AiValue $record.AiClassification `
        -DefenderValue $defenderClassification
    $determinationComparison = Compare-NormalizedSignal `
        -AiValue $record.AiDetermination `
        -DefenderValue $defenderDetermination
    $severityComparison = Compare-NormalizedSignal `
        -AiValue $record.AiSeverity `
        -DefenderValue $defenderSeverity
    $fieldComparisons = @($classificationComparison, $determinationComparison, $severityComparison)
    $hasAiConclusion = -not [string]::IsNullOrWhiteSpace($record.AiClassification) -or
        -not [string]::IsNullOrWhiteSpace($record.AiDetermination)

    $verdict = if (-not $isDefenderIncident -or -not $hasAiConclusion) {
        'Insufficient'
    }
    elseif ($fieldComparisons -contains 'Conflict') {
        'Conflict'
    }
    elseif ($classificationComparison -eq 'Match' -and $determinationComparison -eq 'Match') {
        'Agree'
    }
    elseif ($fieldComparisons -contains 'Match' -or $incident.status -eq 'resolved') {
        'Partial'
    }
    else {
        'Insufficient'
    }

    $verdictRationale = switch ($verdict) {
        'Agree' { 'AI classification and determination match Defender.' }
        'Conflict' { 'At least one explicit AI conclusion conflicts with Defender.' }
        'Partial' { 'The available evidence is compatible, but one or more comparison fields are missing or unknown.' }
        default {
            if (-not $hasAiConclusion) {
                'No structured AI classification or determination was found in agent-authored messages.'
            }
            elseif (-not $isDefenderIncident) {
                'The Defender incident could not be retrieved.'
            }
            else {
                'There is not enough comparable evidence for a verdict.'
            }
        }
    }

    $comparison = [pscustomobject]@{
        IncidentId                 = $record.IncidentId
        JoinStatus                 = $joinStatus
        LifecycleComparison        = $lifecycle
        InvestigationCount         = $investigationCounts[
            $(if ([string]::IsNullOrWhiteSpace($record.IncidentId)) { '(unresolved)' } else { $record.IncidentId })
        ]
        PerceptionSessionId         = $record.SessionId
        PerceptionState             = $record.State
        PerceptionCreatedAt         = $record.CreatedAt
        PerceptionUpdatedAt         = $record.UpdatedAt
        PerceptionDisplayName       = $record.DisplayName
        PerceptionWebUrl            = $record.WebUrl
        PerceptionRunCount          = $record.RunCount
        PerceptionRunStates         = $record.RunStates
        PerceptionAgents            = $record.Agents
        PerceptionRunLookupError    = $record.RunLookupError
        AiStatus                    = if ($hasAiConclusion) { 'Concluded' } elseif ($record.State -in @('queued', 'running', 'pendingInput')) { 'InProgress' } else { 'NoConclusion' }
        AiClassification            = $record.AiClassification
        AiDetermination             = $record.AiDetermination
        AiSeverity                  = $record.AiSeverity
        AiEvidence                  = $record.AiEvidence
        AiMessagesScanned           = $record.MessagesScanned
        AiMessagePagesRead          = $record.MessagePagesRead
        AiArtifactsScanned          = $record.ArtifactsScanned
        DefenderDisplayName         = if ($isDefenderIncident) { $incident.displayName } else { $null }
        DefenderStatus              = if ($isDefenderIncident) { $incident.status } else { $null }
        DefenderSeverity            = if ($isDefenderIncident) { $incident.severity } else { $null }
        DefenderClassification      = if ($isDefenderIncident) { $incident.classification } else { $null }
        DefenderDetermination       = if ($isDefenderIncident) { $incident.determination } else { $null }
        DefenderCreatedDateTime     = if ($isDefenderIncident) { $incident.createdDateTime } else { $null }
        DefenderLastUpdateDateTime  = if ($isDefenderIncident) { $incident.lastUpdateDateTime } else { $null }
        DefenderIncidentWebUrl      = if ($isDefenderIncident) { $incident.incidentWebUrl } else { $null }
        DefenderLookupError         = $defenderError
        ClassificationComparison    = $classificationComparison
        DeterminationComparison     = $determinationComparison
        SeverityComparison          = $severityComparison
        Verdict                     = $verdict
        VerdictRationale            = $verdictRationale
    }
    $comparisons.Add($comparison)
}

$collectionStopwatch.Stop()
$generatedAt = [DateTimeOffset]::Now
$matchedCount = @($comparisons | Where-Object JoinStatus -eq 'Matched').Count
$uniqueIncidentCount = $incidentIds.Count
$duplicateInvestigationCount = @($comparisons | Where-Object InvestigationCount -gt 1).Count
$errorCount = $errors.Count
$agreeCount = @($comparisons | Where-Object Verdict -eq 'Agree').Count
$partialCount = @($comparisons | Where-Object Verdict -eq 'Partial').Count
$conflictCount = @($comparisons | Where-Object Verdict -eq 'Conflict').Count
$insufficientCount = @($comparisons | Where-Object Verdict -eq 'Insufficient').Count
$collectionScope = if ($SessionId.Count -gt 0) { 'ExplicitSessionIds' }
elseif ($fallbackStatuses.Count -gt 0) { 'AllSessionsWithStatusFallback' }
else { 'AllSessions' }
$collectionComplete = $errors.Count -eq 0
$coverageMessage = if (-not $collectionComplete) {
    "INCOMPLETE COLLECTION: $errorCount collection error(s). Results cover only successfully retrieved sessions and evidence; missing investigations or conclusions must not be treated as absent."
}
elseif ($SessionId.Count -gt 0) {
    'LIMITED SCOPE: Only explicitly requested session IDs were collected. Automatic session discovery was bypassed.'
}
else {
    'Collection completed for all discovered sessions within the selected incident filter.'
}
if ($fallbackStatuses.Count -gt 0) {
    $coverageMessage += " Status-filtered recovery added $fallbackAdditionalSessions additional session(s) across $($fallbackStatuses.Count) observed API status(es). Unseen statuses and failed continuation pages may contain further investigations."
}
if (-not $collectionComplete) {
    Write-Warning $coverageMessage
    foreach ($collectionError in $errors) {
        Write-Warning "$($collectionError.Area): $($collectionError.Code) - $($collectionError.Message)"
    }
}

$report = [pscustomobject]@{
    GeneratedAt = $generatedAt
    Source = [pscustomobject]@{
        PerceptionApiBaseUrl = $PerceptionApiBaseUrl
        SessionPageSize = $SessionPageSize
        MaxSessionPagesPerState = $MaxSessionPagesPerState
        IncidentIdFilter = $IncidentIdFilter
        CollectionScope = $collectionScope
        RequestedSessionIds = @($SessionId | Sort-Object -Unique)
        PagesReadByState = $pagesReadByState
        StatusDiscoveryFallbackUsed = $fallbackStatuses.Count -gt 0
        StatusDiscoveryFallbackStatuses = $fallbackStatuses.ToArray()
        StatusDiscoveryFallbackAdditionalSessions = $fallbackAdditionalSessions
    }
    Summary = [pscustomobject]@{
        CollectionComplete = $collectionComplete
        SessionDiscoveryComplete = $sessionDiscoveryComplete
        CoverageMessage = $coverageMessage
        SessionsEnumerated = $sessionsById.Count
        InvestigationSessions = $investigationSessions.Count
        UniqueDefenderIncidentIds = $uniqueIncidentCount
        MatchedComparisons = $matchedCount
        DuplicateInvestigationRows = $duplicateInvestigationCount
        Verdicts = [pscustomobject]@{
            Agree = $agreeCount
            Partial = $partialCount
            Conflict = $conflictCount
            Insufficient = $insufficientCount
        }
        Errors = $errorCount
        Requests = $script:requestCount
        RetryAttempts = $script:retryAttemptCount
        Duration = $collectionStopwatch.Elapsed
    }
    Comparisons = $comparisons.ToArray()
    Errors = $errors.ToArray()
}

foreach ($path in @($OutputPath, $JsonOutputPath, $CsvOutputPath)) {
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    $directory = Split-Path -Parent $resolvedPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory
    }
}

$resolvedJsonPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JsonOutputPath)
$resolvedCsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvOutputPath)
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

[IO.File]::WriteAllText(
    $resolvedJsonPath,
    ($report | ConvertTo-Json -Depth 12),
    [Text.UTF8Encoding]::new($false)
)

$comparisons |
    Select-Object `
        @{ Name = 'CollectionScope'; Expression = { $collectionScope } },
        @{ Name = 'CollectionComplete'; Expression = { $collectionComplete } },
        @{ Name = 'SessionDiscoveryComplete'; Expression = { $sessionDiscoveryComplete } },
        IncidentId,
        JoinStatus,
        Verdict,
        VerdictRationale,
        LifecycleComparison,
        InvestigationCount,
        PerceptionSessionId,
        PerceptionState,
        PerceptionCreatedAt,
        PerceptionUpdatedAt,
        PerceptionDisplayName,
        PerceptionRunCount,
        @{ Name = 'PerceptionRunStates'; Expression = { @($_.PerceptionRunStates) -join '; ' } },
        @{ Name = 'PerceptionAgents'; Expression = { @($_.PerceptionAgents) -join '; ' } },
        AiStatus,
        AiClassification,
        AiDetermination,
        AiSeverity,
        ClassificationComparison,
        DeterminationComparison,
        SeverityComparison,
        AiMessagesScanned,
        AiMessagePagesRead,
        @{ Name = 'AiArtifactsScanned'; Expression = { @($_.AiArtifactsScanned) -join '; ' } },
        @{ Name = 'AiEvidence'; Expression = { @($_.AiEvidence) -join '; ' } },
        DefenderDisplayName,
        DefenderStatus,
        DefenderSeverity,
        DefenderClassification,
        DefenderDetermination,
        DefenderCreatedDateTime,
        DefenderLastUpdateDateTime,
        PerceptionWebUrl,
        DefenderIncidentWebUrl |
    Export-Csv -LiteralPath $resolvedCsvPath -NoTypeInformation -Encoding utf8

$sortedComparisons = @(
    $comparisons |
        Sort-Object `
            @{ Expression = {
                switch ($_.Verdict) {
                    'Conflict' { 0 }
                    'Partial' { 1 }
                    'Agree' { 2 }
                    default { 3 }
                }
            } },
            @{ Expression = { [DateTimeOffset]$_.PerceptionCreatedAt }; Descending = $true }
)

$rows = foreach ($comparison in $sortedComparisons) {
    $joinClass = if ($comparison.JoinStatus -eq 'Matched') { 'good' } else { 'bad' }
    $verdictClass = switch ($comparison.Verdict) {
        'Agree' { 'good' }
        'Conflict' { 'bad' }
        'Partial' { 'partial' }
        default { '' }
    }
    $sessionLink = if ([string]::IsNullOrWhiteSpace($comparison.PerceptionWebUrl)) {
        "<code>$(ConvertTo-HtmlText $comparison.PerceptionSessionId)</code>"
    }
    else {
        "<a class=""action-link"" href=""$(ConvertTo-HtmlText $comparison.PerceptionWebUrl)"" target=""_blank"" rel=""noopener noreferrer"">Open Perception session</a><br><code>$(ConvertTo-HtmlText $comparison.PerceptionSessionId)</code>"
    }
    $incidentLink = if ([string]::IsNullOrWhiteSpace($comparison.DefenderIncidentWebUrl)) {
        ConvertTo-HtmlText $comparison.IncidentId
    }
    else {
        "<a href=""$(ConvertTo-HtmlText $comparison.DefenderIncidentWebUrl)"" target=""_blank"" rel=""noopener noreferrer"">$(ConvertTo-HtmlText $comparison.IncidentId)</a>"
    }
    $defenderAction = if ([string]::IsNullOrWhiteSpace($comparison.DefenderIncidentWebUrl)) {
        ''
    }
    else {
        "<a class=""action-button defender-action"" href=""$(ConvertTo-HtmlText $comparison.DefenderIncidentWebUrl)"" target=""_blank"" rel=""noopener noreferrer"">Open Defender incident <span aria-hidden=""true"">&#8599;</span></a>"
    }
    $runSummary = if ($comparison.PerceptionRunCount -gt 0) {
        "$($comparison.PerceptionRunCount) ($(ConvertTo-HtmlText (@($comparison.PerceptionRunStates) -join ', ')))"
    }
    elseif ($null -ne $comparison.PerceptionRunLookupError) {
        'Lookup failed'
    }
    else {
        '0'
    }
    $aiClassification = if ([string]::IsNullOrWhiteSpace($comparison.AiClassification)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.AiClassification }
    $aiDetermination = if ([string]::IsNullOrWhiteSpace($comparison.AiDetermination)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.AiDetermination }
    $aiSeverity = if ([string]::IsNullOrWhiteSpace($comparison.AiSeverity)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.AiSeverity }
    $defenderClassification = if ([string]::IsNullOrWhiteSpace($comparison.DefenderClassification)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.DefenderClassification }
    $defenderDetermination = if ([string]::IsNullOrWhiteSpace($comparison.DefenderDetermination)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.DefenderDetermination }
    $defenderSeverity = if ([string]::IsNullOrWhiteSpace($comparison.DefenderSeverity)) { 'Not stated' } else { ConvertTo-HtmlText $comparison.DefenderSeverity }
    $evidence = if (@($comparison.AiEvidence).Count -gt 0) {
        "<details class=""evidence""><summary><span>Evidence inspected</span><strong>$($comparison.AiMessagesScanned) messages &middot; $(@($comparison.AiArtifactsScanned).Count) artifacts</strong></summary><div>$(ConvertTo-HtmlText (@($comparison.AiEvidence) -join '; '))</div></details>"
    }
    else {
        "<div class=""evidence-empty"">$(ConvertTo-HtmlText $comparison.AiMessagesScanned) AI messages inspected; no structured conclusion found.</div>"
    }

    @"
<article class="comparison-card verdict-$(ConvertTo-HtmlText $comparison.Verdict.ToLowerInvariant())" data-join="$(ConvertTo-HtmlText $comparison.JoinStatus)" data-verdict="$(ConvertTo-HtmlText $comparison.Verdict)" data-perception="$(ConvertTo-HtmlText $comparison.PerceptionState)" data-defender="$(ConvertTo-HtmlText $comparison.DefenderStatus)" data-search="$(ConvertTo-HtmlText ("$($comparison.IncidentId) $($comparison.PerceptionDisplayName) $($comparison.DefenderDisplayName) $($comparison.Verdict)".ToLowerInvariant()))">
  <div class="case-head">
    <div>
      <div class="eyebrow">Defender incident $incidentLink &middot; $($comparison.InvestigationCount) AI investigation(s)</div>
      <h3>$(ConvertTo-HtmlText $comparison.DefenderDisplayName)</h3>
      <div class="quick-compare">
        <span><small>AI</small>$aiClassification &middot; $aiDetermination</span>
        <b aria-hidden="true">&rarr;</b>
        <span><small>Defender</small>$defenderClassification &middot; $defenderDetermination</span>
      </div>
    </div>
    <div class="headline-verdict">
      <span class="verdict-label">Comparison verdict</span>
      <span class="pill verdict-pill $verdictClass">$(ConvertTo-HtmlText $comparison.Verdict)</span>
    </div>
  </div>

  <details class="case-details">
    <summary><span>View full comparison</span><strong>$(ConvertTo-HtmlText $comparison.PerceptionState) &middot; $(ConvertTo-HtmlText $comparison.DefenderStatus)</strong></summary>
    <div class="case-detail-body">
      <div class="comparison-stage">
        <div class="system-panel ai-panel">
          <div class="system-head"><span class="system-icon">AI</span><div><span>Perception</span><strong>Agent investigation</strong></div></div>
          <div class="status-line"><span>AI status</span><strong>$(ConvertTo-HtmlText $comparison.AiStatus)</strong></div>
          <div class="status-line"><span>Session state</span><strong>$(ConvertTo-HtmlText $comparison.PerceptionState)</strong></div>
          <div class="status-line"><span>Agent runs</span><strong>$runSummary</strong></div>
          <div class="panel-action">$sessionLink</div>
        </div>

        <div class="verdict-core $verdictClass">
          <span class="versus">VS</span>
          <strong>$(ConvertTo-HtmlText $comparison.Verdict)</strong>
          <p>$(ConvertTo-HtmlText $comparison.VerdictRationale)</p>
        </div>

        <div class="system-panel defender-panel">
          <div class="system-head"><span class="system-icon">D</span><div><span>Microsoft Defender</span><strong>Incident record</strong></div></div>
          <div class="status-line"><span>Incident status</span><strong>$(ConvertTo-HtmlText $comparison.DefenderStatus)</strong></div>
          <div class="status-line"><span>Last updated</span><strong>$(ConvertTo-HtmlText $comparison.DefenderLastUpdateDateTime)</strong></div>
          <div class="status-line"><span>Join result</span><strong><span class="pill $joinClass">$(ConvertTo-HtmlText $comparison.JoinStatus)</span></strong></div>
          <div class="panel-action">$defenderAction</div>
        </div>
      </div>

      <div class="signal-matrix">
        <div class="signal-header"><span>Signal</span><span>Perception AI</span><span>Comparison</span><span>Defender</span></div>
        <div class="signal-row result-$(ConvertTo-HtmlText $comparison.ClassificationComparison.ToLowerInvariant())"><span>Classification</span><strong>$aiClassification</strong><span class="comparison-chip">$(ConvertTo-HtmlText $comparison.ClassificationComparison)</span><strong>$defenderClassification</strong></div>
        <div class="signal-row result-$(ConvertTo-HtmlText $comparison.DeterminationComparison.ToLowerInvariant())"><span>Determination</span><strong>$aiDetermination</strong><span class="comparison-chip">$(ConvertTo-HtmlText $comparison.DeterminationComparison)</span><strong>$defenderDetermination</strong></div>
        <div class="signal-row result-$(ConvertTo-HtmlText $comparison.SeverityComparison.ToLowerInvariant())"><span>Severity</span><strong>$aiSeverity</strong><span class="comparison-chip">$(ConvertTo-HtmlText $comparison.SeverityComparison)</span><strong>$defenderSeverity</strong></div>
      </div>

      <div class="case-footer">
        <div><span>Lifecycle</span><strong>$(ConvertTo-HtmlText $comparison.LifecycleComparison)</strong></div>
        <div><span>Session created</span><strong>$(ConvertTo-HtmlText $comparison.PerceptionCreatedAt)</strong></div>
        <div><span>Session ID</span><code>$(ConvertTo-HtmlText $comparison.PerceptionSessionId)</code></div>
      </div>
      $evidence
    </div>
  </details>
</article>
"@
}

$errorRows = if ($errors.Count -eq 0) {
    '<tr><td colspan="7">No collection errors.</td></tr>'
}
else {
    foreach ($errorRecord in $errors) {
        "<tr><td>$(ConvertTo-HtmlText $errorRecord.Area)</td><td>$(ConvertTo-HtmlText $errorRecord.SessionId)</td><td>$(ConvertTo-HtmlText $errorRecord.IncidentId)</td><td>$(ConvertTo-HtmlText $errorRecord.StatusCode)</td><td>$(ConvertTo-HtmlText $errorRecord.Code)</td><td>$(ConvertTo-HtmlText $errorRecord.Message)</td><td>$(ConvertTo-HtmlText $errorRecord.RequestId)</td></tr>"
    }
}

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Perception and Defender Investigation Comparison</title>
<style>
  :root { --ink:#172033; --muted:#617086; --navy:#123b66; --blue:#2b78c5; --line:#d8e0e9; --canvas:#edf3f8; --good:#237a43; --bad:#ad3434; --amber:#a76613; --violet:#7256b8; }
  * { box-sizing:border-box; }
  body { margin:0; background:radial-gradient(circle at 85% 0,rgba(56,189,248,.13),transparent 28%),var(--canvas); color:var(--ink); font-family:Aptos,"Segoe UI",Arial,sans-serif; }
  header { padding:34px clamp(20px,5vw,70px); background:radial-gradient(circle at 82% 15%,rgba(56,189,248,.23),transparent 28%),linear-gradient(130deg,#061d35,#0b4777 68%,#11699d); color:white; }
  header h1 { margin:0; font-size:clamp(28px,4vw,44px); }
  header p { margin:8px 0 0; color:#dbeeff; }
  main { max-width:1600px; margin:0 auto; padding:24px; }
  .cards { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:12px; }
  .card, section { border:1px solid var(--line); border-radius:13px; background:white; box-shadow:0 8px 24px rgba(20,45,70,.07); }
  .card { position:relative; padding:17px; overflow:hidden; }
  .card::after { content:""; position:absolute; inset:auto -20px -30px auto; width:70px; height:70px; border-radius:50%; background:rgba(43,120,197,.07); }
  .card span { color:var(--muted); font-size:12px; }
  .card strong { display:block; margin-top:5px; color:var(--navy); font-size:27px; }
  section { margin-top:18px; padding:20px; }
  h2 { margin:0 0 6px; color:var(--navy); }
  .muted { color:var(--muted); }
  .controls { display:flex; flex-wrap:wrap; gap:9px; margin:15px 0; }
  .controls input,.controls select { min-height:39px; padding:8px 10px; border:1px solid var(--line); border-radius:8px; background:white; }
  .controls input { flex:1 1 320px; }
  .table-scroll { overflow:auto; border:1px solid var(--line); border-radius:9px; }
  table { width:100%; min-width:2200px; border-collapse:collapse; font-size:13px; }
  th,td { padding:9px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
  th { position:sticky; top:0; background:#eaf2f8; color:var(--navy); text-transform:uppercase; font-size:11px; letter-spacing:.03em; }
  tbody tr:hover { background:#f8fbfd; }
  code { font-family:Consolas,"Courier New",monospace; font-size:11px; }
  a { color:var(--blue); }
  .action-link { display:inline-block; margin-bottom:5px; font-weight:700; white-space:nowrap; }
  .action-button { display:inline-flex; align-items:center; justify-content:center; gap:7px; min-height:40px; padding:9px 14px; border-radius:9px; color:white; font-size:13px; font-weight:750; text-decoration:none; box-shadow:0 5px 14px rgba(20,45,70,.14); }
  .defender-action { background:linear-gradient(135deg,#286fbb,#174f8d); }
  .pill { display:inline-block; padding:3px 8px; border-radius:999px; color:white; background:#6c7180; font-size:11px; font-weight:700; }
  .pill.good { background:var(--good); }
  .pill.bad { background:var(--bad); }
  .pill.partial { background:var(--amber); }
  .comparison-list { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); align-items:start; gap:12px; }
  .comparison-card { position:relative; border:1px solid var(--line); border-radius:14px; background:white; box-shadow:0 8px 22px rgba(20,45,70,.08); overflow:hidden; }
  .comparison-card.is-open { grid-column:1 / -1; box-shadow:0 14px 36px rgba(20,45,70,.12); }
  .comparison-card.is-open .case-head { min-height:0; padding:11px 14px 10px; }
  .comparison-card.is-open .case-head h3 { font-size:16px; }
  .comparison-card.is-open .quick-compare { margin-top:6px; }
  .comparison-card.is-open .quick-compare span { padding:4px 6px; }
  .comparison-card::before { content:""; position:absolute; inset:0 0 auto; height:4px; background:#6c7180; }
  .comparison-card.verdict-conflict::before { background:linear-gradient(90deg,#d64747,#8f2525); }
  .comparison-card.verdict-agree::before { background:linear-gradient(90deg,#2b9a56,#176f3b); }
  .comparison-card.verdict-partial::before { background:linear-gradient(90deg,#d7932c,#955c0c); }
  .case-head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; min-height:142px; padding:16px 16px 13px; border-bottom:1px solid #e8edf2; }
  .eyebrow { color:var(--blue); font-size:10px; font-weight:750; letter-spacing:.04em; text-transform:uppercase; }
  .case-head h3 { max-width:1000px; margin:5px 0 0; color:var(--navy); font-size:17px; line-height:1.22; }
  .quick-compare { display:flex; align-items:center; flex-wrap:wrap; gap:6px; margin-top:9px; color:#45566a; font-size:11px; }
  .quick-compare span { display:inline-flex; align-items:center; gap:5px; padding:5px 7px; border-radius:7px; background:#f3f6f9; }
  .quick-compare small { color:var(--muted); font-size:9px; font-weight:800; letter-spacing:.05em; text-transform:uppercase; }
  .quick-compare b { color:#8b98a6; }
  .headline-verdict { flex:0 0 auto; text-align:right; }
  .verdict-label { display:block; margin-bottom:5px; color:var(--muted); font-size:11px; text-transform:uppercase; }
  .verdict-pill { padding:6px 11px; font-size:12px; box-shadow:0 4px 12px rgba(20,45,70,.11); }
  .comparison-stage { display:grid; grid-template-columns:minmax(230px,1fr) minmax(150px,.4fr) minmax(230px,1fr); gap:8px; padding:10px 12px; background:#f8fafc; }
  .case-details { margin:0; border-top:1px solid #e8edf2; }
  .case-details > summary { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:9px 16px; background:#fbfcfd; color:var(--blue); font-size:12px; }
  .case-details > summary strong { color:var(--muted); font-size:11px; font-weight:650; text-transform:uppercase; }
  .case-details[open] > summary { border-bottom:1px solid #e8edf2; background:#f3f8fc; }
  .case-detail-body { padding-bottom:1px; }
  .system-panel { display:flex; flex-direction:column; min-height:150px; padding:10px; border:1px solid var(--line); border-radius:10px; background:white; }
  .ai-panel { border-color:#cfc5ec; background:linear-gradient(155deg,#fff,#f5f2fc); }
  .defender-panel { border-color:#b9d5ec; background:linear-gradient(155deg,#fff,#eef7fd); }
  .system-head { display:flex; align-items:center; gap:8px; margin-bottom:5px; }
  .system-icon { display:grid; place-items:center; width:28px; height:28px; border-radius:8px; background:var(--violet); color:white; font-size:10px; font-weight:800; box-shadow:0 4px 11px rgba(114,86,184,.22); }
  .defender-panel .system-icon { background:var(--blue); box-shadow:0 5px 14px rgba(43,120,197,.25); }
  .system-head div span { display:block; color:var(--muted); font-size:9px; text-transform:uppercase; }
  .system-head div strong { color:var(--navy); font-size:14px; }
  .status-line { display:flex; justify-content:space-between; gap:10px; padding:5px 0; border-bottom:1px solid #e9edf1; font-size:11px; }
  .status-line span { color:var(--muted); }
  .status-line strong { color:var(--ink); text-align:right; }
  .panel-action { display:flex; align-items:center; gap:9px; margin-top:auto; padding-top:6px; }
  .panel-action .action-link { display:inline-flex; flex:0 0 auto; min-height:32px; align-items:center; padding:6px 10px; border-radius:8px; background:linear-gradient(135deg,#8064c7,#5d409e); color:white; font-size:12px; text-decoration:none; box-shadow:0 4px 10px rgba(114,86,184,.2); }
  .panel-action .action-button { min-height:32px; padding:6px 10px; font-size:12px; }
  .panel-action code { display:block; margin:0; color:var(--muted); font-size:9px; overflow-wrap:anywhere; }
  .verdict-core { display:flex; flex-direction:column; align-items:center; justify-content:center; padding:9px; border:1px dashed #c9d1da; border-radius:10px; background:white; text-align:center; }
  .versus { display:grid; place-items:center; width:30px; height:30px; margin-bottom:5px; border-radius:50%; background:#eef2f6; color:var(--navy); font-size:9px; font-weight:850; }
  .verdict-core > strong { font-size:16px; color:#5e6875; }
  .verdict-core.bad > strong { color:var(--bad); }
  .verdict-core.good > strong { color:var(--good); }
  .verdict-core.partial > strong { color:var(--amber); }
  .verdict-core p { margin:6px 0 0; color:var(--muted); font-size:11px; line-height:1.35; }
  .signal-matrix { margin:0 12px 8px; border:1px solid var(--line); border-radius:9px; overflow:hidden; }
  .signal-header,.signal-row { display:grid; grid-template-columns:1fr 1.25fr .85fr 1.25fr; align-items:center; gap:8px; padding:6px 9px; }
  .signal-header { background:#eaf2f8; color:var(--navy); font-size:10px; font-weight:800; letter-spacing:.05em; text-transform:uppercase; }
  .signal-row { border-top:1px solid var(--line); font-size:12px; }
  .signal-row > span:first-child { color:var(--muted); font-weight:650; }
  .comparison-chip { justify-self:start; padding:3px 7px; border-radius:999px; background:#edf1f5; color:#586574; font-size:10px; font-weight:750; }
  .result-conflict { background:#fff8f8; }
  .result-conflict .comparison-chip { background:#fde3e3; color:#9a2929; }
  .result-match { background:#f7fcf8; }
  .result-match .comparison-chip { background:#ddf3e4; color:#1d6d3a; }
  .case-footer { display:grid; grid-template-columns:1.1fr 1fr 1.5fr; gap:8px; margin:0 12px 8px; padding:7px 10px; border-radius:8px; background:#f5f7fa; font-size:10px; }
  .case-footer span { display:block; margin-bottom:2px; color:var(--muted); font-size:9px; text-transform:uppercase; }
  .case-footer strong,.case-footer code { color:var(--ink); overflow-wrap:anywhere; }
  .evidence { margin:0 12px 10px; border:1px solid #d8e2eb; border-radius:8px; background:#f8fbfd; }
  .evidence summary { display:flex; justify-content:space-between; gap:10px; padding:7px 10px; }
  .evidence summary strong { color:var(--muted); font-size:12px; }
  .evidence > div { padding:0 12px 11px; color:var(--muted); font-size:12px; line-height:1.45; }
  .evidence-empty { margin:0 14px 14px; padding:10px 12px; border-radius:9px; background:#f5f7fa; color:var(--muted); font-size:12px; }
  .pagination { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-top:16px; padding:12px 14px; border:1px solid var(--line); border-radius:10px; background:#f8fafc; }
  .pagination-info { color:var(--muted); font-size:13px; }
  .pagination-actions { display:flex; align-items:center; gap:8px; }
  .pagination button { min-height:36px; padding:7px 12px; border:1px solid var(--line); border-radius:8px; background:white; color:var(--blue); font-weight:700; cursor:pointer; }
  .pagination button:disabled { color:#9ba8b5; cursor:not-allowed; }
  .hidden { display:none; }
  details { margin-top:10px; }
  summary { cursor:pointer; color:var(--blue); font-weight:700; }
  @media(max-width:1150px) {
    .cards { grid-template-columns:repeat(3,minmax(0,1fr)); }
    .comparison-list { grid-template-columns:1fr; }
    .comparison-stage { grid-template-columns:1fr; }
    .verdict-core { min-height:150px; }
  }
  @media(max-width:700px) {
    main { padding:12px; }
    .cards { grid-template-columns:1fr 1fr; }
    .case-head { flex-direction:column; }
    .headline-verdict { text-align:left; }
    .signal-header { display:none; }
    .signal-row { grid-template-columns:1fr 1fr; }
    .signal-row .comparison-chip { grid-column:1 / -1; }
    .case-footer { grid-template-columns:1fr; }
    .pagination { align-items:stretch; flex-direction:column; }
    .pagination-actions { justify-content:space-between; }
  }
</style>
</head>
<body>
<header>
  <h1>Perception and Defender Investigation Comparison</h1>
  <p>Every retrievable <code>investigate-incident</code> session joined to its exact Microsoft Defender incident.</p>
</header>
<main>
  <section role="status" aria-label="Collection coverage">
    <h2>Collection coverage</h2>
    <p><strong>$(ConvertTo-HtmlText $coverageMessage)</strong></p>
    <p>Scope: $(ConvertTo-HtmlText $collectionScope). Session discovery complete: $sessionDiscoveryComplete.</p>
  </section>
  <div class="cards">
    <div class="card"><span>Sessions enumerated</span><strong>$($sessionsById.Count)</strong></div>
    <div class="card"><span>Investigations</span><strong>$($investigationSessions.Count)</strong></div>
    <div class="card"><span>Unique incidents</span><strong>$uniqueIncidentCount</strong></div>
    <div class="card"><span>AI conclusions</span><strong>$($agreeCount + $partialCount + $conflictCount)</strong></div>
    <div class="card"><span>Agree / Partial</span><strong>$agreeCount / $partialCount</strong></div>
    <div class="card"><span>Conflict / Insufficient</span><strong>$conflictCount / $insufficientCount</strong></div>
  </div>

  <section>
    <h2>Human Agentic investigation comparison</h2>
    <p class="muted">Generated $(ConvertTo-HtmlText $generatedAt.ToString('yyyy-MM-dd HH:mm:ss zzz')) in $(ConvertTo-HtmlText $collectionStopwatch.Elapsed.ToString('hh\:mm\:ss')). Repeated investigations remain separate rows.</p>
    <div class="controls">
      <input id="search" type="search" placeholder="Search incident or title">
      <select id="join-filter"><option value="">All join results</option></select>
      <select id="verdict-filter"><option value="">All verdicts</option></select>
      <select id="perception-filter"><option value="">All Perception states</option></select>
      <select id="defender-filter"><option value="">All Defender states</option></select>
      <select id="page-size" aria-label="Cases per page"><option value="10">10 per page</option><option value="25" selected>25 per page</option><option value="50">50 per page</option><option value="100">100 per page</option></select>
    </div>
    <div id="comparison-list" class="comparison-list">$($rows -join [Environment]::NewLine)</div>
    <div class="pagination">
      <div id="pagination-info" class="pagination-info"></div>
      <div class="pagination-actions">
        <button id="previous-page" type="button">Previous</button>
        <strong id="page-indicator"></strong>
        <button id="next-page" type="button">Next</button>
      </div>
    </div>
  </section>

  <section>
    <h2>Collection details</h2>
    <p class="muted">Session-list pages read: $(ConvertTo-HtmlText $pagesReadByState['all']). Retries: $script:retryAttemptCount.</p>
    <details>
      <summary>Errors and incomplete records ($errorCount)</summary>
      <div class="table-scroll">
        <table>
          <thead><tr><th>Area</th><th>Session</th><th>Incident</th><th>HTTP</th><th>Code</th><th>Message</th><th>Request ID</th></tr></thead>
          <tbody>$($errorRows -join [Environment]::NewLine)</tbody>
        </table>
      </div>
    </details>
  </section>
</main>
<script>
  const rows = Array.from(document.querySelectorAll('#comparison-list .comparison-card'));
  const search = document.getElementById('search');
  const joinFilter = document.getElementById('join-filter');
  const verdictFilter = document.getElementById('verdict-filter');
  const perceptionFilter = document.getElementById('perception-filter');
  const defenderFilter = document.getElementById('defender-filter');
  const pageSize = document.getElementById('page-size');
  const previousPage = document.getElementById('previous-page');
  const nextPage = document.getElementById('next-page');
  const pageIndicator = document.getElementById('page-indicator');
  const paginationInfo = document.getElementById('pagination-info');
  let currentPage = 1;

  rows.forEach(function (row) {
    const details = row.querySelector('details.case-details');
    if (!details) return;
    details.addEventListener('toggle', function () {
      row.classList.toggle('is-open', details.open);
      if (!details.open) return;
      rows.forEach(function (otherRow) {
        if (otherRow === row) return;
        const otherDetails = otherRow.querySelector('details.case-details');
        if (otherDetails) otherDetails.open = false;
        otherRow.classList.remove('is-open');
      });
    });
  });

  function addOptions(select, attribute) {
    Array.from(new Set(rows.map(function (row) { return row.dataset[attribute] || ''; })))
      .filter(Boolean)
      .sort()
      .forEach(function (value) {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.append(option);
      });
  }

  function applyFilters() {
    const term = search.value.trim().toLowerCase();
    const matches = rows.filter(function (row) {
      return (
        (!term || row.dataset.search.includes(term)) &&
        (!joinFilter.value || row.dataset.join === joinFilter.value) &&
        (!verdictFilter.value || row.dataset.verdict === verdictFilter.value) &&
        (!perceptionFilter.value || row.dataset.perception === perceptionFilter.value) &&
        (!defenderFilter.value || row.dataset.defender === defenderFilter.value)
      );
    });

    const size = Number(pageSize.value);
    const pageCount = Math.max(1, Math.ceil(matches.length / size));
    currentPage = Math.min(currentPage, pageCount);
    const firstIndex = (currentPage - 1) * size;
    const visibleRows = new Set(matches.slice(firstIndex, firstIndex + size));
    rows.forEach(function (row) {
      row.classList.toggle('hidden', !visibleRows.has(row));
      if (!visibleRows.has(row)) {
        const details = row.querySelector('details.case-details');
        if (details) details.open = false;
        row.classList.remove('is-open');
      }
    });

    const firstNumber = matches.length === 0 ? 0 : firstIndex + 1;
    const lastNumber = Math.min(firstIndex + size, matches.length);
    paginationInfo.textContent = 'Showing ' + firstNumber + '-' + lastNumber + ' of ' + matches.length + ' cases';
    pageIndicator.textContent = 'Page ' + currentPage + ' of ' + pageCount;
    previousPage.disabled = currentPage <= 1;
    nextPage.disabled = currentPage >= pageCount;
  }

  addOptions(joinFilter, 'join');
  addOptions(verdictFilter, 'verdict');
  addOptions(perceptionFilter, 'perception');
  addOptions(defenderFilter, 'defender');
  function resetAndFilter() {
    currentPage = 1;
    applyFilters();
  }

  search.addEventListener('input', resetAndFilter);
  joinFilter.addEventListener('change', resetAndFilter);
  verdictFilter.addEventListener('change', resetAndFilter);
  perceptionFilter.addEventListener('change', resetAndFilter);
  defenderFilter.addEventListener('change', resetAndFilter);
  pageSize.addEventListener('change', resetAndFilter);
  previousPage.addEventListener('click', function () {
    if (currentPage > 1) {
      currentPage--;
      applyFilters();
      document.getElementById('comparison-list').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  nextPage.addEventListener('click', function () {
    currentPage++;
    applyFilters();
    document.getElementById('comparison-list').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  applyFilters();
</script>
</body>
</html>
"@

. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$html = Set-PerceptionReportPresentation -Html $html
[IO.File]::WriteAllText($resolvedOutputPath, $html, [Text.UTF8Encoding]::new($false))

if (-not $NoOpen) {
    Start-Process $resolvedOutputPath
}

[pscustomobject]@{
    CollectionScope = $collectionScope
    CollectionComplete = $collectionComplete
    SessionDiscoveryComplete = $sessionDiscoveryComplete
    CoverageMessage = $coverageMessage
    StatusDiscoveryFallbackUsed = $fallbackStatuses.Count -gt 0
    StatusDiscoveryFallbackAdditionalSessions = $fallbackAdditionalSessions
    SessionsEnumerated = $sessionsById.Count
    InvestigationSessions = $investigationSessions.Count
    UniqueDefenderIncidentIds = $uniqueIncidentCount
    MatchedComparisons = $matchedCount
    Agree = $agreeCount
    Partial = $partialCount
    Conflict = $conflictCount
    Insufficient = $insufficientCount
    Errors = $errorCount
    Requests = $script:requestCount
    RetryAttempts = $script:retryAttemptCount
    Duration = $collectionStopwatch.Elapsed
    HtmlPath = $resolvedOutputPath
    JsonPath = $resolvedJsonPath
    CsvPath = $resolvedCsvPath
}
