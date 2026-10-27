[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.html'),

    [string]$SessionDataPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.json'),

    [ValidateRange(1, 500)]
    [int]$SessionLimit = 500,

    [ValidateRange(1, 500)]
    [int]$MessagePageSize = 100,

    [ValidateRange(1, 20)]
    [int]$MaximumMessagePagesPerRun = 5,

    [ValidateRange(1024, 10485760)]
    [int]$MaximumMarkdownOutputBytes = 1048576,

    [string]$ConfigurationPath = '',

    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
$configuration = Get-PerceptionConfiguration -Path $ConfigurationPath

$scope = 'https://api.securitycopilot.microsoft.com/Perception.Operate.All'
$baseUrl = 'https://perception.microsoft.com/api/v1.0'

$accessToken = Get-PerceptionCliToken -Scope $scope -TenantId $configuration.tenantId

$headers = @{
    Authorization = "Bearer $accessToken"
    Accept        = 'application/json'
}

$collectionStopwatch = [Diagnostics.Stopwatch]::StartNew()
$apiRequestCount = 0
$apiRequestDurationMs = [long]0
$retryCount = 0
$retryDelaySeconds = 0

function Invoke-PerceptionGet {
    param([Parameter(Mandatory)][string]$Uri)

    $result = Invoke-PerceptionGetResult -Uri $Uri
    if (-not $result.Succeeded) {
        throw "GET $Uri failed with HTTP $($result.StatusCode): $($result.ErrorCode) - $($result.ErrorMessage)"
    }

    $result
}

function Invoke-PerceptionCollectionGet {
    param(
        [Parameter(Mandatory)][string]$Uri,

        [ValidateRange(0, 10)]
        [int]$EmptyRetryCount = 4,

        [ValidateRange(1, 500)]
        [int]$MinimumCount = 1
    )

    $attempt = 0
    do {
        $result = Invoke-PerceptionGet -Uri $Uri
        $itemCount = @($result.Body.value).Count
        if ($itemCount -ge $MinimumCount -or $attempt -ge $EmptyRetryCount) {
            return $result
        }

        $attempt++
        $script:retryCount++
        $script:retryDelaySeconds += $attempt
        Write-Warning "GET $Uri returned $itemCount item(s); at least $MinimumCount were requested. Retrying in $attempt second(s) ($attempt of $EmptyRetryCount)."
        Start-Sleep -Seconds $attempt
    } while ($true)
}

function Get-PerceptionErrorDetails {
    param(
        [AllowNull()][object]$Body,
        [Parameter(Mandatory)][int]$StatusCode,
        [AllowNull()][string]$HeaderRequestId
    )

    $errorProperty = if ($null -ne $Body) { $Body.PSObject.Properties['error'] } else { $null }
    $errorObject = if ($null -ne $errorProperty) { $errorProperty.Value } else { $Body }
    $codeProperty = if ($null -ne $errorObject) { $errorObject.PSObject.Properties['code'] } else { $null }
    $messageProperty = if ($null -ne $errorObject) { $errorObject.PSObject.Properties['message'] } else { $null }
    $innerErrorProperty = if ($null -ne $errorObject) { $errorObject.PSObject.Properties['innerError'] } else { $null }
    $innerError = if ($null -ne $innerErrorProperty) { $innerErrorProperty.Value } else { $null }
    $requestIdProperty = if ($null -ne $innerError) { $innerError.PSObject.Properties['request-id'] } else { $null }

    $errorCode = if ($null -ne $codeProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$codeProperty.Value)) {
        [string]$codeProperty.Value
    }
    else {
        "http$StatusCode"
    }
    $errorMessage = if ($null -ne $messageProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$messageProperty.Value)) {
        [string]$messageProperty.Value
    }
    else {
        "HTTP $StatusCode returned a non-standard error response."
    }
    $requestId = if ($null -ne $requestIdProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$requestIdProperty.Value)) {
        [string]$requestIdProperty.Value
    }
    else {
        $HeaderRequestId
    }

    [pscustomobject]@{
        Code      = $errorCode
        Message   = $errorMessage
        RequestId = $requestId
    }
}

function Invoke-PerceptionGetResult {
    param(
        [Parameter(Mandatory)][string]$Uri,

        [ValidateRange(0, 5)]
        [int]$RetryCount = 0
    )

    $attempt = 0
    do {
        $script:apiRequestCount++
        $requestStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $response = Invoke-WebRequest `
                -Method Get `
                -Uri $Uri `
                -Headers $headers `
                -SkipHttpErrorCheck
        }
        finally {
            $requestStopwatch.Stop()
            $script:apiRequestDurationMs += $requestStopwatch.ElapsedMilliseconds
        }

        $body = $null
        $bodyParseError = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$response.Content)) {
            try {
                $body = $response.Content | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $bodyParseError = $_
            }
        }

        if ([int]$response.StatusCode -lt 400) {
            if ($null -ne $bodyParseError) {
                throw "GET $Uri returned invalid JSON: $($bodyParseError.Exception.Message)"
            }

            return [pscustomobject]@{
                Succeeded   = $true
                StatusCode  = [int]$response.StatusCode
                RequestId   = [string]$response.Headers['request-id']
                Body        = $body
                ErrorCode   = $null
                ErrorMessage = $null
            }
        }

        $errorDetails = Get-PerceptionErrorDetails `
            -Body $body `
            -StatusCode ([int]$response.StatusCode) `
            -HeaderRequestId ([string]$response.Headers['request-id'])
        $shouldRetry = $attempt -lt $RetryCount -and (
            $errorDetails.Code -eq 'agentRunNotFound' -or
            [int]$response.StatusCode -ge 500
        )
        if (-not $shouldRetry) {
            return [pscustomobject]@{
                Succeeded    = $false
                StatusCode   = [int]$response.StatusCode
                RequestId    = $errorDetails.RequestId
                Body         = $body
                ErrorCode    = $errorDetails.Code
                ErrorMessage = $errorDetails.Message
            }
        }

        $attempt++
        $script:retryCount++
        $script:retryDelaySeconds += $attempt
        Start-Sleep -Seconds $attempt
    } while ($true)
}

function Assert-SameApiOrigin {
    param([Parameter(Mandatory)][string]$Uri)

    $expected = [Uri]$baseUrl
    $candidate = [Uri]$Uri
    if ($candidate.Scheme -ne $expected.Scheme -or
        $candidate.Host -ne $expected.Host -or
        $candidate.Port -ne $expected.Port) {
        throw "Refusing to follow an API link outside the configured host: $Uri"
    }
}

function New-ApiErrorRecord {
    param([Parameter(Mandatory)][object]$Result)

    [pscustomobject]@{
        statusCode = $Result.StatusCode
        code       = $Result.ErrorCode
        message    = $Result.ErrorMessage
        requestId  = $Result.RequestId
    }
}

function Invoke-MarkdownArtifactDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][long]$ExpectedSize
    )

    Assert-SameApiOrigin -Uri $Uri
    if ($ExpectedSize -gt $MaximumMarkdownOutputBytes) {
        return [pscustomobject]@{
            Succeeded    = $false
            Content      = $null
            StatusCode   = $null
            ErrorCode    = 'outputTooLarge'
            ErrorMessage = "The output is $ExpectedSize bytes; the configured limit is $MaximumMarkdownOutputBytes bytes."
            RequestId    = $null
        }
    }

    $script:apiRequestCount++
    $requestStopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest `
            -Method Get `
            -Uri $Uri `
            -Headers $headers `
            -SkipHttpErrorCheck
    }
    finally {
        $requestStopwatch.Stop()
        $script:apiRequestDurationMs += $requestStopwatch.ElapsedMilliseconds
    }

    if ([int]$response.StatusCode -ge 400) {
        $errorBody = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$response.Content)) {
            try {
                $errorBody = $response.Content | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $errorBody = $null
            }
        }
        $errorDetails = Get-PerceptionErrorDetails `
            -Body $errorBody `
            -StatusCode ([int]$response.StatusCode) `
            -HeaderRequestId ([string]$response.Headers['request-id'])
        return [pscustomobject]@{
            Succeeded    = $false
            Content      = $null
            StatusCode   = [int]$response.StatusCode
            ErrorCode    = $errorDetails.Code
            ErrorMessage = $errorDetails.Message
            RequestId    = $errorDetails.RequestId
        }
    }

    $contentProperty = $response.PSObject.Properties['Content']
    $rawStreamProperty = $response.PSObject.Properties['RawContentStream']
    if ($null -ne $contentProperty -and $contentProperty.Value -is [byte[]]) {
        $bytes = [byte[]]$contentProperty.Value
    }
    elseif ($null -ne $rawStreamProperty -and $null -ne $rawStreamProperty.Value) {
        $memory = [IO.MemoryStream]::new()
        try {
            $rawStreamProperty.Value.CopyTo($memory)
            $bytes = $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    else {
        $bytes = [Text.Encoding]::UTF8.GetBytes([string]$contentProperty.Value)
    }

    if ($bytes.LongLength -ne $ExpectedSize) {
        return [pscustomobject]@{
            Succeeded    = $false
            Content      = $null
            StatusCode   = [int]$response.StatusCode
            ErrorCode    = 'outputSizeMismatch'
            ErrorMessage = "Downloaded $($bytes.LongLength) bytes, but the output listing reported $ExpectedSize bytes."
            RequestId    = [string]$response.Headers['request-id']
        }
    }

    [pscustomobject]@{
        Succeeded    = $true
        Content      = [Text.Encoding]::UTF8.GetString($bytes)
        StatusCode   = [int]$response.StatusCode
        ErrorCode    = $null
        ErrorMessage = $null
        RequestId    = [string]$response.Headers['request-id']
    }
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    $property.Value
}

function Get-LifecycleState {
    param([AllowNull()][object]$InputObject)

    $state = [string](Get-PropertyValue -InputObject $InputObject -Name 'state')
    if (-not [string]::IsNullOrWhiteSpace($state)) {
        return $state
    }

    [string](Get-PropertyValue -InputObject $InputObject -Name 'status')
}

function Test-CachedSessionReusable {
    param(
        [AllowNull()][object]$CachedSession,
        [Parameter(Mandatory)][object]$CurrentSession
    )

    if ($null -eq $CachedSession) {
        return $false
    }

    $terminalStates = @('completed', 'failed', 'canceled')
    $currentId = [string](Get-PropertyValue -InputObject $CurrentSession -Name 'id')
    $cachedId = [string](Get-PropertyValue -InputObject $CachedSession -Name 'id')
    $currentState = Get-LifecycleState -InputObject $CurrentSession
    $cachedState = Get-LifecycleState -InputObject $CachedSession
    $currentUpdatedAt = [string](Get-PropertyValue -InputObject $CurrentSession -Name 'updatedAt')
    $cachedUpdatedAt = [string](Get-PropertyValue -InputObject $CachedSession -Name 'updatedAt')
    if ([string]::IsNullOrWhiteSpace($currentId) -or
        $cachedId -ne $currentId -or
        $currentState -notin $terminalStates -or
        $cachedState -ne $currentState -or
        [string]::IsNullOrWhiteSpace($currentUpdatedAt) -or
        $cachedUpdatedAt -ne $currentUpdatedAt -or
        $null -ne (Get-PropertyValue -InputObject $CachedSession -Name 'error') -or
        $null -ne (Get-PropertyValue -InputObject $CachedSession -Name 'outputsError')) {
        return $false
    }

    foreach ($run in @((Get-PropertyValue -InputObject $CachedSession -Name 'runs'))) {
        if ($null -ne (Get-PropertyValue -InputObject $run -Name 'error')) {
            return $false
        }
    }
    foreach ($output in @((Get-PropertyValue -InputObject $CachedSession -Name 'markdownOutputs'))) {
        if ($null -ne (Get-PropertyValue -InputObject $output -Name 'error')) {
            return $false
        }
    }

    $true
}

function Test-CachedZeroRunReusable {
    param(
        [AllowNull()][object]$CachedEntry,
        [Parameter(Mandatory)][object]$CurrentSession
    )

    if ($null -eq $CachedEntry) {
        return $false
    }

    $currentId = [string](Get-PropertyValue -InputObject $CurrentSession -Name 'id')
    $cachedId = [string](Get-PropertyValue -InputObject $CachedEntry -Name 'id')
    $currentState = Get-LifecycleState -InputObject $CurrentSession
    $currentUpdatedAt = [string](Get-PropertyValue -InputObject $CurrentSession -Name 'updatedAt')
    $cachedUpdatedAt = [string](Get-PropertyValue -InputObject $CachedEntry -Name 'updatedAt')
    -not [string]::IsNullOrWhiteSpace($currentId) -and
        $cachedId -eq $currentId -and
        $currentState -in @('completed', 'failed', 'canceled') -and
        -not [string]::IsNullOrWhiteSpace($currentUpdatedAt) -and
        $cachedUpdatedAt -eq $currentUpdatedAt
}

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)

    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-JsonHtml {
    param([Parameter(Mandatory)][object]$Value)

    ConvertTo-HtmlText ($Value | ConvertTo-Json -Depth 20)
}

$discoveryStopwatch = [Diagnostics.Stopwatch]::StartNew()
$playbookResponse = Invoke-PerceptionCollectionGet -Uri "$baseUrl/playbookDefinitions"
$agentResponse = Invoke-PerceptionCollectionGet -Uri "$baseUrl/agents"
$catalogCapturedAt = [DateTimeOffset]::Now.ToString('o')
$discoveryStopwatch.Stop()

$playbooks = @($playbookResponse.Body.value | Sort-Object displayName)
$agents = @($agentResponse.Body.value | Sort-Object agentDefinitionName, displayName)
$enabledAgents = @(
    $agents |
        Where-Object { (Get-PropertyValue -InputObject $_ -Name 'enabled') -eq $true }
)
$enabledAgentNames = @(
    $enabledAgents |
        ForEach-Object { Get-PropertyValue -InputObject $_ -Name 'agentDefinitionName' }
)

$sessionListingQueryCount = 1
$sessionsById = @{}
$sessionListingStopwatch = [Diagnostics.Stopwatch]::StartNew()
$sessionsUri = "$baseUrl/sessions?`$orderby=createdAt%20desc&`$top=500"
$sessionsResponse = Invoke-PerceptionCollectionGet `
    -Uri $sessionsUri `
    -MinimumCount $SessionLimit
foreach ($session in @($sessionsResponse.Body.value)) {
    $sessionsById[[string]$session.id] = $session
}
$sessionListingStopwatch.Stop()

$sessions = @(
    $sessionsById.Values |
        Sort-Object { [DateTimeOffset]$_.createdAt } -Descending |
        Select-Object -First $SessionLimit
)
$resolvedSessionDataPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
    $SessionDataPath
)
$cachedSessionsById = @{}
$cachedZeroRunSessionsById = @{}
$cacheSettingsCompatible = $false
if (Test-Path -LiteralPath $resolvedSessionDataPath -PathType Leaf) {
    try {
        $cacheDocument = [IO.File]::ReadAllText($resolvedSessionDataPath) |
            ConvertFrom-Json -Depth 30 -ErrorAction Stop
        $schemaVersion = Get-PropertyValue -InputObject $cacheDocument -Name 'schemaVersion'
        $cacheSettings = Get-PropertyValue -InputObject $cacheDocument -Name 'collectionSettings'
        $cachedSessionProperty = $cacheDocument.PSObject.Properties['sessions']
        $cacheSettingsCompatible = $schemaVersion -eq 1 -and
            $null -ne $cacheSettings -and
            [string](Get-PropertyValue -InputObject $cacheDocument -Name 'apiBaseUrl') -eq $baseUrl -and
            [int](Get-PropertyValue -InputObject $cacheSettings -Name 'messagePageSize') -eq $MessagePageSize -and
            [int](Get-PropertyValue -InputObject $cacheSettings -Name 'maximumMessagePagesPerRun') -eq $MaximumMessagePagesPerRun -and
            [int](Get-PropertyValue -InputObject $cacheSettings -Name 'maximumMarkdownOutputBytes') -eq $MaximumMarkdownOutputBytes -and
            $null -ne $cachedSessionProperty
        if ($cacheSettingsCompatible) {
            foreach ($cachedSession in @($cachedSessionProperty.Value)) {
                $cachedSessionsById[[string]$cachedSession.id] = $cachedSession
            }
            foreach ($zeroRunEntry in @(
                Get-PropertyValue -InputObject $cacheDocument -Name 'zeroRunSessions'
            )) {
                $cachedZeroRunSessionsById[[string]$zeroRunEntry.id] = $zeroRunEntry
            }
        }
        else {
            Write-Host 'Existing session JSON uses a different schema or collection depth; session details will be refreshed.'
        }
    }
    catch {
        Write-Warning "Existing session JSON could not be used as a cache and will be replaced: $($_.Exception.Message)"
    }
}
$sessionNodes = [Collections.Generic.List[object]]::new()
$zeroRunSessionNodes = [Collections.Generic.List[object]]::new()
$totalRunCount = 0
$totalMessageCount = 0
$totalMarkdownOutputCount = 0
$totalMessagePageCount = 0
$outputListingCount = 0
$artifactDownloadAttemptCount = 0
$zeroRunSessionCount = 0
$reusedSessionDetailCount = 0
$reusedZeroRunSessionCount = 0
$reusedMessagePageCount = 0

$drilldownStopwatch = [Diagnostics.Stopwatch]::StartNew()
for ($sessionIndex = 0; $sessionIndex -lt $sessions.Count; $sessionIndex++) {
    $session = $sessions[$sessionIndex]
    Write-Progress `
        -Activity 'Collecting Perception session drill-down data' `
        -Status "Session $($sessionIndex + 1) of $($sessions.Count)" `
        -PercentComplete ((($sessionIndex + 1) / [Math]::Max(1, $sessions.Count)) * 100)

    $sessionId = [string]$session.id
    $cachedSession = $cachedSessionsById[$sessionId]
    if (Test-CachedSessionReusable -CachedSession $cachedSession -CurrentSession $session) {
        $sessionNodes.Add($cachedSession)
        $cachedRuns = @((Get-PropertyValue -InputObject $cachedSession -Name 'runs'))
        $cachedOutputs = @((Get-PropertyValue -InputObject $cachedSession -Name 'markdownOutputs'))
        $totalRunCount += $cachedRuns.Count
        $totalMessageCount += @(
            $cachedRuns |
                ForEach-Object { @((Get-PropertyValue -InputObject $_ -Name 'messages')) }
        ).Count
        $cachedMessagePageCount = [int](
            $cachedRuns |
                ForEach-Object {
                    [int](Get-PropertyValue -InputObject $_ -Name 'messagePagesRead')
                } |
                Measure-Object -Sum
        ).Sum
        $totalMessagePageCount += $cachedMessagePageCount
        $reusedMessagePageCount += $cachedMessagePageCount
        $totalMarkdownOutputCount += $cachedOutputs.Count
        $reusedSessionDetailCount++
        continue
    }

    $cachedZeroRunEntry = $cachedZeroRunSessionsById[$sessionId]
    if (Test-CachedZeroRunReusable -CachedEntry $cachedZeroRunEntry -CurrentSession $session) {
        $zeroRunSessionNodes.Add($cachedZeroRunEntry)
        $zeroRunSessionCount++
        $reusedZeroRunSessionCount++
        continue
    }

    $encodedSessionId = [Uri]::EscapeDataString($sessionId)
    $runsResult = Invoke-PerceptionGetResult `
        -Uri "$baseUrl/sessions/$encodedSessionId/agentRuns" `
        -RetryCount 2

    $runNodes = [Collections.Generic.List[object]]::new()
    $sessionError = $null
    $markdownOutputs = [Collections.Generic.List[object]]::new()
    $outputsError = $null

    if (-not $runsResult.Succeeded) {
        $sessionError = New-ApiErrorRecord -Result $runsResult
    }
    elseif (@($runsResult.Body.value).Count -eq 0) {
        $zeroRunSessionCount++
        $zeroRunSessionNodes.Add([pscustomobject]@{
            id = $sessionId
            state = Get-LifecycleState -InputObject $session
            updatedAt = Get-PropertyValue -InputObject $session -Name 'updatedAt'
        })
        continue
    }
    else {
        foreach ($run in @($runsResult.Body.value)) {
            $totalRunCount++
            $messages = [Collections.Generic.List[object]]::new()
            $messageError = $null
            $messagePagesRead = 0
            $messagesTruncated = $false
            $encodedRunId = [Uri]::EscapeDataString([string]$run.id)
            $messagesUri = "$baseUrl/sessions/$encodedSessionId/agentRuns/$encodedRunId/messages?`$top=$MessagePageSize"

            while (-not [string]::IsNullOrWhiteSpace($messagesUri)) {
                if ($messagePagesRead -ge $MaximumMessagePagesPerRun) {
                    $messagesTruncated = $true
                    break
                }

                Assert-SameApiOrigin -Uri $messagesUri
                $messagesResult = Invoke-PerceptionGetResult -Uri $messagesUri -RetryCount 2
                if (-not $messagesResult.Succeeded) {
                    $messageError = New-ApiErrorRecord -Result $messagesResult
                    break
                }

                $messagePagesRead++
                $totalMessagePageCount++
                foreach ($message in @($messagesResult.Body.value)) {
                    $messages.Add([pscustomobject]@{
                        messageId  = Get-PropertyValue -InputObject $message -Name 'messageId'
                        sequenceId = Get-PropertyValue -InputObject $message -Name 'sequenceId'
                        timestamp  = Get-PropertyValue -InputObject $message -Name 'timestamp'
                        role       = Get-PropertyValue -InputObject $message -Name 'role'
                        type       = Get-PropertyValue -InputObject $message -Name 'type'
                        author     = Get-PropertyValue -InputObject $message -Name 'author'
                        content    = Get-PropertyValue -InputObject $message -Name 'content'
                    })
                    $totalMessageCount++
                }

                $nextLink = $messagesResult.Body.PSObject.Properties['@odata.nextLink']
                $messagesUri = if ($null -ne $nextLink) { [string]$nextLink.Value } else { '' }
            }

            $runNodes.Add([pscustomobject]@{
                id                = $run.id
                state             = Get-LifecycleState -InputObject $run
                createdAt         = Get-PropertyValue -InputObject $run -Name 'createdAt'
                updatedAt         = Get-PropertyValue -InputObject $run -Name 'updatedAt'
                startedAt         = Get-PropertyValue -InputObject $run -Name 'startedAt'
                completedAt       = Get-PropertyValue -InputObject $run -Name 'completedAt'
                durationMs        = Get-PropertyValue -InputObject $run -Name 'durationMs'
                agent             = Get-PropertyValue -InputObject $run -Name 'agent'
                messages          = $messages.ToArray()
                messagePagesRead  = $messagePagesRead
                messagesTruncated = $messagesTruncated
                error             = $messageError
            })
        }
    }

    $outputListingCount++
    $outputsResult = Invoke-PerceptionGetResult `
        -Uri "$baseUrl/sessions/$encodedSessionId/outputs" `
        -RetryCount 2

    if (-not $outputsResult.Succeeded) {
        $outputsError = New-ApiErrorRecord -Result $outputsResult
    }
    else {
        foreach ($output in @($outputsResult.Body.value)) {
            $artifactPath = [string](Get-PropertyValue -InputObject $output -Name 'path')
            if ($artifactPath -notmatch '(?i)^shared/outputs/.+\.md$') {
                continue
            }

            $outputSize = [long](Get-PropertyValue -InputObject $output -Name 'size')
            $downloadUrl = [string](Get-PropertyValue -InputObject $output -Name 'downloadUrl')
            $downloadUri = [Uri]::new([Uri]$baseUrl, $downloadUrl).AbsoluteUri
            $artifactDownloadAttemptCount++
            $downloadResult = Invoke-MarkdownArtifactDownload `
                -Uri $downloadUri `
                -ExpectedSize $outputSize

            $outputError = if ($downloadResult.Succeeded) {
                $null
            }
            else {
                New-ApiErrorRecord -Result $downloadResult
            }

            $markdownOutputs.Add([pscustomobject]@{
                path    = $artifactPath
                size    = $outputSize
                content = $downloadResult.Content
                error   = $outputError
            })
            $totalMarkdownOutputCount++
        }
    }

    $sessionNodes.Add([pscustomobject]@{
        id          = $session.id
        state       = Get-LifecycleState -InputObject $session
        createdAt   = $session.createdAt
        updatedAt   = Get-PropertyValue -InputObject $session -Name 'updatedAt'
        displayName = Get-PropertyValue -InputObject $session -Name 'displayName'
        webUrl      = Get-PropertyValue -InputObject $session -Name 'webUrl'
        initiatedBy = Get-PropertyValue -InputObject $session -Name 'initiatedBy'
        tags        = @(Get-PropertyValue -InputObject $session -Name 'tags')
        runs        = $runNodes.ToArray()
        error       = $sessionError
        markdownOutputs = $markdownOutputs.ToArray()
        outputsError    = $outputsError
    })
}
$drilldownStopwatch.Stop()
$agentRunListingCount = $sessions.Count - $reusedSessionDetailCount - $reusedZeroRunSessionCount
$fetchedMessagePageCount = $totalMessagePageCount - $reusedMessagePageCount

Write-Progress -Activity 'Collecting Perception session drill-down data' -Completed

$sessionJson = ConvertTo-Json -InputObject $sessionNodes.ToArray() -Depth 20 -Compress
$sessionJsonBytes = [Text.Encoding]::UTF8.GetBytes($sessionJson)
$sessionDataBase64 = [Convert]::ToBase64String($sessionJsonBytes)
$sessionCacheDocument = [ordered]@{
    schemaVersion = 1
    generatedAt = [DateTimeOffset]::Now.ToString('o')
    environment = 'Production'
    apiBaseUrl = $baseUrl
    catalog = [ordered]@{
        capturedAt = $catalogCapturedAt
        playbooks = $playbooks
        agents = $agents
    }
    collectionSettings = [ordered]@{
        messagePageSize = $MessagePageSize
        maximumMessagePagesPerRun = $MaximumMessagePagesPerRun
        maximumMarkdownOutputBytes = $MaximumMarkdownOutputBytes
    }
    zeroRunSessions = $zeroRunSessionNodes.ToArray()
    sessions = $sessionNodes.ToArray()
}
$sessionCacheJson = $sessionCacheDocument | ConvertTo-Json -Depth 30 -Compress
$collectionStopwatch.Stop()
$collectionDurationText = $collectionStopwatch.Elapsed.ToString('hh\:mm\:ss\.fff')
$apiDurationText = [TimeSpan]::FromMilliseconds($apiRequestDurationMs).ToString('hh\:mm\:ss\.fff')
$sessionJsonSizeMiB = [Math]::Round($sessionJsonBytes.LongLength / 1MB, 2)
$maximumPhaseDurationMs = [Math]::Max(
    1,
    [Math]::Max(
        $discoveryStopwatch.ElapsedMilliseconds,
        [Math]::Max($sessionListingStopwatch.ElapsedMilliseconds, $drilldownStopwatch.ElapsedMilliseconds)
    )
)
$discoveryPhaseWidth = [Math]::Max(1, [Math]::Round(($discoveryStopwatch.ElapsedMilliseconds / $maximumPhaseDurationMs) * 100, 1))
$sessionListingPhaseWidth = [Math]::Max(1, [Math]::Round(($sessionListingStopwatch.ElapsedMilliseconds / $maximumPhaseDurationMs) * 100, 1))
$drilldownPhaseWidth = [Math]::Max(1, [Math]::Round(($drilldownStopwatch.ElapsedMilliseconds / $maximumPhaseDurationMs) * 100, 1))

$knownDependencies = [ordered]@{
    'investigate-incident' = @(
        'Global.Microsoft.Defender.MainAgent'
        'Global.Microsoft.Defender.InvestigationAgent'
    )
    'analyze-article' = @(
        'Global.Microsoft.Defender.MainAgent'
        'Global.Microsoft.Defender.ThreatIntelligenceAgent'
    )
}

$playbookRows = foreach ($playbook in $playbooks) {
    $inputTypes = @(Get-PropertyValue -InputObject $playbook -Name 'acceptedInputTypes')
    $inputText = if ($inputTypes.Count -gt 0) {
        ($inputTypes | ForEach-Object { "<code>$(ConvertTo-HtmlText $_)</code>" }) -join ', '
    }
    else {
        '<span class="muted">None advertised</span>'
    }

    "<tr><td><code>$(ConvertTo-HtmlText (Get-PropertyValue -InputObject $playbook -Name 'id'))</code></td><td>$(ConvertTo-HtmlText (Get-PropertyValue -InputObject $playbook -Name 'displayName'))</td><td>$inputText</td></tr>"
}

$agentRows = if ($agents.Count -eq 0) {
    '<tr><td colspan="4" class="empty">The Production versioned agent registry returned no agents.</td></tr>'
}
else {
    foreach ($agent in $agents) {
        $isEnabled = (Get-PropertyValue -InputObject $agent -Name 'enabled') -eq $true
        $enabledClass = if ($isEnabled) { 'good' } else { 'bad' }
        $enabledText = if ($isEnabled) { 'Enabled' } else { 'Disabled' }
        "<tr><td><code>$(ConvertTo-HtmlText (Get-PropertyValue -InputObject $agent -Name 'agentDefinitionName'))</code></td><td>$(ConvertTo-HtmlText (Get-PropertyValue -InputObject $agent -Name 'displayName'))</td><td><code>$(ConvertTo-HtmlText (Get-PropertyValue -InputObject $agent -Name 'id'))</code></td><td><span class=""pill $enabledClass"">$enabledText</span></td></tr>"
    }
}

$readinessRows = foreach ($entry in $knownDependencies.GetEnumerator()) {
    $playbook = $playbooks |
        Where-Object { (Get-PropertyValue -InputObject $_ -Name 'id') -eq $entry.Key } |
        Select-Object -First 1
    if ($null -eq $playbook) {
        continue
    }

    $missing = @($entry.Value | Where-Object { $_ -notin $enabledAgentNames })
    $statusClass = if ($missing.Count -eq 0) { 'good' } else { 'bad' }
    $statusText = if ($missing.Count -eq 0) { 'Ready' } else { 'Not ready' }
    $required = ($entry.Value | ForEach-Object { "<code>$(ConvertTo-HtmlText $_)</code>" }) -join '<br>'
    $missingText = if ($missing.Count -eq 0) {
        '<span class="muted">None</span>'
    }
    else {
        ($missing | ForEach-Object { "<code>$(ConvertTo-HtmlText $_)</code>" }) -join '<br>'
    }

    "<tr><td><code>$(ConvertTo-HtmlText $entry.Key)</code></td><td>$required</td><td>$missingText</td><td><span class=""pill $statusClass"">$statusText</span></td></tr>"
}

$generatedAt = [DateTimeOffset]::Now
$catalogWarning = if ($playbooks.Count -gt 0 -and $agents.Count -eq 0) {
    @'
<div class="banner danger">
  <strong>Catalog-to-runtime mismatch detected.</strong>
  Production advertises playbooks, but its versioned agent registry returned zero agents.
  Playbooks with required agent dependencies may fail at runtime.
</div>
'@
}
else {
    ''
}
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Perception Production Environment</title>
<style>
  :root {
    color-scheme: light;
    --ink: #172033;
    --muted: #617086;
    --navy: #123b66;
    --blue: #2b78c5;
    --line: #d8e0e9;
    --panel: #ffffff;
    --canvas: #f3f6f9;
    --good: #237a43;
    --bad: #ad3434;
    --cyan: #38bdf8;
    --shadow: 0 10px 30px rgba(20, 45, 70, .08);
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    background: var(--canvas);
    color: var(--ink);
    font-family: Aptos, "Segoe UI", Arial, sans-serif;
  }
  .hero {
    padding: 30px clamp(20px, 5vw, 70px) 34px;
    background:
      radial-gradient(circle at 82% 15%, rgba(56, 189, 248, .2), transparent 30%),
      linear-gradient(130deg, #071f38, #0d4f80 68%, #1472aa);
    color: white;
  }
  .hero-inner {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 28px;
    max-width: 1360px;
    margin: 0 auto;
  }
  .environment-label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 9px;
    color: #cfeeff;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #64e58c;
    box-shadow: 0 0 0 4px rgba(100, 229, 140, .14);
  }
  .hero h1 { margin: 0; font-size: clamp(30px, 4vw, 46px); line-height: 1.06; letter-spacing: -.025em; }
  .hero-subtitle { max-width: 700px; margin: 9px 0 0; color: #dbeeff; font-size: 16px; }
  .hero-meta {
    display: grid;
    gap: 4px;
    min-width: min(100%, 390px);
    padding: 12px 15px;
    border: 1px solid rgba(255,255,255,.2);
    border-radius: 10px;
    background: rgba(2, 19, 35, .24);
  }
  .hero-meta span { color: #a9d7f3; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  .hero-meta strong { font-size: 14px; }
  .hero-meta code { color: #e9f7ff; font-size: 12px; overflow-wrap: anywhere; }
  .jump-nav {
    position: sticky;
    z-index: 10;
    top: 0;
    border-bottom: 1px solid var(--line);
    background: rgba(255,255,255,.96);
    box-shadow: 0 4px 16px rgba(20, 45, 70, .06);
    backdrop-filter: blur(10px);
  }
  .jump-nav div { display: flex; gap: 4px; max-width: 1360px; margin: 0 auto; padding: 8px 20px; overflow-x: auto; scrollbar-width: none; }
  .jump-nav div::-webkit-scrollbar { display: none; }
  .jump-nav a {
    flex: 0 0 auto;
    padding: 7px 11px;
    border-radius: 6px;
    color: #38536d;
    font-size: 13px;
    font-weight: 650;
    text-decoration: none;
  }
  .jump-nav a:hover, .jump-nav a:focus-visible { background: #eaf3fa; color: var(--navy); }
  main { max-width: 1400px; margin: 0 auto; padding: 26px 24px 36px; }
  .cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 22px;
  }
  .card, section {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    box-shadow: var(--shadow);
  }
  .card { position: relative; min-height: 112px; padding: 20px; overflow: hidden; }
  .card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--blue); }
  .card[data-tone="operations"]::before { background: #6f55b7; }
  .card .kicker { color: #75869a; font-size: 10px; font-weight: 750; letter-spacing: .1em; text-transform: uppercase; }
  .card .value { margin-top: 5px; color: var(--navy); font-size: 32px; font-weight: 750; line-height: 1; }
  .card .label { color: var(--muted); font-size: 14px; }
  .efficiency-kpis {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin: 16px 0 20px;
  }
  .efficiency-kpi {
    padding: 14px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: #f8fbfd;
  }
  .efficiency-kpi span { display: block; color: var(--muted); font-size: 12px; font-weight: 650; }
  .efficiency-kpi strong { display: block; margin-top: 3px; color: var(--navy); font-size: 22px; }
  .efficiency-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.25fr) minmax(300px, .75fr);
    gap: 18px;
  }
  .efficiency-panel {
    min-width: 0;
    padding: 17px;
    border: 1px solid var(--line);
    border-radius: 11px;
    background: #fbfcfd;
  }
  .efficiency-panel h3 { margin: 0 0 13px; color: var(--navy); font-size: 17px; }
  .funnel {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
  }
  .funnel-stage {
    min-height: 90px;
    padding: 13px 11px;
    border-radius: 9px;
    background: #e8f2fa;
    text-align: center;
  }
  .funnel-stage:nth-child(2n) { background: #e9e5f6; }
  .funnel-stage strong { display: block; color: var(--navy); font-size: 23px; }
  .funnel-stage span { color: var(--muted); font-size: 12px; }
  .phase-row { margin-top: 12px; }
  .phase-label { display: flex; justify-content: space-between; gap: 12px; color: var(--muted); font-size: 12px; }
  .phase-track { height: 9px; margin-top: 5px; border-radius: 999px; background: #e4eaf0; overflow: hidden; }
  .phase-fill { height: 100%; min-width: 3px; border-radius: inherit; background: linear-gradient(90deg, var(--blue), var(--cyan)); }
  .action-list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
  .action-list li { display: flex; justify-content: space-between; gap: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
  .action-list li:last-child { padding-bottom: 0; border-bottom: 0; }
  .action-list strong { color: var(--navy); }
  .comparison { margin-top: 18px; }
  .comparison td:nth-child(2) { background: #fafcfd; }
  .comparison td:nth-child(3) { background: #f2f8fd; }
  section { margin: 20px 0; padding: 24px; overflow-x: visible; scroll-margin-top: 65px; }
  h2 { margin: 0 0 6px; color: var(--navy); font-size: 24px; letter-spacing: -.015em; }
  .section-intro { margin: 0 0 17px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { padding: 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
  th { background: #eaf2f8; color: var(--navy); font-size: 12px; letter-spacing: .035em; text-transform: uppercase; }
  tbody tr:hover { background: #f8fbfd; }
  .table-scroll { width: 100%; overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }
  .table-scroll table { min-width: 720px; }
  .table-scroll tr:last-child td { border-bottom: 0; }
  .quick-run {
    display: grid;
    grid-template-columns: minmax(230px, 1fr) auto;
    gap: 10px;
    margin: 14px 0 18px;
    padding: 16px;
    border: 1px solid #9cc4e8;
    border-radius: 10px;
    background: #eef7fd;
  }
  .quick-run-copy { grid-column: 1 / -1; }
  .quick-run-copy strong { display: block; color: var(--navy); font-size: 16px; }
  .quick-run-copy span { color: var(--muted); font-size: 13px; }
  .quick-run input, .quick-run button {
    min-height: 42px;
    padding: 9px 11px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: white;
    color: var(--ink);
  }
  .quick-run button {
    border-color: var(--blue);
    background: var(--blue);
    color: white;
    cursor: pointer;
    font-weight: 700;
  }
  .quick-run button:disabled { border-color: #9cadbb; background: #9cadbb; cursor: not-allowed; }
  .quick-run-status { grid-column: 1 / -1; min-height: 19px; color: var(--muted); font-size: 13px; }
  .quick-run-status.success { color: var(--good); }
  .quick-run-status.error { color: var(--bad); }
  .quick-run-status a { color: inherit; font-weight: 700; }
  code { color: #712b68; font-family: Consolas, "Courier New", monospace; }
  .pill {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    color: white;
    font-size: 12px;
    font-weight: 700;
  }
  .pill:not(.good):not(.bad) { background: #6c7180; }
  .good { background: var(--good); }
  .bad { background: var(--bad); }
  .muted { color: var(--muted); }
  .empty { padding: 22px; color: var(--bad); font-weight: 600; text-align: center; }
  .banner {
    margin-bottom: 18px;
    padding: 14px 16px;
    border-radius: 8px;
    border: 1px solid;
  }
  .banner.danger { border-color: #dc8f8f; background: #fff0f0; color: #761f1f; }
  details { margin-top: 12px; }
  summary { cursor: pointer; color: var(--blue); font-weight: 600; }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 15px 0 18px;
    padding: 12px;
    border: 1px solid #d7e5ef;
    border-radius: 10px;
    background: #f5f9fc;
  }
  .controls input, .controls select, .controls button {
    min-height: 38px;
    padding: 8px 10px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: white;
    color: var(--ink);
  }
  .controls input:focus, .controls select:focus, .controls button:focus-visible {
    border-color: var(--blue);
    outline: 3px solid rgba(43, 120, 197, .14);
  }
  .controls input { flex: 1 1 320px; }
  .controls button { cursor: pointer; color: var(--blue); font-weight: 650; }
  .controls button.primary { border-color: var(--blue); background: var(--blue); color: white; }
  .api-flow {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
    gap: 12px;
  }
  details.rest-step, details.session-rest-calls {
    margin: 0;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: #fbfcfd;
    transition: border-color .16s ease, box-shadow .16s ease;
  }
  details.rest-step:hover { border-color: #9dbdd6; box-shadow: 0 5px 16px rgba(20, 45, 70, .07); }
  details.rest-step > summary, details.session-rest-calls > summary {
    padding: 11px 12px;
  }
  details.rest-step pre, details.session-rest-calls pre {
    margin: 0 12px 12px;
    max-height: 420px;
    background: #17222d;
    color: #ecf3f9;
  }
  details.session, details.run {
    min-width: 0;
    margin: 9px 0;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: white;
    overflow: hidden;
    transition: border-color .16s ease, box-shadow .16s ease, transform .16s ease;
  }
  details.session:hover { border-color: #aac4d8; box-shadow: 0 5px 16px rgba(20, 45, 70, .07); }
  details.session.deep-linked, details.run.deep-linked {
    border-color: #2b78c5;
    box-shadow: 0 0 0 3px rgba(43, 120, 197, .2), 0 8px 22px rgba(20, 45, 70, .12);
  }
  details.session[data-state="completed"] { border-left: 4px solid var(--good); }
  details.session[data-state="failed"], details.session[data-state="canceled"] { border-left: 4px solid var(--bad); }
  details.session[data-state="running"], details.session[data-state="queued"] { border-left: 4px solid var(--blue); }
  details.session > summary, details.run > summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 14px 15px;
    list-style-position: inside;
  }
  details.session[open] > summary { border-bottom: 1px solid var(--line); background: #f8fbfd; }
  .session-title-row { display: flex; align-items: center; gap: 9px; width: 100%; min-width: 0; }
  .session-title-row strong { color: #1e659d; font-size: 15px; line-height: 1.35; overflow-wrap: anywhere; }
  .session-facts {
    display: flex;
    flex: 1 0 100%;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 15px;
    padding-left: 22px;
    color: var(--muted);
    font-size: 12px;
  }
  .session-facts code { font-size: 12px; }
  details.run { margin-left: 18px; background: #fbfcfd; }
  details.markdown-output {
    margin: 9px 0 9px 18px;
    border: 1px solid #aac8df;
    border-radius: 8px;
    background: #f8fbfd;
  }
  details.markdown-output > summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 9px;
    padding: 12px;
  }
  .detail-body { min-width: 0; padding: 0 12px 12px; overflow: hidden; }
  .subsection-title { margin: 18px 0 8px; color: var(--navy); font-size: 17px; }
  .metadata {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 6px 14px;
    margin: 3px 0 12px;
    color: var(--muted);
    font-size: 13px;
  }
  .message {
    margin: 8px 0 8px 36px;
    padding: 10px;
    border-left: 4px solid #9cc4e8;
    background: #f5f8fb;
  }
  .message header {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 0;
    background: none;
    color: var(--muted);
    font-size: 12px;
  }
  .message pre { max-height: 300px; margin-bottom: 0; background: white; }
  .output-actions { margin: 0 0 12px; }
  .output-actions button {
    padding: 7px 11px;
    border: 1px solid var(--blue);
    border-radius: 6px;
    background: white;
    color: var(--blue);
    cursor: pointer;
    font-weight: 600;
  }
  .markdown {
    width: 100%;
    max-width: 980px;
    min-width: 0;
    padding: 20px 24px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: white;
    color: #202a33;
    line-height: 1.6;
    overflow-wrap: anywhere;
  }
  .markdown h1, .markdown h2, .markdown h3,
  .markdown h4, .markdown h5, .markdown h6 {
    margin: 1.4em 0 .55em;
    color: var(--navy);
    line-height: 1.25;
    overflow-wrap: anywhere;
  }
  .markdown h1 { padding-bottom: .3em; border-bottom: 2px solid var(--line); font-size: 2em; }
  .markdown h2 { padding-bottom: .25em; border-bottom: 1px solid var(--line); font-size: 1.55em; }
  .markdown h3 { font-size: 1.25em; }
  .markdown h1:first-child, .markdown h2:first-child, .markdown h3:first-child { margin-top: 0; }
  .markdown p, .markdown ul, .markdown ol, .markdown blockquote { margin: .7em 0; }
  .markdown blockquote {
    padding: .1em 1em;
    border-left: 4px solid #7eacd0;
    background: #f4f8fb;
    color: #43576a;
  }
  .markdown-table-scroll { width: 100%; overflow-x: auto; }
  .markdown table { min-width: 760px; margin: 1em 0; }
  .markdown th { background: #eaf2f8; }
  .markdown pre { max-height: 520px; background: #17222d; color: #ecf3f9; }
  .markdown pre code { color: inherit; }
  .markdown code {
    padding: .12em .35em;
    border-radius: 4px;
    background: #eef2f5;
    color: #37495a;
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .markdown pre code { padding: 0; background: transparent; white-space: pre-wrap; }
  .markdown a { color: var(--blue); overflow-wrap: anywhere; }
  .markdown hr { border: 0; border-top: 1px solid var(--line); margin: 1.4em 0; }
  .error-box {
    margin: 9px 0 9px 18px;
    padding: 10px;
    border: 1px solid #dc8f8f;
    border-radius: 6px;
    background: #fff0f0;
    color: #761f1f;
  }
  .count { color: var(--muted); font-size: 12px; font-weight: 500; }
  .hidden { display: none; }
  pre {
    max-height: 420px;
    overflow: auto;
    padding: 13px;
    background: #f5f7fa;
    border: 1px solid var(--line);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  footer { padding: 4px 24px 28px; color: var(--muted); text-align: center; font-size: 13px; }
  @media (max-width: 900px) {
    .hero-inner { align-items: start; flex-direction: column; }
    .hero-meta { width: 100%; }
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .efficiency-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .efficiency-grid { grid-template-columns: 1fr; }
    .funnel { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .api-flow { grid-template-columns: 1fr; }
  }
  @media (max-width: 560px) {
    .hero { padding: 24px 18px 26px; }
    .jump-nav div { padding-inline: 12px; }
    main { padding: 16px 12px 28px; }
    .cards { grid-template-columns: 1fr; }
    .efficiency-kpis, .funnel { grid-template-columns: 1fr; }
    section { padding: 17px; }
    details.run, details.markdown-output, .message, .error-box { margin-left: 0; }
    .session-facts { padding-left: 0; }
    .controls > * { width: 100%; }
    .quick-run { grid-template-columns: 1fr; }
    .quick-run-copy, .quick-run-status { grid-column: 1; }
  }
</style>
</head>
<body class="perception-environment">
<header class="hero">
  <div class="hero-inner">
    <div>
      <div class="environment-label"><span class="status-dot"></span>Production API snapshot</div>
      <h1>Perception Production Environment</h1>
      <p class="hero-subtitle">Explore the live catalog, session activity, agent runs, messages, and generated Markdown outputs.</p>
      <div class="environment-actions">
        <a class="button primary" href="#sessions">Explore sessions</a>
        <a class="button" href="#agents">View agent registry</a>
      </div>
    </div>
    <div class="hero-meta">
      <span>Generated</span>
      <strong>$(ConvertTo-HtmlText $generatedAt.ToString('yyyy-MM-dd HH:mm:ss zzz'))</strong>
      <code>$(ConvertTo-HtmlText $baseUrl)</code>
    </div>
  </div>
</header>
<nav class="jump-nav" aria-label="Dashboard sections">
  <div>
    <a href="#overview">Overview</a>
    <a href="#efficiency">Efficiency</a>
    <a href="#rest-calls">REST calls</a>
    <a href="#sessions">Session explorer</a>
    <a href="#readiness">Readiness</a>
    <a href="#playbooks">Playbooks</a>
    <a href="#agents">Agents</a>
    <a href="/assurance-freshness">Run Quality</a>
    <a href="/threat-protection">Threat Briefing</a>
    <a href="/systemic-threat-signals">Systemic Threat Signals</a>
    <a href="/agent-behavior">Agent Behavior Analysis</a>
  </div>
</nav>
<main>
  $catalogWarning
  <div class="cards" id="overview">
    <div class="card"><div class="kicker">Discovery</div><div class="value">$($playbooks.Count)</div><div class="label">Playbook definitions</div></div>
    <div class="card"><div class="kicker">Discovery</div><div class="value">$($agents.Count)</div><div class="label">Registered agents</div></div>
    <div class="card"><div class="kicker">Readiness</div><div class="value">$($enabledAgents.Count)</div><div class="label">Enabled agents</div></div>
    <div class="card"><div class="kicker">Readiness</div><div class="value">$($readinessRows.Count)</div><div class="label">Known dependency checks</div></div>
    <div class="card" data-tone="operations"><div class="kicker">Operations</div><div class="value">$($sessionNodes.Count)</div><div class="label">Sessions retained with runs or diagnostics</div></div>
    <div class="card" data-tone="operations"><div class="kicker">Operations</div><div class="value">$totalRunCount</div><div class="label">Agent runs collected</div></div>
    <div class="card" data-tone="operations"><div class="kicker">Evidence</div><div class="value">$totalMessageCount</div><div class="label">Messages collected</div></div>
    <div class="card" data-tone="operations"><div class="kicker">Evidence</div><div class="value">$totalMarkdownOutputCount</div><div class="label">Markdown outputs collected</div></div>
  </div>

  <section id="efficiency">
    <h2>Efficiency and action volume</h2>
    <p class="section-intro">Measured values from this generated snapshot. Optimization targets are shown separately and are not presented as completed savings.</p>
    <div class="efficiency-kpis">
      <div class="efficiency-kpi"><span>API requests, including retries</span><strong>$apiRequestCount</strong></div>
      <div class="efficiency-kpi"><span>Collection elapsed</span><strong>$collectionDurationText</strong></div>
      <div class="efficiency-kpi"><span>Retries / backoff</span><strong>$retryCount / $retryDelaySeconds s</strong></div>
      <div class="efficiency-kpi"><span>Embedded session JSON</span><strong>$sessionJsonSizeMiB MiB</strong></div>
    </div>

    <div class="efficiency-grid">
      <div class="efficiency-panel">
        <h3>Collection funnel</h3>
        <div class="funnel">
          <div class="funnel-stage"><strong>$sessionListingQueryCount</strong><span>session listing query</span></div>
          <div class="funnel-stage"><strong>$($sessions.Count)</strong><span>session candidates, limit $SessionLimit</span></div>
          <div class="funnel-stage"><strong>$zeroRunSessionCount</strong><span>zero-run sessions discarded</span></div>
          <div class="funnel-stage"><strong>$($sessionNodes.Count)</strong><span>sessions retained</span></div>
          <div class="funnel-stage"><strong>$totalRunCount</strong><span>agent runs</span></div>
          <div class="funnel-stage"><strong>$totalMessagePageCount</strong><span>message pages represented</span></div>
          <div class="funnel-stage"><strong>$totalMessageCount</strong><span>messages collected</span></div>
          <div class="funnel-stage"><strong>$outputListingCount</strong><span>output listings</span></div>
          <div class="funnel-stage"><strong>$artifactDownloadAttemptCount</strong><span>Markdown artifacts considered</span></div>
          <div class="funnel-stage"><strong>$sessionJsonSizeMiB MiB</strong><span>embedded JSON payload</span></div>
        </div>
      </div>

      <div class="efficiency-panel">
        <h3>Action volume</h3>
        <ul class="action-list">
          <li><span>Catalog discovery</span><strong>2 logical calls</strong></li>
          <li><span>Session listing</span><strong>$sessionListingQueryCount logical call</strong></li>
          <li><span>Cached session details reused</span><strong>$reusedSessionDetailCount</strong></li>
          <li><span>Cached zero-run results reused</span><strong>$reusedZeroRunSessionCount</strong></li>
          <li><span>Agent-run listings fetched</span><strong>$agentRunListingCount</strong></li>
          <li><span>Zero-run sessions skipped</span><strong>$zeroRunSessionCount</strong></li>
          <li><span>Message pages fetched</span><strong>$fetchedMessagePageCount</strong></li>
          <li><span>Output listings</span><strong>$outputListingCount</strong></li>
          <li><span>Artifact candidates</span><strong>$artifactDownloadAttemptCount</strong></li>
          <li><span>Actual API attempts</span><strong>$apiRequestCount</strong></li>
          <li><span>Time inside HTTP requests</span><strong>$apiDurationText</strong></li>
        </ul>
      </div>
    </div>

    <div class="efficiency-panel" style="margin-top: 18px">
      <h3>Collection time by phase</h3>
      <div class="phase-row">
        <div class="phase-label"><span>Catalog discovery</span><strong>$($discoveryStopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))</strong></div>
        <div class="phase-track"><div class="phase-fill" style="width: $discoveryPhaseWidth%"></div></div>
      </div>
      <div class="phase-row">
        <div class="phase-label"><span>Session-state listing</span><strong>$($sessionListingStopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))</strong></div>
        <div class="phase-track"><div class="phase-fill" style="width: $sessionListingPhaseWidth%"></div></div>
      </div>
      <div class="phase-row">
        <div class="phase-label"><span>Session drill-down, messages, and outputs</span><strong>$($drilldownStopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))</strong></div>
        <div class="phase-track"><div class="phase-fill" style="width: $drilldownPhaseWidth%"></div></div>
      </div>
    </div>

    <div class="table-scroll comparison">
      <table>
        <thead><tr><th>Dimension</th><th>Current measured snapshot</th><th>Recommended after target</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td>Collection model</td><td>Sequential, eager drill-down</td><td>Bounded session concurrency</td><td><span class="pill">Proposed</span></td></tr>
          <tr><td>Default session limit</td><td>$SessionLimit</td><td>500 with a smaller override for diagnostics</td><td><span class="pill good">Applied</span></td></tr>
          <tr><td>Zero-run sessions</td><td>Discarded after the run lookup</td><td>No output-list or payload work</td><td><span class="pill good">Applied</span></td></tr>
          <tr><td>Transcript depth</td><td>Full collection</td><td>Summary and Full modes</td><td><span class="pill">Proposed</span></td></tr>
          <tr><td>Markdown content</td><td>Eagerly downloaded</td><td>Fetched on demand</td><td><span class="pill">Proposed</span></td></tr>
          <tr><td>Repeated refreshes</td><td>Reuse by session ID and <code>updatedAt</code></td><td>Refresh only new, changed, active, or previously incomplete sessions</td><td><span class="pill good">Applied</span></td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <section id="rest-calls">
    <h2>REST calls used by this dashboard</h2>
    <p class="section-intro">
      Every request uses <code>Authorization: Bearer &lt;access-token&gt;</code> and
      <code>Accept: application/json</code>.
    </p>
    <div class="api-flow">
      <details class="rest-step">
        <summary>1. Discover playbooks</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/playbookDefinitions HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json</pre>
      </details>
      <details class="rest-step">
        <summary>2. Read the versioned agent registry</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/agents HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json</pre>
      </details>
      <details class="rest-step">
        <summary>3. List newest sessions</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/sessions?`$orderby=createdAt desc&amp;`$top=500 HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json</pre>
        <p class="small">The API returns lifecycle values as <code>state</code>. The collector does not apply a status filter because runtime-only states such as <code>queued</code> are not accepted as filter values.</p>
      </details>
      <details class="rest-step">
        <summary>4. List a session's agent runs</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/sessions/{sessionId}/agentRuns HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json</pre>
      </details>
      <details class="rest-step">
        <summary>5. Read paged run messages</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/sessions/{sessionId}/agentRuns/{agentRunId}/messages?`$top=$MessagePageSize HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json</pre>
        <p class="small">Follow each same-origin <code>@odata.nextLink</code> until exhausted or the configured page limit is reached.</p>
      </details>
      <details class="rest-step">
        <summary>6. List and download Markdown outputs</summary>
        <pre>GET $(ConvertTo-HtmlText $baseUrl)/sessions/{sessionId}/outputs HTTP/1.1
Authorization: Bearer &lt;access-token&gt;
Accept: application/json

GET {origin}{artifact.downloadUrl} HTTP/1.1
Authorization: Bearer &lt;access-token&gt;</pre>
        <p class="small">Use the exact relative <code>downloadUrl</code> returned by the output listing; do not construct a URL from a transcript path.</p>
      </details>
    </div>
  </section>

  <section id="sessions">
    <h2>Session explorer</h2>
    <p class="section-intro">Search and expand the newest sessions to inspect outputs, agent runs, and message transcripts.</p>
    <div class="controls">
      <input id="session-search" type="search" placeholder="Search session ID, display name, or tag" aria-label="Search sessions">
      <select id="state-filter" aria-label="Filter sessions by state"><option value="">All states</option></select>
      <button id="expand-sessions" class="primary" type="button">Expand visible sessions</button>
      <button id="collapse-sessions" type="button">Collapse all</button>
    </div>
    <div id="session-root"></div>
    <noscript>This drill-down requires JavaScript enabled in the local browser.</noscript>
  </section>

  <section id="readiness">
    <h2>Known playbook dependency readiness</h2>
    <form id="incident-runner" class="quick-run">
      <div class="quick-run-copy">
        <strong>Run an incident investigation</strong>
        <span>Starts the <code>investigate-incident</code> playbook using the current Azure CLI account.</span>
      </div>
      <input id="incident-id" name="incidentId" inputmode="numeric" pattern="[0-9]{1,32}" maxlength="32" placeholder="Defender incident ID" aria-label="Defender incident ID" required>
      <button id="run-incident" type="submit" disabled>Run investigation</button>
      <div id="incident-runner-status" class="quick-run-status" role="status" aria-live="polite">Start this page with <code>Start-PerceptionLiveEnvironment.ps1</code> to enable this action.</div>
    </form>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Playbook</th><th>Required agents</th><th>Missing agents</th><th>Status</th></tr></thead>
        <tbody>$($readinessRows -join [Environment]::NewLine)</tbody>
      </table>
    </div>
  </section>

  <section id="playbooks">
    <h2>Live playbook catalog</h2>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Playbook ID</th><th>Display name</th><th>Accepted inputs</th></tr></thead>
        <tbody>$($playbookRows -join [Environment]::NewLine)</tbody>
      </table>
    </div>
    <details>
      <summary>Raw playbook API response</summary>
      <pre>$(ConvertTo-JsonHtml $playbookResponse.Body)</pre>
    </details>
  </section>

  <section id="agents">
    <h2>Live versioned agent registry</h2>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Definition name</th><th>Display name</th><th>Agent ID</th><th>Status</th></tr></thead>
        <tbody>$($agentRows -join [Environment]::NewLine)</tbody>
      </table>
    </div>
    <details>
      <summary>Raw agent API response</summary>
      <pre>$(ConvertTo-JsonHtml $agentResponse.Body)</pre>
    </details>
  </section>
</main>
<footer>
  Generated from live Production API responses. No access token is stored in this page.
</footer>
<script>
  const encodedSessionData = '$(ConvertTo-HtmlText $sessionDataBase64)';
  const binarySessionData = atob(encodedSessionData);
  const sessionBytes = Uint8Array.from(binarySessionData, function (character) {
    return character.charCodeAt(0);
  });
  const sessions = JSON.parse(new TextDecoder().decode(sessionBytes));
  const root = document.getElementById('session-root');
  const search = document.getElementById('session-search');
  const stateFilter = document.getElementById('state-filter');
  const incidentRunner = document.getElementById('incident-runner');
  const incidentIdInput = document.getElementById('incident-id');
  const runIncidentButton = document.getElementById('run-incident');
  const incidentRunnerStatus = document.getElementById('incident-runner-status');
  const apiBaseUrl = '$(ConvertTo-HtmlText $baseUrl)';
  const messagePageSize = $MessagePageSize;

  function element(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function appendMetadata(container, label, value) {
    if (value === undefined || value === null || value === '') return;
    const item = element('div');
    item.append(element('strong', null, label + ': '));
    item.append(document.createTextNode(String(value)));
    container.append(item);
  }

  function appendError(container, error) {
    if (!error) return;
    const box = element('div', 'error-box');
    box.append(element('strong', null, (error.code || 'API error') + ' '));
    box.append(document.createTextNode(error.message || 'The API request failed.'));
    if (error.statusCode) box.append(element('div', null, 'HTTP ' + error.statusCode));
    if (error.requestId) box.append(element('code', null, 'Request ID: ' + error.requestId));
    container.append(box);
  }

  function setIncidentRunnerStatus(message, className) {
    incidentRunnerStatus.className = 'quick-run-status' + (className ? ' ' + className : '');
    incidentRunnerStatus.replaceChildren(document.createTextNode(message));
  }

  async function enableIncidentRunner() {
    try {
      const response = await fetch('/api/health', {
        method: 'GET',
        headers: { Accept: 'application/json' }
      });
      if (!response.ok) throw new Error('Local runner is unavailable.');
      runIncidentButton.disabled = false;
      setIncidentRunnerStatus('Ready. Enter a Defender incident ID.', '');
    }
    catch {
      runIncidentButton.disabled = true;
    }
  }

  incidentRunner.addEventListener('submit', async function (event) {
    event.preventDefault();
    const incidentId = incidentIdInput.value.trim();
    if (!/^[0-9]{1,32}$/.test(incidentId)) {
      setIncidentRunnerStatus('Incident ID must contain 1 to 32 digits.', 'error');
      incidentIdInput.focus();
      return;
    }

    runIncidentButton.disabled = true;
    incidentIdInput.disabled = true;
    setIncidentRunnerStatus('Starting investigation for incident ' + incidentId + '...', '');

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ incidentId: incidentId })
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error && result.error.message
          ? result.error.message
          : 'The investigation could not be started.');
      }

      incidentRunnerStatus.className = 'quick-run-status success';
      incidentRunnerStatus.replaceChildren(
        document.createTextNode('Session ' + result.id + ' created with state ' + (result.state || 'unknown') + '. ')
      );
      if (result.webUrl) {
        const link = element('a', null, 'Open session');
        link.href = result.webUrl;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        incidentRunnerStatus.append(link);
      }
    }
    catch (error) {
      setIncidentRunnerStatus(error.message || 'The investigation could not be started.', 'error');
    }
    finally {
      incidentIdInput.disabled = false;
      runIncidentButton.disabled = false;
    }
  });

  enableIncidentRunner();

  function createStatePill(state) {
    const terminalGood = state === 'completed' || state === 'succeeded';
    const className = terminalGood ? 'pill good' : (state === 'failed' || state === 'canceled' || state === 'cancelled' ? 'pill bad' : 'pill');
    const pill = element('span', className, state || 'unknown');
    return pill;
  }

  function messageContent(message) {
    if (message.content === undefined || message.content === null) return '';
    return typeof message.content === 'string'
      ? message.content
      : JSON.stringify(message.content, null, 2);
  }

  function appendInlineMarkdown(container, text) {
    const tokenPattern = /(``[^``\r\n]+``|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g;
    let cursor = 0;
    let match;
    while ((match = tokenPattern.exec(text)) !== null) {
      if (match.index > cursor) {
        container.append(document.createTextNode(text.slice(cursor, match.index)));
      }

      const token = match[0];
      if (token.startsWith('``')) {
        container.append(element('code', null, token.slice(1, -1)));
      } else if (token.startsWith('**')) {
        container.append(element('strong', null, token.slice(2, -2)));
      } else {
        const linkMatch = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
        let allowedUrl = null;
        try {
          const parsedUrl = new URL(linkMatch[2]);
          if (parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'http:') {
            allowedUrl = parsedUrl.href;
          }
        } catch (error) {
          allowedUrl = null;
        }

        if (allowedUrl) {
          const link = element('a', null, linkMatch[1]);
          link.href = allowedUrl;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          container.append(link);
        } else {
          container.append(document.createTextNode(linkMatch[1] + ' (' + linkMatch[2] + ')'));
        }
      }
      cursor = tokenPattern.lastIndex;
    }
    if (cursor < text.length) {
      container.append(document.createTextNode(text.slice(cursor)));
    }
  }

  function markdownTableCells(line) {
    let value = line.trim();
    if (value.startsWith('|')) value = value.slice(1);
    if (value.endsWith('|')) value = value.slice(0, -1);
    return value.split('|').map(function (cell) { return cell.trim(); });
  }

  function isMarkdownTableDivider(line) {
    const cells = markdownTableCells(line);
    return cells.length > 0 && cells.every(function (cell) {
      return /^:?-{3,}:?$/.test(cell);
    });
  }

  function isMarkdownBlockStart(lines, index) {
    const line = lines[index];
    if (
      /^#{1,6}\s+/.test(line) ||
      /^``````/.test(line.trim()) ||
      /^\s*([-+*])\s+/.test(line) ||
      /^\s*\d+\.\s+/.test(line) ||
      /^\s*>\s?/.test(line) ||
      /^\s*((-{3,})|(\*{3,})|(_{3,}))\s*$/.test(line)
    ) return true;
    return index + 1 < lines.length && line.includes('|') && isMarkdownTableDivider(lines[index + 1]);
  }

  function renderMarkdown(markdown, container) {
    const lines = String(markdown || '').replace(/\r\n?/g, '\n').split('\n');
    let index = 0;
    while (index < lines.length) {
      const line = lines[index];
      if (!line.trim()) {
        index++;
        continue;
      }

      const fence = /^``````\s*([A-Za-z0-9_-]*)/.exec(line.trim());
      if (fence) {
        index++;
        const codeLines = [];
        while (index < lines.length && !/^``````/.test(lines[index].trim())) {
          codeLines.push(lines[index]);
          index++;
        }
        if (index < lines.length) index++;
        const pre = element('pre');
        const code = element('code', null, codeLines.join('\n'));
        if (fence[1]) code.className = 'language-' + fence[1];
        pre.append(code);
        container.append(pre);
        continue;
      }

      const heading = /^(#{1,6})\s+(.+)$/.exec(line);
      if (heading) {
        const headingElement = element('h' + heading[1].length);
        appendInlineMarkdown(headingElement, heading[2]);
        container.append(headingElement);
        index++;
        continue;
      }

      if (/^\s*((-{3,})|(\*{3,})|(_{3,}))\s*$/.test(line)) {
        container.append(element('hr'));
        index++;
        continue;
      }

      if (index + 1 < lines.length && line.includes('|') && isMarkdownTableDivider(lines[index + 1])) {
        const table = element('table');
        const head = element('thead');
        const headRow = element('tr');
        markdownTableCells(line).forEach(function (cellText) {
          const cell = element('th');
          appendInlineMarkdown(cell, cellText);
          headRow.append(cell);
        });
        head.append(headRow);
        table.append(head);
        index += 2;

        const tableBody = element('tbody');
        while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {
          const row = element('tr');
          markdownTableCells(lines[index]).forEach(function (cellText) {
            const cell = element('td');
            appendInlineMarkdown(cell, cellText);
            row.append(cell);
          });
          tableBody.append(row);
          index++;
        }
        table.append(tableBody);
        const tableWrapper = element('div', 'markdown-table-scroll');
        tableWrapper.append(table);
        container.append(tableWrapper);
        continue;
      }

      const unordered = /^\s*[-+*]\s+/.test(line);
      const ordered = /^\s*\d+\.\s+/.test(line);
      if (unordered || ordered) {
        const list = element(ordered ? 'ol' : 'ul');
        const itemPattern = ordered ? /^\s*\d+\.\s+(.+)$/ : /^\s*[-+*]\s+(.+)$/;
        while (index < lines.length) {
          const itemMatch = itemPattern.exec(lines[index]);
          if (!itemMatch) break;
          const item = element('li');
          appendInlineMarkdown(item, itemMatch[1]);
          list.append(item);
          index++;
        }
        container.append(list);
        continue;
      }

      if (/^\s*>\s?/.test(line)) {
        const quoteLines = [];
        while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
          quoteLines.push(lines[index].replace(/^\s*>\s?/, ''));
          index++;
        }
        const quote = element('blockquote');
        appendInlineMarkdown(quote, quoteLines.join(' '));
        container.append(quote);
        continue;
      }

      const paragraphLines = [line.trim()];
      index++;
      while (index < lines.length && lines[index].trim() && !isMarkdownBlockStart(lines, index)) {
        paragraphLines.push(lines[index].trim());
        index++;
      }
      const paragraph = element('p');
      appendInlineMarkdown(paragraph, paragraphLines.join(' '));
      container.append(paragraph);
    }
  }

  function downloadMarkdown(output) {
    const blob = new Blob([output.content || ''], { type: 'text/markdown;charset=utf-8' });
    const objectUrl = URL.createObjectURL(blob);
    const link = element('a');
    const pathParts = String(output.path || 'output.md').split('/');
    link.href = objectUrl;
    link.download = pathParts[pathParts.length - 1] || 'output.md';
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  }

  function renderMarkdownOutput(output, body) {
    if (body.dataset.loaded === 'true') return;
    body.dataset.loaded = 'true';
    appendError(body, output.error);
    if (output.error || output.content === undefined || output.content === null) return;

    const actions = element('div', 'output-actions');
    const downloadButton = element('button', null, 'Download Markdown');
    downloadButton.type = 'button';
    downloadButton.addEventListener('click', function () { downloadMarkdown(output); });
    actions.append(downloadButton);
    body.append(actions);

    const rendered = element('article', 'markdown');
    renderMarkdown(output.content, rendered);
    body.append(rendered);
  }

  function appendSessionRestCalls(session, body) {
    const details = element('details', 'session-rest-calls');
    details.append(element('summary', null, 'REST calls for this session'));
    const sessionId = encodeURIComponent(session.id);
    const calls = [
      'GET ' + apiBaseUrl + '/sessions/' + sessionId + '/agentRuns',
      'GET ' + apiBaseUrl + '/sessions/' + sessionId + '/outputs'
    ];

    (session.runs || []).forEach(function (run) {
      calls.push(
        'GET ' + apiBaseUrl + '/sessions/' + sessionId +
        '/agentRuns/' + encodeURIComponent(run.id) + '/messages?`$top=' + messagePageSize
      );
    });
    (session.markdownOutputs || []).forEach(function (output) {
      calls.push(
        'GET {origin}{downloadUrl returned for "' + output.path + '"}'
      );
    });

    const requestHeaders = [
      'Authorization: Bearer <access-token>',
      'Accept: application/json'
    ].join('\n');
    details.append(element('pre', null, calls.map(function (call) {
      return call + ' HTTP/1.1\n' + requestHeaders;
    }).join('\n\n')));
    body.append(details);
  }

  function renderMessages(run, body) {
    if (body.dataset.loaded === 'true') return;
    body.dataset.loaded = 'true';
    appendError(body, run.error);

    if (!run.messages || run.messages.length === 0) {
      body.append(element('div', 'empty', run.error ? 'No messages were retrieved.' : 'This run returned no messages.'));
      return;
    }

    run.messages.forEach(function (message) {
      const card = element('article', 'message');
      const header = element('header');
      header.append(element('strong', null, message.type || 'message'));
      header.append(element('span', null, message.role || ''));
      header.append(element('span', null, message.timestamp || ''));
      header.append(element('code', null, message.messageId || ''));
      card.append(header);
      card.append(element('pre', null, messageContent(message)));
      body.append(card);
    });

    if (run.messagesTruncated) {
      body.append(element('div', 'error-box', 'Message collection reached the configured page limit and is incomplete.'));
    }
  }

  function renderSessionDetails(session, body) {
    if (body.dataset.loaded === 'true') return;
    body.dataset.loaded = 'true';
    body.append(element('h3', 'subsection-title', 'Markdown outputs under shared/outputs/'));
    body.append(element(
      'p',
      'muted small',
      'This per-session list includes Markdown artifacts in shared/outputs/ and all nested subdirectories.'
    ));
    appendError(body, session.outputsError);

    const markdownOutputs = (session.markdownOutputs || []).slice().sort(function (left, right) {
      return String(left.path || '').localeCompare(String(right.path || ''));
    });
    if (markdownOutputs.length > 0) {
      markdownOutputs.forEach(function (output) {
        const outputDetails = element('details', 'markdown-output');
        const outputSummary = element('summary');
        outputSummary.append(element('strong', null, output.path || 'Markdown output'));
        outputSummary.append(element('span', 'count', Number(output.size || 0).toLocaleString() + ' bytes'));
        if (output.error) outputSummary.append(element('span', 'pill bad', 'unavailable'));
        outputDetails.append(outputSummary);

        const outputBody = element('div', 'detail-body');
        outputDetails.append(outputBody);
        outputDetails.addEventListener('toggle', function () {
          if (outputDetails.open) renderMarkdownOutput(output, outputBody);
        });
        body.append(outputDetails);
      });
    }
    else if (!session.outputsError) {
      body.append(element('div', 'empty', 'No Markdown artifacts were returned under shared/outputs/ for this session.'));
    }

    appendSessionRestCalls(session, body);

    body.append(element('h3', 'subsection-title', 'Agent runs'));
    appendError(body, session.error);

    if (!session.runs || session.runs.length === 0) {
      body.append(element('div', 'empty', session.error ? 'Agent runs could not be retrieved.' : 'No agent runs were returned.'));
      return;
    }

    session.runs.forEach(function (run) {
      const details = element('details', 'run');
      details.dataset.runId = run.id || '';
      details.id = 'run-' + String(run.id || '').replace(/[^A-Za-z0-9_-]/g, '-');
      const summary = element('summary');
      const agentName = run.agent && (run.agent.displayName || run.agent.agentDefinitionName || run.agent.id);
      summary.append(element('strong', null, agentName || 'Agent run'));
      summary.append(createStatePill(run.state));
      summary.append(element('span', 'count', (run.messages ? run.messages.length : 0) + ' messages'));
      summary.append(element('code', null, run.id));
      details.append(summary);

      const runBody = element('div', 'detail-body');
      const metadata = element('div', 'metadata');
      appendMetadata(metadata, 'Created', run.createdAt);
      appendMetadata(metadata, 'Started', run.startedAt);
      appendMetadata(metadata, 'Completed', run.completedAt);
      appendMetadata(metadata, 'Duration (ms)', run.durationMs);
      appendMetadata(metadata, 'Message pages', run.messagePagesRead);
      runBody.append(metadata);
      details.append(runBody);
      details.addEventListener('toggle', function () {
        if (details.open) renderMessages(run, runBody);
      });
      body.append(details);
    });
  }

  function createSession(session) {
    const details = element('details', 'session');
    details.dataset.state = session.state || '';
    details.dataset.sessionId = session.id || '';
    details.id = 'session-' + String(session.id || '').replace(/[^A-Za-z0-9_-]/g, '-');
    details.dataset.search = [
      session.id,
      session.displayName,
      (session.tags || []).join(' '),
      (session.markdownOutputs || []).map(function (output) { return output.path || ''; }).join(' ')
    ].join(' ').toLowerCase();

    const summary = element('summary');
    const titleRow = element('span', 'session-title-row');
    titleRow.append(element('strong', null, session.displayName || 'Unnamed session'));
    titleRow.append(createStatePill(session.state));
    summary.append(titleRow);

    const facts = element('span', 'session-facts');
    facts.append(element('span', null, (session.markdownOutputs ? session.markdownOutputs.length : 0) + ' outputs'));
    facts.append(element('span', null, (session.runs ? session.runs.length : 0) + ' runs'));
    const createdDate = new Date(session.createdAt);
    const createdText = Number.isNaN(createdDate.getTime()) ? (session.createdAt || '') : createdDate.toLocaleString();
    const created = element('span', null, createdText);
    created.title = session.createdAt || '';
    facts.append(created);
    facts.append(element('code', null, session.id));
    summary.append(facts);
    details.append(summary);

    const body = element('div', 'detail-body');
    const metadata = element('div', 'metadata');
    appendMetadata(metadata, 'Created', session.createdAt);
    appendMetadata(metadata, 'Updated', session.updatedAt);
    appendMetadata(metadata, 'Tags', (session.tags || []).join('; '));
    body.append(metadata);
    if (session.webUrl) {
      const link = element('a', null, 'Open portal link');
      link.href = session.webUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      body.append(link);
    }
    details.append(body);
    details.addEventListener('toggle', function () {
      if (details.open) renderSessionDetails(session, body);
    });
    return details;
  }

  sessions.forEach(function (session) {
    root.append(createSession(session));
  });

  Array.from(new Set(sessions.map(function (session) { return session.state || ''; })))
    .filter(Boolean)
    .sort()
    .forEach(function (state) {
      const option = element('option', null, state);
      option.value = state;
      stateFilter.append(option);
    });

  function applyFilters() {
    const term = search.value.trim().toLowerCase();
    const state = stateFilter.value;
    root.querySelectorAll('details.session').forEach(function (details) {
      const matchesTerm = !term || details.dataset.search.includes(term);
      const matchesState = !state || details.dataset.state === state;
      details.classList.toggle('hidden', !(matchesTerm && matchesState));
    });
  }

  function focusDeepLinkedSession() {
    const parameters = new URLSearchParams(location.hash.replace(/^#/, ''));
    const requestedSessionId = parameters.get('session');
    const requestedRunId = parameters.get('run');
    if (!requestedSessionId) return;

    search.value = '';
    stateFilter.value = '';
    applyFilters();
    root.querySelectorAll('.deep-linked').forEach(function (item) {
      item.classList.remove('deep-linked');
    });
    const sessionDetails = Array.from(root.querySelectorAll('details.session'))
      .find(function (item) { return item.dataset.sessionId === requestedSessionId; });
    if (!sessionDetails) return;

    sessionDetails.classList.remove('hidden');
    sessionDetails.classList.add('deep-linked');
    sessionDetails.open = true;
    sessionDetails.dispatchEvent(new Event('toggle'));
    requestAnimationFrame(function () {
      let target = sessionDetails;
      if (requestedRunId) {
        const runDetails = Array.from(sessionDetails.querySelectorAll('details.run'))
          .find(function (item) { return item.dataset.runId === requestedRunId; });
        if (runDetails) {
          runDetails.classList.add('deep-linked');
          runDetails.open = true;
          runDetails.dispatchEvent(new Event('toggle'));
          target = runDetails;
        }
      }
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  }

  search.addEventListener('input', applyFilters);
  stateFilter.addEventListener('change', applyFilters);
  window.addEventListener('hashchange', focusDeepLinkedSession);
  document.getElementById('expand-sessions').addEventListener('click', function () {
    root.querySelectorAll('details.session:not(.hidden)').forEach(function (details) {
      details.open = true;
    });
  });
  document.getElementById('collapse-sessions').addEventListener('click', function () {
    root.querySelectorAll('details').forEach(function (details) {
      details.open = false;
    });
  });
  focusDeepLinkedSession();
</script>
</body>
</html>
"@

. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')
$html = Set-PerceptionReportPresentation -Html $html
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
foreach ($directory in @(
    (Split-Path -Parent $resolvedOutputPath),
    (Split-Path -Parent $resolvedSessionDataPath)
) | Sort-Object -Unique) {
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory
    }
}

$sessionDataTemporaryPath = "$resolvedSessionDataPath.$([guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllText(
        $sessionDataTemporaryPath,
        $sessionCacheJson,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::Move($sessionDataTemporaryPath, $resolvedSessionDataPath, $true)
}
finally {
    if (Test-Path -LiteralPath $sessionDataTemporaryPath) {
        Remove-Item -LiteralPath $sessionDataTemporaryPath
    }
}
[IO.File]::WriteAllText($resolvedOutputPath, $html, [Text.UTF8Encoding]::new($false))
Write-Host "Reusable session data written to $resolvedSessionDataPath"
Write-Host "Dashboard written to $resolvedOutputPath"

if (-not $NoOpen) {
    Start-Process $resolvedOutputPath
}

[pscustomobject]@{
    Environment       = 'Production'
    GeneratedAt       = $generatedAt
    PlaybookCount     = $playbooks.Count
    AgentCount        = $agents.Count
    EnabledAgentCount = $enabledAgents.Count
    SessionCount      = $sessionNodes.Count
    CandidateSessionCount = $sessions.Count
    SkippedZeroRunSessionCount = $zeroRunSessionCount
    ReusedSessionDetailCount = $reusedSessionDetailCount
    ReusedZeroRunSessionCount = $reusedZeroRunSessionCount
    AgentRunListingCount = $agentRunListingCount
    FetchedMessagePageCount = $fetchedMessagePageCount
    AgentRunCount     = $totalRunCount
    MessageCount      = $totalMessageCount
    MarkdownOutputCount = $totalMarkdownOutputCount
    ApiRequestCount     = $apiRequestCount
    RetryCount          = $retryCount
    RetryDelaySeconds   = $retryDelaySeconds
    CollectionDuration  = $collectionStopwatch.Elapsed
    SessionJsonBytes    = $sessionJsonBytes.LongLength
    SessionDataPath     = $resolvedSessionDataPath
    OutputPath        = $resolvedOutputPath
}
