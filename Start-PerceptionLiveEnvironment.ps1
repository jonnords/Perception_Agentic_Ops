[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,

    [string]$DashboardPath = (Join-Path $PSScriptRoot 'Perception-Live-Environment.html'),

    [Alias('RunQuality')][switch]$AssuranceFreshness,

    [Alias('ThreatBriefing')][switch]$ThreatProtection,

    [switch]$OperationalLoops,

    [switch]$SystemicThreatSignals,

    [Alias('AgentBehavior')][switch]$AgentBehaviorAnalysis,

    [switch]$DefenderInvestigations,

    [string]$ConfigurationPath = '',

    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (@($AssuranceFreshness, $ThreatProtection, $OperationalLoops, $SystemicThreatSignals, $AgentBehaviorAnalysis, $DefenderInvestigations | Where-Object { $_ }).Count -gt 1) {
    throw 'Choose only one initial report: -AssuranceFreshness, -ThreatProtection, -OperationalLoops, -SystemicThreatSignals, -AgentBehaviorAnalysis or -DefenderInvestigations.'
}
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionAiSettings.ps1')
$configuration = Get-PerceptionConfiguration -Path $ConfigurationPath
$workspacePath = Join-Path $PSScriptRoot 'Perception-Workspace.template.html'
if (-not (Test-Path -LiteralPath $workspacePath -PathType Leaf)) { throw 'Workspace template is missing. Restore the complete customer package.' }

$scope = 'https://api.securitycopilot.microsoft.com/Perception.Operate.All'
$baseUrl = 'https://perception.microsoft.com/api/v1.0'
$prefix = "http://127.0.0.1:$Port/"
$reportRoutes = @{
    '/environment' = @{
        file = $DashboardPath
        code = 'environmentReportNotFound'
        generator = 'Show-PerceptionLiveEnvironment.ps1'
        title = 'Environment explorer'
    }
    '/assurance-freshness' = @{
        file = 'Perception-Assurance-Freshness.html'
        code = 'assuranceReportNotFound'
        generator = 'New-PerceptionAssuranceFreshnessReport.ps1'
        title = 'Freshness & Run Quality'
    }
    '/threat-protection' = @{
        file = 'Perception-Threat-Protection.html'
        code = 'protectionReportNotFound'
        generator = 'New-PerceptionThreatProtectionReport.ps1'
        title = 'Operational Briefing'
    }
    '/systemic-threat-signals' = @{
        file = 'Perception-Systemic-Threat-Signals.html'
        code = 'systemicReportNotFound'
        generator = 'New-PerceptionSystemicThreatReport.ps1'
        title = 'Systemic Threat Signals'
    }
    '/operational-loops' = @{
        file = 'Perception-Operational-Loops.html'
        code = 'operationalLoopsReportNotFound'
        generator = 'New-PerceptionOperationalLoopsReport.ps1'
        title = 'Operational Loops & Outcomes'
    }
    '/agent-behavior' = @{
        file = 'Perception-Agent-Behavior-Analysis.html'
        code = 'agentBehaviorReportNotFound'
        generator = 'New-PerceptionAgentBehaviorReport.ps1'
        title = 'Agent Behavior Analysis'
    }
    '/defender-investigations' = @{
        file = 'Perception-Defender-Investigations.html'
        code = 'defenderReportNotFound'
        generator = 'New-PerceptionDefenderInvestigationReport.ps1'
        title = 'Defender investigations'
    }
}

function Get-WorkspaceReportPath {
    param([object]$Route)
    if ([IO.Path]::IsPathRooted($Route.file)) { return $Route.file }
    Join-Path $PSScriptRoot $Route.file
}

function Write-JsonResponse {
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerResponse]$Response,

        [Parameter(Mandatory)]
        [int]$StatusCode,

        [Parameter(Mandatory)]
        [object]$Body
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $Body -Depth 8 -Compress)
    )
    $Response.StatusCode = $StatusCode
    $Response.ContentType = 'application/json; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
}

function Get-ApiError {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = 502
    $code = 'sessionCreateFailed'
    $message = $ErrorRecord.Exception.Message
    $requestId = $null

    if ($null -ne $ErrorRecord.ErrorDetails -and
        -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        try {
            $details = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
            if ($null -ne $details.error) {
                if ($details.error.code) {
                    $code = [string]$details.error.code
                }
                if ($details.error.message) {
                    $message = [string]$details.error.message
                }
            }
        }
        catch {
            $message = $ErrorRecord.ErrorDetails.Message
        }
    }

    if ($null -ne $ErrorRecord.Exception.Response) {
        try {
            $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
            $requestId = [string]$ErrorRecord.Exception.Response.Headers['request-id']
        }
        catch {
            $statusCode = 502
        }
    }

    [pscustomobject]@{
        StatusCode = $statusCode
        Body       = [pscustomobject]@{
            error = [pscustomobject]@{
                code      = $code
                message   = $message
                requestId = $requestId
            }
        }
    }
}

$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
}
catch {
    throw "Could not start the localhost runner at $prefix. $($_.Exception.Message)"
}

Write-Host "Perception live environment: $prefix"
Write-Host 'Press Ctrl+C to stop the local runner.'

if (-not $NoOpen) {
    $view = if ($AgentBehaviorAnalysis) { 'agent-behavior' }
    elseif ($SystemicThreatSignals) { 'systemic-threat-signals' }
    elseif ($ThreatProtection) { 'threat-protection' }
    elseif ($OperationalLoops) { 'operational-loops' }
    elseif ($AssuranceFreshness) { 'assurance-freshness' }
    elseif ($DefenderInvestigations) { 'defender-investigations' } else { 'overview' }
    $openUrl = "${prefix}#view=$view"
    Start-Process $openUrl
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        try {
            $response.Headers['Cache-Control'] = 'no-store'
            $response.Headers['X-Content-Type-Options'] = 'nosniff'
            $response.Headers['X-Frame-Options'] = 'SAMEORIGIN'
            $response.Headers['Referrer-Policy'] = 'no-referrer'
            if (-not [Net.IPAddress]::IsLoopback($request.RemoteEndPoint.Address)) {
                Write-JsonResponse -Response $response -StatusCode 403 -Body @{
                    error = @{ code = 'forbidden'; message = 'Only loopback requests are accepted.' }
                }
                continue
            }

            $path = $request.Url.AbsolutePath
            if ($request.HttpMethod -eq 'GET' -and $reportRoutes.ContainsKey($path)) {
                $route = $reportRoutes[$path]
                $reportPath = Get-WorkspaceReportPath $route
                if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
                    Write-JsonResponse -Response $response -StatusCode 404 -Body @{
                        error = @{
                            code = $route.code
                            message = "Generate the report with $($route.generator) first."
                        }
                    }
                    continue
                }
                $bytes = [IO.File]::ReadAllBytes($reportPath)
                $response.StatusCode = 200
                $response.ContentType = 'text/html; charset=utf-8'
                $response.ContentLength64 = $bytes.Length
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
                continue
            }
            if ($request.HttpMethod -eq 'GET' -and $path -eq '/') {
                $bytes = [IO.File]::ReadAllBytes($workspacePath)
                $response.StatusCode = 200
                $response.ContentType = 'text/html; charset=utf-8'
                $response.ContentLength64 = $bytes.Length
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
                continue
            }

            if ($request.HttpMethod -eq 'GET' -and $path -eq '/api/health') {
                Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                    status = 'ready'
                }
                continue
            }
            if ($request.HttpMethod -eq 'GET' -and $path -eq '/api/workspace') {
                try { $configuration = Get-PerceptionConfiguration -Path $ConfigurationPath }
                catch {
                    Write-Warning 'Workspace setup status could not read the local configuration.'
                    Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                        error = @{ code = 'settingsReadFailed'; message = 'Could not read local configuration. Verify the configuration file before reloading workspace status.' }
                    }
                    continue
                }
                $reports = @(
                    foreach ($routePath in @('/environment','/threat-protection','/assurance-freshness','/operational-loops','/agent-behavior','/systemic-threat-signals','/defender-investigations')) {
                        $route = $reportRoutes[$routePath]
                        $file = Get-WorkspaceReportPath $route
                        $available = Test-Path -LiteralPath $file -PathType Leaf
                        [pscustomobject]@{
                            id = $routePath.TrimStart('/'); title = $route.title; path = $routePath
                            available = $available
                            modifiedAt = if ($available) { (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o') } else { $null }
                            command = ".\$($route.generator)"
                        }
                    }
                )
                Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                    reports = $reports
                    azureCliAvailable = $null -ne (Get-Command az -ErrorAction SilentlyContinue)
                    modelConfigured = [bool]($configuration.model.endpoint -and $configuration.model.deployment)
                }
                continue
            }

            if ($path -in @('/api/ai-settings', '/api/ai-settings/test')) {
                if ($request.HttpMethod -eq 'GET' -and $path -eq '/api/ai-settings') {
                    try {
                        $settings = Get-PerceptionAiSettings -ConfigurationPath $ConfigurationPath
                        Write-JsonResponse -Response $response -StatusCode 200 -Body $settings
                    }
                    catch {
                        Write-Warning 'Could not read AI settings or Azure CLI account context.'
                        Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                            error = @{ code = 'settingsReadFailed'; message = 'Could not read AI settings. Verify the local configuration and Azure CLI installation.' }
                        }
                    }
                    continue
                }
                if ($request.HttpMethod -ne 'POST') {
                    Write-JsonResponse -Response $response -StatusCode 405 -Body @{
                        error = @{ code = 'methodNotAllowed'; message = 'This AI settings operation requires POST.' }
                    }
                    continue
                }
                if ([string]$request.Headers['Origin'] -cne $prefix.TrimEnd('/') -or
                    [string]$request.Headers['X-Perception-Settings'] -cne '1') {
                    Write-JsonResponse -Response $response -StatusCode 403 -Body @{
                        error = @{ code = 'invalidOrigin'; message = 'AI settings actions require the local workspace origin and settings header.' }
                    }
                    continue
                }
                if ($request.ContentType -notmatch '^application/json(?:\s*;.*)?$' -or
                    $request.ContentLength64 -lt 1 -or $request.ContentLength64 -gt 16384) {
                    Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                        error = @{ code = 'invalidRequest'; message = 'Send an application/json request body between 1 and 16384 bytes.' }
                    }
                    continue
                }
                $reader = [IO.StreamReader]::new($request.InputStream, [Text.Encoding]::UTF8)
                try {
                    try { $payload = $reader.ReadToEnd() | ConvertFrom-Json -Depth 10 -ErrorAction Stop }
                    catch {
                        Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                            error = @{ code = 'invalidJson'; message = 'The settings request must contain valid JSON.' }
                        }
                        continue
                    }
                }
                finally { $reader.Dispose() }
                $isTest = $path -eq '/api/ai-settings/test'
                $allowed = if ($isTest) { @('model','consent') } else { @('model') }
                if ($payload -isnot [pscustomobject] -or $null -eq $payload.PSObject.Properties['model'] -or
                    @($payload.PSObject.Properties.Name | Where-Object { $_ -cnotin $allowed }).Count -gt 0 -or
                    ($isTest -and ($null -eq $payload.PSObject.Properties['consent'] -or
                        $payload.consent -isnot [bool] -or -not $payload.consent))) {
                    Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                        error = @{ code = 'invalidSettings'; message = 'Send only model settings, plus consent: true for the chargeable connection test. Credentials and file paths are not accepted.' }
                    }
                    continue
                }
                try { $current = Get-PerceptionConfiguration -Path $ConfigurationPath }
                catch {
                    Write-Warning 'AI settings action failed because the existing local configuration could not be read.'
                    Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                        error = @{ code = 'settingsReadFailed'; message = 'The existing local configuration is invalid or unreadable. Fix it before saving or testing.' }
                    }
                    continue
                }
                try { $candidate = ConvertTo-PerceptionAiConfiguration -Model $payload.model -TenantId $current.tenantId }
                catch {
                    Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                        error = @{ code = 'invalidSettings'; message = $_.Exception.Message }
                    }
                    continue
                }
                if ($isTest) {
                    try {
                        $testResult = Test-PerceptionAiConnection -Configuration $candidate
                        Write-JsonResponse -Response $response -StatusCode 200 -Body $testResult
                    }
                    catch {
                        Write-Warning 'Explicit AI connection check failed.'
                        Write-JsonResponse -Response $response -StatusCode 502 -Body @{
                            error = @{ code = 'connectionTestFailed'; message = $_.Exception.Message }
                        }
                    }
                }
                else {
                    try {
                        Save-PerceptionAiSettings -Configuration $candidate -ConfigurationPath $ConfigurationPath
                        $configuration = $candidate
                    }
                    catch {
                        Write-Warning 'Could not save AI settings to the local configuration.'
                        Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                            error = @{ code = 'settingsSaveFailed'; message = 'Could not save AI settings. Verify that the configuration folder is writable. No model call was made.' }
                        }
                        continue
                    }
                    Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                        model = $configuration.model
                        configured = $true
                        message = 'Settings saved locally. No model call was made and no reports were regenerated.'
                    }
                }
                continue
            }

            if ($request.HttpMethod -ne 'POST' -or $path -ne '/api/investigate') {
                Write-JsonResponse -Response $response -StatusCode 404 -Body @{
                    error = @{ code = 'routeNotFound'; message = 'No route matches the requested path.' }
                }
                continue
            }

            if ($request.ContentLength64 -lt 1 -or $request.ContentLength64 -gt 4096) {
                Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                    error = @{ code = 'invalidRequest'; message = 'The request body must be between 1 and 4096 bytes.' }
                }
                continue
            }

            $origin = [string]$request.Headers['Origin']
            if (-not [string]::IsNullOrWhiteSpace($origin) -and
                $origin.TrimEnd('/') -ne $prefix.TrimEnd('/')) {
                Write-JsonResponse -Response $response -StatusCode 403 -Body @{
                    error = @{ code = 'invalidOrigin'; message = 'The request origin is not allowed.' }
                }
                continue
            }

            $reader = [IO.StreamReader]::new(
                $request.InputStream,
                $request.ContentEncoding,
                $true,
                1024,
                $false
            )
            try {
                $payload = $reader.ReadToEnd() | ConvertFrom-Json
            }
            finally {
                $reader.Dispose()
            }

            $incidentId = [string]$payload.incidentId
            if ($incidentId -notmatch '^[0-9]{1,32}$') {
                Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                    error = @{
                        code    = 'invalidIncidentId'
                        message = 'Incident ID must contain 1 to 32 digits.'
                    }
                }
                continue
            }

            $accessToken = Get-PerceptionCliToken -Scope $scope -TenantId $configuration.tenantId

            $headers = @{
                Authorization              = "Bearer $accessToken"
                Accept                     = 'application/json'
                'Repeatability-Request-ID' = [guid]::NewGuid().ToString()
            }
            $body = @{
                sourceType = 'playbook'
                sourceId   = 'investigate-incident'
                inputs     = @(
                    @{
                        type        = 'defenderIncidentId'
                        value       = $incidentId
                        displayName = "Incident $incidentId"
                    }
                )
            } | ConvertTo-Json -Depth 5

            try {
                $session = Invoke-RestMethod `
                    -Method Post `
                    -Uri "$baseUrl/sessions" `
                    -Headers $headers `
                    -ContentType 'application/json' `
                    -Body $body
            }
            catch {
                $apiError = Get-ApiError -ErrorRecord $_
                Write-JsonResponse `
                    -Response $response `
                    -StatusCode $apiError.StatusCode `
                    -Body $apiError.Body
                continue
            }

            $stateProperty = $session.PSObject.Properties['state']
            $statusProperty = $session.PSObject.Properties['status']
            $sessionState = if ($null -ne $stateProperty) {
                [string]$stateProperty.Value
            }
            elseif ($null -ne $statusProperty) {
                [string]$statusProperty.Value
            }
            else {
                ''
            }
            Write-JsonResponse -Response $response -StatusCode 201 -Body @{
                id          = $session.id
                state       = $sessionState
                createdAt   = $session.createdAt
                displayName = $session.displayName
                webUrl      = $session.webUrl
                incidentId  = $incidentId
            }
        }
        catch [Net.HttpListenerException] {
            Write-Warning "Local response delivery failed for $($request.Url.AbsolutePath): $($_.Exception.Message)"
        }
        catch {
            $requestError = $_.Exception.Message
            try {
                Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                    error = @{
                        code    = 'localRunnerError'
                        message = $requestError
                    }
                }
            }
            catch [Net.HttpListenerException], [ObjectDisposedException] {
                Write-Warning "Could not deliver the local error response: $requestError. Transport error: $($_.Exception.Message)"
            }
        }
        finally {
            try { $response.Close() }
            catch [Net.HttpListenerException], [ObjectDisposedException] {
                Write-Warning "Local response cleanup failed: $($_.Exception.Message)"
            }
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
