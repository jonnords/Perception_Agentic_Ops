Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PerceptionConfiguration.ps1')
. (Join-Path $PSScriptRoot 'Get-PerceptionAuthentication.ps1')

function Get-PerceptionCliIdentity {
    $identity = [pscustomobject]@{
        cliAvailable = [bool](Get-Command az -ErrorAction SilentlyContinue)
        signedIn = $false
        accountName = ''
        accountType = ''
        tenantId = ''
        message = 'Azure CLI is not installed. Install it and run az login in a terminal.'
    }
    if (-not $identity.cliAvailable) { return $identity }
    $json = (& az account show --query '{accountName:user.name,accountType:user.type,tenantId:tenantId}' --output json --only-show-errors 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        $identity.message = 'No Azure CLI account context is available. Run az login for the intended tenant in a terminal.'
        return $identity
    }
    try { $account = $json | ConvertFrom-Json -Depth 5 -ErrorAction Stop }
    catch {
        $identity.message = 'Azure CLI returned invalid account metadata. Check az account show in a terminal.'
        return $identity
    }
    $guid = [Guid]::Empty
    if ($account -isnot [pscustomobject] -or
        $null -eq $account.PSObject.Properties['tenantId'] -or
        -not [Guid]::TryParse([string]$account.tenantId, [ref]$guid) -or
        $null -eq $account.PSObject.Properties['accountName'] -or $account.accountName -isnot [string] -or
        $null -eq $account.PSObject.Properties['accountType'] -or $account.accountType -isnot [string]) {
        $identity.message = 'Azure CLI account metadata is incomplete. Check az account show in a terminal.'
        return $identity
    }
    $identity.signedIn = $true
    $identity.accountName = $account.accountName
    $identity.accountType = $account.accountType
    $identity.tenantId = $guid.ToString()
    $identity.message = 'Cached Azure CLI account context is available. Token validity and model permissions have not been tested.'
    $identity
}

function Get-PerceptionAiSettings {
    param([string]$ConfigurationPath = '')
    $config = Get-PerceptionConfiguration -Path $ConfigurationPath
    $identity = Get-PerceptionCliIdentity
    [pscustomobject]@{
        model = $config.model
        configured = [bool]($config.model.endpoint -and $config.model.deployment)
        authentication = $identity
        effectiveTenantId = if ($config.model.tenantId) { $config.model.tenantId }
            elseif ($config.tenantId) { $config.tenantId } else { $identity.tenantId }
    }
}

function ConvertTo-PerceptionAiConfiguration {
    param([AllowNull()][object]$Model, [string]$TenantId = '')
    $config = ConvertTo-PerceptionConfiguration -Value ([pscustomobject]@{
        schemaVersion = 1; tenantId = $TenantId; model = $Model
    })
    if ([string]::IsNullOrWhiteSpace($config.model.endpoint) -or
        [string]::IsNullOrWhiteSpace($config.model.deployment)) {
        throw 'Provide both a complete Azure model endpoint and a deployment name.'
    }
    $config
}

function Save-PerceptionAiSettings {
    param([Parameter(Mandatory)][object]$Configuration, [string]$ConfigurationPath = '')
    $validated = ConvertTo-PerceptionConfiguration -Value $Configuration
    $path = Resolve-PerceptionConfigurationPath -Path $ConfigurationPath
    $temporaryPath = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporaryPath, ($validated | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $path, $true)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -ErrorAction Stop }
    }
}

function Test-PerceptionAiConnection {
    param([Parameter(Mandatory)][object]$Configuration)
    $config = ConvertTo-PerceptionAiConfiguration -Model $Configuration.model -TenantId $Configuration.tenantId
    $tenant = if ($config.model.tenantId) { $config.model.tenantId } else { $config.tenantId }
    try { $token = Get-PerceptionCliToken -Resource $config.model.tokenResource -TenantId $tenant }
    catch { throw 'Azure CLI could not acquire a model access token. Run az login for the intended tenant and verify the token audience and required permissions/consent.' }
    $prompt = 'This is a connection check. Reply only with the JSON object {"connected":true}. No tenant evidence is included.'
    $body = if ($config.model.apiFormat -eq 'responses') {
        @{ model = $config.model.deployment; input = $prompt; text = @{ format = @{ type = 'json_object' } } }
    }
    else {
        @{ model = $config.model.deployment; messages = @(@{ role = 'user'; content = $prompt }); response_format = @{ type = 'json_object' } }
    }
    try {
        $response = Invoke-WebRequest -Uri $config.model.endpoint -Method Post -ContentType 'application/json' `
            -Headers @{ Authorization = "Bearer $token" } -Body ($body | ConvertTo-Json -Depth 8 -Compress) `
            -TimeoutSec 60 -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction Stop
    }
    catch {
        throw 'The Azure connection request failed or timed out. Check the endpoint and network. Redirects are not followed. A timed-out request may still incur model charges.'
    }
    finally { $token = $null }
    if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
        throw "Azure returned HTTP $([int]$response.StatusCode). Check the deployment, API format/version, CLI tenant, token audience and model permissions. No provider error body is exposed."
    }
    try {
        $result = $response.Content | ConvertFrom-Json -Depth 30 -ErrorAction Stop
        if ($config.model.apiFormat -eq 'responses') {
            if ($result.status -ne 'completed') { throw 'Incomplete response.' }
            $text = @(
                foreach ($item in $result.output) {
                    if ($item.type -eq 'message') {
                        foreach ($part in $item.content) {
                            if ($part.type -eq 'output_text') { $part.text }
                        }
                    }
                }
            ) -join ''
        }
        else {
            if ($result.choices[0].finish_reason -ne 'stop') { throw 'Incomplete response.' }
            $text = $result.choices[0].message.content
        }
        $answer = $text | ConvertFrom-Json -Depth 5 -ErrorAction Stop
        if ($answer -isnot [pscustomobject] -or $answer.connected -isnot [bool] -or -not $answer.connected) {
            throw 'Unexpected connection-check answer.'
        }
    }
    catch {
        throw 'Azure accepted the request but did not return a complete, valid connection-check response. No provider response content is exposed.'
    }
    [pscustomobject]@{
        connected = $true
        deployment = $config.model.deployment
        apiFormat = $config.model.apiFormat
        testedAtUtc = [DateTime]::UtcNow.ToString('o')
        message = 'Connection verified using synthetic input only. No report evidence was sent and no settings or reports were changed.'
    }
}
