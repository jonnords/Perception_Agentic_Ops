Set-StrictMode -Version Latest

function Assert-PerceptionModelEndpoint {
    param([Parameter(Mandatory)][string]$Endpoint)

    $uri = $null
    if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment -or
        $uri.Host -notmatch '^[a-z0-9-]+\.(openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$' -or
        $uri.AbsolutePath -notmatch '/(responses|chat/completions)$' -or
        ($uri.Query -and $uri.Query -notmatch '^\?api-version=[A-Za-z0-9.-]+$')) {
        throw 'Model endpoint must be a complete Azure HTTPS Responses or chat-completions URL on port 443, without credentials, fragments or query parameters other than api-version.'
    }
}

function Resolve-PerceptionConfigurationPath {
    param([string]$Path = '')
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Join-Path $PSScriptRoot 'perception.config.json' }
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertTo-PerceptionConfiguration {
    param([AllowNull()][object]$Value)
    $config = [pscustomobject]@{
        schemaVersion = 1
        tenantId = ''
        model = [pscustomobject]@{
            endpoint = ''; deployment = ''; apiFormat = 'responses'
            tenantId = ''; tokenResource = 'https://cognitiveservices.azure.com'
        }
    }
    if ($value -isnot [pscustomobject] -or
        @($value.PSObject.Properties | ForEach-Object Name | Where-Object { $_ -notin @('schemaVersion','tenantId','model') }).Count -gt 0 -or
        $null -eq $value.PSObject.Properties['schemaVersion'] -or $value.schemaVersion -ne 1) {
        throw 'Configuration requires schemaVersion 1 and only tenantId/model settings. Credentials do not belong in this file.'
    }
    foreach ($name in @('tenantId')) {
        if ($null -ne $value.PSObject.Properties[$name]) { $config.$name = $value.$name }
    }
    if ($null -ne $value.PSObject.Properties['model']) {
        $model = $value.model
        if ($model -isnot [pscustomobject] -or
            @($model.PSObject.Properties | ForEach-Object Name | Where-Object { $_ -notin $config.model.PSObject.Properties.Name }).Count -gt 0) {
            throw 'Model configuration contains unsupported fields. Do not store tokens or API keys in configuration.'
        }
        foreach ($property in $model.PSObject.Properties) { $config.model.($property.Name) = $property.Value }
    }
    foreach ($item in @($config.tenantId, $config.model.tenantId)) {
        $guid = [Guid]::Empty
        if ($item -isnot [string] -or ($item -and -not [Guid]::TryParse($item, [ref]$guid))) {
            throw 'Configured tenant IDs must be GUID strings or empty to use the signed-in CLI tenant.'
        }
    }
    foreach ($name in @('endpoint','deployment','apiFormat','tokenResource')) {
        if ($config.model.$name -isnot [string] -or $config.model.$name -match '[\x00-\x1f\x7f]') {
            throw "Model $name must be a single-line string."
        }
    }
    if ($config.model.apiFormat -cnotin @('responses','chat')) { throw 'model.apiFormat must be responses or chat.' }
    if ($config.model.tokenResource -notin @('https://cognitiveservices.azure.com','https://ai.azure.com')) {
        throw 'Model tokenResource must be https://cognitiveservices.azure.com or https://ai.azure.com.'
    }
    if ($config.model.endpoint) {
        Assert-PerceptionModelEndpoint $config.model.endpoint
        if (($config.model.apiFormat -eq 'responses') -ne $config.model.endpoint.Contains('/responses')) {
            throw 'Model apiFormat does not match the configured endpoint.'
        }
    }
    $config
}

function Get-PerceptionConfiguration {
    param([string]$Path = '')
    $explicitPath = -not [string]::IsNullOrWhiteSpace($Path)
    $resolvedPath = Resolve-PerceptionConfigurationPath -Path $Path
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        if ($explicitPath) { throw "Configuration file not found: $Path" }
        return ConvertTo-PerceptionConfiguration -Value ([pscustomobject]@{ schemaVersion = 1 })
    }
    $value = [IO.File]::ReadAllText($resolvedPath) | ConvertFrom-Json -Depth 10 -ErrorAction Stop
    ConvertTo-PerceptionConfiguration -Value $value
}
