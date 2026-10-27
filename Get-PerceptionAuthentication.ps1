Set-StrictMode -Version Latest

function Get-PerceptionCliToken {
    [CmdletBinding(DefaultParameterSetName = 'Scope')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Scope')][string]$Scope,
        [Parameter(Mandatory, ParameterSetName = 'Resource')][string]$Resource,
        [string]$TenantId = '',
        [string]$SubscriptionId = ''
    )

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI is required. Install it, then run az login for the intended customer tenant.'
    }
    $arguments = @('account','get-access-token','--query','accessToken','--output','tsv','--only-show-errors')
    if ($PSCmdlet.ParameterSetName -eq 'Scope') { $arguments += @('--scope', $Scope) }
    else { $arguments += @('--resource', $Resource) }
    if ($TenantId) { $arguments += @('--tenant', $TenantId) }
    if ($SubscriptionId) { $arguments += @('--subscription', $SubscriptionId) }
    $token = (& az @arguments 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token) -or $token -match '\s') {
        throw 'Azure CLI could not acquire the requested access token. Run az login with the intended tenant and verify the required API permissions/consent. No token-file or alternate credential fallback was attempted.'
    }
    $token
}
