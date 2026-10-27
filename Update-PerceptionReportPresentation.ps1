[CmdletBinding()]
param([switch]$RefreshManifest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Set-PerceptionReportPresentation.ps1')

foreach ($name in @(
    'Perception-Live-Environment.html',
    'Perception-Assurance-Freshness.html',
    'Perception-Operational-Loops.html',
    'Perception-Threat-Protection.html',
    'Perception-Agent-Behavior-Analysis.html',
    'Perception-Systemic-Threat-Signals.html',
    'Perception-Defender-Investigations.html'
)) {
    $path = Join-Path $PSScriptRoot $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $html = Set-PerceptionReportPresentation -Html ([IO.File]::ReadAllText($path))
        [IO.File]::WriteAllText($path, $html, [Text.UTF8Encoding]::new($false))
        Write-Output "Updated presentation: $name"
    }
}

if ($RefreshManifest) {
    $manifestPath = Join-Path $PSScriptRoot 'manifest.json'
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json -Depth 10 -ErrorAction Stop
    $paths = @($manifest.files | ForEach-Object path) + @(
        'Set-PerceptionReportPresentation.ps1', 'Update-PerceptionReportPresentation.ps1',
        'Get-PerceptionAiSettings.ps1', 'Get-PerceptionOperationalLoops.ps1',
        'New-PerceptionOperationalLoopsReport.ps1'
    )
    $manifest.files = @(
        foreach ($path in @($paths | Sort-Object -Unique)) {
            $source = Join-Path $PSScriptRoot $path
            $file = Get-Item -LiteralPath $source -ErrorAction Stop
            [pscustomobject]@{
                path = $path
                size = $file.Length
                sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Write-Output 'Updated local source manifest; tenant reports and real configuration remain excluded.'
}
