param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,

    [Parameter(Mandatory = $true)]
    [string]$Metadata,

    [string]$Output = "work/7.1.0-global/windows-x64",
    [string]$Python = "python",
    [string]$AstaPS = "",
    [switch]$SkipRegenerate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $OutputArgument = $Output
    if ([System.IO.Path]::IsPathRooted($OutputArgument)) {
        $OutputRoot = [System.IO.Path]::GetFullPath($OutputArgument)
    } else {
        $OutputRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $OutputArgument))
    }

    if (-not $SkipRegenerate) {
        $RegenerateArgs = @(
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $PSScriptRoot "regenerate-7.1.ps1"),
            "-Exe", $Exe,
            "-Metadata", $Metadata,
            "-Output", $OutputArgument,
            "-Python", $Python
        )
        if ($AstaPS) {
            $RegenerateArgs += @("-AstaPS", $AstaPS)
        }
        & powershell @RegenerateArgs
        if ($LASTEXITCODE -ne 0) {
            throw "7.1 regeneration failed with exit code $LASTEXITCODE"
        }
    }

    $Methods = Join-Path $OutputRoot "metadata/methods.csv"
    $RuntimeTypes = Join-Path $OutputRoot "metadata/runtime-types.csv"
    $UsageTypes = Join-Path $OutputRoot "metadata-usage-types.csv"
    $ParameterProbe = Join-Path $OutputRoot "parameter-probe-71.json"
    $RegistryLayout = Join-Path $OutputRoot "registry-layout-71.json"
    $UsageRegistryLayout = Join-Path $OutputRoot "registry-usage-layout-71.json"

    foreach ($Required in @($Methods, $RuntimeTypes, $UsageTypes)) {
        if (-not (Test-Path $Required)) {
            throw "required generated artifact missing: $Required"
        }
    }

    & $Python -m genshinre.paramprobe `
        $Exe `
        $Metadata `
        $Methods `
        $RuntimeTypes `
        $ParameterProbe `
        | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "parameter probe failed with exit code $LASTEXITCODE"
    }

    & $Python -m genshinre.registrylayout `
        $Exe `
        $RegistryLayout `
        | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "registry layout probe failed with exit code $LASTEXITCODE"
    }

    & $Python -m genshinre.registryusagelayout `
        $Exe `
        $UsageTypes `
        $UsageRegistryLayout `
        | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "usage-backed registry layout probe failed with exit code $LASTEXITCODE"
    }

    Write-Host "Parameter probe written to: $ParameterProbe"
    Write-Host "Registry layout probe written to: $RegistryLayout"
    Write-Host "Usage-backed registry layout probe written to: $UsageRegistryLayout"
    $CandidateReport = Join-Path $OutputRoot "registry-candidate-report.md"
    $StaticCandidates = Join-Path $OutputRoot "registry-static-candidates.csv"
    if (Test-Path $CandidateReport) {
        Write-Host "Registry convergence report: $CandidateReport"
    }
    if (Test-Path $StaticCandidates) {
        Write-Host "Strict static candidates: $StaticCandidates"
    }
    Write-Host "These are derived static-analysis artifacts; keep raw game binaries out of Git."
} finally {
    Pop-Location
}
