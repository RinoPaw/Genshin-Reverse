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
    $Output = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Output))

    if (-not $SkipRegenerate) {
        $RegenerateArgs = @(
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $PSScriptRoot "regenerate-7.1.ps1"),
            "-Exe", $Exe,
            "-Metadata", $Metadata,
            "-Output", $Output,
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

    $Methods = Join-Path $Output "metadata/methods.csv"
    $RuntimeTypes = Join-Path $Output "metadata/runtime-types.csv"
    $Probe = Join-Path $Output "parameter-probe-71.json"

    foreach ($Required in @($Methods, $RuntimeTypes)) {
        if (-not (Test-Path $Required)) {
            throw "required generated artifact missing: $Required"
        }
    }

    & $Python -m genshinre.paramprobe `
        $Exe `
        $Metadata `
        $Methods `
        $RuntimeTypes `
        $Probe `
        | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "parameter probe failed with exit code $LASTEXITCODE"
    }

    Write-Host "Parameter probe written to: $Probe"
    Write-Host "This file is small and contains only derived static-analysis records; keep raw game binaries out of Git."
} finally {
    Pop-Location
}
