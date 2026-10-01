param(
    [string]$Work = "work/7.1.0-global/windows-x64",
    [string]$Version = "versions/7.1.0-global/windows-x64",
    [string]$CanonicalRegistry = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $Work = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Work))
    $Version = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Version))

    $Arguments = @(
        "-m", "genshinre.artifactpublish",
        $Work,
        $Version
    )
    if ($CanonicalRegistry) {
        $CanonicalRegistry = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $CanonicalRegistry))
        $Arguments += @("--canonical-registry", $CanonicalRegistry)
    }

    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Generated artifact publication failed with exit code $LASTEXITCODE"
    }

    Write-Host "Published validated 7.1 research artifacts into: $Version"
    Write-Host "Canonical registry files are emitted only when the stricter registry publication gate has already passed."
} finally {
    Pop-Location
}
