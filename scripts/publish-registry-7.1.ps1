param(
    [string]$Work = "work/7.1.0-global/windows-x64",
    [string]$Destination = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $Work = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Work))
    if (-not $Destination) {
        $Destination = Join-Path $Work "historical-native-registry"
    } else {
        $Destination = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Destination))
    }

    Write-Host "Historical native-layout projection helper; current canonical registry is xref-published."

    $Required = @(
        (Join-Path $Work "registry-native-direct.csv"),
        (Join-Path $Work "registry-native-usage.csv"),
        (Join-Path $Work "registry-native-compare.json"),
        (Join-Path $Work "registry-direction-audit.json"),
        (Join-Path $Work "control-set.csv"),
        (Join-Path $Work "getcmdid-candidates.csv"),
        (Join-Path $RepoRoot "versions/7.1.0-global/windows-x64/hashes.json")
    )
    foreach ($Path in $Required) {
        if (-not (Test-Path $Path)) {
            throw "Required historical projection artifact is missing: $Path. Run regeneration and strict native registry closure first."
        }
    }

    & $Python -m genshinre.registrypublish `
        (Join-Path $Work "registry-native-direct.csv") `
        (Join-Path $Work "registry-native-usage.csv") `
        (Join-Path $Work "registry-native-compare.json") `
        (Join-Path $Work "registry-direction-audit.json") `
        (Join-Path $Work "control-set.csv") `
        (Join-Path $Work "getcmdid-candidates.csv") `
        (Join-Path $RepoRoot "versions/7.1.0-global/windows-x64/hashes.json") `
        $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Historical native registry projection failed with exit code $LASTEXITCODE"
    }

    Write-Host "Historical native registry projection gates passed."
    Write-Host "Output: $Destination"
    Write-Host "This output is comparison evidence only; current canonical registry publication remains genshinre.registryxrefpublish."
} finally {
    Pop-Location
}
