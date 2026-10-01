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
        $Destination = Join-Path $Work "canonical-registry"
    } else {
        $Destination = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Destination))
    }

    $Required = @(
        (Join-Path $Work "registry-native-direct.csv"),
        (Join-Path $Work "registry-native-usage.csv"),
        (Join-Path $Work "registry-native-compare.json"),
        (Join-Path $Work "registry-direction-audit.json"),
        (Join-Path $Work "known-opcodes.csv"),
        (Join-Path $Work "getcmdid-candidates.csv"),
        (Join-Path $RepoRoot "versions/7.1.0-global/windows-x64/hashes.json")
    )
    foreach ($Path in $Required) {
        if (-not (Test-Path $Path)) {
            throw "Required publication artifact is missing: $Path. Run regeneration and strict registry closure first."
        }
    }

    & $Python -m genshinre.registrypublish `
        (Join-Path $Work "registry-native-direct.csv") `
        (Join-Path $Work "registry-native-usage.csv") `
        (Join-Path $Work "registry-native-compare.json") `
        (Join-Path $Work "registry-direction-audit.json") `
        (Join-Path $Work "known-opcodes.csv") `
        (Join-Path $Work "getcmdid-candidates.csv") `
        (Join-Path $RepoRoot "versions/7.1.0-global/windows-x64/hashes.json") `
        $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical registry publication failed with exit code $LASTEXITCODE"
    }

    Write-Host "Canonical registry publication gates passed."
    Write-Host "Output: $Destination"
    Write-Host "Review summary.json and the semantic-name gaps before committing generated artifacts."
} finally {
    Pop-Location
}
