param(
    [string]$Output = "inputs/7.1.0-global",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Profile = "7.1.0-global/windows-x64"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    & $Python -m genshinre.samplefetch `
        --profile $Profile `
        --output $Output
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned 7.1 sample fetch failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
