param(
    [string]$Output = "inputs/7.1.0-global",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    & $Python tools/fetch_sophon_targets.py `
        --manifest-url 'https://autopatchhk.yuanshen.com/client_app/sophon/manifests/cxhpq4g4rgg0/sMXGW2ll3Fuu/manifest_671e1a92a6cf53ff_8d4dfb34d2ee2cf64aae45a9b1ecf58d' `
        --chunk-prefix 'https://autopatchhk.yuanshen.com/client_app/sophon/chunks/cxhpq4g4rgg0/sMXGW2ll3Fuu' `
        --output $Output `
        --expected-exe-sha256 '08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d' `
        --expected-metadata-sha256 '05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0'
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned 7.1 sample fetch failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
