param(
    [string]$Work = "work/7.1.0-global/windows-x64",
    [string]$Version = "versions/7.1.0-global/windows-x64",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    if ([System.IO.Path]::IsPathRooted($Work)) {
        $Work = [System.IO.Path]::GetFullPath($Work)
    } else {
        $Work = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Work))
    }
    if ([System.IO.Path]::IsPathRooted($Version)) {
        $Version = [System.IO.Path]::GetFullPath($Version)
    } else {
        $Version = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Version))
    }

    & $Python -m genshinre.artifactpublish $Work $Version
    if ($LASTEXITCODE -ne 0) {
        throw "Generated artifact publication failed with exit code $LASTEXITCODE"
    }

    Write-Host "Published validated 7.1 research artifacts into: $Version"
    Write-Host "Existing canonical registry identity artifacts were validated and preserved."
} finally {
    Pop-Location
}
