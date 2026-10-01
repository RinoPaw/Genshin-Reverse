param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,

    [string]$Output = "work/7.1.0-global/windows-x64",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE: $Python $($Arguments -join ' ')"
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $Output = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Output))

    $Required = @(
        (Join-Path $Output "registry-layout-probe.json"),
        (Join-Path $Output "registry-usage-layout-probe.json"),
        (Join-Path $Output "metadata-usage-types.csv")
    )
    foreach ($Path in $Required) {
        if (-not (Test-Path $Path)) {
            throw "Required regeneration artifact is missing: $Path. Run scripts/regenerate-7.1.ps1 first."
        }
    }

    Write-Host "[1/3] Exporting direct-slot native registry rows"
    Invoke-Python -m genshinre.registryraw `
        $Exe `
        (Join-Path $Output "registry-layout-probe.json") `
        (Join-Path $Output "registry-native-direct.csv") `
        --summary (Join-Path $Output "registry-native-direct.summary.json") `
        --require-4896-unique `
        | Out-Null

    Write-Host "[2/3] Exporting usage-backed native registry rows"
    Invoke-Python -m genshinre.registryusageraw `
        $Exe `
        (Join-Path $Output "registry-usage-layout-probe.json") `
        (Join-Path $Output "metadata-usage-types.csv") `
        (Join-Path $Output "registry-native-usage.csv") `
        --summary (Join-Path $Output "registry-native-usage.summary.json") `
        --require-4896-unique `
        | Out-Null

    Write-Host "[3/3] Requiring independent row-by-row agreement"
    Invoke-Python -m genshinre.registrycompare `
        (Join-Path $Output "registry-native-direct.csv") `
        (Join-Path $Output "registry-native-usage.csv") `
        --output (Join-Path $Output "registry-native-compare.json") `
        --require-full-agreement `
        | Out-Null

    Write-Host "Registry closure passed."
    Write-Host "Direct raw: $(Join-Path $Output 'registry-native-direct.csv')"
    Write-Host "Usage raw:  $(Join-Path $Output 'registry-native-usage.csv')"
    Write-Host "Comparison: $(Join-Path $Output 'registry-native-compare.json')"
    Write-Host "Next evidence layer: independently audit registry_flag direction semantics, then project stable fields into canonical registry.csv."
} finally {
    Pop-Location
}
