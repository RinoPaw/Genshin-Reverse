param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,

    [string]$Output = "work/7.1.0-global/windows-x64",
    [string]$Python = "python",
    [switch]$RequireDirectionPerfect
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

    Write-Host "[1/4] Exporting direct-slot native registry rows"
    Invoke-Python -m genshinre.registryraw `
        $Exe `
        (Join-Path $Output "registry-layout-probe.json") `
        (Join-Path $Output "registry-native-direct.csv") `
        --summary (Join-Path $Output "registry-native-direct.summary.json") `
        --require-4896-unique `
        | Out-Null

    Write-Host "[2/4] Exporting usage-backed native registry rows"
    Invoke-Python -m genshinre.registryusageraw `
        $Exe `
        (Join-Path $Output "registry-usage-layout-probe.json") `
        (Join-Path $Output "metadata-usage-types.csv") `
        (Join-Path $Output "registry-native-usage.csv") `
        --summary (Join-Path $Output "registry-native-usage.summary.json") `
        --require-4896-unique `
        | Out-Null

    Write-Host "[3/4] Requiring independent row-by-row agreement"
    Invoke-Python -m genshinre.registrycompare `
        (Join-Path $Output "registry-native-direct.csv") `
        (Join-Path $Output "registry-native-usage.csv") `
        --output (Join-Path $Output "registry-native-compare.json") `
        --require-full-agreement `
        | Out-Null

    Write-Host "[4/4] Auditing registry_flag direction semantics"
    $KnownOpcodes = Join-Path $Output "known-opcodes.csv"
    $DirectionAudit = Join-Path $Output "registry-direction-audit.json"
    if (Test-Path $KnownOpcodes) {
        $DirectionArguments = @(
            "-m", "genshinre.directionaudit",
            (Join-Path $Output "registry-native-usage.csv"),
            $KnownOpcodes,
            "--output", $DirectionAudit
        )
        if ($RequireDirectionPerfect) {
            $DirectionArguments += "--require-perfect"
        }
        & $Python @DirectionArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Direction audit failed with exit code $LASTEXITCODE"
        }
    } elseif ($RequireDirectionPerfect) {
        throw "known-opcodes.csv is required by -RequireDirectionPerfect; rerun regeneration with -AstaPS <path>"
    } else {
        Write-Host "      skipped; known-opcodes.csv was not generated (pass -AstaPS <path> to regenerate-7.1.ps1)"
    }

    Write-Host "Registry structural closure passed."
    Write-Host "Direct raw: $(Join-Path $Output 'registry-native-direct.csv')"
    Write-Host "Usage raw:  $(Join-Path $Output 'registry-native-usage.csv')"
    Write-Host "Comparison: $(Join-Path $Output 'registry-native-compare.json')"
    if (Test-Path $DirectionAudit) {
        Write-Host "Direction audit: $DirectionAudit"
    }
    Write-Host "Canonical projection is allowed only after the direction audit and current control-set mismatches have been reviewed."
} finally {
    Pop-Location
}
