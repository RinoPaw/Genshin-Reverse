param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,

    [Parameter(Mandatory = $true)]
    [string]$Metadata,

    [string]$Output = "work/7.1.0-global/windows-x64",
    [string]$Python = "python",
    [string]$AstaPS = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OptionalFailures = [System.Collections.Generic.List[string]]::new()

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE`: $Python $($Arguments -join ' ')"
    }
}

function Invoke-OptionalPython {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $Python @Arguments | Out-Null
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        $OptionalFailures.Add($Name)
        Write-Warning "Optional stage failed ($ExitCode): $Name"
        return $false
    }
    return $true
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $Output = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Output))
    $MetadataOut = Join-Path $Output "metadata"
    New-Item -ItemType Directory -Force -Path $MetadataOut | Out-Null

    Write-Host "[core 1/5] Fingerprinting exact samples"
    Invoke-Python -m genshinre fingerprint $Exe $Metadata | Out-File -FilePath (Join-Path $Output "fingerprints.json") -Encoding utf8

    Write-Host "[core 2/5] Decoding native 7.1 MHY metadata"
    Invoke-Python -m genshinre decode-metadata-71 $Exe $Metadata $MetadataOut

    Write-Host "[core 3/5] Verifying full 7.1 metadata anchors"
    Invoke-Python -m genshinre verify-metadata `
        $MetadataOut `
        "versions/7.1.0-global/windows-x64/metadata/anchors.json" `
        | Out-File -FilePath (Join-Path $Output "metadata-anchor-check.json") -Encoding utf8

    Write-Host "[core 4/5] Exporting IL2CPP runtime type index"
    Invoke-Python -m genshinre.typearray `
        $Exe `
        (Join-Path $MetadataOut "types.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        --summary (Join-Path $MetadataOut "runtime-types.summary.json") `
        | Out-Null

    Write-Host "[core 5/5] Scanning conservative constant-return CmdId candidates"
    Invoke-Python -m genshinre scan-constant-cmdids `
        $Exe `
        (Join-Path $MetadataOut "methods.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        --summary (Join-Path $Output "getcmdid-candidates.summary.json")

    Write-Host "[optional 1/13] Auditing metadata-usage initializer call sites"
    $null = Invoke-OptionalPython -Name "metadata-usage-sites" `
        -m genshinre.usage `
        $Exe `
        (Join-Path $Output "metadata-usage-sites.csv") `
        --summary (Join-Path $Output "metadata-usage-sites.summary.json")

    Write-Host "[optional 2/13] Probing metadata registration structure"
    $null = Invoke-OptionalPython -Name "metadata-registration-probe" `
        -m genshinre.metareg `
        $Exe `
        (Join-Path $Output "metadata-registration-probe.json")

    Write-Host "[optional 3/13] Recovering metadata usage destination table"
    $UsageSlotsOk = Invoke-OptionalPython -Name "metadata-usage-table" `
        -m genshinre.metausage `
        $Exe `
        (Join-Path $Output "metadata-usage-slots.csv") `
        --summary (Join-Path $Output "metadata-usage-slots.summary.json")
    if (-not $UsageSlotsOk -and (Test-Path (Join-Path $Output "metadata-usage-sites.csv"))) {
        Write-Host "      falling back to direct initializer call-site evidence"
        $UsageSlotsOk = Invoke-OptionalPython -Name "metadata-usage-slots-fallback" `
            -m genshinre.usageslots `
            (Join-Path $Output "metadata-usage-sites.csv") `
            (Join-Path $Output "metadata-usage-slots.csv") `
            --summary (Join-Path $Output "metadata-usage-slots.summary.json")
    }

    Write-Host "[optional 4/13] Joining metadata usages to runtime types"
    $UsageTypesOk = $false
    if ($UsageSlotsOk) {
        $UsageTypesOk = Invoke-OptionalPython -Name "metadata-usage-type-join" `
            -m genshinre.usagejoin `
            $Exe `
            (Join-Path $Output "metadata-usage-slots.csv") `
            (Join-Path $MetadataOut "runtime-types.csv") `
            (Join-Path $Output "metadata-usage-types.csv") `
            --summary (Join-Path $Output "metadata-usage-types.summary.json")
    } else {
        Write-Host "      skipped; metadata usage slots unavailable"
    }

    Write-Host "[optional 5/13] Building registry candidate graph"
    $GraphOk = $false
    if ($UsageTypesOk) {
        $GraphOk = Invoke-OptionalPython -Name "registry-candidate-graph" `
            -m genshinre.registrygraph `
            (Join-Path $Output "metadata-usage-types.csv") `
            (Join-Path $Output "getcmdid-candidates.csv") `
            (Join-Path $Output "registry-candidate-graph.csv") `
            --summary (Join-Path $Output "registry-candidate-graph.summary.json")
    } else {
        Write-Host "      skipped; metadata usage/type join unavailable"
    }

    Write-Host "[optional 6/13] Refining one-to-one static registry candidates"
    $StaticCandidatesOk = $false
    if ($GraphOk) {
        $StaticCandidatesOk = Invoke-OptionalPython -Name "registry-static-candidates" `
            -m genshinre.registryselect `
            (Join-Path $Output "registry-candidate-graph.csv") `
            (Join-Path $Output "registry-static-candidates.csv") `
            --summary (Join-Path $Output "registry-static-candidates.summary.json")
    } else {
        Write-Host "      skipped; registry candidate graph unavailable"
    }

    Write-Host "[optional 7/13] Probing preserved registry type-slot anchors"
    $null = Invoke-OptionalPython -Name "registry-anchor-probe" `
        -m genshinre probe-registry-71 `
        $Exe `
        (Join-Path $Output "registry-probe-71.json")

    Write-Host "[optional 8/13] Inferring direct-slot native protocol-registry layout"
    $null = Invoke-OptionalPython -Name "registry-direct-layout" `
        -m genshinre.registrylayout `
        $Exe `
        (Join-Path $Output "registry-layout-probe.json")

    Write-Host "[optional 9/13] Inferring usage-backed native protocol-registry layout"
    if ($UsageTypesOk) {
        $null = Invoke-OptionalPython -Name "registry-usage-layout" `
            -m genshinre.registryusagelayout `
            $Exe `
            (Join-Path $Output "metadata-usage-types.csv") `
            (Join-Path $Output "registry-usage-layout-probe.json")
    } else {
        Write-Host "      skipped; metadata usage/type join unavailable"
    }

    Write-Host "[optional 10/13] Importing AstaPS control set"
    $ControlSetOk = $false
    if ($AstaPS) {
        $PacketOpcodes = Join-Path $AstaPS "src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java"
        if (Test-Path $PacketOpcodes) {
            $ControlSetOk = Invoke-OptionalPython -Name "astaps-control-set" `
                -m genshinre import-opcodes-java `
                $PacketOpcodes `
                (Join-Path $Output "control-set.csv")
        } else {
            $OptionalFailures.Add("astaps-packet-opcodes-not-found")
            Write-Warning "Expected current AstaPS PacketOpcodes.java at: $PacketOpcodes"
        }
    } else {
        Write-Host "      skipped; pass -AstaPS <path> to generate control-set.csv"
    }

    Write-Host "[optional 11/13] Candidate graph diagnostics"
    if ($ControlSetOk -and $GraphOk) {
        $null = Invoke-OptionalPython -Name "registry-candidate-diagnostics" `
            -m genshinre.graphdiag `
            (Join-Path $Output "registry-candidate-graph.csv") `
            (Join-Path $Output "control-set.csv") `
            --output (Join-Path $Output "registry-candidate-graph.diagnostic.json")
    } else {
        Write-Host "      skipped; candidate graph or control set unavailable"
    }

    Write-Host "[optional 12/13] Strict candidate diagnostics"
    if ($ControlSetOk -and $StaticCandidatesOk) {
        $null = Invoke-OptionalPython -Name "registry-static-diagnostics" `
            -m genshinre.graphdiag `
            (Join-Path $Output "registry-static-candidates.csv") `
            (Join-Path $Output "control-set.csv") `
            --output (Join-Path $Output "registry-static-candidates.diagnostic.json")
    } else {
        Write-Host "      skipped; static candidates or control set unavailable"
    }

    Write-Host "[optional 13/13] Human-readable registry convergence report"
    if ($GraphOk) {
        $ReportArguments = @(
            "-m", "genshinre.registryreport",
            (Join-Path $Output "registry-candidate-graph.csv"),
            (Join-Path $Output "registry-candidate-graph.summary.json"),
            (Join-Path $Output "registry-candidate-report.md"),
            "--focus", "186,9369,22899,26105"
        )
        if ($ControlSetOk) {
            $ReportArguments += @("--known-opcodes", (Join-Path $Output "control-set.csv"))
        }
        & $Python @ReportArguments | Out-File -FilePath (Join-Path $Output "registry-candidate-report.summary.json") -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            $OptionalFailures.Add("registry-convergence-report")
            Write-Warning "Optional registry convergence report failed with exit code $LASTEXITCODE"
        }
    } else {
        Write-Host "      skipped; registry candidate graph unavailable"
    }

    Write-Host "Core regeneration complete: $Output"
    if ($OptionalFailures.Count -gt 0) {
        Write-Host "Optional registry/research stages with unresolved results: $($OptionalFailures -join ', ')"
    } else {
        Write-Host "All optional registry/research stages completed."
    }
} finally {
    Pop-Location
}
