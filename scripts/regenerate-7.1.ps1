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
    $MetadataOut = Join-Path $Output "metadata"
    New-Item -ItemType Directory -Force -Path $MetadataOut | Out-Null

    Write-Host "[1/18] Fingerprinting exact samples"
    Invoke-Python -m genshinre fingerprint $Exe $Metadata | Out-File -FilePath (Join-Path $Output "fingerprints.json") -Encoding utf8

    Write-Host "[2/18] Decoding native 7.1 MHY metadata"
    Invoke-Python -m genshinre decode-metadata-71 $Exe $Metadata $MetadataOut

    Write-Host "[3/18] Verifying native 7.1 anchors"
    Invoke-Python -m genshinre verify-metadata `
        $MetadataOut `
        "versions/7.1.0-global/windows-x64/metadata/anchors-native.json" `
        | Out-File -FilePath (Join-Path $Output "metadata-anchor-check.json") -Encoding utf8

    Write-Host "[4/18] Exporting IL2CPP runtime type index"
    Invoke-Python -m genshinre.typearray `
        $Exe `
        (Join-Path $MetadataOut "types.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        --summary (Join-Path $MetadataOut "runtime-types.summary.json") `
        | Out-Null

    Write-Host "[5/18] Scanning conservative constant-return CmdId candidates"
    Invoke-Python -m genshinre scan-constant-cmdids `
        $Exe `
        (Join-Path $MetadataOut "methods.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        --summary (Join-Path $Output "getcmdid-candidates.summary.json")

    Write-Host "[6/18] Auditing metadata-usage initializer call sites"
    Invoke-Python -m genshinre.usage `
        $Exe `
        (Join-Path $Output "metadata-usage-sites.csv") `
        --summary (Join-Path $Output "metadata-usage-sites.summary.json") `
        --require-9369-anchor `
        | Out-Null

    Write-Host "[7/18] Probing metadata registration structure"
    Invoke-Python -m genshinre.metareg `
        $Exe `
        (Join-Path $Output "metadata-registration-probe.json") `
        | Out-Null

    Write-Host "[8/18] Recovering anchored metadata usage destination table"
    Invoke-Python -m genshinre.metausage `
        $Exe `
        (Join-Path $Output "metadata-usage-slots.csv") `
        --summary (Join-Path $Output "metadata-usage-slots.summary.json") `
        | Out-Null

    Write-Host "[9/18] Joining metadata usages to runtime types"
    Invoke-Python -m genshinre.usagejoin `
        $Exe `
        (Join-Path $Output "metadata-usage-slots.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        (Join-Path $Output "metadata-usage-types.csv") `
        --summary (Join-Path $Output "metadata-usage-types.summary.json") `
        | Out-Null

    Write-Host "[10/18] Building registry candidate graph"
    Invoke-Python -m genshinre.registrygraph `
        (Join-Path $Output "metadata-usage-types.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        (Join-Path $Output "registry-candidate-graph.csv") `
        --summary (Join-Path $Output "registry-candidate-graph.summary.json") `
        --require-anchors `
        | Out-Null

    Write-Host "[11/18] Refining one-to-one static registry candidates"
    Invoke-Python -m genshinre.registryselect `
        (Join-Path $Output "registry-candidate-graph.csv") `
        (Join-Path $Output "registry-static-candidates.csv") `
        --summary (Join-Path $Output "registry-static-candidates.summary.json") `
        | Out-Null

    Write-Host "[12/18] Probing preserved registry type-slot anchors"
    Invoke-Python -m genshinre probe-registry-71 `
        $Exe `
        (Join-Path $Output "registry-probe-71.json") `
        | Out-Null

    Write-Host "[13/18] Inferring direct-slot native protocol-registry layout"
    Invoke-Python -m genshinre.registrylayout `
        $Exe `
        (Join-Path $Output "registry-layout-probe.json") `
        | Out-Null

    Write-Host "[14/18] Inferring usage-backed native protocol-registry layout"
    Invoke-Python -m genshinre.registryusagelayout `
        $Exe `
        (Join-Path $Output "metadata-usage-types.csv") `
        (Join-Path $Output "registry-usage-layout-probe.json") `
        | Out-Null

    Write-Host "[15/18] Optional AstaPS control set"
    if ($AstaPS) {
        $PacketOpcodes = Join-Path $AstaPS "src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java"
        if (-not (Test-Path $PacketOpcodes)) {
            throw "PacketOpcodes.java not found at: $PacketOpcodes"
        }
        Invoke-Python -m genshinre import-opcodes-java $PacketOpcodes (Join-Path $Output "known-opcodes.csv")
    } else {
        Write-Host "      skipped; pass -AstaPS <path> to generate known-opcodes.csv"
    }

    Write-Host "[16/18] Candidate graph diagnostics"
    if ($AstaPS) {
        Invoke-Python -m genshinre.graphdiag `
            (Join-Path $Output "registry-candidate-graph.csv") `
            (Join-Path $Output "known-opcodes.csv") `
            --output (Join-Path $Output "registry-candidate-graph.diagnostic.json") `
            | Out-Null
    } else {
        Write-Host "      skipped; AstaPS control set unavailable"
    }

    Write-Host "[17/18] Strict candidate diagnostics"
    if ($AstaPS) {
        Invoke-Python -m genshinre.graphdiag `
            (Join-Path $Output "registry-static-candidates.csv") `
            (Join-Path $Output "known-opcodes.csv") `
            --output (Join-Path $Output "registry-static-candidates.diagnostic.json") `
            | Out-Null
    } else {
        Write-Host "      skipped; AstaPS control set unavailable"
    }

    Write-Host "[18/18] Human-readable registry convergence report"
    $ReportArguments = @(
        "-m", "genshinre.registryreport",
        (Join-Path $Output "registry-candidate-graph.csv"),
        (Join-Path $Output "registry-candidate-graph.summary.json"),
        (Join-Path $Output "registry-candidate-report.md"),
        "--focus", "186,9369,22899,26105"
    )
    if ($AstaPS) {
        $ReportArguments += @("--known-opcodes", (Join-Path $Output "known-opcodes.csv"))
    }
    & $Python @ReportArguments | Out-File -FilePath (Join-Path $Output "registry-candidate-report.summary.json") -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "registry convergence report failed with exit code $LASTEXITCODE"
    }

    Write-Host "Done: $Output"
    Write-Host "Read registry-candidate-report.md, registry-layout-probe.json and registry-usage-layout-probe.json first. Agreement between the two native-layout paths is stronger evidence than either path alone."
} finally {
    Pop-Location
}
