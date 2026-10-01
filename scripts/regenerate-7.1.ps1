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

    Write-Host "[1/13] Fingerprinting exact samples"
    Invoke-Python -m genshinre fingerprint $Exe $Metadata | Out-File -FilePath (Join-Path $Output "fingerprints.json") -Encoding utf8

    Write-Host "[2/13] Decoding native 7.1 MHY metadata"
    Invoke-Python -m genshinre decode-metadata-71 $Exe $Metadata $MetadataOut

    Write-Host "[3/13] Verifying native 7.1 anchors"
    Invoke-Python -m genshinre verify-metadata `
        $MetadataOut `
        "versions/7.1.0-global/windows-x64/metadata/anchors-native.json" `
        | Out-File -FilePath (Join-Path $Output "metadata-anchor-check.json") -Encoding utf8

    Write-Host "[4/13] Exporting IL2CPP runtime type index"
    Invoke-Python -m genshinre.typearray `
        $Exe `
        (Join-Path $MetadataOut "types.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        --summary (Join-Path $MetadataOut "runtime-types.summary.json") `
        | Out-Null

    Write-Host "[5/13] Scanning conservative constant-return CmdId candidates"
    Invoke-Python -m genshinre scan-constant-cmdids `
        $Exe `
        (Join-Path $MetadataOut "methods.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        --summary (Join-Path $Output "getcmdid-candidates.summary.json")

    Write-Host "[6/13] Auditing metadata-usage initializer call sites"
    Invoke-Python -m genshinre.usage `
        $Exe `
        (Join-Path $Output "metadata-usage-sites.csv") `
        --summary (Join-Path $Output "metadata-usage-sites.summary.json") `
        --require-9369-anchor `
        | Out-Null

    Write-Host "[7/13] Probing metadata registration structure"
    Invoke-Python -m genshinre.metareg `
        $Exe `
        (Join-Path $Output "metadata-registration-probe.json") `
        | Out-Null

    Write-Host "[8/13] Recovering anchored metadata usage destination table"
    Invoke-Python -m genshinre.metausage `
        $Exe `
        (Join-Path $Output "metadata-usage-slots.csv") `
        --summary (Join-Path $Output "metadata-usage-slots.summary.json") `
        | Out-Null

    Write-Host "[9/13] Joining metadata usages to runtime types"
    Invoke-Python -m genshinre.usagejoin `
        $Exe `
        (Join-Path $Output "metadata-usage-slots.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        (Join-Path $Output "metadata-usage-types.csv") `
        --summary (Join-Path $Output "metadata-usage-types.summary.json") `
        | Out-Null

    Write-Host "[10/13] Building registry candidate graph"
    Invoke-Python -m genshinre.registrygraph `
        (Join-Path $Output "metadata-usage-types.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        (Join-Path $Output "registry-candidate-graph.csv") `
        --summary (Join-Path $Output "registry-candidate-graph.summary.json") `
        --require-anchors `
        | Out-Null

    Write-Host "[11/13] Probing preserved registry type-slot anchors"
    Invoke-Python -m genshinre probe-registry-71 `
        $Exe `
        (Join-Path $Output "registry-probe-71.json") `
        | Out-Null

    Write-Host "[12/13] Optional AstaPS control set"
    if ($AstaPS) {
        $PacketOpcodes = Join-Path $AstaPS "src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java"
        if (-not (Test-Path $PacketOpcodes)) {
            throw "PacketOpcodes.java not found at: $PacketOpcodes"
        }
        Invoke-Python -m genshinre import-opcodes-java $PacketOpcodes (Join-Path $Output "known-opcodes.csv")
    } else {
        Write-Host "      skipped; pass -AstaPS <path> to generate known-opcodes.csv"
    }

    Write-Host "[13/13] Candidate graph diagnostics"
    if ($AstaPS) {
        Invoke-Python -m genshinre.graphdiag `
            (Join-Path $Output "registry-candidate-graph.csv") `
            (Join-Path $Output "known-opcodes.csv") `
            --output (Join-Path $Output "registry-candidate-graph.diagnostic.json") `
            | Out-Null
    } else {
        Write-Host "      skipped; AstaPS control set unavailable"
    }

    Write-Host "Done: $Output"
    Write-Host "Inspect registry-candidate-graph.summary.json and registry-candidate-graph.diagnostic.json first. metadata-usage-sites.csv is call-site audit evidence; metadata-usage-slots.csv is the anchored destination-to-slot table used by the join."
} finally {
    Pop-Location
}
