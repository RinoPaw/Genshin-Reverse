param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,

    [Parameter(Mandatory = $true)]
    [string]$Metadata,

    [string]$Output = "work/7.1.0-global/windows-x64",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE`: $Python $($Arguments -join ' ')"
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    if ([System.IO.Path]::IsPathRooted($Output)) {
        $Output = [System.IO.Path]::GetFullPath($Output)
    } else {
        $Output = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Output))
    }
    $MetadataOut = Join-Path $Output "metadata"
    New-Item -ItemType Directory -Force -Path $MetadataOut | Out-Null

    Write-Host "[1/5] Fingerprinting exact samples"
    Invoke-Python -m genshinre fingerprint $Exe $Metadata | Out-File -FilePath (Join-Path $Output "fingerprints.json") -Encoding utf8

    Write-Host "[2/5] Decoding native 7.1 MHY metadata"
    Invoke-Python -m genshinre decode-metadata-71 $Exe $Metadata $MetadataOut

    Write-Host "[3/5] Verifying full 7.1 metadata anchors"
    Invoke-Python -m genshinre verify-metadata `
        $MetadataOut `
        "versions/7.1.0-global/windows-x64/metadata/anchors.json" `
        | Out-File -FilePath (Join-Path $Output "metadata-anchor-check.json") -Encoding utf8

    Write-Host "[4/5] Exporting IL2CPP runtime type index"
    Invoke-Python -m genshinre.typearray `
        $Exe `
        (Join-Path $MetadataOut "types.csv") `
        (Join-Path $MetadataOut "runtime-types.csv") `
        --summary (Join-Path $MetadataOut "runtime-types.summary.json") `
        | Out-Null

    Write-Host "[5/5] Scanning conservative constant-return CmdId candidates"
    Invoke-Python -m genshinre scan-constant-cmdids `
        $Exe `
        (Join-Path $MetadataOut "methods.csv") `
        (Join-Path $Output "getcmdid-candidates.csv") `
        --summary (Join-Path $Output "getcmdid-candidates.summary.json")

    Write-Host "Exact-sample regeneration complete: $Output"
} finally {
    Pop-Location
}
