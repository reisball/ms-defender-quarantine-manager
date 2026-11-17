param(
    [Parameter(Mandatory = $true)]
    [string] $Base64Path,

    [Parameter(Mandatory = $true)]
    [long] $ExpectedDecodedSize,

    [ValidateSet("InspectOnly", "Stream")]
    [string] $Mode = "Stream"
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "runbook.ps1"
$source = [System.IO.File]::ReadAllText($runbookPath)
$helperStart = $source.IndexOf("function Write-ErrorResult")
$stepOne = $source.IndexOf("# Step 1: Validate webhook input")

if ($helperStart -lt 0 -or $stepOne -le $helperStart) {
    throw "Could not locate the runbook helper section."
}

Invoke-Expression $source.Substring($helperStart, $stepOne - $helperStart)

$base64 = [System.IO.File]::ReadAllText($Base64Path)
$info = Get-Base64PayloadInfo -Base64 $base64

if ($info.DecodedSize -ne $ExpectedDecodedSize) {
    throw "Decoded-size mismatch: expected $ExpectedDecodedSize, got $($info.DecodedSize)."
}
if ($info.DecodedSize -gt $ExportMaxDecodedBytes) {
    throw "Fixture exceeds the configured runbook cap."
}

if ($Mode -eq "InspectOnly") {
    Write-Output ($info | ConvertTo-Json -Compress)
    exit 0
}

[System.GC]::Collect()
Write-ChunkedExport `
    -Base64 $base64 `
    -Identity "00000000-0000-0000-0000-000000000000\11111111-1111-1111-1111-111111111111" `
    -Base64Length $info.Base64Length `
    -DecodedSize $info.DecodedSize `
    -HasWhitespace $info.HasWhitespace
