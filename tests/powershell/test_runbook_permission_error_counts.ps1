$ErrorActionPreference = "Stop"

$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$source = [System.IO.File]::ReadAllText($runbookPath)
$helperStart = $source.IndexOf("function Write-ErrorResult")
$stepOne = $source.IndexOf("# Step 1: Validate webhook input")
if ($helperStart -lt 0 -or $stepOne -le $helperStart) {
    throw "Could not locate the runbook helper section."
}
Invoke-Expression $source.Substring($helperStart, $stepOne - $helperStart)

foreach ($expectedCount in @(0, 1, 20, 21, 50, 200)) {
    $errors = New-Object "System.Collections.Generic.List[object]"
    for ([int] $index = 0; $index -lt $expectedCount; $index++) {
        Add-PermissionQueryError `
            -Errors $errors `
            -Query "query-$index" `
            -ErrorRecord "native error $index"
    }
    $evidence = @{}
    Set-PermissionQueryErrorEvidence -Evidence $evidence -Errors $errors

    if ($evidence.permission_query_error_count -ne $expectedCount) {
        throw "Total permission error count mismatch for $expectedCount."
    }
    $expectedRetained = [System.Math]::Min(
        $expectedCount,
        $PermissionQueryErrorMaxRecords
    )
    $expectedDropped = $expectedCount - $expectedRetained
    if ($evidence.permission_query_error_retained_count -ne $expectedRetained) {
        throw "Retained permission error count mismatch for $expectedCount."
    }
    if ($evidence.permission_query_error_dropped_count -ne $expectedDropped) {
        throw "Dropped permission error count mismatch for $expectedCount."
    }
    if (
        $evidence.permission_query_errors_truncated -ne
        ($expectedDropped -gt 0)
    ) {
        throw "Permission error truncation flag mismatch for $expectedCount."
    }
    if (@($evidence.permission_query_errors).Count -ne $expectedRetained) {
        throw "Retained permission error records mismatch for $expectedCount."
    }
    for ([int] $index = 0; $index -lt $expectedRetained; $index++) {
        if ($evidence.permission_query_errors[$index].query -ne "query-$index") {
            throw "Permission error order changed at index $index."
        }
    }
    $json = ConvertTo-Json `
        -InputObject ([object[]] @($evidence.permission_query_errors)) `
        -Depth 8 `
        -Compress
    if ((Get-Utf8ByteCount $json) -gt $PermissionQueryErrorMaxUtf8Bytes) {
        throw "Permission error JSON exceeded its UTF-8 byte budget."
    }
}

$largeErrors = New-Object "System.Collections.Generic.List[object]"
Add-PermissionQueryError `
    -Errors $largeErrors `
    -Query "large-native-error" `
    -ErrorRecord ("native " + ("x" * 10000))
$largeEvidence = @{}
Set-PermissionQueryErrorEvidence `
    -Evidence $largeEvidence `
    -Errors $largeErrors
if (
    $largeEvidence.permission_query_error_count -ne 1 -or
    $largeEvidence.permission_query_error_retained_count -ne 1 -or
    $largeEvidence.permission_query_error_dropped_count -ne 0 -or
    $largeEvidence.permission_query_errors_truncated -ne $false -or
    $largeEvidence.permission_query_errors[0].error.Length -gt
        $DiagnosticMaxChars -or
    -not $largeEvidence.permission_query_errors[0].error.EndsWith(
        " [truncated]"
    )
) {
    throw "Large native permission error was not bounded correctly."
}

$byteBudgetErrors = New-Object "System.Collections.Generic.List[object]"
for ([int] $index = 0; $index -lt 20; $index++) {
    Add-PermissionQueryError `
        -Errors $byteBudgetErrors `
        -Query "byte-budget-$index" `
        -ErrorRecord ("error-$index " + ("y" * 2048))
}
$byteBudgetEvidence = @{}
Set-PermissionQueryErrorEvidence `
    -Evidence $byteBudgetEvidence `
    -Errors $byteBudgetErrors
$byteBudgetJson = ConvertTo-Json `
    -InputObject ([object[]] @($byteBudgetEvidence.permission_query_errors)) `
    -Depth 8 `
    -Compress
if (
    $byteBudgetEvidence.permission_query_error_count -ne 20 -or
    $byteBudgetEvidence.permission_query_error_dropped_count -le 0 -or
    $byteBudgetEvidence.permission_query_errors_truncated -ne $true -or
    $byteBudgetEvidence.permission_query_error_count -ne (
        $byteBudgetEvidence.permission_query_error_retained_count +
        $byteBudgetEvidence.permission_query_error_dropped_count
    ) -or
    (Get-Utf8ByteCount $byteBudgetJson) -gt
        $PermissionQueryErrorMaxUtf8Bytes
) {
    throw "Permission error UTF-8 byte budget contract failed."
}

Write-Output (@{
    status = "permission error count contract passed"
    scenarios = 8
    maximum_error_count = 200
    record_limit = $PermissionQueryErrorMaxRecords
    utf8_byte_limit = $PermissionQueryErrorMaxUtf8Bytes
    maximum_dropped_records = 180
} | ConvertTo-Json -Compress)
