param(
    [switch] $RawOutput,

    [ValidateSet("release_requested", "needs_review")]
    [string] $SelectionMode = "release_requested",

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 1000)]
    [int] $MessageCount,

    [ValidateRange(1, 1000000)]
    [int] $SubjectLength = 3,

    [switch] $UseStringDates,

    [switch] $ExpectOversizedItem,

    [ValidateRange(0, 999)]
    [int] $OversizedMessageIndex = 0,

    [ValidateRange(0, 1000)]
    [int] $RequestedPageSize = 0
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$global:RunbookTestSelectionStatus = "Requested"
$global:RunbookTestMessageCount = $MessageCount
$global:RunbookTestSubjectLength = $SubjectLength
$global:RunbookTestUseStringDates = $UseStringDates.IsPresent
$global:RunbookTestRequestedPageSize = $RequestedPageSize

function Get-AutomationVariable {
    param([string] $Name)
    if ($Name -eq "ExchangeOrganization") {
        return "example.onmicrosoft.com"
    }
    throw "Unexpected Automation Variable: $Name"
}

function Import-Module {
    param(
        [Parameter(Position = 0)]
        [string] $Name
    )
    if ($Name -ne "ExchangeOnlineManagement") {
        throw "Unexpected module: $Name"
    }
}

function Connect-ExchangeOnline {
    param(
        [switch] $ManagedIdentity,
        [string] $Organization,
        [switch] $ShowBanner
    )
}

function Disconnect-ExchangeOnline {
    param(
        [switch] $Confirm
    )
}

function Get-QuarantineMessage {
    param(
        [string] $ReleaseStatus,
        [int] $PageSize
    )

    $expectedPageSize = if ($global:RunbookTestRequestedPageSize -gt 0) {
        $global:RunbookTestRequestedPageSize
    } else {
        50
    }
    if ($ReleaseStatus -ne $global:RunbookTestSelectionStatus -or $PageSize -ne $expectedPageSize) {
        throw (
            "List invocation mismatch: ReleaseStatus='$ReleaseStatus', " +
            "PageSize=$PageSize, expected PageSize=$expectedPageSize."
        )
    }

    if ($global:RunbookTestMessageCount -eq 0) {
        return
    }

    $messages = @(
        for ($index = 0; $index -lt $global:RunbookTestMessageCount; $index++) {
            if ($global:RunbookTestUseStringDates) {
                if (($index % 2) -eq 0) {
                    $received = "2026-07-28T00:00:00Z"
                    $expires = "not-a-date-$index"
                } else {
                    $received = [datetime]"2026-07-28T00:00:00Z"
                    $expires = [datetime]"2026-08-28T00:00:00Z"
                }
            } else {
                $received = [datetime]"2026-07-28T00:00:00Z"
                $expires = [datetime]"2026-08-28T00:00:00Z"
            }

            [pscustomobject]@{
                Identity = (
                    "00000000-0000-0000-0000-{0:D12}\11111111-1111-1111-1111-{0:D12}" `
                    -f $index
                )
                SenderAddress = "sender$index@example.com"
                RecipientAddress = "recipient$index@example.com"
                Subject = "測" * $(if (
                    $ExpectOversizedItem.IsPresent -and
                    $index -ne $OversizedMessageIndex
                ) {
                    3
                } else {
                    $global:RunbookTestSubjectLength
                })
                Type = "Spam"
                ReceivedTime = $received
                Expires = $expires
                PolicyName = "Policy"
                ReleaseStatus = $global:RunbookTestSelectionStatus
            }
        }
    )

    if ($global:RunbookTestMessageCount -eq 1) {
        return $messages[0]
    }
    return $messages
}

$request = @{ action = "list"; quarantine_selection_mode = $SelectionMode }
if ($RequestedPageSize -gt 0) {
    $request.page_size = $RequestedPageSize
}
$webhookData = [pscustomobject]@{
    RequestBody = ($request | ConvertTo-Json -Compress)
}

$output = @(& $runbookPath -WebhookData $webhookData)
$jsonLines = @($output | Where-Object {
    $_ -is [string] -and $_.TrimStart().StartsWith("{")
})
if ($jsonLines.Count -lt 1) {
    throw "Expected at least one JSON result."
}

$records = @($jsonLines | ForEach-Object { $_ | ConvertFrom-Json })
if ($RawOutput.IsPresent) {
    $jsonLines | ForEach-Object { Write-Output $_ }
    exit 0
}
if ($ExpectOversizedItem.IsPresent) {
    if ($records.Count -ne 1) {
        throw "Expected exactly one structured list_record_oversized result."
    }
    $errorResult = $records[0]
    if (
        $errorResult.action -ne "list" -or
        $errorResult.error -ne $true -or
        $errorResult.error_code -ne "list_record_oversized" -or
        -not $errorResult.message -or
        $errorResult.mode -or
        [System.Text.Encoding]::UTF8.GetByteCount($jsonLines[0]) -gt 64KB
    ) {
        throw "Unexpected oversized-list result: $($jsonLines[0])"
    }
    Write-Output (@{
        status = "list_record_oversized"
        utf8_bytes = [System.Text.Encoding]::UTF8.GetByteCount($jsonLines[0])
    } | ConvertTo-Json -Compress)
    exit 0
}

$oversizedRecords = @(
    for ($index = 0; $index -lt $jsonLines.Count; $index++) {
        $utf8Bytes = [System.Text.Encoding]::UTF8.GetByteCount($jsonLines[$index])
        if ($utf8Bytes -gt (900 * 1024)) {
            $utf8Bytes
        }
    }
)
if ($oversizedRecords.Count -gt 0) {
    throw "One or more list records exceeded the 900 KiB contract: $oversizedRecords"
}

$complete = @($records | Where-Object { $_.mode -eq "list_complete" })
$chunks = @($records | Where-Object { $_.mode -eq "list_chunk" })

if ($complete.Count -eq 0) {
    if ($records.Count -ne 1) {
        throw "Legacy/small list output must contain exactly one JSON record."
    }
    $result = $records[0]
    if ($result.action -ne "list") {
        throw "Expected action=list, got '$($result.action)'."
    }
    $messages = @($result.messages)
    if ($MessageCount -eq 0 -and $null -eq $result.messages) {
        $messages = @()
    }
} else {
    if ($complete.Count -ne 1) {
        throw "Expected exactly one list_complete trailer."
    }
    $trailer = $complete[0]
    if ($chunks.Count -ne $trailer.chunk_count) {
        throw "Chunk count mismatch."
    }
    $indexes = @($chunks | ForEach-Object { [int]$_.chunk_index } | Sort-Object)
    for ($index = 0; $index -lt $indexes.Count; $index++) {
        if ($indexes[$index] -ne $index) {
            throw "Missing or duplicate chunk index."
        }
    }
    $messages = @(
        $chunks |
            Sort-Object { [int]$_.chunk_index } |
            ForEach-Object { @($_.messages) }
    )
    $result = $trailer
}

$expectedVersion = (Get-Content (Join-Path $PSScriptRoot "../../app/ms_quarantine_for_splunk_soar.json") -Raw | ConvertFrom-Json).app_version
if ($result.runbook_version -ne $expectedVersion) {
    throw "Expected runbook_version=$expectedVersion, got '$($result.runbook_version)'."
}
if ($result.count -ne $MessageCount) {
    throw "Expected count=$MessageCount, got '$($result.count)'."
}
if ($messages.Count -ne $MessageCount) {
    throw "Expected $MessageCount reconstructed message(s), got $($messages.Count)."
}
if ($MessageCount -gt 0 -and $global:RunbookTestUseStringDates) {
    if (-not $messages[0].ReceivedTime) {
        throw "String ReceivedTime was not preserved or parsed."
    }
    if ($messages[0].Expires -ne "not-a-date-0") {
        throw "Unparseable string Expires must be preserved without failing list."
    }
}

Write-Output (@{
    count = $result.count
    page_size = if ($RequestedPageSize -gt 0) {
        $RequestedPageSize
    } else {
        50
    }
    chunked = ($complete.Count -eq 1)
    json_records = $jsonLines.Count
    max_utf8_bytes = (
        $jsonLines |
            ForEach-Object { [System.Text.Encoding]::UTF8.GetByteCount($_) } |
            Measure-Object -Maximum
    ).Maximum
} | ConvertTo-Json -Compress)
