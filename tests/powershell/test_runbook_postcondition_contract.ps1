$ErrorActionPreference = "Stop"

$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$source = [System.IO.File]::ReadAllText($runbookPath)
$helperStart = $source.IndexOf("function Write-ErrorResult")
$stepOne = $source.IndexOf("# Step 1: Validate webhook input")

if ($helperStart -lt 0 -or $stepOne -le $helperStart) {
    throw "Could not locate the runbook helper section."
}

Invoke-Expression $source.Substring($helperStart, $stepOne - $helperStart)

$global:PostconditionTestStatuses = @()
$global:PostconditionTestQueryCount = 0
$global:PostconditionTestIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
)
$global:PostconditionTestCaseVariantIdentity = (
    $global:PostconditionTestIdentity.ToUpperInvariant()
)
$global:PostconditionTestForeignIdentity = (
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\" +
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

function Set-PostconditionScenario {
    param([object[]] $Statuses)
    $global:PostconditionTestStatuses = @($Statuses)
    $global:PostconditionTestQueryCount = 0
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )

    if (-not $Identity) {
        throw "Identity is required."
    }
    if ($global:PostconditionTestStatuses.Count -lt 1) {
        throw "No postcondition test status configured."
    }

    $index = [System.Math]::Min(
        $global:PostconditionTestQueryCount,
        $global:PostconditionTestStatuses.Count - 1
    )
    $value = $global:PostconditionTestStatuses[$index]
    $global:PostconditionTestQueryCount++

    if ($value -eq "__ERROR__") {
        throw "Transient Exchange read error."
    }
    if ($value -eq "__EMPTY__") {
        return
    }
    if ($value -eq "__MULTIPLE__") {
        return @(
            [pscustomobject]@{
                Identity = $Identity
                ReleaseStatus = "Requested"
            },
            [pscustomobject]@{
                Identity = $Identity
                ReleaseStatus = "Requested"
            }
        )
    }
    if ($value -eq "__FOREIGN_RELEASED__") {
        return [pscustomobject]@{
            Identity = $global:PostconditionTestForeignIdentity
            ReleaseStatus = "Released"
        }
    }
    if ($value -eq "__CASE_VARIANT_RELEASED__") {
        return [pscustomobject]@{
            Identity = $global:PostconditionTestCaseVariantIdentity
            ReleaseStatus = "Released"
        }
    }
    return [pscustomobject]@{
        Identity = $Identity
        ReleaseStatus = [string] $value
    }
}

$global:PostconditionSleepSeconds = [System.Collections.Generic.List[int]]::new()
function Start-Sleep {
    param([int] $Seconds)
    $global:PostconditionSleepSeconds.Add($Seconds)
}

function Assert-Result {
    param(
        [string] $Name,
        [hashtable] $Result,
        [bool] $Confirmed,
        [int] $Attempts,
        [string] $ObservedStatus
    )

    if ($Result.Confirmed -ne $Confirmed) {
        throw "$Name confirmed mismatch."
    }
    if ($Result.Attempts -ne $Attempts) {
        throw "$Name attempts mismatch: $($Result.Attempts)."
    }
    if ($Result.ObservedStatus -ne $ObservedStatus) {
        throw "$Name observed status mismatch: '$($Result.ObservedStatus)'."
    }
}

Set-PostconditionScenario -Statuses @("Released")
$releaseImmediate = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "immediate release" `
    -Result $releaseImmediate `
    -Confirmed $true `
    -Attempts 1 `
    -ObservedStatus "Released"

Set-PostconditionScenario -Statuses @(
    "Requested",
    "PreparingToRelease",
    "Released"
)
$releaseDelayed = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "delayed release" `
    -Result $releaseDelayed `
    -Confirmed $true `
    -Attempts 3 `
    -ObservedStatus "Released"
if ($releaseDelayed.ObservedIdentity -ne $global:PostconditionTestIdentity) {
    throw "Release confirmation did not retain the exact observed identity."
}

Set-PostconditionScenario -Statuses @("denied")
$denyCaseInsensitive = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Denied" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "case-insensitive deny" `
    -Result $denyCaseInsensitive `
    -Confirmed $true `
    -Attempts 1 `
    -ObservedStatus "denied"

Set-PostconditionScenario -Statuses @("Requested")
$releaseUnconfirmed = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "unconfirmed release" `
    -Result $releaseUnconfirmed `
    -Confirmed $false `
    -Attempts 3 `
    -ObservedStatus "Requested"

Set-PostconditionScenario -Statuses @("__ERROR__", "Released")
$transientReadError = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "transient read error" `
    -Result $transientReadError `
    -Confirmed $true `
    -Attempts 2 `
    -ObservedStatus "Released"

Set-PostconditionScenario -Statuses @(
    "__EMPTY__",
    "__MULTIPLE__",
    "Denied"
)
$ambiguousThenDenied = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Denied" `
    -MaxAttempts 3 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "ambiguous then denied" `
    -Result $ambiguousThenDenied `
    -Confirmed $true `
    -Attempts 3 `
    -ObservedStatus "Denied"

Set-PostconditionScenario -Statuses @("__ERROR__")
$permanentReadError = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 2 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "permanent read error" `
    -Result $permanentReadError `
    -Confirmed $false `
    -Attempts 2 `
    -ObservedStatus ""
if ($permanentReadError.LastError -ne "Transient Exchange read error.") {
    throw "Permanent read error was not preserved."
}

Set-PostconditionScenario -Statuses @("__FOREIGN_RELEASED__")
$foreignReleased = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 1 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "foreign released object" `
    -Result $foreignReleased `
    -Confirmed $false `
    -Attempts 1 `
    -ObservedStatus ""
if ($foreignReleased.ObservedIdentity -ne "") {
    throw "A foreign identity must not become a trusted observation."
}
if ($foreignReleased.LastError -notmatch "instead of") {
    throw "Foreign identity mismatch was not reported."
}

Set-PostconditionScenario -Statuses @("__CASE_VARIANT_RELEASED__")
$caseVariantReleased = Wait-QuarantinePostcondition `
    -Identity $global:PostconditionTestIdentity `
    -ExpectedStatus "Released" `
    -MaxAttempts 1 `
    -PollIntervalSeconds 0
Assert-Result `
    -Name "case-variant identity" `
    -Result $caseVariantReleased `
    -Confirmed $true `
    -Attempts 1 `
    -ObservedStatus "Released"

if (-not (Test-QuarantineIdentityMatch `
    -Left $global:PostconditionTestIdentity `
    -Right $global:PostconditionTestCaseVariantIdentity
)) {
    throw "Semantically identical GUID pairs did not match."
}
foreach ($invalidIdentity in @(
    " $($global:PostconditionTestIdentity)",
    "$($global:PostconditionTestIdentity) ",
    "$($global:PostconditionTestIdentity)\\extra",
    "not-a-guid-pair"
)) {
    if (Test-QuarantineIdentityMatch `
        -Left $global:PostconditionTestIdentity `
        -Right $invalidIdentity
    ) {
        throw "Invalid quarantine identity unexpectedly matched."
    }
}

$boundedDiagnostic = ConvertTo-BoundedDiagnosticText `
    -Records @(("x" * 100), "must-not-fit") `
    -MaxRecords 1 `
    -MaxChars 64
if (
    $boundedDiagnostic.Length -ne 64 -or
    -not $boundedDiagnostic.EndsWith(" [truncated]")
) {
    throw "Diagnostic text did not respect its record/character bounds."
}
if ($boundedDiagnostic.Contains("must-not-fit")) {
    throw "Diagnostic text exceeded its record bound."
}

if ($PostconditionMaxAttempts -ne 7 -or $PostconditionPollSeconds -ne 10) {
    throw "Default status-read budget changed."
}
Set-PostconditionScenario -Statuses @("Requested")
$global:PostconditionSleepSeconds.Clear()
$defaultWindow = Wait-QuarantinePostcondition -Identity $global:PostconditionTestIdentity -ExpectedStatus "Released"
if ($defaultWindow.Confirmed -or $defaultWindow.Attempts -ne 7 -or $global:PostconditionSleepSeconds.Count -ne 6) {
    throw "Default bounded status-read loop did not use seven attempts and six intervals."
}
foreach ($seconds in $global:PostconditionSleepSeconds) {
    if ($seconds -ne 10) { throw "Default polling interval changed." }
}
Write-Output (@{
    scenarios = 10
    status = "postcondition contract passed"
} | ConvertTo-Json -Compress)
