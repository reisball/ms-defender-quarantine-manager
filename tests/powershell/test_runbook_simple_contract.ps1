$ErrorActionPreference = "Stop"
$fixture = Join-Path $PSScriptRoot "test_runbook_irreversible_action.ps1"
$connectionFixture = Join-Path $PSScriptRoot "test_runbook_connection_contract.ps1"
$script:scenarios = 0
$runbookSource = Get-Content (Join-Path $PSScriptRoot "../../runbook/runbook.ps1") -Raw
$expectedMetadata = @{}
foreach ($name in @("Version", "SourceRevision", "BuildId")) {
    $match = [regex]::Match($runbookSource, ('(?m)^\$Runbook' + $name + '\s*=\s*"([^"]+)"$'))
    if (-not $match.Success) { throw "Missing stamped metadata: $name" }
    $key = "runbook_" + ([regex]::Replace($name, '(?<!^)[A-Z]', '_$0')).ToLowerInvariant()
    $expectedMetadata[$key] = $match.Groups[1].Value
}

function Assert-Scenario {
    param([string] $Action, [string] $Sequence, [string] $Status, [int] $Reads, [int] $Writes, [string] $ErrorCode = "", [string[]] $Flags = @())
    $json = & pwsh -NoLogo -NoProfile -File $fixture -Action $Action -StatusSequence $Sequence -ReportCalls @Flags
    if ($LASTEXITCODE -ne 0) { throw "Fixture process failed: $Action $Sequence" }
    $data = $json | ConvertFrom-Json
    if ($data.reads -ne $Reads -or $data.writes -ne $Writes) {
        throw "Unexpected read/write count for $Action $Sequence ($($data.reads)/$($data.writes)); expected $Reads/$Writes"
    }
    if ($data.metadata_calls -ne 0 -or $data.leaked_secret) { throw "Normal operation collected optional metadata or leaked a secret." }
    if ($data.disconnects -ne 1) { throw "Connection not cleaned up exactly once." }
    $result = $data.result
    foreach ($key in $expectedMetadata.Keys) {
        if ($Action -in @("release", "deny")) {
            if ($result.$key -cne $expectedMetadata[$key]) { throw "Wrong disposition metadata: $key" }
        } elseif ($result.PSObject.Properties.Name -contains $key) {
            throw "Unexpected metadata on reconcile: $key"
        }
    }
    if ($ErrorCode) {
        if (-not $result.error -or $result.error_code -ne $ErrorCode) { throw "Wrong error: $json" }
        if (-not $result.message -or -not $result.identity -or -not $result.error_context) { throw "Incomplete error: $json" }
        if ($result.details -or $result.mode) { throw "Normal error contains retired envelope fields." }
        if ($Flags -contains "-CmdletFailure" -and $result.message -cne "mock cmdlet failure") { throw "Original cmdlet error changed." }
    } else {
        $expectedKeys = if ($Action -eq "reconcile") { "action,identity,observed_identity,observed_release_status" } else { "action,identity,observed_identity,observed_release_status,runbook_build_id,runbook_source_revision,runbook_version,status" }
        if ((($result.PSObject.Properties.Name | Sort-Object) -join ",") -ne $expectedKeys) { throw "Non-minimal normal result: $json" }
        if ($Action -eq "reconcile" -and $result.observed_release_status -ne $Status) { throw "Wrong observation: $json" }
        if ($Action -ne "reconcile" -and $result.status -ne $Status) { throw "Wrong status: $json" }
        if ($result.observed_identity -ine $result.identity) { throw "Result identity is not bound." }
    }
    $script:scenarios++
}

foreach ($action in @("release", "deny")) {
    $target = if ($action -eq "release") { "Released" } else { "Denied" }
    $status = $target.ToLowerInvariant()
    Assert-Scenario $action "Requested,$target" $status 2 1
    Assert-Scenario $action "Requested,Requested,PreparingToRelease,$target" $status 4 1
    Assert-Scenario $action "Requested,__ERROR__,$target" $status 3 1
    Assert-Scenario $action $target "already_$status" 1 0 -Flags @("-ForbidCmdlet")
    Assert-Scenario $action "NotReleased" "" 1 0 "precondition_unconfirmed" -Flags @("-ForbidCmdlet")
    Assert-Scenario $action "__EMPTY__" "" 1 0 "precondition_unconfirmed"
    Assert-Scenario $action "__MULTIPLE__" "" 1 0 "precondition_unconfirmed"
    Assert-Scenario $action "__ERROR__" "" 1 0 "precondition_unconfirmed"
    Assert-Scenario $action "Requested" "" 4 1 "postcondition_unconfirmed"
    Assert-Scenario $action "PreparingToRelease" "" 1 0 "release_pending"
    Assert-Scenario $action "Requested,PreparingToRelease" "" 4 1 "release_pending"
    foreach ($flag in @("-CmdletFailure", "-TransportFailure", "-AuthorizationFailure", "-NonTerminatingError")) {
        # Even if a hypothetical later status would be terminal, no read follows failure.
        Assert-Scenario $action "Requested,$target" "" 1 1 "disposition_failed" -Flags @($flag)
    }
    Assert-Scenario $action "Requested,$target" $status 2 1 -Flags @("-MetadataFailure", "-StreamSecrets")
    Assert-Scenario $action "Requested,$target" $status 2 1 -Flags @("-DisconnectFailure")
    Assert-Scenario $action "Requested,$target" $status 2 1 -Flags @("-ObservedExchangeParameterSets")
    Assert-Scenario $action "Requested,$target" $status 2 1 -Flags @("-CaseVariantObservedIdentity")
    Assert-Scenario $action "Requested,$target" "" 1 0 "disposition_failed" -Flags @("-IncompatibleParameterSets")
}
foreach ($status in @("Requested", "Released", "Denied", "PreparingToRelease")) {
    Assert-Scenario "reconcile" $status $status 1 0 -Flags @("-ForbidCmdlet")
}
Assert-Scenario "reconcile" "__EMPTY__" "NotFound" 1 0 -Flags @("-ForbidCmdlet")
Assert-Scenario "reconcile" "__ERROR__" "" 1 0 "runbook_unhandled_error" -Flags @("-ForbidCmdlet")

foreach ($request in @(
    @{ action = "list"; organization = "example.onmicrosoft.com" },
    @{ action = "list" },
    @{ action = "config_check"; organization = "example.onmicrosoft.com" },
    @{ action = "release"; identity = "__IDENTITY__"; auth_method = "Credential" },
    @{ action = "release"; identity = "__IDENTITY__"; credential_name = "old-asset" }
)) {
    $json = & pwsh -NoLogo -NoProfile -File $connectionFixture -RequestJson ($request | ConvertTo-Json -Compress) -OrganizationVariable "fallback.onmicrosoft.com" -EnableVerbose
    if ($LASTEXITCODE -ne 0) { throw "Connection fixture failed." }
    $data = $json | ConvertFrom-Json
    if ($data.leaked_secret_any_stream -or $data.get_module_calls -or $data.credential_reads.Count) { throw "Unexpected metadata/credential read or stream leak." }
    if ($request.action -eq "list") {
        $expectedOrg = if ($request.organization) { $request.organization } else { "fallback.onmicrosoft.com" }
        if ($data.connect_calls.Count -ne 1 -or -not $data.connect_calls[0].managed_identity -or $data.connect_calls[0].organization -ne $expectedOrg) { throw "Managed identity/organization fallback failed." }
    } elseif (-not $data.result.error -or $data.connect_calls.Count -or $data.quarantine_reads) { throw "Unsupported request reached Exchange." }
    $script:scenarios++
}
@{ status = "simple Runbook contract passed"; scenarios = $script:scenarios } | ConvertTo-Json -Compress
