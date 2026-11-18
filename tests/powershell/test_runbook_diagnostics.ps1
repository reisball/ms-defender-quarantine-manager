param(
    [ValidateSet(
        "role_group",
        "direct",
        "claim_only_group",
        "external_object_id",
        "name_collision",
        "unmatched_group_error",
        "many_role_groups_late_match",
        "many_role_groups_no_match",
        "empty_contracts"
    )]
    [string] $AssignmentMode = "role_group",
    [ValidateSet("available", "unavailable", "token_failure", "missing_guids", "malformed_guids")]
    [string] $IdentityMode = "available"
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$global:DiagnosticTestIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
)
$global:DiagnosticTestDispositionCalls = 0
$global:DiagnosticTestAppId = "11111111-2222-3333-4444-555555555555"
$global:DiagnosticTestObjectId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
$global:DiagnosticTestRoleGroupOtherMember = (
    "must-not-appear-in-diagnostic-output"
)
$global:DiagnosticTestUnmatchedRoleGroup = (
    "must-not-persist-unmatched-role-group"
)
$global:DiagnosticTestLateRoleGroup = "Role Group 23"
$global:DiagnosticTestAssignmentMode = $AssignmentMode
$env:IDENTITY_ENDPOINT = "http://127.0.0.1/mock-msi/token"
$env:IDENTITY_HEADER = "must-never-leave-runbook"

$global:DiagnosticTestIdentityMode = $IdentityMode
if ($IdentityMode -eq "unavailable") {
    $env:IDENTITY_ENDPOINT = ""
    $env:IDENTITY_HEADER = ""
}
if ($IdentityMode -eq "missing_guids") {
    $global:DiagnosticTestAppId = ""
    $global:DiagnosticTestObjectId = ""
} elseif ($IdentityMode -eq "malformed_guids") {
    $global:DiagnosticTestAppId = "not-a-guid"
    $global:DiagnosticTestObjectId = "not-a-guid"
}

$claimsJson = (@{
    appid = $global:DiagnosticTestAppId
    oid = $global:DiagnosticTestObjectId
    xms_mirid = (
        "/subscriptions/00000000-0000-0000-0000-000000000000" +
        "/resourceGroups/rg/providers/Microsoft.Automation/" +
        "automationAccounts/ms_quarantine_for_splunk_soar"
    )
} | ConvertTo-Json -Compress)
$claimsPayload = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($claimsJson)
).TrimEnd("=").Replace("+", "-").Replace("/", "_")
$global:DiagnosticTestAccessToken = "e30.$claimsPayload.signature"

function Get-AutomationVariable {
    param([string] $Name)
    if ($Name -eq "ExchangeOrganization") {
        return "example.onmicrosoft.com"
    }
    throw "Unexpected Automation Variable: $Name"
}

function Import-Module {
    param([Parameter(Position = 0)][string] $Name)
    if ($Name -ne "ExchangeOnlineManagement") {
        throw "Unexpected module: $Name"
    }
}

function Get-Module {
    param([Parameter(Position = 0)][string] $Name)
    if ($Name -ne "ExchangeOnlineManagement") {
        throw "Unexpected module query: $Name"
    }
    return [pscustomobject]@{
        Version = [version] "3.5.0"
        Path = "/mock/ExchangeOnlineManagement.psd1"
    }
}

function Connect-ExchangeOnline {
    param(
        [switch] $ManagedIdentity,
        [string] $Organization,
        [switch] $ShowBanner
    )
}

function Invoke-RestMethod {
    param(
        [string] $Method,
        [string] $Uri,
        [hashtable] $Headers,
        [object] $ErrorAction
    )
    if ($global:DiagnosticTestIdentityMode -eq "token_failure") {
        throw "Synthetic identity token failure."
    }
    if ($Headers["X-IDENTITY-HEADER"] -ne $env:IDENTITY_HEADER) {
        throw "Managed identity header mismatch."
    }
    return [pscustomobject]@{
        access_token = $global:DiagnosticTestAccessToken
    }
}

function Disconnect-ExchangeOnline {
    param([switch] $Confirm)
}

function Release-QuarantineMessage {
    [CmdletBinding(DefaultParameterSetName = "Identities")]
    param(
        [Parameter(ParameterSetName = "Identity", Mandatory = $true)]
        [string] $Identity,

        [Parameter(ParameterSetName = "Identities", Mandatory = $true)]
        [string[]] $Identities,

        [Parameter(ParameterSetName = "Identities", Mandatory = $true)]
        [ValidateSet("Release", "Deny")]
        [string] $ActionType,

        [Parameter(ParameterSetName = "Identity")]
        [switch] $ReleaseToAll
    )

    $global:DiagnosticTestDispositionCalls++
    throw "The read-only diagnose action invoked an irreversible cmdlet."
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )

    if ($Identity -ne $global:DiagnosticTestIdentity) {
        throw "Diagnostic identity mismatch."
    }
    return [pscustomobject]@{
        Identity = $Identity
        ReleaseStatus = "Requested"
    }
}

function Get-ManagementRole {
    param(
        [string] $Cmdlet,
        [string[]] $CmdletParameters,
        [string] $Identity,
        [object] $ErrorAction
    )
    if ($global:DiagnosticTestAssignmentMode -eq "empty_contracts") {
        return @()
    }
    if ($Identity -eq "Quarantine") {
        return [pscustomobject]@{ Name = "Quarantine" }
    }
    if ($Cmdlet -in @(
        "Get-QuarantineMessage",
        "Export-QuarantineMessage",
        "Release-QuarantineMessage"
    )) {
        return [pscustomobject]@{ Name = "Quarantine" }
    }
    throw "Unexpected management-role query."
}

function Get-ManagementRoleEntry {
    param(
        [string] $Identity,
        [string[]] $Parameters,
        [object] $ErrorAction
    )
    if ($global:DiagnosticTestAssignmentMode -eq "empty_contracts") {
        return @()
    }
    throw "Management-role entry fallback should not be required."
}

function Get-ServicePrincipal {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    if ($global:DiagnosticTestAssignmentMode -eq "claim_only_group") {
        throw "Service-principal lookup is unavailable in this fixture."
    }
    if ($Identity -notin @(
        $global:DiagnosticTestAppId,
        $global:DiagnosticTestObjectId
    )) {
        throw "Unexpected service-principal identity."
    }
    $objectId = $global:DiagnosticTestObjectId
    $externalDirectoryObjectId = $null
    if ($global:DiagnosticTestAssignmentMode -eq "external_object_id") {
        $objectId = $null
        $externalDirectoryObjectId = $global:DiagnosticTestObjectId
    }
    if ($global:DiagnosticTestAssignmentMode -eq "name_collision") {
        $appId = "12345678-1234-1234-1234-123456789abc"
        $objectId = "22222222-3333-4444-5555-666666666666"
    }
    return [pscustomobject]@{
        AppId = if ($global:DiagnosticTestAssignmentMode -eq "name_collision") {
            $appId
        } else {
            $global:DiagnosticTestAppId
        }
        ObjectId = $objectId
        ExternalDirectoryObjectId = $externalDirectoryObjectId
        Identity = "service-principal-ms_quarantine_for_splunk_soar"
    }
}

function Get-ManagementRoleAssignment {
    param(
        [string] $Role,
        [switch] $Delegating,
        [object] $ErrorAction
    )
    if ($Role -ne "Quarantine") {
        throw "Unexpected management role assignment query."
    }
    if ($global:DiagnosticTestAssignmentMode -in @(
        "direct",
        "name_collision"
    )) {
        return [pscustomobject]@{
            RoleAssigneeName = "service-principal-ms_quarantine_for_splunk_soar"
            RoleAssigneeType = "ServicePrincipal"
            RoleAssignee = if (
                $global:DiagnosticTestAssignmentMode -eq "name_collision"
            ) {
                "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
            } else {
                $global:DiagnosticTestObjectId
            }
        }
    }
    if ($global:DiagnosticTestAssignmentMode -in @(
        "many_role_groups_late_match",
        "many_role_groups_no_match"
    )) {
        return @(
            1..25 | ForEach-Object {
                [pscustomobject]@{
                    RoleAssigneeName = "Role Group {0:D2}" -f $_
                    RoleAssigneeType = "RoleGroup"
                }
            }
        )
    }
    return @(
        [pscustomobject]@{
            RoleAssigneeName = "Quarantine Administrator"
            RoleAssigneeType = "RoleGroup"
        },
        [pscustomobject]@{
            RoleAssigneeName = $global:DiagnosticTestUnmatchedRoleGroup
            RoleAssigneeType = "RoleGroup"
        }
    )
}

function Get-RoleGroupMember {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    if ($global:DiagnosticTestAssignmentMode -eq "direct") {
        throw "Direct assignment mode must not query an unassigned role group."
    }
    if ($global:DiagnosticTestAssignmentMode -in @(
        "many_role_groups_late_match",
        "many_role_groups_no_match"
    )) {
        if ($Identity -notmatch '^Role Group (0[1-9]|1[0-9]|20)$') {
            throw "Role-group inspection exceeded its first-20 safety cap."
        }
        if (
            $global:DiagnosticTestAssignmentMode -eq
            "many_role_groups_late_match" -and
            $Identity -eq $global:DiagnosticTestLateRoleGroup
        ) {
            return [pscustomobject]@{
                AppId = $global:DiagnosticTestAppId
                ObjectId = $global:DiagnosticTestObjectId
                Identity = "service-principal-ms_quarantine_for_splunk_soar"
            }
        }
        return [pscustomobject]@{
            Identity = $global:DiagnosticTestRoleGroupOtherMember
            ExternalDirectoryObjectId = (
                "99999999-8888-7777-6666-555555555555"
            )
        }
    }
    $allowedGroups = @(
        "Quarantine Administrator",
        $global:DiagnosticTestUnmatchedRoleGroup
    )
    if ($Identity -notin $allowedGroups) {
        throw "Unexpected role-group query."
    }
    if ($Identity -eq $global:DiagnosticTestUnmatchedRoleGroup) {
        if (
            $global:DiagnosticTestAssignmentMode -eq
            "unmatched_group_error"
        ) {
            throw "Cannot read members of $Identity."
        }
        return [pscustomobject]@{
            Identity = $global:DiagnosticTestRoleGroupOtherMember
            ExternalDirectoryObjectId = (
                "99999999-8888-7777-6666-555555555555"
            )
        }
    }
    return @(
        [pscustomobject]@{
            AppId = $global:DiagnosticTestAppId
            ObjectId = $global:DiagnosticTestObjectId
            Identity = "service-principal-ms_quarantine_for_splunk_soar"
        },
        [pscustomobject]@{
            Identity = $global:DiagnosticTestRoleGroupOtherMember
            ExternalDirectoryObjectId = (
                "99999999-8888-7777-6666-555555555555"
            )
        }
    )
}

$webhookData = [pscustomobject]@{
    RequestBody = (@{
        action = "diagnose"
        identity = $global:DiagnosticTestIdentity
        include_rbac = $true
    } | ConvertTo-Json -Compress)
}

$output = & $runbookPath -WebhookData $webhookData
if ($global:DiagnosticTestDispositionCalls -ne 0) {
    throw "The diagnose action executed Release-QuarantineMessage."
}
Write-Output $output
