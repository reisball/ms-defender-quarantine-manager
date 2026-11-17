param(
    [ValidateSet("default", "mismatch_opt_in")]
    [string] $Scenario = "default"
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "runbook.ps1"
$requestedIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
)
$differentIdentity = (
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\" +
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

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
    throw "The read-only diagnose action invoked an irreversible cmdlet."
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    return [pscustomobject]@{
        Identity = if ($Scenario -eq "mismatch_opt_in") {
            $differentIdentity
        } else {
            $Identity
        }
        ReleaseStatus = "Requested"
    }
}

function Get-ManagementRole { throw "RBAC_QUERY_MUST_NOT_RUN" }
function Get-ManagementRoleEntry { throw "RBAC_QUERY_MUST_NOT_RUN" }
function Get-ServicePrincipal { throw "RBAC_QUERY_MUST_NOT_RUN" }
function Get-ManagementRoleAssignment { throw "RBAC_QUERY_MUST_NOT_RUN" }
function Get-RoleGroupMember { throw "RBAC_QUERY_MUST_NOT_RUN" }

$request = @{
    action = "diagnose"
    identity = $requestedIdentity
}
if ($Scenario -eq "mismatch_opt_in") {
    $request.include_rbac = $true
}
$webhookData = [pscustomobject]@{
    RequestBody = ($request | ConvertTo-Json -Compress)
}

& $runbookPath -WebhookData $webhookData
