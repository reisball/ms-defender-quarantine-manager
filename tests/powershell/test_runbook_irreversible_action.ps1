param(
    [ValidateSet("release_requested", "needs_review")]
    [string] $SelectionMode = "release_requested",

    [Parameter(Mandatory = $true)]
    [ValidateSet("release", "deny", "reconcile")]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $StatusSequence,

    [switch] $CmdletFailure,

    [switch] $AuthorizationFailure,

    [switch] $TransportFailure,

    [switch] $MisleadingServerFailure,

    [switch] $MisleadingThrottleFailure,

    [switch] $StructuredForbiddenFailure,

    [switch] $NonTerminatingError,

    [switch] $ForbidCmdlet,

    [ValidateSet("release", "deny")]
    [string] $OperationAction = "release",

    [switch] $IncompatibleParameterSets,

    [switch] $ObservedExchangeParameterSets,

    [switch] $AliasCommand,

    [switch] $BrokenAliasCommand,

    [switch] $MetadataFailure,

    [switch] $DisconnectFailure,

    [switch] $PartialRbacEvidence,

    [switch] $MissingRbacCmdlets,

    [switch] $CaseVariantObservedIdentity,

    [switch] $ReportCalls,

    [switch] $StreamSecrets
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$global:IrreversibleTestAction = $Action
$global:IrreversibleTestIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
)
$global:IrreversibleTestStatuses = @($StatusSequence.Split(","))
$global:IrreversibleTestStatusIndex = 0
$global:IrreversibleTestCmdletFailure = $CmdletFailure.IsPresent
$global:IrreversibleTestAuthorizationFailure = (
    $AuthorizationFailure.IsPresent
)
$global:IrreversibleTestTransportFailure = $TransportFailure.IsPresent
$global:IrreversibleTestMisleadingServerFailure = (
    $MisleadingServerFailure.IsPresent
)
$global:IrreversibleTestMisleadingThrottleFailure = (
    $MisleadingThrottleFailure.IsPresent
)
$global:IrreversibleTestStructuredForbiddenFailure = (
    $StructuredForbiddenFailure.IsPresent
)
$global:IrreversibleTestNonTerminatingError = (
    $NonTerminatingError.IsPresent
)
$global:IrreversibleTestForbidCmdlet = $ForbidCmdlet.IsPresent
$global:IrreversibleTestMetadataCalls = 0
$global:IrreversibleTestCmdletCalls = 0
$global:IrreversibleTestLastParameterSet = ""
$global:IrreversibleTestAppId = "11111111-2222-3333-4444-555555555555"
$global:IrreversibleTestObjectId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
$env:IDENTITY_ENDPOINT = "http://127.0.0.1/mock-msi/token"
$env:IDENTITY_HEADER = "must-never-leave-runbook"
$claimsJson = (@{
    appid = $global:IrreversibleTestAppId
    oid = $global:IrreversibleTestObjectId
    xms_mirid = (
        "/subscriptions/00000000-0000-0000-0000-000000000000" +
        "/resourceGroups/rg/providers/Microsoft.Automation/" +
        "automationAccounts/ms_quarantine_for_splunk_soar"
    )
} | ConvertTo-Json -Compress)
$claimsPayload = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($claimsJson)
).TrimEnd("=").Replace("+", "-").Replace("/", "_")
$global:IrreversibleTestAccessToken = "e30.$claimsPayload.signature"

function Get-Command {
    param(
        [string] $Name,
        [object] $ErrorAction
    )
    $global:IrreversibleTestMetadataCalls++
    if (
        $MissingRbacCmdlets.IsPresent -and
        $Name -eq "Get-ManagementRole"
    ) {
        return $null
    }
    if (
        $MetadataFailure.IsPresent -and
        $Name -in @("Release-QuarantineMessage", "Get-ConnectionInformation")
    ) {
        throw "mock metadata lookup failure"
    }
    return Microsoft.PowerShell.Core\Get-Command `
        -Name $Name `
        -ErrorAction $ErrorAction
}

function Get-AutomationVariable {
    param([string] $Name)
    if ($Name -eq "ExchangeOrganization") {
        return "example.onmicrosoft.com"
    }
    if ($Name -eq "QuarantinePostconditionMaxAttempts") {
        return 3
    }
    if ($Name -eq "QuarantinePostconditionPollSeconds") {
        return 0
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
    [CmdletBinding()]
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
    if ($Headers["X-IDENTITY-HEADER"] -ne $env:IDENTITY_HEADER) {
        throw "Managed identity header mismatch."
    }
    return [pscustomobject]@{
        access_token = $global:IrreversibleTestAccessToken
    }
}

$global:IrreversibleTestDisconnectCalls = 0
function Disconnect-ExchangeOnline {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $global:IrreversibleTestDisconnectCalls++
    if ($DisconnectFailure.IsPresent) {
        throw "mock disconnect failure"
    }
}

function Release-QuarantineMessage {
    [CmdletBinding(
        DefaultParameterSetName = "Release",
        SupportsShouldProcess
    )]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Release")]
        [Parameter(ParameterSetName = "Deny")]
        [string] $Identity,

        [Parameter(ParameterSetName = "Deny")]
        [string[]] $Identities,

        [Parameter(ParameterSetName = "Release")]
        [Parameter(ParameterSetName = "Deny")]
        [switch] $ReleaseToAll,

        [Parameter(Mandatory = $true, ParameterSetName = "Deny")]
        [ValidateSet("Deny")]
        [string] $ActionType
    )

    if ($AliasCommand.IsPresent) {
        throw "Alias fixture resolved to the direct function, not the alias."
    }
    $global:IrreversibleTestCmdletCalls++
    $global:IrreversibleTestLastParameterSet = $PSCmdlet.ParameterSetName
    if ($global:IrreversibleTestForbidCmdlet) {
        throw "Release-QuarantineMessage must not execute in this fixture."
    }
    $boundNames = @($PSBoundParameters.Keys | Sort-Object)
    $expectedNames = if ($global:IrreversibleTestAction -eq "release") {
        @("Confirm", "ErrorAction", "Identity", "ReleaseToAll")
    } else {
        @("ActionType", "Confirm", "ErrorAction", "Identity", "ReleaseToAll")
    }
    if (
        ($boundNames -join ",") -ne ($expectedNames -join ",") -or
        $PSBoundParameters["Confirm"] -isnot [System.Management.Automation.SwitchParameter] -or
        $PSBoundParameters["Confirm"].IsPresent -ne $false -or
        [string] $PSBoundParameters["ErrorAction"] -ne "Stop"
    ) {
        throw "exact bound-parameter contract mismatch: $boundNames"
    }

    if ($global:IrreversibleTestAction -eq "release") {
        if (
            $Identity -ne $global:IrreversibleTestIdentity -or
            -not $ReleaseToAll.IsPresent -or
            $PSBoundParameters.ContainsKey("Identities") -or
            $PSBoundParameters.ContainsKey("ActionType")
        ) {
            throw "release parameter contract mismatch."
        }
    } else {
        if (
            $PSBoundParameters.ContainsKey("Identities") -or
            $ActionType -ne "Deny" -or
            $Identity -cne $global:IrreversibleTestIdentity -or
            -not $ReleaseToAll.IsPresent
        ) {
            throw "deny parameter contract mismatch."
        }
    }

    if ($StreamSecrets.IsPresent) {
        Write-Warning "password=must-never-leave-runbook"
        Write-Verbose "Authorization: Bearer must-never-leave-runbook"
        Write-Information "token=must-never-leave-runbook" -InformationAction Continue
    }
    Write-Warning "mock warning"
    Write-Information "mock information"
    Write-Verbose "mock verbose"
    if ($global:IrreversibleTestNonTerminatingError) {
        Write-Error "mock non-terminating cmdlet error" -ErrorAction Continue
        return
    }
    if ($global:IrreversibleTestAuthorizationFailure) {
        throw [System.UnauthorizedAccessException]::new(
            "HTTP 403 Forbidden: quarantine action is not authorized."
        )
    }
    if ($global:IrreversibleTestTransportFailure) {
        throw [System.TimeoutException]::new(
            "The Exchange request timed out before a response was received."
        )
    }
    if ($global:IrreversibleTestMisleadingServerFailure) {
        throw [System.TimeoutException]::new(
            "HTTP 500 Internal Server Error; " +
            "RequestId=9f403aab-1111-2222-3333-444455556666."
        )
    }
    if ($global:IrreversibleTestMisleadingThrottleFailure) {
        throw [System.TimeoutException]::new(
            "HTTP 429 Too Many Requests; " +
            "CorrelationId=9f401aab-1111-2222-3333-444455556666."
        )
    }
    if ($global:IrreversibleTestStructuredForbiddenFailure) {
        throw [System.Net.Http.HttpRequestException]::new(
            "Exchange rejected the request.",
            $null,
            [System.Net.HttpStatusCode]::Forbidden
        )
    }
    if ($global:IrreversibleTestCmdletFailure) {
        $exception = [System.Exception]::new("mock cmdlet failure")
        $exception.Data["RequestId"] = (
            "11111111-aaaa-bbbb-cccc-222222222222"
        )
        $exception.Data["CorrelationId"] = (
            "33333333-aaaa-bbbb-cccc-444444444444"
        )
        $exception.Data["Server-Timestamp"] = "2026-07-30T08:00:00Z"
        $exception.Data["Authorization"] = "Bearer must-never-leave-runbook"
        throw $exception
    }
}

if ($IncompatibleParameterSets.IsPresent) {
    function Release-QuarantineMessage {
        [CmdletBinding(
            DefaultParameterSetName = "ReleaseIdentity",
            SupportsShouldProcess
        )]
        param(
            [Parameter(
                Mandatory = $true,
                ParameterSetName = "ReleaseIdentity"
            )]
            [string] $Identity,

            [Parameter(
                Mandatory = $true,
                ParameterSetName = "DenyIdentities"
            )]
            [string[]] $Identities,

            [Parameter(
                Mandatory = $true,
                ParameterSetName = "ReleaseAll"
            )]
            [switch] $ReleaseToAll,

            [Parameter(
                Mandatory = $true,
                ParameterSetName = "DenyAction"
            )]
            [string] $ActionType
        )
        throw "Incompatible parameter-set fixture must never execute."
    }
}

if ($ObservedExchangeParameterSets.IsPresent) {
    function Release-QuarantineMessage {
        # Mirrors the six business parameter sets captured from the customer
        # ExchangeOnlineManagement 3.5.0 REST proxy. The overlapping optional
        # parameters are intentional and are the regression fixture.
        [CmdletBinding(
            DefaultParameterSetName = "IdentityOnly",
            SupportsShouldProcess
        )]
        param(
            [Parameter(ParameterSetName = "Identitities")]
            [Parameter(
                Mandatory = $true,
                ParameterSetName = "IdentityOnly"
            )]
            [Parameter(ParameterSetName = "OrgReleaseToAll")]
            [Parameter(ParameterSetName = "OrgReleaseToUser")]
            [string] $Identity,

            [Parameter(
                Mandatory = $true,
                ParameterSetName = "Identitities"
            )]
            [Parameter(ParameterSetName = "OrgReleaseToAll")]
            [Parameter(ParameterSetName = "OrgReleaseToUser")]
            [string[]] $Identities,

            [Parameter(ParameterSetName = "Identitities")]
            [Parameter(ParameterSetName = "IdentityOnly")]
            [Parameter(ParameterSetName = "OceReleaseToAll")]
            [Parameter(ParameterSetName = "OceReleaseToUser")]
            [Parameter(ParameterSetName = "OrgReleaseToAll")]
            [Parameter(ParameterSetName = "OrgReleaseToUser")]
            [ValidateSet("Release", "Deny")]
            [string] $ActionType,

            [Parameter(
                Mandatory = $true,
                ParameterSetName = "OceReleaseToAll"
            )]
            [Parameter(
                Mandatory = $true,
                ParameterSetName = "OrgReleaseToAll"
            )]
            [switch] $ReleaseToAll
        )

        $global:IrreversibleTestCmdletCalls++
        $global:IrreversibleTestLastParameterSet = $PSCmdlet.ParameterSetName
        if ($global:IrreversibleTestForbidCmdlet) {
            throw "Release-QuarantineMessage must not execute in this fixture."
        }
        if ($global:IrreversibleTestAction -eq "release") {
            if (
                $Identity -ne $global:IrreversibleTestIdentity -or
                -not $ReleaseToAll.IsPresent -or
                $PSCmdlet.ParameterSetName -ne "OrgReleaseToAll"
            ) {
                throw "observed release parameter contract mismatch."
            }
        } else {
            if (
                $PSBoundParameters.ContainsKey("Identities") -or
                $ActionType -ne "Deny" -or
                $Identity -cne $global:IrreversibleTestIdentity -or
                -not $ReleaseToAll.IsPresent -or
                $PSCmdlet.ParameterSetName -ne "OrgReleaseToAll"
            ) {
                throw "observed deny parameter contract mismatch."
            }
        }
    }
}

if ($AliasCommand.IsPresent) {
    function global:Invoke-AliasedReleaseQuarantineMessage {
        [CmdletBinding(
            DefaultParameterSetName = "Release",
            SupportsShouldProcess
        )]
        param(
            [Parameter(Mandatory = $true, ParameterSetName = "Release")]
            [Parameter(ParameterSetName = "Deny")]
            [string] $Identity,

            [Parameter(ParameterSetName = "Deny")]
            [string[]] $Identities,

            [Parameter(ParameterSetName = "Release")]
            [Parameter(ParameterSetName = "Deny")]
            [switch] $ReleaseToAll,

            [Parameter(Mandatory = $true, ParameterSetName = "Deny")]
            [ValidateSet("Deny")]
            [string] $ActionType
        )

        $global:IrreversibleTestCmdletCalls++
        $global:IrreversibleTestLastParameterSet = $PSCmdlet.ParameterSetName
        if ($global:IrreversibleTestForbidCmdlet) {
            throw "Aliased Release-QuarantineMessage must not execute."
        }
        if ($global:IrreversibleTestAction -eq "release") {
            if (
                $PSCmdlet.ParameterSetName -ne "Release" -or
                $Identity -ne $global:IrreversibleTestIdentity -or
                -not $ReleaseToAll.IsPresent -or
                $PSBoundParameters.ContainsKey("Identities") -or
                $PSBoundParameters.ContainsKey("ActionType")
            ) {
                throw "aliased release parameter contract mismatch."
            }
        } else {
            if (
                $PSCmdlet.ParameterSetName -ne "Deny" -or
                $PSBoundParameters.ContainsKey("Identities") -or
                $ActionType -ne "Deny" -or
                $Identity -cne $global:IrreversibleTestIdentity -or
                -not $ReleaseToAll.IsPresent
            ) {
                throw "aliased deny parameter contract mismatch."
            }
        }
    }
    Set-Alias -Scope Global -Force `
        -Name "Release-QuarantineMessage" `
        -Value "Invoke-AliasedReleaseQuarantineMessage"
}

if ($BrokenAliasCommand.IsPresent) {
    Set-Alias -Scope Global -Force `
        -Name "Release-QuarantineMessage" `
        -Value "Missing-AliasTarget"
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )

    if ($Identity -ne $global:IrreversibleTestIdentity) {
        throw "Postcondition identity mismatch."
    }
    if (
        $global:IrreversibleTestAction -in @("release", "deny") -and
        $global:IrreversibleTestStatusIndex -gt 0 -and
        $global:IrreversibleTestCmdletCalls -gt 1
    ) {
        throw "Postcondition read must not follow duplicate disposition calls."
    }
    $index = [System.Math]::Min(
        $global:IrreversibleTestStatusIndex,
        $global:IrreversibleTestStatuses.Count - 1
    )
    $value = $global:IrreversibleTestStatuses[$index]
    $global:IrreversibleTestStatusIndex++

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
    return [pscustomobject]@{
        Identity = if ($CaseVariantObservedIdentity.IsPresent) {
            $Identity.ToUpperInvariant()
        } else {
            $Identity
        }
        ReleaseStatus = $value
    }
}

function Get-ManagementRole {
    param(
        [string] $Cmdlet,
        [string[]] $CmdletParameters,
        [string] $Identity,
        [object] $ErrorAction
    )
    if ($PartialRbacEvidence.IsPresent) {
        throw "Mock RBAC query failure."
    }
    return [pscustomobject]@{ Name = "Quarantine" }
}

function Get-ManagementRoleEntry {
    param(
        [string] $Identity,
        [string[]] $Parameters,
        [object] $ErrorAction
    )
    return [pscustomobject]@{
        Identity = "Quarantine\Release-QuarantineMessage"
        Role = "Quarantine"
    }
}

function Get-ServicePrincipal {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    if (
        $Identity -notin @(
            $global:IrreversibleTestAppId,
            $global:IrreversibleTestObjectId
        )
    ) {
        return @()
    }
    return [pscustomobject]@{
        Identity = "ms_quarantine_for_splunk_soar-managed-identity"
        AppId = $global:IrreversibleTestAppId
        ObjectId = $global:IrreversibleTestObjectId
    }
}

function Get-ManagementRoleAssignment {
    param(
        [string] $Role,
        [bool] $Delegating,
        [object] $ErrorAction
    )
    return [pscustomobject]@{
        RoleAssigneeName = "SOAR Quarantine Automation"
        RoleAssigneeType = "RoleGroup"
    }
}

function Get-RoleGroupMember {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    return [pscustomobject]@{
        Name = "ms_quarantine_for_splunk_soar-managed-identity"
        AppId = $global:IrreversibleTestAppId
        ObjectId = $global:IrreversibleTestObjectId
    }
}

function Start-Sleep {
    param([int] $Seconds)
}

$requestBody = @{
    action = $Action
    quarantine_selection_mode = $SelectionMode
    identity = $global:IrreversibleTestIdentity
}
$webhookData = [pscustomobject]@{
    RequestBody = ($requestBody | ConvertTo-Json -Compress)
}

if ($StreamSecrets.IsPresent) { $VerbosePreference = "Continue" }
if ($ReportCalls.IsPresent) {
    $allStreams = @(& $runbookPath -WebhookData $webhookData *>&1)
    $output = @($allStreams | Where-Object { $_ -is [string] })
    $allText = ($allStreams | Out-String)
    @{
        result = (($output -join "`n") | ConvertFrom-Json)
        reads = $global:IrreversibleTestStatusIndex
        writes = $global:IrreversibleTestCmdletCalls
        metadata_calls = $global:IrreversibleTestMetadataCalls
        disconnects = $global:IrreversibleTestDisconnectCalls
        leaked_secret = $allText.Contains("must-never-leave-runbook")
    } | ConvertTo-Json -Depth 20 -Compress
} else {
    & $runbookPath -WebhookData $webhookData
}
