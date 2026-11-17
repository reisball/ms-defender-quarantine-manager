$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "runbook.ps1"
$env:IDENTITY_ENDPOINT = $null
$env:IDENTITY_HEADER = $null
$global:MissingCmdletTestIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
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

function Disconnect-ExchangeOnline {
    param([switch] $Confirm)
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [object] $ErrorAction
    )
    return [pscustomobject]@{
        Identity = $Identity
        ReleaseStatus = "Requested"
    }
}

$webhookData = [pscustomobject]@{
    RequestBody = (@{
        action = "diagnose"
        identity = $global:MissingCmdletTestIdentity
        include_rbac = $true
    } | ConvertTo-Json -Compress)
}

& $runbookPath -WebhookData $webhookData
