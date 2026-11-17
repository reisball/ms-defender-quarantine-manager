param(
    [Parameter(Mandatory = $true)]
    [string] $RequestJson,

    # Stale value offered for the retired ExchangeAuthMethod Automation
    # Variable. The runbook must never read it; the read is recorded so the
    # caller can prove that. "__UNSET__" makes a (forbidden) read throw.
    [string] $AuthMethodVariable = "__UNSET__",

    [string] $OrganizationVariable = "__UNSET__",

    [switch] $ConnectFailure,

    [ValidateSet("ok", "throws", "throws_secret", "null", "bad_property", "huge_path")]
    [string] $GetModuleMode = "ok",

    [switch] $ImportFailure,

    [switch] $EnableVerbose,

    [switch] $OrganizationVariableReadFailure
)

$ErrorActionPreference = "Stop"
$runbookPath = Join-Path $PSScriptRoot "runbook.ps1"
$global:ConnTest = @{
    variable_reads = [System.Collections.Generic.List[string]]::new()
    credential_reads = [System.Collections.Generic.List[string]]::new()
    connect_calls = [System.Collections.Generic.List[object]]::new()
    release_calls = 0
    get_module_calls = 0
    quarantine_reads = 0
    disconnect_calls = 0
    status = "Requested"
}
$global:ConnTestIdentity = (
    "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\" +
    "4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
)
$secretUser = "svc-account@example.invalid"
$secretPassword = "never-leave-the-runbook-PASSWORD"
$env:IDENTITY_ENDPOINT = "http://127.0.0.1/mock-msi/token"
$env:IDENTITY_HEADER = "never-leave-the-runbook-HEADER"

function Get-AutomationVariable {
    param([string] $Name)
    $global:ConnTest.variable_reads.Add($Name)
    if ($Name -eq "ExchangeAuthMethod") {
        if ($AuthMethodVariable -eq "__UNSET__") {
            throw "Automation Variable 'ExchangeAuthMethod' does not exist."
        }
        return $AuthMethodVariable
    }
    if ($Name -eq "ExchangeOrganization") {
        if ($OrganizationVariableReadFailure.IsPresent) {
            throw "mock organization variable read failure"
        }
        if ($OrganizationVariable -eq "__UNSET__") {
            return $null
        }
        return $OrganizationVariable
    }
    if ($Name -eq "QuarantinePostconditionMaxAttempts") { return 2 }
    if ($Name -eq "QuarantinePostconditionPollSeconds") { return 0 }
    throw "Unexpected Automation Variable: $Name"
}

function Get-AutomationPSCredential {
    param([string] $Name)
    # Offered only so any (forbidden) retrieval is recorded and visible.
    $global:ConnTest.credential_reads.Add($Name)
    return [pscredential]::new(
        $secretUser,
        (ConvertTo-SecureString $secretPassword -AsPlainText -Force)
    )
}

function Import-Module {
    param([Parameter(Position = 0)][string] $Name)
    if ($ImportFailure.IsPresent) {
        throw "mock module import failure"
    }
}

function Get-Module {
    param([Parameter(Position = 0)][string] $Name)
    $global:ConnTest.get_module_calls++
    switch ($GetModuleMode) {
        "throws" { throw "mock passive Get-Module failure" }
        "throws_secret" { throw "lookup failed for $secretPassword" }
        "null" { return $null }
        "bad_property" {
            $module = [pscustomobject]@{ Path = "/mock/x.psd1" }
            $module | Add-Member -MemberType ScriptProperty -Name Version -Value {
                throw "mock Version property failure"
            }
            return $module
        }
        "huge_path" {
            return [pscustomobject]@{
                Version = [version] "3.5.0"
                Path = ("/p" * 4000)
            }
        }
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
        [pscredential] $Credential,
        [switch] $ShowBanner
    )
    $global:ConnTest.connect_calls.Add(@{
        managed_identity = $ManagedIdentity.IsPresent
        organization = $Organization
        organization_bound = $PSBoundParameters.ContainsKey("Organization")
        credential_bound = $PSBoundParameters.ContainsKey("Credential")
        credential_user_matches = (
            $null -ne $Credential -and $Credential.UserName -eq $secretUser
        )
    })
    if ($ConnectFailure.IsPresent) {
        throw "mock connect failure"
    }
}

function Disconnect-ExchangeOnline {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $global:ConnTest.disconnect_calls++
}

function Release-QuarantineMessage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $Identity,
        [string[]] $Identities,
        [switch] $ReleaseToAll,
        [string] $ActionType
    )
    $global:ConnTest.release_calls++
    $global:ConnTest.status = if ($ActionType -eq "Deny") {
        "Denied"
    } else {
        "Released"
    }
}

function Get-QuarantineMessage {
    param(
        [string] $Identity,
        [string] $ReleaseStatus,
        [int] $PageSize,
        [object] $ErrorAction
    )
    $global:ConnTest.quarantine_reads++
    if ($Identity) {
        return [pscustomobject]@{
            Identity = $Identity
            ReleaseStatus = $global:ConnTest.status
        }
    }
    return @(
        [pscustomobject]@{
            Identity = $global:ConnTestIdentity
            SenderAddress = "a@example.invalid"
            RecipientAddress = "b@example.invalid"
            Subject = "s"
            Type = "Spam"
            ReceivedTime = [datetime]::UtcNow
            Expires = [datetime]::UtcNow
            PolicyName = "p"
            ReleaseStatus = "Requested"
        }
    )
}

function Export-QuarantineMessage {
    param([string] $Identity, [object] $ErrorAction)
    return [pscustomobject]@{
        Eml = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Subject: s"))
    }
}

function Start-Sleep {
    param([int] $Seconds)
}

$requestBody = $RequestJson | ConvertFrom-Json
if (
    $requestBody.PSObject.Properties["identity"] -and
    $requestBody.identity -eq "__IDENTITY__"
) {
    $requestBody.identity = $global:ConnTestIdentity
}
$webhookData = [pscustomobject]@{
    RequestBody = ($requestBody | ConvertTo-Json -Compress)
}

if ($EnableVerbose.IsPresent) {
    $VerbosePreference = "Continue"
}
# Capture every stream so verbose/information/error text is inspected too,
# and keep the success stream (the SOAR result) separate from the rest.
$allStreams = @(& $runbookPath -WebhookData $webhookData *>&1)
$successStream = @(
    $allStreams | Where-Object {
        $_ -isnot [System.Management.Automation.InformationalRecord] -and
        $_ -isnot [System.Management.Automation.ErrorRecord] -and
        $_ -isnot [System.Management.Automation.WarningRecord]
    }
)
$verboseRecords = @(
    $allStreams | Where-Object {
        $_ -is [System.Management.Automation.VerboseRecord]
    }
)
$raw = ($successStream | Out-String).Trim()
$allText = (@($allStreams | ForEach-Object { [string] $_ }) -join "`n")
$parsed = $raw | ConvertFrom-Json
$envelope = [ordered]@{
    result = $parsed
    variable_reads = @($global:ConnTest.variable_reads.ToArray())
    credential_reads = @($global:ConnTest.credential_reads.ToArray())
    connect_calls = @($global:ConnTest.connect_calls.ToArray())
    release_calls = $global:ConnTest.release_calls
    get_module_calls = $global:ConnTest.get_module_calls
    quarantine_reads = $global:ConnTest.quarantine_reads
    disconnect_calls = $global:ConnTest.disconnect_calls
    leaked_secret = (
        $raw.Contains($secretUser) -or
        $raw.Contains($secretPassword) -or
        $raw.Contains($env:IDENTITY_HEADER)
    )
    leaked_secret_any_stream = (
        $allText.Contains($secretUser) -or
        $allText.Contains($secretPassword) -or
        $allText.Contains($env:IDENTITY_HEADER)
    )
    verbose_record_count = $verboseRecords.Count
    verbose_has_connect_notice = (
        $allText.Contains("Connecting to Exchange Online")
    )
    verbose_has_lookup_notice = (
        $allText.Contains("module version reported as unknown")
    )
}
$envelope | ConvertTo-Json -Depth 20 -Compress
