$ErrorActionPreference = "Stop"

$runbookPath = Join-Path $PSScriptRoot "../../runbook/runbook.ps1"
$source = [System.IO.File]::ReadAllText($runbookPath)
$helperStart = $source.IndexOf("function Write-ErrorResult")
$stepOne = $source.IndexOf("# Step 1: Validate webhook input")

if ($helperStart -lt 0 -or $stepOne -le $helperStart) {
    throw "Could not locate the runbook helper section."
}

Invoke-Expression $source.Substring($helperStart, $stepOne - $helperStart)

$nativeMessage = (
    "Microsoft Exchange Online returned:`r`n" +
    "The requested operation failed. (Code: ErrorAccessDenied)`n" +
    "RequestId: 12345678-1234-1234-1234-123456789abc; " +
    "CorrelationId: abcdefab-cdef-abcd-efab-cdefabcdefab`n" +
    "Mailbox: analyst+quarantine@example.com`n" +
    "URL: https://outlook.office365.com/adminapi/beta/tenant/messages"
)
try {
    throw [System.InvalidOperationException]::new($nativeMessage)
} catch {
    $nativeRecord = $_
}

$preserved = Get-OriginalErrorMessage -ErrorRecord $nativeRecord
if ($preserved -cne $nativeMessage) {
    throw "Native PowerShell/Microsoft error text was not preserved exactly."
}

$detailsMessage = (
    "Microsoft service detail`n" +
    "HTTP 403 Forbidden; request-id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)
$detailsRecord = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new("wrapper must not replace ErrorDetails"),
    "Microsoft.Exchange.ErrorAccessDenied",
    [System.Management.Automation.ErrorCategory]::PermissionDenied,
    $null
)
$detailsRecord.ErrorDetails = (
    [System.Management.Automation.ErrorDetails]::new($detailsMessage)
)
if ((Get-OriginalErrorMessage $detailsRecord) -cne $detailsMessage) {
    throw "ErrorDetails.Message was not retained as the native operator text."
}

$jwt = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJhdWQiOiJodHRwczovL291dGxvb2sub2ZmaWNlMzY1LmNvbSJ9." +
    "signaturesignature"
)
$secretText = (
    "Authorization: Bearer $jwt`n" +
    "x-identity-header=identity-secret`n" +
    "callback=https://example.invalid/hook?token=webhook-secret&safe=keep`n" +
    "Mailbox: analyst@example.com`n" +
    "RequestId: 12345678-1234-1234-1234-123456789abc"
)
$expectedRedacted = (
    "Authorization: Bearer [redacted]`n" +
    "x-identity-header=[redacted]`n" +
    "callback=https://example.invalid/hook?token=[redacted]&safe=keep`n" +
    "Mailbox: analyst@example.com`n" +
    "RequestId: 12345678-1234-1234-1234-123456789abc"
)
$actualRedacted = ConvertTo-SecretRedactedText -Text $secretText
if ($actualRedacted -cne $expectedRedacted) {
    throw "Secret redaction changed non-secret error text or missed a secret."
}
foreach ($secret in @($jwt, "identity-secret", "webhook-secret")) {
    if ($actualRedacted.Contains($secret)) {
        throw "Secret '$secret' survived error redaction."
    }
}

$extendedCredentialCases = @(
    @{
        input = "Cookie: session=abc123; csrf=def456"
        expected = "Cookie: [redacted]"
    },
    @{
        input = "Set-Cookie: session=abc123; HttpOnly; Secure"
        expected = "Set-Cookie: [redacted]"
    },
    @{
        input = '{"refresh_token":"rotate-me"}'
        expected = '{"refresh_token":"[redacted]"}'
    },
    @{
        input = "client_assertion='signed-assertion'"
        expected = "client_assertion='[redacted]'"
    },
    @{
        input = "password=hunter2"
        expected = "password=[redacted]"
    },
    @{
        input = "pwd:secret-value"
        expected = "pwd:[redacted]"
    },
    @{
        input = "https://example.invalid/?refresh_token=query-secret"
        expected = "https://example.invalid/?refresh_token=[redacted]"
    }
)
foreach ($case in $extendedCredentialCases) {
    $redacted = ConvertTo-SecretRedactedText -Text $case.input
    if ($redacted -cne $case.expected) {
        throw (
            "Extended credential redaction mismatch. Expected " +
            "'$($case.expected)', got '$redacted'."
        )
    }
}

$standaloneJwt = ConvertTo-SecretRedactedText -Text "Token payload: $jwt"
if ($standaloneJwt -cne "Token payload: [redacted]") {
    throw "A standalone valid JWT was not redacted."
}

$prefixedJwt = ConvertTo-SecretRedactedText `
    -Text "login.microsoftonline.$jwt"
if ($prefixedJwt -cne "login.microsoftonline.[redacted]") {
    throw "A JWT at the end of a dotted chain was not redacted."
}

$oversizedJwt = (
    ("A" * ($MaxJwtHeaderSegmentChars + 1)) +
    ".payloadxx.signature"
)
if ((ConvertTo-SecretRedactedText -Text $oversizedJwt) -cne "[redacted]") {
    throw "An oversized JWT-shaped candidate did not fail closed."
}

foreach ($nonSecretText in @(
    "The mailbox is on server nam02-am6-obe.outbound.protection.outlook.com and failed.",
    "Module Microsoft.Exchange.Management.RestApiClient.dll failed.",
    "Identifier abcdefgh.ijklmnop.qrstuvwx is not a JWT."
)) {
    if ((ConvertTo-SecretRedactedText -Text $nonSecretText) -cne $nonSecretText) {
        throw "Non-secret dotted Exchange/error text was changed by JWT redaction."
    }
}

$largeMessage = (
    "Microsoft large diagnostic begin`n" +
    ("äΩ-error-detail;" * 70000) +
    "`nMicrosoft large diagnostic end"
)
$largeEnvelope = @{
    action = "diagnose"
    error = $true
    error_code = "fixture_large_error"
    message = $largeMessage
}
$records = @(Write-ErrorEnvelope -Data $largeEnvelope)
if ($records.Count -ne 1) { throw "Error must be a single JSON record." }
$bounded = $records[0] | ConvertFrom-Json
if ($bounded.message.Length -gt 8192 -or -not $bounded.message.EndsWith(" [truncated]")) {
    throw "Large native error was not bounded explicitly."
}
if ($bounded.mode -or (Get-Utf8ByteCount $records[0]) -gt 64KB) {
    throw "Error unexpectedly used chunking or exceeded its transport budget."
}
$secretEnvelope = @{ action = "release"; error = $true; message = ("password=hidden-value " + ("x" * 9000)) }
$safeEnvelope = Write-ErrorEnvelope $secretEnvelope
if ($safeEnvelope.Contains("hidden-value") -or -not $safeEnvelope.Contains("[redacted]")) {
    throw "Error was not redacted before truncation."
}
# Offline integration: no provider call can fall through to live Exchange.
$global:DefensiveFixtureProviderCalls = 0
$global:DefensiveFixtureDispositionCalls = 0
$global:DefensiveFixtureReadMode = "empty"
$fixtureIdentity = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
function Get-AutomationVariable {
    param([string] $Name)
    if ($Name -eq "ExchangeOrganization") { return "fixture.onmicrosoft.com" }
    return $null
}
function Import-Module {
    param([Parameter(Position = 0)][string] $Name)
    $global:DefensiveFixtureProviderCalls++
    if ($Name -ne "ExchangeOnlineManagement") { throw "Unexpected module lookup." }
}
function Connect-ExchangeOnline { }
function Disconnect-ExchangeOnline { }
function Get-Module {
    Write-Warning "fixture-provider-stream"
    [pscustomobject] @{ Version = [version] "3.5.0"; Path = "/fixture/module.psd1" }
}
function Get-QuarantineMessage {
    param([string] $Identity, [object] $ErrorAction)
    if ($ErrorAction -ne "Stop") { throw "Expected -ErrorAction Stop." }
    Write-Warning "fixture-provider-stream"
    Write-Verbose "fixture-provider-stream"
    Write-Debug "fixture-provider-stream"
    Write-Information "fixture-provider-stream"
    Write-Host "fixture-provider-stream"
    if ($global:DefensiveFixtureReadMode -in @("row", "row_and_error")) {
        [pscustomobject] @{ Identity = $Identity; ReleaseStatus = "Requested" }
    }
    if ($global:DefensiveFixtureReadMode -in @("error", "row_and_error")) {
        Write-Error -Message "Exchange fixture read failed." -ErrorAction Continue
    }
}
function Get-ConnectionInformation {
    Write-Warning "fixture-provider-stream"
    Write-Verbose "fixture-provider-stream"
    Write-Debug "fixture-provider-stream"
    Write-Information "fixture-provider-stream"
    [pscustomobject] @{
        State = "Connected"
        ConnectionUri = "https://fixture-user@example.invalid:444/fixture-path?fixture-query=sample#fixture-fragment"
    }
    [pscustomobject] @{ ConnectionUri = "unparseable fixture-uri" }
}
function Release-QuarantineMessage {
    param([string] $Identity, [switch] $ReleaseToAll)
    # fixture-script-body
    $global:DefensiveFixtureDispositionCalls++
    throw "Unexpected disposition."
}
function Get-ManagementRole { throw "Unexpected diagnostic provider call." }
function Get-ManagementRoleEntry { throw "Unexpected diagnostic provider call." }
function Get-ServicePrincipal { throw "Unexpected diagnostic provider call." }
function Get-ManagementRoleAssignment { throw "Unexpected diagnostic provider call." }
function Get-RoleGroupMember { throw "Unexpected diagnostic provider call." }
function Invoke-RestMethod { throw "Unexpected diagnostic provider call." }

function Invoke-OfflineWebhook {
    param([object] $RequestBody)
    $VerbosePreference = "Continue"
    $DebugPreference = "Continue"
    $InformationPreference = "Continue"
    $output = @(& $runbookPath -WebhookData @{ RequestBody = $RequestBody } *>&1)
    if (@($output | Where-Object { [string] $_ -like "*fixture-provider-stream*" }).Count) {
        throw "A raw diagnostic provider stream was emitted."
    }
    $lines = @($output | Where-Object { $_ -is [string] })
    if ($lines.Count -ne 1 -or @($output | Where-Object {
        $_ -isnot [string] -and $_ -isnot [System.Management.Automation.VerboseRecord]
    }).Count) {
        throw "Expected one JSON result and no raw provider error records."
    }
    return ConvertFrom-Json $lines[0] -ErrorAction Stop
}

foreach ($case in @(
    @{ Body = "{broken fixture"; Expected = "invalid_webhook_json" },
    @{ Body = "[]"; Expected = "invalid_webhook_body_type" },
    @{ Body = "[{}]"; Expected = "invalid_webhook_body_type" },
    @{ Body = "[{},{}]"; Expected = "invalid_webhook_body_type" },
    @{ Body = "null"; Expected = "invalid_webhook_body_type" },
    @{ Body = "true"; Expected = "invalid_webhook_body_type" },
    @{ Body = "123"; Expected = "invalid_webhook_body_type" },
    @{ Body = '"fixture"'; Expected = "invalid_webhook_body_type" },
    @{ Body = @("{}"); Expected = "invalid_webhook_body_type" },
    @{ Body = "{}"; Expected = "missing_action" }
)) {
    $result = Invoke-OfflineWebhook $case.Body
    if (-not $result.error -or $result.error_code -ne $case.Expected) {
        throw "Unexpected webhook validation result: $($result.error_code); expected $($case.Expected)."
    }
    if ($result.message -like "*broken fixture*") { throw "JSON parser echoed request text." }
}
if ($global:DefensiveFixtureProviderCalls -ne 0) { throw "An invalid request loaded the Exchange module." }

function Invoke-ExactReadFixture {
    param([string] $Action)
    Invoke-OfflineWebhook (@{ action = $Action; identity = $fixtureIdentity } | ConvertTo-Json -Compress)
}

$missing = Invoke-ExactReadFixture "reconcile"
if ($missing.error -or $missing.observed_release_status -ne "NotFound") {
    throw "A successful empty exact read must report NotFound."
}
$global:DefensiveFixtureReadMode = "row"
$observation = Invoke-ExactReadFixture "reconcile"
if ($observation.error -or $observation.observed_release_status -ne "Requested") {
    throw "Reconcile did not accept the clean exact read."
}
$diagnosed = Invoke-ExactReadFixture "diagnose"
if ($diagnosed.status -ne "inspected" -or $diagnosed.exchange_connection_metadata -ne (
    "State=Connected,ConnectionUri=https://example.invalid:444 | ConnectionUri=[unavailable]"
)) {
    throw "Diagnosis did not retain only the verified connection origin."
}
$proxy = ConvertFrom-Json $diagnosed.cmdlet_proxy_diagnostics
$entry = $proxy.commands[0]
if ($entry.source_sha256 -notmatch '^[0-9a-f]{64}$' -or $entry.source_chars -lt 1 -or
    $null -ne $entry.PSObject.Properties["source"] -or
    $null -ne $entry.PSObject.Properties["forwarding_excerpts"] -or
    $diagnosed.cmdlet_proxy_diagnostics.Contains("fixture-script-body")) {
    throw "Proxy diagnostics must report source metadata without source text."
}

foreach ($mode in @("error", "row_and_error")) {
    $global:DefensiveFixtureReadMode = $mode
    foreach ($case in @(
        @{ Action = "reconcile"; Expected = "runbook_unhandled_error" },
        @{ Action = "diagnose"; Expected = "diagnostic_inspection_failed" },
        @{ Action = "release"; Expected = "precondition_unconfirmed" },
        @{ Action = "deny"; Expected = "precondition_unconfirmed" }
    )) {
        $result = Invoke-ExactReadFixture $case.Action
        if (-not $result.error -or $result.error_code -ne $case.Expected -or
            $result.message -ne "Exchange fixture read failed." -or
            $result.observed_release_status) {
            throw "An errored exact read was trusted or lost its native message: $($case.Action)/$mode."
        }
    }
}
if ($global:DefensiveFixtureDispositionCalls -ne 0) { throw "An errored precondition read attempted a disposition." }

Write-Output "Runbook bounded error and defensive read/diagnostics contracts passed."
