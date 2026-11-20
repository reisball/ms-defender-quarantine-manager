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

$joined = Join-OriginalRecordText -Records @($nativeRecord, $detailsRecord)
if ($joined -cne ($nativeMessage + "`n" + $detailsMessage)) {
    throw "Multiple native error records were not joined without rewriting."
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
Write-Output "Runbook bounded error contract passed."
