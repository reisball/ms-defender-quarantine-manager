<#
.SYNOPSIS
    MS Quarantine for Splunk SOAR – Azure Automation Runbook

.DESCRIPTION
    Manages Exchange Online quarantined emails on behalf of Splunk SOAR.
    Called via Azure Automation Webhook. Results are written via Write-Output
    and retrieved by SOAR through the Azure Automation Job Output API.

    Target runtime: the same Automation Account, system-assigned identity,
             runtime environment and ExchangeOnlineManagement module version
             as the exact known-good Microsoft quarantine job (not pinned
             here; PowerShell 7.4 with module 3.5.0 was only a dated
             historical example from 29 July 2026). The loaded module version
             is reported by manual diagnose when it can be read.

    Supported actions:
        list    -> Get-QuarantineMessage -ReleaseStatus Requested
        export  -> Export-QuarantineMessage -Identity <identity>
        diagnose -> Read-only runtime/cmdlet/identity/RBAC inspection
        reconcile -> Single read-only status refresh for the active window
        release -> Release-QuarantineMessage -Identity <identity> -ReleaseToAll -Confirm:$false
        deny    -> Release-QuarantineMessage -Identity <identity> -ReleaseToAll -ActionType Deny -Confirm:$false

    Expected webhook body (JSON):
        { "action": "list" }
        { "action": "export",  "identity": "GUID1\\GUID2" }
        { "action": "diagnose", "identity": "GUID1\\GUID2", "include_rbac": false }
        { "action": "reconcile", "identity": "GUID1\\GUID2" }
        { "action": "release", "identity": "GUID1\\GUID2" }
        { "action": "deny",    "identity": "GUID1\\GUID2" }

    Intake selects only ReleaseStatus Requested (a recipient release request).
    Release/deny require that source status before invoking the existing cmdlet.
    Only exact Released/Denied readback proves success. Obsolete selection-mode
    webhook fields do not alter this fixed behavior.

    Optional connection settings, accepted on every action (all are strings;
    surrounding whitespace is trimmed; blank values count as omitted):
        "auth_method"     Omitted/blank or exactly "ManagedIdentity". Exchange
                          Online authentication is ALWAYS the system-assigned
                          Managed Identity of this Automation Account; any other
                          value (including the former "Credential") is rejected
                          with error_code invalid_exchange_auth_method before
                          the module is loaded, Exchange is contacted or any
                          message is read. There is no fallback.
        "organization"    Exchange organization (contoso.onmicrosoft.com).
                          Omitted: the ExchangeOrganization Automation
                          Variable, which is then required and is not read when
                          this field is present.
        "credential_name" No longer supported. A non-blank value is rejected
                          with error_code unsupported_credential_name before
                          any connection. The app never sends it.
    The former ExchangeAuthMethod Automation Variable is no longer read; a
    stale value cannot change the sign-in. Every result that reports connection
    evidence names the effective method (ManagedIdentity), the organization and
    where each value came from (webhook, automation_variable or default).

    Output format (always JSON, written via Write-Output):
        list:
            { "action": "list", "count": 2, "messages": [ {...}, {...} ] }
        export, small EML:
            { "action": "export", "identity": "...", "eml": "<base64>" }
        export, large EML:
            { "action": "export", "mode": "chunked", "identity": "...", "encoding": "base64", "chunk_index": 0, "chunk_count": 3, "eml_chunk": "..." }
            { "action": "export", "mode": "chunked", "identity": "...", "encoding": "base64", "chunk_index": 1, "chunk_count": 3, "eml_chunk": "..." }
            { "action": "export", "mode": "chunked_complete", "identity": "...", "chunk_count": 3, "eml_base64_length": 123456, "decoded_size": 92592, "sha256": "..." }
        diagnose:
            { "action": "diagnose", "identity": "...", "status": "inspected", "observed_release_status": "Requested", "cmdlet_contract_id": "identity_releasetoall", "rbac_diagnostics_status": "complete", "release_to_all_roles": "Quarantine", "service_principal_registered": true, "role_assignment_matches_identity": true }
        release:
            { "action": "release", "identity": "...", "status": "released", "observed_release_status": "Released", "observed_identity": "..." }
        deny:
            { "action": "deny", "identity": "...", "status": "denied", "observed_release_status": "Denied", "observed_identity": "..." }
        error (any action):
            { "action": "...", "error": true, "message": "..." }

    Prerequisites
    -------------
    Automation Account:
        - System-assigned Managed Identity enabled
        - ExchangeOnlineManagement module installed from PowerShell Gallery
        - The Exchange organization (e.g. contoso.onmicrosoft.com) from the
          webhook "organization" field or the ExchangeOrganization Automation
          Variable
        - No Automation Credential asset, user name, password or Azure app
          client secret is used for Exchange authentication

    Managed Identity permissions:
        - Exchange.ManageAsApp API permission assigned
        - Operational Exchange/Email & collaboration RBAC assigned
        - Least privilege: register the Managed Identity service principal in
          Exchange and add it to a custom role group containing Quarantine
        - Broader alternative: Security Administrator Entra role
        - Reference: https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity
        - Reference: https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-2-assign-custom-role-groups-to-the-application-using-service-principals

.PARAMETER WebhookData
    Provided automatically by Azure Automation when triggered via webhook.
    Contains the HTTP request body with action and identity parameters.

.NOTES
    Author:  Kai Seidenschnur
    Copyright: 2026 Kai Seidenschnur
    License: Apache-2.0
    Version: 1.0.0
    Runtime: match the exact known-good Microsoft Automation job (account,
             system identity, runtime, module); the loaded
             ExchangeOnlineManagement version is reported by diagnose and
             is deliberately not pinned here

    Export transport limits:
        Azure Automation has a 1 MiB maximum job stream limit. Small exports
        keep the legacy single JSON object. Exports with a base64 string byte
        length >= 750 KiB are split into 250 KiB base64 chunks. Decoded EML
        payloads larger than 24 MiB fail closed with a structured error. Large
        exports are normalised, validated, hashed, and decoded blockwise so
        the transport stage does not create full-size duplicate strings or
        byte arrays. The Exchange cmdlet itself still materialises .Eml.

    Irreversible-action confirmation:
        After the exact Requested precondition read, Release-QuarantineMessage
        is invoked directly, exactly as in Microsoft's documented example
        (-Identity <identity> -ReleaseToAll -Confirm:$false -ErrorAction
        Stop). Deny uses -Identity <identity> -ReleaseToAll -ActionType Deny
        -Confirm:$false -ErrorAction Stop. No
        synthetic parameter-binding probe or other pre-flight capability
        gate can veto the call; a genuine PowerShell binding error surfaces
        with its original message and error record. Tenant RBAC
        introspection is deliberately not a prerequisite for the operational
        call: a least-privileged disposition identity may run the exact command
        without being allowed to enumerate Exchange management roles. Full
        RBAC inspection remains available only through diagnose with
        include_rbac=true.
        Release-QuarantineMessage has no output object. Release and deny are
        therefore confirmed by polling the exact identity with
        Get-QuarantineMessage. Success requires ReleaseStatus=Released or
        ReleaseStatus=Denied. An unconfirmed postcondition fails closed as
        outcome unknown and must not be retried blindly.

    Normal results contain only action, identity, status and the verified
    observed_identity/observed_release_status. After a successful cmdlet the
    default status-read budget is 7 attempts, 10 seconds apart. A cmdlet error
    is reported immediately: there is no later error-to-success reconstruction.
    Errors use one JSON object with redacted, bounded native text, error_code,
    error_context and optional native exception fields (no error chunk stream).

    Optional manual diagnostics:
        Only diagnose collects build, runtime, connection and command metadata,
        proxy details, and (with include_rbac=true) tenant RBAC evidence.
        Diagnostics are never a prerequisite for normal commands. Missing RBAC
        diagnostic cmdlets are reported explicitly as not evaluated.

    PowerShell Cmdlet references:
        Get-QuarantineMessage:
            https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-quarantinemessage
        Export-QuarantineMessage:
            https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/export-quarantinemessage
        Release-QuarantineMessage:
            https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/release-quarantinemessage
        Connect via Managed Identity:
            https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity
#>

param (
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

# ---------------------------------------------------------------------------
# Helper: write a JSON application error result and exit successfully
# ---------------------------------------------------------------------------
function Write-ErrorResult {
    param(
        [string] $Action,
        [string] $Message = "",
        [string] $ErrorCode = "",
        [hashtable] $Details = @{},
        [object] $ErrorRecord = $null,
        [string] $ErrorContext = ""
    )
    if ($null -ne $ErrorRecord) {
        $Message = Get-OriginalErrorMessage -ErrorRecord $ErrorRecord
    }
    if (-not $Message) { $Message = "Unknown error." }
    $resultData = @{
        action = ConvertTo-RedactedBoundedScalarText -Value $Action -MaxChars 32
        error = $true
        message = ConvertTo-RedactedBoundedScalarText -Value $Message -MaxChars 8192
        error_code = if ($ErrorCode) { $ErrorCode } else { "runbook_error" }
        error_context = if ($ErrorContext) { $ErrorContext } else { $Action }
    }
    $knownIdentity = if ($Details.identity) { $Details.identity } else { $script:identity }
    if ($knownIdentity) {
        $resultData.identity = ConvertTo-RedactedBoundedScalarText -Value $knownIdentity -MaxChars 128
    }
    $resultData.error_context = ConvertTo-RedactedBoundedScalarText -Value $resultData.error_context -MaxChars 128
    if ($null -ne $ErrorRecord) {
        foreach ($field in @{
            exception_type = $ErrorRecord.Exception.GetType().FullName
            fully_qualified_error_id = $ErrorRecord.FullyQualifiedErrorId
            error_category = $ErrorRecord.CategoryInfo.Category
            error_reason = $ErrorRecord.CategoryInfo.Reason
        }.GetEnumerator()) {
            $resultData[$field.Key] = ConvertTo-RedactedBoundedScalarText -Value $field.Value -MaxChars 512
        }
    }
    # Only explicitly requested diagnostics include the optional evidence report.
    if ($Action -eq "diagnose" -and $Details.Count -gt 0) {
        $resultData.details = $Details
    }
    Write-ErrorEnvelope -Data $resultData
    # Azure job completion is transport success; error=true is application failure.
    exit 0
}

function ConvertTo-RunbookJson {
    param([hashtable] $Data)
    # Preserve list/export transport metadata; ordinary action results stay small.
    if ($Data.action -in @("list", "export", "diagnose")) {
        Add-RunbookEnvelopeMetadata -Data $Data
    }
    return ($Data | ConvertTo-Json -Depth 10 -Compress)
}

function Write-SuccessResult {
    param([hashtable] $Data)
    if ($Data.action -eq "diagnose") {
        foreach ($key in @("cmdlet_metadata_error", "exchange_connection_metadata_error")) {
            if ($Data.ContainsKey($key)) {
                $Data[$key] = ConvertTo-RedactedBoundedScalarText -Value $Data[$key]
            }
        }
    }
    Write-Output (ConvertTo-RunbookJson -Data $Data)
}

# ---------------------------------------------------------------------------
# Transport limits. These values intentionally mirror the SOAR parser.
# ---------------------------------------------------------------------------
$ListMaxRecordBytes        = 900 * 1024
$ListMaxResultCount        = 1000
$ExportChunkThresholdBytes = 750 * 1024
$ExportChunkSizeChars     = 250 * 1024
$ExportMaxChunkCount      = 200
$ExportMaxDecodedBytes    = 24 * 1024 * 1024
$ExportScanBlockChars     = 256 * 1024
$Base64AllowedWhitespacePattern = "[\x09\x0A\x0D\x20]"
$Base64UnsupportedWhitespacePattern = "[^\S\x09\x0A\x0D\x20]"
$RunbookVersion           = "1.0.0"
$RunbookSourceRevision    = "sha256:fa3c859db6f45459a301f6ede1ffdef148586bdbad4f5d607ed8861d39f4c6bc"
$RunbookBuildId           = "ms-quarantine-for-splunk-soar-runbook-1.0.0+sha256.fa3c859db6f45459a301f6ede1ffdef148586bdbad4f5d607ed8861d39f4c6bc"
$ReleaseContractId        = "identity_releasetoall"
$DenyContractId           = "identity_releasetoall_actiontype_deny"
$PostconditionMaxAttempts = 7
$PostconditionPollSeconds = 10
$DiagnosticMaxRecords     = 20
$DiagnosticMaxChars       = 2048
$DiagnosticTraceMaxChars  = 8192
$MaxJwtHeaderSegmentChars = 8 * 1024
$RbacDiagnosticMaxGroups  = 20
$PermissionQueryErrorMaxRecords = 20
$PermissionQueryErrorMaxUtf8Bytes = 32 * 1024
$ExchangeSettingMaxLength = 256
$selectionReleaseStatus = "Requested"
$script:ExchangeOnlineManagementVersion = "unknown"
$script:ExchangeOnlineManagementPath = ""
$script:ExchangeConfigEvidence = @{
    exchange_auth_method = ""
    exchange_auth_method_source = ""
    exchange_organization = ""
    exchange_organization_source = ""
}
$script:RuntimeDiagnosticEvidence = @{}
$script:PassiveExchangeEvidence = $null
$script:ExchangeCleanupEvidence = $null

function Add-RunbookEnvelopeMetadata {
    param([hashtable] $Data)

    $Data.runbook_version = [string] $RunbookVersion
    $Data.runbook_source_revision = [string] $RunbookSourceRevision
    $Data.runbook_build_id = [string] $RunbookBuildId
}

# ---------------------------------------------------------------------------
# Helpers: bounded list output and defensive timestamp serialisation
# ---------------------------------------------------------------------------
function Get-Utf8ByteCount {
    param([string] $Content)
    return [System.Text.Encoding]::UTF8.GetByteCount($Content)
}

function Get-Sha256Hex {
    param([byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return -join (
            $sha256.ComputeHash($Bytes) |
                ForEach-Object { $_.ToString("x2") }
        )
    } finally {
        $sha256.Dispose()
    }
}

function Write-ErrorEnvelope {
    param([hashtable] $Data)
    # One bounded JSON record, never a second error chunk protocol. Diagnostic
    # reports may be larger than normal errors, but cannot exceed one record.
    $Data.message = ConvertTo-RedactedBoundedScalarText -Value $Data.message -MaxChars 8192
    $json = $Data | ConvertTo-Json -Depth 10 -Compress
    if ((Get-Utf8ByteCount -Content $json) -gt 64KB -and $Data.ContainsKey("details")) {
        $Data.Remove("details")
        $Data.diagnostic_details_truncated = $true
        $json = $Data | ConvertTo-Json -Depth 10 -Compress
    }
    Write-Output $json
}

function ConvertTo-OutputTimestamp {
    param([object] $Value, [switch] $ExpiryEvidence)

    if ($null -eq $Value) {
        return ""
    }
    if ($ExpiryEvidence) {
        # Never infer a date, time, or offset for the intake retirement check.
        if ($Value -is [datetime] -and $Value.Kind -ne [DateTimeKind]::Utc) {
            return [datetime]::SpecifyKind($Value, [DateTimeKind]::Unspecified).ToString(
                "o", [System.Globalization.CultureInfo]::InvariantCulture
            )
        }
        if ($Value -isnot [datetime] -and $Value -isnot [datetimeoffset]) {
            return $Value.ToString()
        }
    }
    if ($Value -is [datetime]) {
        return $Value.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $text = $Value.ToString()
    [datetimeoffset] $parsed = [datetimeoffset]::MinValue
    $styles = (
        [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal
    )
    if ([datetimeoffset]::TryParse(
        $text,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed
    )) {
        return $parsed.ToString(
            "o",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    }

    # A future ExchangeOnlineManagement version may return a non-DateTime
    # scalar. Preserve it as text rather than failing the complete list action.
    return $text
}

function ConvertTo-BoundedDiagnosticText {
    param(
        [object[]] $Records,
        [int] $MaxRecords = $DiagnosticMaxRecords,
        [int] $MaxChars = $DiagnosticMaxChars
    )

    if ($MaxRecords -lt 1 -or $MaxChars -lt 1) {
        throw "Diagnostic bounds must be positive."
    }

    $parts = New-Object "System.Collections.Generic.List[string]"
    foreach ($record in @($Records | Select-Object -First $MaxRecords)) {
        if ($null -eq $record) {
            continue
        }
        $text = ([string] $record -replace "\s+", " ").Trim()
        if ($text -and -not $parts.Contains($text)) {
            $parts.Add($text)
        }
    }

    [string] $joined = $parts -join " | "
    if ($joined.Length -le $MaxChars) {
        return $joined
    }

    [string] $suffix = " [truncated]"
    [int] $prefixLength = [System.Math]::Max(
        0,
        $MaxChars - $suffix.Length
    )
    return $joined.Substring(0, $prefixLength) + $suffix
}

function ConvertTo-BoundedScalarText {
    param(
        [object] $Value,
        [int] $MaxChars = $DiagnosticMaxChars
    )

    if ($null -eq $Value) {
        return ""
    }
    return ConvertTo-BoundedDiagnosticText `
        -Records @([string] $Value) `
        -MaxChars $MaxChars
}

function ConvertTo-DiagnosticJson {
    param([object[]] $Records)

    $json = ConvertTo-Json `
        -InputObject ([object[]] $Records) `
        -Depth 8 `
        -Compress
    if ($json.Length -le $DiagnosticTraceMaxChars) {
        return $json
    }

    # Keep valid JSON while progressively reducing the retained head/tail.
    # Never substring JSON: a syntactically broken trace is worse than a
    # smaller but explicit trace.
    for ([int] $edgeCount = 5; $edgeCount -ge 1; $edgeCount--) {
        $bounded = @($Records | Select-Object -First $edgeCount)
        $tailCount = [System.Math]::Min(
            $edgeCount,
            [System.Math]::Max(0, @($Records).Count - $edgeCount)
        )
        $retainedCount = $edgeCount + $tailCount
        if (@($Records).Count -gt $retainedCount) {
            $bounded += @{
                truncated_records = @($Records).Count - $retainedCount
            }
        }
        if ($tailCount -gt 0) {
            $bounded += @($Records | Select-Object -Last $tailCount)
        }
        $boundedJson = ConvertTo-Json `
            -InputObject ([object[]] $bounded) `
            -Depth 8 `
            -Compress
        if ($boundedJson.Length -le $DiagnosticTraceMaxChars) {
            return $boundedJson
        }
    }
    return (ConvertTo-Json `
        -InputObject ([object[]] @(@{
            truncated_records = @($Records).Count
            reason = "trace_exceeded_safe_output_bound"
        })) `
        -Compress)
}

function ConvertFrom-Base64UrlText {
    param([string] $Value)

    if (-not $Value) {
        throw "Base64url input is empty."
    }
    $padded = $Value.Replace("-", "+").Replace("_", "/")
    switch ($padded.Length % 4) {
        0 { }
        2 { $padded += "==" }
        3 { $padded += "=" }
        default { throw "Base64url input has invalid length." }
    }
    return [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String($padded)
    )
}

function Test-JwtCompactSerialization {
    param([string] $Value)

    if (-not $Value) {
        return $false
    }
    $segments = @($Value.Split("."))
    if ($segments.Count -ne 3) {
        return $false
    }
    if ($segments[0].Length -gt $MaxJwtHeaderSegmentChars) {
        return $true
    }
    try {
        $header = ConvertFrom-Base64UrlText -Value $segments[0] |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $false
    }
    if ($null -eq $header) {
        return $false
    }
    $algorithmProperty = $header.PSObject.Properties["alg"]
    return (
        $null -ne $algorithmProperty -and
        -not [string]::IsNullOrWhiteSpace([string] $algorithmProperty.Value)
    )
}

function ConvertTo-SecretRedactedText {
    param([AllowEmptyString()][string] $Text)

    if ($null -eq $Text) {
        return ""
    }
    $safe = $Text
    # An object-member prefix and quoted key/colon select JSON: backticks are literal,
    # only backslashes escape characters. Handle this before native diagnostics
    # so a literal backtick cannot hide an escaped quote or consume the close.
    $safe = [regex]::Replace(
        $safe,
        '(?i)((?:\{|,)\s*"(?:authorization|set-cookie|cookie)"\s*:\s*")(?:\\[^\r\n]|[^"\\\r\n]|\\(?=[\r\n]|$))*("|(?=[\r\n]|$))',
        '$1[redacted]$2'
    )
    # Native headers support doubled quotes and backslash/backtick escapes.
    # Unterminated values end at the physical line boundary or input end;
    # subsequent diagnostic lines remain readable.
    foreach ($delimiter in @('"', "'")) {
        $pattern = (
            '(?i)(["'']?(?:authorization|set-cookie|cookie)["'']?\s*[:=]\s*' +
            $delimiter + ')(?:[\\`][^\r\n]|' + $delimiter + $delimiter +
            '|[^' + $delimiter + '\\`\r\n]|[\\`](?=[\r\n]|$))*(' +
            $delimiter + '|(?=[\r\n]|$))'
        )
        $safe = [regex]::Replace($safe, $pattern, '$1[redacted]$2')
    }
    $safe = [regex]::Replace(
        $safe,
        '(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+',
        '$1[redacted]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)(authorization\s*[:=]\s*(?!bearer\b)(?:basic\s+)?)(?!["''\s])[^\s,;]+',
        '$1[redacted]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?im)^(\s*(?:set-cookie|cookie)\s*:\s*)[^\r\n]*',
        '$1[redacted]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)(["'']?(?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|refresh[_ -]?token|client[_ -]?assertion|password|pwd|x-identity-header|identity_header)["'']?\s*[:=]\s*")[^"\r\n]*(")',
        '$1[redacted]$2'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)(["'']?(?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|refresh[_ -]?token|client[_ -]?assertion|password|pwd|x-identity-header|identity_header)["'']?\s*[:=]\s*'')[^''\r\n]*('')',
        '$1[redacted]$2'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)((?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|refresh[_ -]?token|client[_ -]?assertion|password|pwd|x-identity-header|identity_header)\s*[:=]\s*)(?:bearer\s+)?(?!["''])[^\s,;&]+',
        '$1[redacted]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)([?&](?:token|sig|signature|code|client_secret|access_token|refresh_token|client_assertion|password|pwd)=)[^&\s"'']+',
        '$1[redacted]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?!\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])',
        {
            param([System.Text.RegularExpressions.Match] $Match)
            if (Test-JwtCompactSerialization -Value $Match.Value) {
                return '[redacted]'
            }
            return $Match.Value
        }
    )
    return $safe
}

function Get-OriginalErrorMessage {
    param([object] $ErrorRecord)

    $message = ""
    if ($null -ne $ErrorRecord) {
        # ErrorRecord.ToString() is the exact message PowerShell presents to
        # the operator. It also honours ErrorDetails.Message when Microsoft
        # supplies a service-side message that differs from Exception.Message.
        $message = [string] $ErrorRecord
    }
    if (-not $message -and $null -ne $ErrorRecord.Exception) {
        $message = [string] $ErrorRecord.Exception.Message
    }
    return ConvertTo-SecretRedactedText -Text $message
}

function Join-OriginalRecordText {
    param([object[]] $Records)

    $messages = New-Object "System.Collections.Generic.List[string]"
    foreach ($record in @($Records)) {
        if ($null -eq $record) {
            continue
        }
        $message = Get-OriginalErrorMessage -ErrorRecord $record
        # ErrorVariable can expose the same ErrorRecord more than once when a
        # terminating error also crosses the catch boundary. Suppress only an
        # exactly identical transport duplicate; never rewrite the text.
        if (-not $messages.Contains($message)) {
            $messages.Add($message)
        }
    }
    return ($messages -join "`n")
}

function ConvertTo-CanonicalQuarantineIdentity {
    param([string] $Value)

    if (-not $Value -or $Value.Length -gt 73) {
        return ""
    }
    $parts = @($Value -split '\\')
    if ($parts.Count -ne 2) {
        return ""
    }
    [guid] $first = [guid]::Empty
    [guid] $second = [guid]::Empty
    if (
        -not [guid]::TryParseExact($parts[0], "D", [ref] $first) -or
        -not [guid]::TryParseExact($parts[1], "D", [ref] $second)
    ) {
        return ""
    }
    return "$($first.ToString('D'))\$($second.ToString('D'))"
}

function Test-QuarantineIdentityValue {
    param([string] $Value)

    return [bool] (ConvertTo-CanonicalQuarantineIdentity -Value $Value)
}

function Test-QuarantineIdentityMatch {
    param(
        [string] $Left,
        [string] $Right
    )

    $canonicalLeft = ConvertTo-CanonicalQuarantineIdentity -Value $Left
    $canonicalRight = ConvertTo-CanonicalQuarantineIdentity -Value $Right
    return (
        [bool] $canonicalLeft -and
        [bool] $canonicalRight -and
        [string]::Equals(
            $canonicalLeft,
            $canonicalRight,
            [System.StringComparison]::Ordinal
        )
    )
}

function ConvertTo-SafePermissionError {
    param([object] $ErrorRecord)

    return Get-OriginalErrorMessage -ErrorRecord $ErrorRecord
}

function Add-PermissionQueryError {
    param(
        [System.Collections.Generic.List[object]] $Errors,
        [string] $Query,
        [object] $ErrorRecord,
        [string[]] $RedactedValues = @()
    )

    $exceptionType = ""
    if ($null -ne $ErrorRecord -and $ErrorRecord.Exception) {
        $exceptionType = [string] $ErrorRecord.Exception.GetType().FullName
    }
    $errorText = ConvertTo-SafePermissionError -ErrorRecord $ErrorRecord
    foreach ($redactedValue in @($RedactedValues)) {
        if ($redactedValue) {
            $errorText = $errorText.Replace(
                [string] $redactedValue,
                "[redacted-role-group]",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
    }
    $Errors.Add(@{
        query = ConvertTo-BoundedScalarText -Value $Query -MaxChars 128
        error = $errorText
        exception_type = ConvertTo-BoundedScalarText `
            -Value $exceptionType `
            -MaxChars 256
    })
}

function ConvertTo-BoundedPermissionQueryErrorRecord {
    param([object] $Record)

    $bounded = @{
        query = ConvertTo-BoundedScalarText `
            -Value $Record.query `
            -MaxChars 128
        error = ConvertTo-BoundedScalarText `
            -Value (ConvertTo-SecretRedactedText -Text ([string] $Record.error)) `
            -MaxChars $DiagnosticMaxChars
        exception_type = ConvertTo-BoundedScalarText `
            -Value $Record.exception_type `
            -MaxChars 256
    }
    if ($Record.cmdlet) {
        $bounded.cmdlet = ConvertTo-BoundedScalarText `
            -Value $Record.cmdlet `
            -MaxChars 128
    }
    return $bounded
}

function ConvertTo-PermissionQueryErrorEvidence {
    param(
        [object[]] $Records,
        [int] $MaxRecords = $PermissionQueryErrorMaxRecords,
        [int] $MaxUtf8Bytes = $PermissionQueryErrorMaxUtf8Bytes
    )

    if ($MaxRecords -lt 1 -or $MaxUtf8Bytes -lt 2) {
        throw "Permission-query error bounds must be positive."
    }

    $allRecords = [object[]] @($Records)
    $retained = New-Object "System.Collections.Generic.List[object]"
    foreach ($record in $allRecords) {
        if ($retained.Count -ge $MaxRecords) {
            break
        }
        $boundedRecord = ConvertTo-BoundedPermissionQueryErrorRecord `
            -Record $record
        [object[]] $candidate = @($retained.ToArray()) + @($boundedRecord)
        $candidateJson = ConvertTo-Json `
            -InputObject $candidate `
            -Depth 8 `
            -Compress
        if ((Get-Utf8ByteCount -Content $candidateJson) -gt $MaxUtf8Bytes) {
            break
        }
        $retained.Add($boundedRecord)
    }
    [object[]] $retainedRecords = @($retained.ToArray())
    $droppedCount = $allRecords.Count - $retainedRecords.Count
    return @{
        TotalCount = $allRecords.Count
        RetainedCount = $retainedRecords.Count
        DroppedCount = $droppedCount
        Truncated = ($droppedCount -gt 0)
        Records = $retainedRecords
        Json = ConvertTo-Json `
            -InputObject $retainedRecords `
            -Depth 8 `
            -Compress
    }
}

function Set-PermissionQueryErrorEvidence {
    param(
        [hashtable] $Evidence,
        [System.Collections.Generic.List[object]] $Errors
    )

    $permissionErrorEvidence = ConvertTo-PermissionQueryErrorEvidence `
        -Records ([object[]] @($Errors | ForEach-Object { $_ }))
    $Evidence.permission_query_error_count = (
        [int] $permissionErrorEvidence.TotalCount
    )
    $Evidence.permission_query_error_retained_count = (
        [int] $permissionErrorEvidence.RetainedCount
    )
    $Evidence.permission_query_error_dropped_count = (
        [int] $permissionErrorEvidence.DroppedCount
    )
    $Evidence.permission_query_errors_truncated = (
        [bool] $permissionErrorEvidence.Truncated
    )
    $Evidence.permission_query_errors = (
        [object[]] @($permissionErrorEvidence.Records)
    )
}

function Get-PermissionEvidenceErrorMessage {
    param(
        [hashtable] $Evidence,
        [string] $Fallback
    )

    $messages = New-Object "System.Collections.Generic.List[string]"
    foreach ($record in @($Evidence.permission_query_errors)) {
        if ($null -eq $record) {
            continue
        }
        $message = ConvertTo-SecretRedactedText -Text ([string] $record.error)
        if ($message) {
            $messages.Add($message)
        }
    }
    if ($messages.Count -gt 0) {
        return ($messages -join "`n")
    }
    return $Fallback
}

function Get-ManagedIdentityClaimEvidence {
    param(
        [System.Collections.Generic.List[object]] $Errors
    )

    $evidence = @{
        managed_identity_claims_status = "unavailable"
        managed_identity_app_id = ""
        managed_identity_object_id = ""
    }
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
        Add-PermissionQueryError `
            -Errors $Errors `
            -Query "managed_identity_claims" `
            -ErrorRecord "Azure Automation identity endpoint variables are unavailable."
        return $evidence
    }

    try {
        $separator = if ($env:IDENTITY_ENDPOINT.Contains("?")) {
            "&"
        } else {
            "?"
        }
        $resource = [uri]::EscapeDataString(
            "https://outlook.office365.com"
        )
        $identityUri = (
            "$($env:IDENTITY_ENDPOINT)$separator" +
            "resource=$resource&api-version=2019-08-01"
        )
        $headers = @{
            "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER
            "Metadata" = "True"
        }
        $tokenResponse = Invoke-RestMethod `
            -Method Get `
            -Uri $identityUri `
            -Headers $headers `
            -ErrorAction Stop
        $accessToken = [string] $tokenResponse.access_token
        $segments = @($accessToken.Split("."))
        if ($segments.Count -ne 3) {
            throw "Managed identity endpoint returned a malformed JWT."
        }
        $claimsJson = ConvertFrom-Base64UrlText -Value $segments[1]
        $claims = $claimsJson | ConvertFrom-Json -ErrorAction Stop

        $appId = [string] $claims.appid
        if (-not $appId) {
            $appId = [string] $claims.azp
        }
        $objectId = [string] $claims.oid
        [guid] $parsedAppId = [guid]::Empty
        [guid] $parsedObjectId = [guid]::Empty
        if ([guid]::TryParse($appId, [ref] $parsedAppId)) {
            $evidence.managed_identity_app_id = $parsedAppId.ToString()
        }
        if ([guid]::TryParse($objectId, [ref] $parsedObjectId)) {
            $evidence.managed_identity_object_id = (
                $parsedObjectId.ToString()
            )
        }
        if (
            $evidence.managed_identity_app_id -and
            $evidence.managed_identity_object_id
        ) {
            $evidence.managed_identity_claims_status = "resolved"
        } else {
            $evidence.managed_identity_claims_status = "incomplete"
            Add-PermissionQueryError `
                -Errors $Errors `
                -Query "managed_identity_claims" `
                -ErrorRecord "Managed identity token did not contain valid appid/azp and oid GUID claims."
        }
    } catch {
        Add-PermissionQueryError `
            -Errors $Errors `
            -Query "managed_identity_claims" `
            -ErrorRecord $_
    } finally {
        # The token and decoded claims are deliberately never returned.
        $accessToken = $null
        $tokenResponse = $null
        $claims = $null
        $claimsJson = $null
    }
    return $evidence
}

function Get-RoleNameFromEntry {
    param([object] $Entry)

    foreach ($propertyName in @("Role", "RoleName")) {
        $property = $Entry.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $property.Value) {
            return [string] $property.Value
        }
    }
    $identityProperty = $Entry.PSObject.Properties["Identity"]
    if ($null -ne $identityProperty -and $identityProperty.Value) {
        return ([string] $identityProperty.Value).Split("\")[0]
    }
    return ""
}

function Invoke-ManagementRoleContractQuery {
    param(
        [string] $QueryName,
        [string] $CmdletName,
        [string[]] $Parameters,
        [System.Collections.Generic.List[object]] $Errors
    )

    $roleNames = @()
    try {
        if (@($Parameters).Count -gt 0) {
            $roles = @(
                Get-ManagementRole `
                    -Cmdlet $CmdletName `
                    -CmdletParameters $Parameters `
                    -ErrorAction Stop
            )
        } else {
            $roles = @(
                Get-ManagementRole `
                    -Cmdlet $CmdletName `
                    -ErrorAction Stop
            )
        }
        $roleNames = @(
            $roles |
                ForEach-Object { [string] $_.Name } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    } catch {
        Add-PermissionQueryError `
            -Errors $Errors `
            -Query "$QueryName.management_roles" `
            -ErrorRecord $_
    }

    if (@($roleNames).Count -eq 0) {
        try {
            if (@($Parameters).Count -gt 0) {
                $entries = @(
                    Get-ManagementRoleEntry `
                        -Identity "*\$CmdletName" `
                        -Parameters $Parameters `
                        -ErrorAction Stop
                )
            } else {
                $entries = @(
                    Get-ManagementRoleEntry `
                        -Identity "*\$CmdletName" `
                        -ErrorAction Stop
                )
            }
            $roleNames = @(
                $entries |
                    ForEach-Object {
                        Get-RoleNameFromEntry -Entry $_
                    } |
                    Where-Object { $_ } |
                    Sort-Object -Unique
            )
        } catch {
            Add-PermissionQueryError `
                -Errors $Errors `
                -Query "$QueryName.management_role_entries" `
                -ErrorRecord $_
        }
    }

    return ConvertTo-BoundedDiagnosticText `
        -Records @($roleNames) `
        -MaxChars $DiagnosticMaxChars
}

function Get-ObjectIdentityGuids {
    param([object] $InputObject)

    if ($null -eq $InputObject) {
        return @()
    }
    $values = New-Object "System.Collections.Generic.List[string]"
    foreach ($propertyName in @(
        "AppId",
        "ObjectId",
        "ExternalDirectoryObjectId",
        "Guid",
        "Id",
        "RoleAssignee"
    )) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $property.Value) {
            $value = ([string] $property.Value).Trim()
            [guid] $parsed = [guid]::Empty
            if ([guid]::TryParse($value, [ref] $parsed)) {
                $canonical = $parsed.ToString("D")
                if (-not $values.Contains($canonical)) {
                    $values.Add($canonical)
                }
            }
        }
    }
    return @($values)
}

function Test-ObjectIdentityMatch {
    param(
        [object] $InputObject,
        [string[]] $ExpectedValues
    )

    foreach ($actualValue in @(Get-ObjectIdentityGuids $InputObject)) {
        foreach ($expectedValue in @($ExpectedValues)) {
            [guid] $parsedExpected = [guid]::Empty
            if (
                $expectedValue -and
                [guid]::TryParse(
                    [string] $expectedValue,
                    [ref] $parsedExpected
                ) -and
                [string]::Equals(
                    $actualValue,
                    $parsedExpected.ToString("D"),
                    [System.StringComparison]::Ordinal
                )
            ) {
                return $true
            }
        }
    }
    return $false
}

function Get-QuarantineRbacDiagnosticEvidence {
    param(
        [switch] $IncludeTenantRbac
    )

    $errors = New-Object "System.Collections.Generic.List[object]"
    [string[]] $requiredCmdlets = @(
        "Get-ManagementRole",
        "Get-ManagementRoleEntry",
        "Get-ServicePrincipal",
        "Get-ManagementRoleAssignment",
        "Get-RoleGroupMember"
    )
    $availableCmdlets = New-Object "System.Collections.Generic.List[string]"
    $missingCmdlets = New-Object "System.Collections.Generic.List[string]"
    foreach ($cmdletName in $requiredCmdlets) {
        $command = Get-Command `
            -Name $cmdletName `
            -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $availableCmdlets.Add($cmdletName)
        } else {
            $missingCmdlets.Add($cmdletName)
        }
    }

    $evidence = @{
        permission_queries_read_only = $true
        rbac_included = [bool] $IncludeTenantRbac
        rbac_diagnostics_status = "not_evaluated"
        rbac_diagnostics_reason = ""
        rbac_empty_contracts = [string[]] @()
        rbac_required_cmdlets = [string[]] @($requiredCmdlets)
        rbac_available_cmdlets = [string[]] @($availableCmdlets)
        missing_cmdlets = [string[]] @($missingCmdlets)
        missing_cmdlet_count = [int] $missingCmdlets.Count
        read_roles = ""
        export_roles = ""
        release_to_all_roles = ""
        release_deny_roles = ""
        quarantine_role_present = $null
        quarantine_role_groups = ""
        matched_quarantine_role_groups = ""
        quarantine_role_group_total_count = 0
        quarantine_role_group_inspected_count = 0
        quarantine_role_group_inspection_truncated = $false
        service_principal_registered = $null
        registered_service_principal_identity = ""
        registered_service_principal_app_id = ""
        registered_service_principal_object_id = ""
        role_group_membership_evaluated = $null
        quarantine_group_membership_confirmed = $null
        quarantine_administrator_membership_confirmed = $null
        role_assignment_matches_identity = $null
        permission_query_error_count = 0
        permission_query_error_retained_count = 0
        permission_query_error_dropped_count = 0
        permission_query_errors_truncated = $false
        permission_query_errors = [object[]] @()
    }

    if (-not $IncludeTenantRbac.IsPresent) {
        $evidence.rbac_diagnostics_status = "not_requested"
        $evidence.rbac_diagnostics_reason = "tenant_rbac_opt_in_required"
        return $evidence
    }

    $claimEvidence = Get-ManagedIdentityClaimEvidence -Errors $errors
    foreach ($key in $claimEvidence.Keys) {
        $evidence[$key] = $claimEvidence[$key]
    }

    if ($missingCmdlets.Count -gt 0) {
        $evidence.rbac_diagnostics_reason = (
            "required_cmdlets_unavailable_in_current_exchange_session"
        )
        foreach ($cmdletName in @($missingCmdlets)) {
            $errors.Add(@{
                query = "required_cmdlet.$cmdletName"
                cmdlet = $cmdletName
                error = (
                    "Required read-only Exchange RBAC diagnostic cmdlet " +
                    "'$cmdletName' is not available in the current " +
                    "Exchange Online session. Tenant RBAC was not evaluated."
                )
                exception_type = (
                    "System.Management.Automation.CommandNotFoundException"
                )
            })
        }
        Set-PermissionQueryErrorEvidence `
            -Evidence $evidence `
            -Errors $errors
        return $evidence
    }

    $evidence.read_roles = Invoke-ManagementRoleContractQuery `
        -QueryName "read" `
        -CmdletName "Get-QuarantineMessage" `
        -Parameters @() `
        -Errors $errors
    $evidence.export_roles = Invoke-ManagementRoleContractQuery `
        -QueryName "export" `
        -CmdletName "Export-QuarantineMessage" `
        -Parameters @("Identity") `
        -Errors $errors
    $evidence.release_to_all_roles = (
        Invoke-ManagementRoleContractQuery `
            -QueryName "release_to_all" `
            -CmdletName "Release-QuarantineMessage" `
            -Parameters @("Identity", "ReleaseToAll") `
            -Errors $errors
    )
    $evidence.release_deny_roles = Invoke-ManagementRoleContractQuery `
        -QueryName "release_deny" `
        -CmdletName "Release-QuarantineMessage" `
        -Parameters @("Identity", "ReleaseToAll", "ActionType") `
        -Errors $errors

    try {
        $quarantineRole = @(
            Get-ManagementRole `
                -Identity "Quarantine" `
                -ErrorAction Stop
        )
        $evidence.quarantine_role_present = (
            @($quarantineRole).Count -gt 0
        )
    } catch {
        Add-PermissionQueryError `
            -Errors $errors `
            -Query "quarantine_role" `
            -ErrorRecord $_
    }

    $expectedIdentityValues = @(
        $evidence.managed_identity_app_id,
        $evidence.managed_identity_object_id
    ) | Where-Object { $_ }
    $registeredServicePrincipal = $null
    $servicePrincipalLookupError = $null
    [bool] $servicePrincipalLookupSucceeded = $false
    [bool] $servicePrincipalLookupHadError = $false
    if (@($expectedIdentityValues).Count -gt 0) {
        foreach ($candidate in @($expectedIdentityValues)) {
            try {
                $candidateResults = @(
                    Get-ServicePrincipal `
                        -Identity $candidate `
                        -ErrorAction Stop
                )
                $servicePrincipalLookupSucceeded = $true
                $registeredServicePrincipal = @(
                    $candidateResults |
                        Where-Object {
                            Test-ObjectIdentityMatch `
                                -InputObject $_ `
                                -ExpectedValues $expectedIdentityValues
                        }
                ) | Select-Object -First 1
                if ($null -ne $registeredServicePrincipal) {
                    break
                }
            } catch {
                # Different Exchange builds accept either app ID or object ID.
                # Do not mark a successful alternate lookup as partial.
                $servicePrincipalLookupError = $_
                $servicePrincipalLookupHadError = $true
            }
        }
        if (
            $null -eq $registeredServicePrincipal -and
            $null -ne $servicePrincipalLookupError
        ) {
            Add-PermissionQueryError `
                -Errors $errors `
                -Query "exchange_service_principal" `
                -ErrorRecord $servicePrincipalLookupError
        }
    }

    if ($null -ne $registeredServicePrincipal) {
        $evidence.service_principal_registered = $true
        $evidence.registered_service_principal_identity = (
            ConvertTo-BoundedScalarText `
                -Value $registeredServicePrincipal.Identity `
                -MaxChars 512
        )
        $evidence.registered_service_principal_app_id = (
            ConvertTo-BoundedScalarText `
                -Value $registeredServicePrincipal.AppId `
                -MaxChars 128
        )
        $registeredServicePrincipalObjectId = @(
            $registeredServicePrincipal.ObjectId,
            $registeredServicePrincipal.ExternalDirectoryObjectId,
            $registeredServicePrincipal.Guid
        ) | Where-Object { $_ } | Select-Object -First 1
        $evidence.registered_service_principal_object_id = (
            ConvertTo-BoundedScalarText `
                -Value $registeredServicePrincipalObjectId `
                -MaxChars 128
        )
        $expectedIdentityValues = @(
            $expectedIdentityValues +
            (Get-ObjectIdentityGuids $registeredServicePrincipal)
        ) | Where-Object { $_ } | Sort-Object -Unique
    } elseif (
        $servicePrincipalLookupSucceeded -and
        -not $servicePrincipalLookupHadError
    ) {
        $evidence.service_principal_registered = $false
    }

    $quarantineRoleGroups = @()
    [bool] $directRoleAssignmentMatchesIdentity = $false
    [bool] $roleAssignmentQuerySucceeded = $false
    try {
        $assignments = @(
            Get-ManagementRoleAssignment `
                -Role "Quarantine" `
                -Delegating:$false `
                -ErrorAction Stop
        )
        $roleAssignmentQuerySucceeded = $true
        $roleGroupNames = New-Object "System.Collections.Generic.List[string]"
        foreach ($assignment in @($assignments)) {
            $roleAssigneeName = (
                [string] $assignment.RoleAssigneeName
            ).Trim()
            $roleAssigneeType = (
                [string] $assignment.RoleAssigneeType
            ).Trim()
            if (
                -not $roleAssigneeType -or
                $roleAssigneeType -match "(?i)RoleGroup$"
            ) {
                if (
                    $roleAssigneeName -and
                    -not $roleGroupNames.Contains($roleAssigneeName)
                ) {
                    $roleGroupNames.Add($roleAssigneeName)
                }
                continue
            }
            if (
                @($expectedIdentityValues).Count -gt 0 -and
                (Test-ObjectIdentityMatch `
                    -InputObject $assignment `
                    -ExpectedValues $expectedIdentityValues)
            ) {
                $directRoleAssignmentMatchesIdentity = $true
            }
        }
        $allQuarantineRoleGroups = @(
            $roleGroupNames |
                Sort-Object -Unique
        )
        $quarantineRoleGroups = @(
            $allQuarantineRoleGroups |
                Select-Object -First $RbacDiagnosticMaxGroups
        )
        $evidence.quarantine_role_group_total_count = [int] (
            @($allQuarantineRoleGroups).Count
        )
        $evidence.quarantine_role_group_inspected_count = [int] (
            @($quarantineRoleGroups).Count
        )
        $evidence.quarantine_role_group_inspection_truncated = [bool] (
            @($allQuarantineRoleGroups).Count -gt
            @($quarantineRoleGroups).Count
        )
    } catch {
        Add-PermissionQueryError `
            -Errors $errors `
            -Query "quarantine_role_assignments" `
            -ErrorRecord $_
    }
    # Inspect only role groups actually returned by the Exchange RBAC
    # assignment query. "Quarantine Administrator" is an Email &
    # collaboration role group and is not guaranteed to exist on the
    # Exchange Online endpoint used by this runbook.
    $groupsToInspect = @($quarantineRoleGroups)
    $matchedGroups = New-Object "System.Collections.Generic.List[string]"
    [bool] $roleGroupMembershipQueryHadError = $false
    if ($roleAssignmentQuerySucceeded) {
        $evidence.role_group_membership_evaluated = $false
    }
    for (
        [int] $groupIndex = 0;
        $groupIndex -lt @($groupsToInspect).Count;
        $groupIndex++
    ) {
        $groupName = [string] $groupsToInspect[$groupIndex]
        try {
            $members = @(
                Get-RoleGroupMember `
                    -Identity $groupName `
                    -ErrorAction Stop
            )
            $evidence.role_group_membership_evaluated = $true
            if (@($expectedIdentityValues).Count -gt 0) {
                $matchedMember = @(
                    $members |
                        Where-Object {
                            Test-ObjectIdentityMatch `
                                -InputObject $_ `
                                -ExpectedValues $expectedIdentityValues
                        }
                ) | Select-Object -First 1
                if (
                    $null -ne $matchedMember -and
                    -not $matchedGroups.Contains($groupName)
                ) {
                    $matchedGroups.Add($groupName)
                }
            }
        } catch {
            $roleGroupMembershipQueryHadError = $true
            Add-PermissionQueryError `
                -Errors $errors `
                -Query "role_group_members[$groupIndex]" `
                -ErrorRecord $_ `
                -RedactedValues @($groupName)
        }
    }

    $matchedGroupText = (
        ConvertTo-BoundedDiagnosticText `
            -Records @($matchedGroups) `
            -MaxChars $DiagnosticMaxChars
    )
    # Both public fields intentionally expose only GUID-confirmed matches.
    # The broader assignment list remains ephemeral inside this runbook.
    $evidence.quarantine_role_groups = $matchedGroupText
    $evidence.matched_quarantine_role_groups = $matchedGroupText
    if ($matchedGroups.Count -gt 0) {
        $evidence.quarantine_group_membership_confirmed = $true
    } elseif (
        $roleAssignmentQuerySucceeded -and
        @($expectedIdentityValues).Count -gt 0 -and
        -not $roleGroupMembershipQueryHadError -and
        -not $evidence.quarantine_role_group_inspection_truncated
    ) {
        $evidence.quarantine_group_membership_confirmed = $false
    }
    if ($directRoleAssignmentMatchesIdentity -or $matchedGroups.Count -gt 0) {
        $evidence.role_assignment_matches_identity = $true
    } elseif (
        $roleAssignmentQuerySucceeded -and
        @($expectedIdentityValues).Count -gt 0 -and
        -not $roleGroupMembershipQueryHadError -and
        -not $evidence.quarantine_role_group_inspection_truncated
    ) {
        $evidence.role_assignment_matches_identity = $false
    }
    if (@($matchedGroups) -contains "Quarantine Administrator") {
        $evidence.quarantine_administrator_membership_confirmed = $true
    } elseif (
        $roleAssignmentQuerySucceeded -and
        @($expectedIdentityValues).Count -gt 0 -and
        -not $roleGroupMembershipQueryHadError -and
        -not $evidence.quarantine_role_group_inspection_truncated
    ) {
        $evidence.quarantine_administrator_membership_confirmed = $false
    }

    Set-PermissionQueryErrorEvidence `
        -Evidence $evidence `
        -Errors $errors
    if ($errors.Count -gt 0) {
        $evidence.rbac_diagnostics_status = "partial"
        $evidence.rbac_diagnostics_reason = "one_or_more_permission_queries_failed"
        return $evidence
    }

    $emptyContracts = New-Object "System.Collections.Generic.List[string]"
    foreach ($contractName in @(
        "read_roles",
        "export_roles",
        "release_to_all_roles",
        "release_deny_roles"
    )) {
        if (-not [string] $evidence[$contractName]) {
            $emptyContracts.Add($contractName)
        }
    }
    if ($evidence.quarantine_role_present -ne $true) {
        $emptyContracts.Add("quarantine_role")
    }
    $evidence.rbac_empty_contracts = [string[]] @($emptyContracts)
    if ($evidence.quarantine_role_group_inspection_truncated) {
        $evidence.rbac_diagnostics_status = "partial"
        $evidence.rbac_diagnostics_reason = "role_group_inspection_truncated"
    } elseif ($emptyContracts.Count -gt 0) {
        $evidence.rbac_diagnostics_status = "partial"
        $evidence.rbac_diagnostics_reason = "no_role_contracts_visible"
    } elseif (
        $evidence.managed_identity_claims_status -in @(
            "resolved",
            "not_applicable"
        )
    ) {
        $evidence.rbac_diagnostics_status = "complete"
    }
    return $evidence
}

function Add-RbacDiagnosticEvidence {
    param(
        [hashtable] $Data,
        [hashtable] $Evidence
    )

    foreach ($key in $Evidence.Keys) {
        $Data[$key] = $Evidence[$key]
    }
}

function Resolve-ReleaseCommandMetadataTarget {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Command
    )

    $current = $Command
    $seenAliases = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    for ($depth = 0; $depth -lt 8; $depth++) {
        if ([string] $current.CommandType -ne "Alias") {
            break
        }
        $aliasKey = "$([string] $current.Name)|$([string] $current.Definition)"
        if (-not $seenAliases.Add($aliasKey)) {
            throw "Release-QuarantineMessage alias resolution is cyclic."
        }
        $resolved = $current.ResolvedCommand
        if ($null -eq $resolved) {
            throw "Release-QuarantineMessage alias has no resolvable target."
        }
        $current = $resolved
    }
    if ([string] $current.CommandType -eq "Alias") {
        throw "Release-QuarantineMessage alias resolution exceeded 8 hops."
    }
    if (
        [string] $current.CommandType -notin @(
            "Function",
            "Filter",
            "Cmdlet"
        )
    ) {
        throw (
            "Release-QuarantineMessage resolves to unsupported command type " +
            "'$([string] $current.CommandType)'."
        )
    }
    return $current
}

function Get-ReleaseCommandMetadataEvidence {
    $evidence = @{
        cmdlet_name                   = "Release-QuarantineMessage"
        cmdlet_command_type           = ""
        cmdlet_module_name            = ""
        cmdlet_module_version         = ""
        cmdlet_default_parameter_set  = ""
        cmdlet_parameter_sets         = ""
        cmdlet_metadata_error         = ""
    }

    try {
        $loadedCommand = Get-Command `
            -Name "Release-QuarantineMessage" `
            -ErrorAction Stop
        $command = Resolve-ReleaseCommandMetadataTarget -Command $loadedCommand
        $evidence.cmdlet_command_type = if (
            [string] $loadedCommand.CommandType -eq "Alias"
        ) {
            "Alias->$([string] $command.CommandType)"
        } else {
            [string] $command.CommandType
        }
        $evidence.cmdlet_module_name = [string] $command.ModuleName
        $evidence.cmdlet_default_parameter_set = (
            [string] $command.DefaultParameterSet
        )
        if ($command.Module -and $command.Module.Version) {
            $evidence.cmdlet_module_version = (
                $command.Module.Version.ToString()
            )
        }

        $setDescriptions = New-Object "System.Collections.Generic.List[string]"
        foreach ($parameterSet in @(
            $command.ParameterSets | Sort-Object -Property Name
        )) {
            $parameterDescriptions = New-Object `
                "System.Collections.Generic.List[string]"
            foreach ($parameterName in @(
                "Identity",
                "Identities",
                "ActionType",
                "ReleaseToAll"
            )) {
                $parameter = @(
                    $parameterSet.Parameters |
                        Where-Object { $_.Name -eq $parameterName }
                ) | Select-Object -First 1
                if ($null -ne $parameter) {
                    $requirement = if ($parameter.IsMandatory) {
                        "required"
                    } else {
                        "optional"
                    }
                    $parameterDescriptions.Add(
                        "$parameterName=$requirement"
                    )
                }
            }
            $setDescriptions.Add(
                "$($parameterSet.Name)[$($parameterDescriptions -join ',')]"
            )
        }
        $evidence.cmdlet_parameter_sets = (
            ConvertTo-BoundedDiagnosticText `
                -Records @($setDescriptions) `
                -MaxChars $DiagnosticMaxChars
        )
    } catch {
        $evidence.cmdlet_metadata_error = (
            Get-OriginalErrorMessage -ErrorRecord $_
        )
    }
    return $evidence
}

function Get-ReleaseProxyDiagnosticEvidence {
    # Static inspection only: never invoke the proxy, helpers or captured code.
    $report = @{
        schema = "exchange_proxy_v1"
        status = "unavailable"
        request_capture = $false
        action_type = @{}
        commands = @()
        error = ""
    }
    try {
        $command = Resolve-ReleaseCommandMetadataTarget -Command (
            Get-Command -Name "Release-QuarantineMessage" -ErrorAction Stop
        )
        $parameter = $command.Parameters["ActionType"]
        if ($null -ne $parameter) {
            $type = $parameter.ParameterType
            $report.action_type = @{
                type = [string] $type.FullName
                is_enum = [bool] $type.IsEnum
                enum_values = @()
                validate_set = @()
            }
            if ($type.IsEnum) {
                $report.action_type.enum_values = @(
                    [Enum]::GetValues($type) | ForEach-Object {
                        @{ name = $_.ToString(); value = $_.ToString("D") }
                    }
                )
            }
            $report.action_type.validate_set = @(
                $parameter.Attributes | Where-Object {
                    $_ -is [System.Management.Automation.ValidateSetAttribute]
                } | ForEach-Object { $_.ValidValues }
            )
        }
        $report.status = "collected"
        foreach ($name in @(
            "Release-QuarantineMessage", "Execute-Command", "CheckRetryAndHandleWaitTime"
        )) {
            $entry = @{ name = $name; status = "unavailable"; error = "" }
            try {
                $target = if ($name -eq "Release-QuarantineMessage") {
                    $command
                } elseif ($null -ne $command.Module) {
                    # Resolve private helpers in the SAME module, not another import.
                    & $command.Module {
                        param($HelperName)
                        Get-Command -Name $HelperName -CommandType Function -ErrorAction Stop
                    } $name
                } else { $null }
                if ($name -ne "Release-QuarantineMessage" -and $null -ne $target -and
                    $target.Module -ne $command.Module) {
                    $target = $null
                }
                if ($null -eq $target) {
                    $entry.error = "No matching helper in the loaded command module."
                } else {
                    $entry.command_type = [string] $target.CommandType
                    $entry.module_name = [string] $target.ModuleName
                    $entry.module_path = [string] $target.Module.Path
                    $entry.module_version = [string] $target.Module.Version
                    $entry.default_parameter_set = [string] $target.DefaultParameterSet
                    $source = if ($null -ne $target.ScriptBlock) {
                        [string] $target.ScriptBlock.ToString()
                    } else { "" }
                    $entry.source_sha256 = Get-Sha256Hex -Bytes (
                        [System.Text.Encoding]::UTF8.GetBytes($source)
                    )
                    $safe = ConvertTo-SecretRedactedText -Text $source
                    $entry.source_chars = $safe.Length
                    $entry.source_truncated = $safe.Length -gt 32768
                    $entry.source = $safe.Substring(0, [Math]::Min(32768, $safe.Length))
                    # Retain late forwarding code even if the full source is clipped.
                    $lines = $safe -split '\r?\n'
                    $selected = [System.Collections.Generic.SortedSet[int]]::new()
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        if ($lines[$i] -match 'ActionType|PSBoundParameters|Execute-Command|Invoke-RestMethod|Invoke-WebRequest|ConvertTo-Json|GetSteppablePipeline|Invoke-Command') {
                            for ($j = [Math]::Max(0, $i - 3); $j -le [Math]::Min($lines.Count - 1, $i + 3); $j++) {
                                $null = $selected.Add($j)
                            }
                        }
                    }
                    $entry.excerpt_lines_truncated = $false
                    $excerpt = (@($selected | ForEach-Object {
                        $line = $lines[$_]
                        if ($line.Length -gt 512) {
                            $line = $line.Substring(0, 512) + " [line truncated]"
                            $entry.excerpt_lines_truncated = $true
                        }
                        "{0}: {1}" -f ($_ + 1), $line
                    }) -join "`n")
                    $entry.excerpts_truncated = $excerpt.Length -gt 16384
                    $entry.forwarding_excerpts = $excerpt.Substring(0, [Math]::Min(16384, $excerpt.Length))
                    $entry.status = if ($source) { "collected" } else { "no_script_source" }
                }
            } catch {
                $entry.error = ConvertTo-BoundedScalarText -Value (
                    ConvertTo-SecretRedactedText -Text (Get-OriginalErrorMessage -ErrorRecord $_)
                ) -MaxChars 1024
            }
            if ($entry.status -ne "collected" -or $entry.source_truncated -or $entry.excerpts_truncated -or $entry.excerpt_lines_truncated) {
                $report.status = "partial"
            }
            $report.commands += $entry
        }
        if ($report.action_type.Count -eq 0) { $report.status = "partial" }
    } catch {
        $report.error = ConvertTo-BoundedScalarText -Value (
            ConvertTo-SecretRedactedText -Text (Get-OriginalErrorMessage -ErrorRecord $_)
        ) -MaxChars 1024
    }
    return @{
        cmdlet_proxy_diagnostics_status = $report.status
        cmdlet_proxy_diagnostics = ($report | ConvertTo-Json -Depth 8 -Compress)
    }
}

function Get-ExchangeConnectionMetadataEvidence {
    $evidence = @{
        exchange_connection_metadata = ""
        exchange_connection_metadata_error = ""
    }
    try {
        $command = Get-Command `
            -Name "Get-ConnectionInformation" `
            -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            $evidence.exchange_connection_metadata_error = (
                "Get-ConnectionInformation is not available in the loaded " +
                "ExchangeOnlineManagement module."
            )
            return $evidence
        }
        $connections = @(Get-ConnectionInformation -ErrorAction Stop)
        $descriptions = New-Object "System.Collections.Generic.List[string]"
        foreach ($connection in @($connections | Select-Object -First 4)) {
            $fields = New-Object "System.Collections.Generic.List[string]"
            foreach ($propertyName in @(
                "State",
                "TokenStatus",
                "ManagedIdentity",
                "Organization",
                "TenantID",
                "ConnectionUri"
            )) {
                $property = $connection.PSObject.Properties[$propertyName]
                if ($null -ne $property -and $null -ne $property.Value) {
                    $fields.Add(
                        "$propertyName=$([string] $property.Value)"
                    )
                }
            }
            if ($fields.Count -gt 0) {
                $descriptions.Add($fields -join ",")
            }
        }
        $evidence.exchange_connection_metadata = (
            ConvertTo-BoundedDiagnosticText `
                -Records @($descriptions) `
                -MaxChars $DiagnosticMaxChars
        )
    } catch {
        $evidence.exchange_connection_metadata_error = (
            Get-OriginalErrorMessage -ErrorRecord $_
        )
    }
    return $evidence
}

function Initialize-DiagnosticEvidence {
    $evidence = @{
        exchange_online_management_version = (
            [string] $script:ExchangeOnlineManagementVersion
        )
        exchange_online_management_path = (
            [string] $script:ExchangeOnlineManagementPath
        )
    }
    foreach ($key in $script:ExchangeConfigEvidence.Keys) {
        $evidence[$key] = [string] $script:ExchangeConfigEvidence[$key]
    }
    try {
        $evidence.powershell_version = [string] $PSVersionTable.PSVersion
        $evidence.powershell_edition = [string] $PSVersionTable.PSEdition
        $evidence.powershell_platform = [string] $PSVersionTable.Platform
        $evidence.powershell_os = ConvertTo-BoundedScalarText `
            -Value $PSVersionTable.OS `
            -MaxChars 512
    } catch {
        # Passive runtime evidence must never prevent the requested action.
    }
    foreach ($key in @(
        "powershell_version",
        "powershell_edition",
        "powershell_platform",
        "powershell_os"
    )) {
        if (-not $evidence.ContainsKey($key)) {
            $evidence[$key] = ""
        }
    }
    $script:RuntimeDiagnosticEvidence = $evidence
}

function Get-PassiveExchangeEvidence {
    # Optional manual diagnosis only: inspect the loaded command and connection.
    # Normal release/deny actions never call these collectors.
    if ($null -ne $script:PassiveExchangeEvidence) {
        return $script:PassiveExchangeEvidence
    }
    $evidence = @{}
    foreach ($collector in @(
        { Get-ReleaseCommandMetadataEvidence },
        { Get-ExchangeConnectionMetadataEvidence }
    )) {
        try {
            $collected = & $collector
            foreach ($key in $collected.Keys) {
                $evidence[$key] = $collected[$key]
            }
        } catch {
            $evidence.cmdlet_metadata_error = (
                Get-OriginalErrorMessage -ErrorRecord $_
            )
        }
    }
    $script:PassiveExchangeEvidence = $evidence
    return $evidence
}

function Close-ExchangeSessionBestEffort {
    # Cleanup is independent of the disposition outcome: record the result
    # but never throw and never run the disconnect twice.
    if ($null -ne $script:ExchangeCleanupEvidence) {
        return $script:ExchangeCleanupEvidence
    }
    $evidence = @{
        exchange_disconnect_status = "completed"
        exchange_disconnect_error = ""
    }
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | Out-Null
        Write-Verbose "Disconnected from Exchange Online."
    } catch {
        $evidence.exchange_disconnect_status = "failed"
        try {
            $evidence.exchange_disconnect_error = (
                ConvertTo-BoundedScalarText `
                    -Value (Get-OriginalErrorMessage -ErrorRecord $_) `
                    -MaxChars $DiagnosticMaxChars
            )
        } catch {
            $evidence.exchange_disconnect_error = "Disconnect-ExchangeOnline failed."
        }
    }
    $script:ExchangeCleanupEvidence = $evidence
    return $evidence
}

function Add-StaticDiagnosticEvidence {
    param(
        [hashtable] $Data,
        [ValidateSet("Release", "Deny")]
        [string] $DispositionAction = "Release"
    )

    $Data.runbook_version = [string] $RunbookVersion
    $Data.runbook_source_revision = [string] $RunbookSourceRevision
    $Data.runbook_build_id = [string] $RunbookBuildId
    foreach ($source in @(
        $script:RuntimeDiagnosticEvidence,
        (Get-PassiveExchangeEvidence)
    )) {
        foreach ($key in $source.Keys) {
            $Data[$key] = $source[$key]
        }
    }
    if ($DispositionAction -eq "Release") {
        $Data.cmdlet_contract_id = $ReleaseContractId
        $Data.cmdlet_expected_argument_names = "Identity,ReleaseToAll"
        $Data.cmdlet_parameter_names = (
            "Identity,ReleaseToAll,Confirm,ErrorAction"
        )
        $Data.cmdlet_invocation_form = (
            "Release-QuarantineMessage -Identity <identity> -ReleaseToAll " +
            "-Confirm:`$false -ErrorAction Stop"
        )
    } else {
        $Data.cmdlet_contract_id = $DenyContractId
        $Data.cmdlet_expected_argument_names = "Identity,ReleaseToAll,ActionType"
        $Data.cmdlet_parameter_names = (
            "Identity,ReleaseToAll,ActionType,Confirm,ErrorAction"
        )
        $Data.cmdlet_invocation_form = (
            "Release-QuarantineMessage -Identity <identity> -ReleaseToAll " +
            "-ActionType Deny -Confirm:`$false -ErrorAction Stop"
        )
    }
}

function ConvertTo-RedactedBoundedScalarText {
    param(
        [object] $Value,
        [int] $MaxChars = $DiagnosticMaxChars
    )

    # Redact the complete source before truncation can cut off a secret marker.
    return ConvertTo-BoundedScalarText `
        -Value (ConvertTo-SecretRedactedText -Text ([string] $Value)) `
        -MaxChars $MaxChars
}

function Invoke-QuarantineDisposition {
    param(
        [string] $Identity,
        [ValidateSet("Release", "Deny")]
        [string] $ActionType
    )
    # Exactly one write. Suppress optional native streams rather than leaking
    # their potentially sensitive text. Also catch providers which explicitly
    # emit non-terminating errors despite ErrorAction Stop; retain only errors.
    & {
        if ($ActionType -eq "Release") {
            Release-QuarantineMessage `
                -Identity $Identity `
                -ReleaseToAll `
                -Confirm:$false `
                -ErrorAction Stop
        } else {
            Release-QuarantineMessage `
                -Identity $Identity `
                -ReleaseToAll `
                -ActionType Deny `
                -Confirm:$false `
                -ErrorAction Stop
        }
    } 2>&1 3>$null 4>$null 5>$null 6>$null | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { throw $_ }
    }
}

function Read-QuarantineStatus {
    param([string] $Identity, [switch] $AllowMissing)
    $messages = @(Get-QuarantineMessage -Identity $Identity -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null)
    if ($AllowMissing -and $messages.Count -eq 0) {
        return @{ ObservedIdentity = $Identity; ObservedStatus = "NotFound" }
    }
    if ($messages.Count -ne 1) {
        throw "Get-QuarantineMessage returned $($messages.Count) results for one identity."
    }
    $observedIdentity = [string] $messages[0].Identity
    if (-not (Test-QuarantineIdentityMatch -Left $observedIdentity -Right $Identity)) {
        throw "Get-QuarantineMessage returned identity '$observedIdentity' instead of '$Identity'."
    }
    $observedStatus = [string] $messages[0].ReleaseStatus
    if (-not $observedStatus) {
        throw "Get-QuarantineMessage returned an empty ReleaseStatus."
    }
    return @{
        ObservedIdentity = $observedIdentity
        ObservedStatus = $observedStatus
    }
}

function Wait-QuarantinePostcondition {
    param(
        [string] $Identity,
        [string] $ExpectedStatus,
        [int] $MaxAttempts = $PostconditionMaxAttempts,
        [int] $PollIntervalSeconds = $PostconditionPollSeconds
    )
    if ($MaxAttempts -lt 1) { throw "Postcondition verification requires at least one attempt." }
    if ($PollIntervalSeconds -lt 0) { throw "Postcondition verification poll interval cannot be negative." }
    for ([int] $attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $result = @{
            Confirmed = $false
            ObservedIdentity = ""
            ObservedStatus = ""
            Attempts = $attempt
            LastError = ""
        }
        try {
            $observation = Read-QuarantineStatus -Identity $Identity
            $result.ObservedIdentity = $observation.ObservedIdentity
            $result.ObservedStatus = $observation.ObservedStatus
            if ([string]::Equals($observation.ObservedStatus, $ExpectedStatus, [System.StringComparison]::OrdinalIgnoreCase)) {
                $result.Confirmed = $true
                return $result
            }
        } catch {
            $result.LastError = Get-OriginalErrorMessage -ErrorRecord $_
        }
        if ($attempt -lt $MaxAttempts -and $PollIntervalSeconds -gt 0) {
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
    return $result
}

function Write-ChunkedList {
    param([object[]] $Messages)

    $jsonChunks = New-Object "System.Collections.Generic.List[string]"
    $currentMessages = New-Object "System.Collections.Generic.List[object]"
    [int] $chunkIndex = 0
    [int] $itemIndex = -1
    [string] $currentJson = ""

    foreach ($message in $Messages) {
        $itemIndex++
        $candidateMessages = @($currentMessages.ToArray()) + @($message)
        $candidateJson = ConvertTo-RunbookJson -Data @{
            action      = "list"
            mode        = "list_chunk"
            chunk_index = $chunkIndex
            messages    = @($candidateMessages)
        }
        $candidateBytes = Get-Utf8ByteCount -Content $candidateJson

        if ($candidateBytes -le $ListMaxRecordBytes) {
            $currentMessages.Add($message)
            $currentJson = $candidateJson
            continue
        }

        if ($currentMessages.Count -eq 0) {
            Write-ErrorResult `
                -Action "list" `
                -Message "One quarantine list item exceeds the safe Azure Automation output-record budget." `
                -ErrorCode "list_record_oversized" `
                -Details @{
                    item_index       = $itemIndex
                    chunk_index      = $chunkIndex
                    utf8_bytes       = $candidateBytes
                    max_record_bytes = $ListMaxRecordBytes
                    handling         = "fail_closed"
                }
        }

        $jsonChunks.Add($currentJson)
        $chunkIndex++
        $currentMessages.Clear()
        $currentMessages.Add($message)
        $currentJson = ConvertTo-RunbookJson -Data @{
            action      = "list"
            mode        = "list_chunk"
            chunk_index = $chunkIndex
            messages    = @($currentMessages.ToArray())
        }

        $singleRecordBytes = Get-Utf8ByteCount -Content $currentJson
        if ($singleRecordBytes -gt $ListMaxRecordBytes) {
            Write-ErrorResult `
                -Action "list" `
                -Message "One quarantine list item exceeds the safe Azure Automation output-record budget." `
                -ErrorCode "list_record_oversized" `
                -Details @{
                    item_index       = $itemIndex
                    chunk_index      = $chunkIndex
                    utf8_bytes       = $singleRecordBytes
                    max_record_bytes = $ListMaxRecordBytes
                    handling         = "fail_closed"
                }
        }
    }

    if ($currentMessages.Count -gt 0) {
        $jsonChunks.Add($currentJson)
    }

    if ($jsonChunks.Count -lt 1) {
        throw "Chunked list output calculated an invalid chunk_count."
    }
    if ($jsonChunks.Count -gt $ListMaxResultCount) {
        throw "Chunked list output requires more than $ListMaxResultCount records."
    }

    foreach ($jsonChunk in $jsonChunks) {
        Write-Output $jsonChunk
    }
    Write-SuccessResult @{
        action      = "list"
        mode        = "list_complete"
        chunk_count = $jsonChunks.Count
        count       = @($Messages).Count
    }
}

# ---------------------------------------------------------------------------
# Helper: inspect base64 blockwise without creating a second full-size string
# ---------------------------------------------------------------------------
function Assert-Base64Alphabet {
    param([string] $Content)
    if ($Content -match "[^A-Za-z0-9+/=]") {
        throw "Base64 content contains an invalid character."
    }
}

function Get-Base64PayloadInfo {
    param([string] $Base64)

    [long] $normalisedLength = 0
    [int] $paddingCount = 0
    [bool] $paddingSeen = $false
    if ($Base64 -match $Base64UnsupportedWhitespacePattern) {
        throw "Base64 content contains unsupported whitespace."
    }
    [bool] $hasWhitespace = $Base64 -match $Base64AllowedWhitespacePattern

    if (-not $hasWhitespace) {
        $normalisedLength = $Base64.Length
        Assert-Base64Alphabet -Content $Base64
        if ($Base64.EndsWith("==")) {
            $paddingCount = 2
        } elseif ($Base64.EndsWith("=")) {
            $paddingCount = 1
        }
        $firstPadding = $Base64.IndexOf("=")
        if ($firstPadding -ge 0 -and
            $firstPadding -ne ($Base64.Length - $paddingCount)) {
            throw "Base64 padding is invalid."
        }
    } else {
        [int] $blockNumber = 0
        for ([int] $offset = 0; $offset -lt $Base64.Length; $offset += $ExportScanBlockChars) {
            $length = [System.Math]::Min($ExportScanBlockChars, $Base64.Length - $offset)
            $block = $Base64.Substring($offset, $length)
            $normalised = $block -replace $Base64AllowedWhitespacePattern, ""

            if ($normalised.Length -gt 0) {
                if ($paddingSeen) {
                    if ($paddingCount -eq 1 -and $normalised -eq "=") {
                        $paddingCount = 2
                        $normalisedLength += 1
                        $normalised = $null
                        $block = $null
                        continue
                    }
                    throw "Base64 padding is invalid."
                }
                Assert-Base64Alphabet -Content $normalised

                $paddingIndex = $normalised.IndexOf("=")
                if ($paddingIndex -ge 0) {
                    $padding = $normalised.Substring($paddingIndex)
                    if ($padding -notmatch "^={1,2}$") {
                        throw "Base64 padding is invalid."
                    }
                    $paddingCount = $padding.Length
                    $paddingSeen = $true
                }

                $normalisedLength += $normalised.Length
            }

            $normalised = $null
            $block = $null
            $blockNumber++
            if (($blockNumber % 8) -eq 0) {
                [System.GC]::Collect()
            }
        }
    }

    if ($normalisedLength -eq 0) {
        throw "Base64 content is empty."
    }
    if (($normalisedLength % 4) -ne 0) {
        throw "Base64 length is not divisible by four."
    }

    [long] $decodedSize = (($normalisedLength / 4) * 3) - $paddingCount
    return @{
        Base64Length = $normalisedLength
        DecodedSize  = $decodedSize
        HasWhitespace = $hasWhitespace
    }
}

# ---------------------------------------------------------------------------
# Helper: stream a large base64 export as bounded chunks
# ---------------------------------------------------------------------------
function Write-ChunkedExport {
    param(
        [string] $Base64,
        [string] $Identity,
        [long] $Base64Length,
        [long] $DecodedSize,
        [bool] $HasWhitespace
    )

    $chunkCount = [int][System.Math]::Ceiling(
        $Base64Length / [double]$ExportChunkSizeChars
    )
    if ($chunkCount -lt 1) {
        throw "Chunked export calculated an invalid chunk_count."
    }
    if ($chunkCount -gt $ExportMaxChunkCount) {
        throw "Chunked export requires $chunkCount chunks, which exceeds the supported maximum of $ExportMaxChunkCount chunks."
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    [long] $decodedTotal = 0
    [int] $chunkIndex = 0
    [string] $carry = ""
    if ($HasWhitespace) {
        $scanBlockChars = $ExportScanBlockChars
    } else {
        $scanBlockChars = $ExportChunkSizeChars
    }

    try {
        for ([int] $offset = 0; $offset -lt $Base64.Length; $offset += $scanBlockChars) {
            $length = [System.Math]::Min($scanBlockChars, $Base64.Length - $offset)
            $block = $Base64.Substring($offset, $length)
            if ($HasWhitespace) {
                $normalised = $block -replace $Base64AllowedWhitespacePattern, ""
            } else {
                $normalised = $block
            }

            if ($normalised.Length -eq 0) {
                continue
            }
            if ($carry.Length -gt 0) {
                $combined = $carry + $normalised
            } else {
                $combined = $normalised
            }
            $carry = ""
            [int] $consumed = 0

            while (($combined.Length - $consumed) -ge $ExportChunkSizeChars) {
                if ($consumed -eq 0 -and
                    $combined.Length -eq $ExportChunkSizeChars) {
                    $chunk = $combined
                } else {
                    $chunk = $combined.Substring($consumed, $ExportChunkSizeChars)
                }
                $decoded = [System.Convert]::FromBase64String($chunk)
                $decodedTotal += $decoded.Length

                if ($chunkIndex -eq ($chunkCount - 1)) {
                    $null = $sha256.TransformFinalBlock($decoded, 0, $decoded.Length)
                } else {
                    $null = $sha256.TransformBlock(
                        $decoded, 0, $decoded.Length, $decoded, 0
                    )
                }

                Write-SuccessResult @{
                    action          = "export"
                    mode            = "chunked"
                    identity        = $Identity
                    encoding        = "base64"
                    chunk_index     = $chunkIndex
                    chunk_count     = $chunkCount
                    eml_chunk       = $chunk
                    runbook_version = $RunbookVersion
                }

                $chunkIndex++
                $consumed += $ExportChunkSizeChars
                $decoded = $null
                $chunk = $null
                if (($chunkIndex % 8) -eq 0) {
                    [System.GC]::Collect()
                }
            }

            if ($consumed -lt $combined.Length) {
                $carry = $combined.Substring($consumed)
            }
            $combined = $null
            $normalised = $null
            $block = $null
        }

        if ($carry.Length -gt 0) {
            $decoded = [System.Convert]::FromBase64String($carry)
            $decodedTotal += $decoded.Length
            $null = $sha256.TransformFinalBlock($decoded, 0, $decoded.Length)

            Write-SuccessResult @{
                action          = "export"
                mode            = "chunked"
                identity        = $Identity
                encoding        = "base64"
                chunk_index     = $chunkIndex
                chunk_count     = $chunkCount
                eml_chunk       = $carry
                runbook_version = $RunbookVersion
            }
            $chunkIndex++
            $decoded = $null
        }

        if ($chunkIndex -ne $chunkCount) {
            throw "Chunked export emitted $chunkIndex chunks, expected $chunkCount."
        }
        if ($decodedTotal -ne $DecodedSize) {
            throw "Chunked export decoded $decodedTotal bytes, expected $DecodedSize."
        }

        $sha256Hex = -join ($sha256.Hash | ForEach-Object { $_.ToString("x2") })
        Write-SuccessResult @{
            action            = "export"
            mode              = "chunked_complete"
            identity          = $Identity
            chunk_count       = $chunkCount
            eml_base64_length = $Base64Length
            decoded_size      = $DecodedSize
            sha256            = $sha256Hex
            runbook_version   = $RunbookVersion
        }
    } finally {
        $sha256.Dispose()
    }
}

function Invoke-RequestedDisposition {
    param(
        [ValidateSet("release", "deny")]
        [string] $Action,
        [string] $Identity
    )
    $expectedStatus = if ($Action -eq "release") { "Released" } else { "Denied" }
    $completedStatus = $expectedStatus.ToLowerInvariant()
    try {
        $before = Read-QuarantineStatus -Identity $Identity
    } catch {
        Write-ErrorResult -Action $Action -ErrorCode "precondition_unconfirmed" -ErrorContext "Get-QuarantineMessage" -ErrorRecord $_
    }
    if ($before.ObservedStatus -ieq $expectedStatus) {
        Write-SuccessResult @{
            action = $Action
            identity = $Identity
            status = "already_$completedStatus"
            observed_identity = $before.ObservedIdentity
            observed_release_status = $before.ObservedStatus
        }
        return
    }
    if ($before.ObservedStatus -ine $selectionReleaseStatus) {
        Write-ErrorResult -Action $Action -ErrorCode "precondition_unconfirmed" -ErrorContext "Get-QuarantineMessage" -Message "Exchange did not confirm ReleaseStatus=$selectionReleaseStatus for identity '$Identity' (observed $($before.ObservedStatus)). No disposition cmdlet was executed."
    }
    try {
        Invoke-QuarantineDisposition -Identity $Identity -ActionType $Action
    } catch {
        # Never turn an actual command exception into success using later reads.
        Write-ErrorResult -Action $Action -ErrorCode "disposition_failed" -ErrorContext "Release-QuarantineMessage" -ErrorRecord $_
    }
    $after = Wait-QuarantinePostcondition -Identity $Identity -ExpectedStatus $expectedStatus
    if (-not $after.Confirmed) {
        $message = "The command returned without error, but Exchange did not confirm ReleaseStatus=$expectedStatus for identity '$Identity' after $($after.Attempts) checks. Outcome is unknown; inspect Exchange before deciding on a new action."
        if ($after.LastError) { $message += " Last status read: $($after.LastError)" }
        Write-ErrorResult -Action $Action -ErrorCode "postcondition_unconfirmed" -ErrorContext "Get-QuarantineMessage" -Message $message
    }
    Write-SuccessResult @{
        action = $Action
        identity = $Identity
        status = $completedStatus
        observed_identity = $after.ObservedIdentity
        observed_release_status = $after.ObservedStatus
    }
}

# ---------------------------------------------------------------------------
# Step 1: Validate webhook input
# ---------------------------------------------------------------------------

if (-not $WebhookData) {
    Write-ErrorResult -Action "unknown" -Message "No WebhookData received. This runbook must be triggered via webhook."
}

if (-not $WebhookData.RequestBody) {
    Write-ErrorResult -Action "unknown" -Message "WebhookData.RequestBody is empty."
}

# Parse the request body
try {
    $body = $WebhookData.RequestBody | ConvertFrom-Json
} catch {
    Write-ErrorResult `
        -Action "unknown" `
        -ErrorCode "invalid_webhook_json" `
        -ErrorContext "webhook_json_parse" `
        -ErrorRecord $_
}
if (
    $null -eq $body -or
    $body -is [array] -or
    $body -is [string] -or
    $body -is [ValueType]
) {
    Write-ErrorResult `
        -Action "unknown" `
        -ErrorCode "invalid_webhook_body_type" `
        -ErrorContext "webhook_body_validation" `
        -Message "Webhook JSON body must be an object."
}

# Extract and validate action
# Note: avoid the ?? operator so the script also runs on PS 5.1, not only 7.2
if ($null -ne $body.action -and $body.action -isnot [string]) {
    Write-ErrorResult `
        -Action "unknown" `
        -ErrorCode "invalid_action_type" `
        -ErrorContext "webhook_body_validation" `
        -Message "Webhook field 'action' must be a string."
}
$action = if ($null -ne $body.action) {
    ([string] $body.action).Trim().ToLowerInvariant()
} else { "" }

if (-not $action) {
    Write-ErrorResult `
        -Action "unknown" `
        -ErrorCode "missing_action" `
        -ErrorContext "webhook_body_validation" `
        -Message "Required field 'action' is missing from webhook body."
}
if ($action.Length -gt 32) {
    Write-ErrorResult `
        -Action "unknown" `
        -ErrorCode "invalid_action_length" `
        -ErrorContext "webhook_body_validation" `
        -Message "Webhook field 'action' exceeds the supported length."
}

$validActions = @(
    "list",
    "export",
    "diagnose",
    "reconcile",
    "release",
    "deny"
)
if ($validActions -notcontains $action) {
    Write-ErrorResult -Action $action -Message "Unknown action '$action'. Valid values: $($validActions -join ', ')."
}

# Extract identity (required for export, diagnose, release, deny)
if ($null -ne $body.identity -and $body.identity -isnot [string]) {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "invalid_identity_type" `
        -ErrorContext "webhook_body_validation" `
        -Message "Webhook field 'identity' must be a string."
}
$identity = if ($null -ne $body.identity) {
    ([string] $body.identity).Trim()
} else { "" }

if ($action -ne "list" -and -not $identity) {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "missing_identity" `
        -ErrorContext "webhook_body_validation" `
        -Message "Required field 'identity' is missing for action '$action'."
}
if (
    $action -ne "list" -and
    -not (Test-QuarantineIdentityValue -Value $identity)
) {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "invalid_identity_format" `
        -ErrorContext "webhook_body_validation" `
        -Message "Webhook field 'identity' must be an exact GUID1\\GUID2 pair."
}

function Get-OptionalWebhookSetting {
    param(
        [string] $Name,
        [string] $TypeErrorCode
    )

    $property = $body.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ""
    }
    if ($property.Value -isnot [string]) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode $TypeErrorCode `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field '$Name' must be a string."
    }
    $setting = ([string] $property.Value).Trim()
    if ($setting.Length -gt $ExchangeSettingMaxLength) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "invalid_${Name}_length" `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field '$Name' exceeds the supported length."
    }
    if ($setting -match "[\x00-\x1F\x7F]") {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "invalid_${Name}_value" `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field '$Name' contains control characters."
    }
    return $setting
}

$requestedOrganization = Get-OptionalWebhookSetting `
    -Name "organization" `
    -TypeErrorCode "invalid_organization_type"
$requestedAuthMethod = Get-OptionalWebhookSetting `
    -Name "auth_method" `
    -TypeErrorCode "invalid_auth_method_type"
$requestedCredentialName = Get-OptionalWebhookSetting `
    -Name "credential_name" `
    -TypeErrorCode "invalid_credential_name_type"

# Exchange authentication is Managed Identity only. Unsupported wire values are
# rejected here, before the module import, any connection or any message
# access; nothing is silently ignored or substituted.
if ($requestedAuthMethod -and $requestedAuthMethod -cne "ManagedIdentity") {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "invalid_exchange_auth_method" `
        -ErrorContext "auth_method" `
        -Message "Unsupported Exchange authentication method '$requestedAuthMethod'. Exchange Online authentication is ManagedIdentity only (the Automation Account's system-assigned identity); omit auth_method or send ManagedIdentity."
}
if ($requestedCredentialName) {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "unsupported_credential_name" `
        -ErrorContext "credential_name" `
        -Message "Webhook field 'credential_name' is no longer supported. Exchange Online authentication is ManagedIdentity only."
}

$includeRbac = $false
if ($null -ne $body.include_rbac) {
    if ($body.include_rbac -isnot [bool]) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "invalid_include_rbac_type" `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field 'include_rbac' must be a boolean."
    }
    if ($action -ne "diagnose") {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "include_rbac_not_supported" `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field 'include_rbac' is supported only for action 'diagnose'."
    }
    $includeRbac = [bool] $body.include_rbac
}

# Extract page_size for the list action (optional). Limits how many
# quarantine messages are returned in one call. Valid range 1-1000 (the
# Get-QuarantineMessage cmdlet maximum). Defaults to 50 if not supplied.
$pageSize = 50
if ($null -ne $body.page_size) {
    $parsedSize = 0
    if (
        $body.page_size -is [array] -or
        $body.page_size -is [System.Collections.IDictionary] -or
        -not [int]::TryParse(
            $body.page_size.ToString(),
            [ref] $parsedSize
        ) -or
        $parsedSize -lt 1 -or
        $parsedSize -gt 1000
    ) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "invalid_page_size" `
            -ErrorContext "webhook_body_validation" `
            -Message "Webhook field 'page_size' must be an integer between 1 and 1000."
    }
    $pageSize = $parsedSize
}

Write-Verbose "Action:   $action"
Write-Verbose "Identity: $identity"
Write-Verbose "PageSize: $pageSize"
Write-Verbose "IncludeRBAC: $includeRbac"

# ---------------------------------------------------------------------------
# Step 2: Load configuration from Automation Variables
# ---------------------------------------------------------------------------

# Effective Exchange connection. Authentication is ALWAYS the system-assigned
# Managed Identity (unsupported auth_method/credential_name values were already
# rejected above). The ExchangeAuthMethod Automation Variable is deliberately
# not read. The organization comes from the webhook field when present, else
# from the ExchangeOrganization Automation Variable, which is then required.
$authMethod = "ManagedIdentity"
$authMethodSource = if ($requestedAuthMethod) { "webhook" } else { "default" }

if ($requestedOrganization) {
    $organization = $requestedOrganization
    $organizationSource = "webhook"
} else {
    try {
        $organizationVariable = Get-AutomationVariable `
            -Name "ExchangeOrganization"
    } catch {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "automation_variable_read_failed" `
            -ErrorContext "ExchangeOrganization" `
            -ErrorRecord $_
    }
    $organization = if ($null -eq $organizationVariable) {
        ""
    } else {
        ([string] $organizationVariable).Trim()
    }
    if (-not $organization) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "automation_variable_empty" `
            -ErrorContext "ExchangeOrganization" `
            -Message "Managed Identity authentication requires an Exchange organization: neither the webhook field 'organization' nor the Automation Variable 'ExchangeOrganization' is set."
    }
    $organizationSource = "automation_variable"
}
$script:ExchangeConfigEvidence = @{
    exchange_auth_method = $authMethod
    exchange_auth_method_source = $authMethodSource
    exchange_organization = $organization
    exchange_organization_source = $organizationSource
}

function Get-OptionalBoundedAutomationInteger {
    param(
        [string] $Name,
        [int] $DefaultValue,
        [int] $Minimum,
        [int] $Maximum
    )
    try {
        $configuredValue = Get-AutomationVariable -Name $Name
    } catch {
        return $DefaultValue
    }
    if ($null -eq $configuredValue -or $configuredValue -eq "") {
        return $DefaultValue
    }
    [int] $parsedValue = 0
    if (
        -not [int]::TryParse(
            $configuredValue.ToString(),
            [ref] $parsedValue
        ) -or
        $parsedValue -lt $Minimum -or
        $parsedValue -gt $Maximum
    ) {
        Write-ErrorResult `
            -Action $action `
            -ErrorCode "automation_variable_invalid" `
            -ErrorContext $Name `
            -Message "Automation Variable '$Name' must be an integer between $Minimum and $Maximum."
    }
    return $parsedValue
}

if ($action -in @("release", "deny")) {
$PostconditionMaxAttempts = Get-OptionalBoundedAutomationInteger `
    -Name "QuarantinePostconditionMaxAttempts" `
    -DefaultValue $PostconditionMaxAttempts `
    -Minimum 1 `
    -Maximum 20
$PostconditionPollSeconds = Get-OptionalBoundedAutomationInteger `
    -Name "QuarantinePostconditionPollSeconds" `
    -DefaultValue $PostconditionPollSeconds `
    -Minimum 0 `
    -Maximum 30
if (
    (($PostconditionMaxAttempts - 1) * $PostconditionPollSeconds) -gt 300
) {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "automation_variable_invalid" `
        -ErrorContext "quarantine_postcondition_window" `
        -Message "Configured quarantine postcondition window must not exceed 300 seconds."
}

}

# ---------------------------------------------------------------------------
# Step 3: Load ExchangeOnlineManagement module
# ---------------------------------------------------------------------------
# Azure Automation does not always auto-load modules - explicit import required.
# The module version is not pinned; the loaded version is reported when known.

try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | Out-Null
} catch {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "module_import_failed" `
        -ErrorContext "ExchangeOnlineManagement" `
        -ErrorRecord $_
}

if ($action -eq "diagnose") {
# Passive module metadata is best-effort evidence: a failing lookup must never
# veto the connection or the disposition, and no version is invented.
try {
    $loadedExchangeModule = (
        Get-Module ExchangeOnlineManagement -ErrorAction Stop |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1
    )
    if ($null -ne $loadedExchangeModule -and $loadedExchangeModule.Version) {
        $script:ExchangeOnlineManagementVersion = (
            ConvertTo-BoundedScalarText `
                -Value $loadedExchangeModule.Version.ToString() `
                -MaxChars 128
        )
    }
    if ($null -ne $loadedExchangeModule -and $loadedExchangeModule.Path) {
        $script:ExchangeOnlineManagementPath = (
            ConvertTo-BoundedScalarText `
                -Value $loadedExchangeModule.Path `
                -MaxChars 1024
        )
    }
} catch {
    $script:ExchangeOnlineManagementVersion = "unknown"
    $script:ExchangeOnlineManagementPath = ""
    # The optional lookup's error body is deliberately never emitted.
    Write-Verbose (
        "ExchangeOnlineManagement metadata lookup failed; " +
        "module version reported as unknown."
    )
}
Write-Verbose (
    "ExchangeOnlineManagement module loaded (version: " +
    "$script:ExchangeOnlineManagementVersion)."
)

}

# ---------------------------------------------------------------------------
# Step 4: Connect to Exchange Online
# ---------------------------------------------------------------------------

Write-Verbose "Connecting to Exchange Online (auth: ManagedIdentity)"

try {
    # The executing Automation Account's system-assigned Managed Identity.
    # Requires Exchange.ManageAsApp plus suitable operational RBAC.
    # Reference: https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity
    Connect-ExchangeOnline `
        -ManagedIdentity `
        -Organization $organization `
        -ShowBanner:$false `
        -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | Out-Null
} catch {
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "exchange_connection_failed" `
        -ErrorContext "Connect-ExchangeOnline" `
        -Details $script:ExchangeConfigEvidence `
        -ErrorRecord $_
}

Write-Verbose "Connected to Exchange Online."
if ($action -eq "diagnose") { Initialize-DiagnosticEvidence }

# ---------------------------------------------------------------------------
# Step 5: Execute the requested action
# ---------------------------------------------------------------------------

try {
    switch ($action) {

        # --------------------------------------------------------------------
        # list: Get-QuarantineMessage -ReleaseStatus Requested
        # Reference: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-quarantinemessage
        # --------------------------------------------------------------------
        "list" {
            Write-Verbose "Executing Get-QuarantineMessage -ReleaseStatus $selectionReleaseStatus -PageSize $pageSize"

            $messages = Get-QuarantineMessage -ReleaseStatus $selectionReleaseStatus -PageSize $pageSize -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null

            # Normalise to array even if single result or null
            if ($null -eq $messages) {
                $messages = @()
            } elseif ($messages -isnot [array]) {
                $messages = @($messages)
            }

            # Select the fields SOAR needs, explicitly named to avoid
            # PowerShell serialisation surprises with complex objects
            # PowerShell unwraps a one-element pipeline result to a scalar.
            # Force array semantics so the JSON contract is stable for 0/1/n
            # messages and .Count always means the number of messages.
            $normalised = @($messages | ForEach-Object {
                @{
                    Identity         = $_.Identity
                    SenderAddress    = $_.SenderAddress
                    RecipientAddress = $_.RecipientAddress
                    Subject          = $_.Subject
                    Type             = $_.Type
                    ReceivedTime     = ConvertTo-OutputTimestamp -Value $_.ReceivedTime
                    Expires          = ConvertTo-OutputTimestamp -Value $_.Expires -ExpiryEvidence
                    PolicyName       = $_.PolicyName
                    ReleaseStatus    = $_.ReleaseStatus
                }
            })

            $listResult = @{
                action   = "list"
                count    = @($normalised).Count
                messages = $normalised
            }
            $listJson = ConvertTo-RunbookJson -Data $listResult
            if ((Get-Utf8ByteCount -Content $listJson) -le $ListMaxRecordBytes) {
                Write-Output $listJson
            } else {
                Write-ChunkedList -Messages @($normalised)
            }
        }

        # --------------------------------------------------------------------
        # export: Export-QuarantineMessage -Identity <identity>
        # Reference: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/export-quarantinemessage
        #
        # Returns an object with .Eml property (base64-encoded EML content).
        # SOAR decodes this to bytes and stores in Vault or returns inline.
        # Large base64 payloads are chunked because Azure Automation job output
        # rejects individual streams larger than 1 MiB.
        # --------------------------------------------------------------------
        "export" {
            Write-Verbose "Executing Export-QuarantineMessage -Identity '$identity'"

            $exported = Export-QuarantineMessage -Identity $identity -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null

            if ($null -eq $exported) {
                Write-ErrorResult -Action $action -Message "Export-QuarantineMessage returned no result for identity '$identity'."
            }

            # .Eml property contains the base64-encoded EML (PascalCase from PS serialisation)
            $emlBase64 = [string]$exported.Eml
            $exported = $null
            if (-not $emlBase64) {
                Write-ErrorResult -Action $action -Message "Export-QuarantineMessage returned an empty Eml field for identity '$identity'."
            }

            # The Exchange session is no longer needed after .Eml was copied.
            # Release its session/module state before processing a large payload.
            Close-ExchangeSessionBestEffort | Out-Null
            try {
                Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
            } catch {
                # Module unload is best effort only.
            }
            [System.GC]::Collect()

            try {
                $payloadInfo = Get-Base64PayloadInfo -Base64 $emlBase64
            } catch {
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "export_invalid_base64" `
                    -ErrorContext "Get-Base64PayloadInfo" `
                    -Details @{ identity = $identity } `
                    -ErrorRecord $_
            }

            $decodedSize = $payloadInfo.DecodedSize
            if ($decodedSize -gt $ExportMaxDecodedBytes) {
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "export_oversized" `
                    -Details @{
                        identity         = $identity
                        decoded_size     = $decodedSize
                        max_decoded_size = $ExportMaxDecodedBytes
                        handling         = "fail_closed"
                    } `
                    -Message "Exported EML size $decodedSize bytes exceeds the cloud-sandbox safety cap of $ExportMaxDecodedBytes bytes. The message remains quarantined; no Vault import, analysis, or release was started."
            }

            if ($payloadInfo.Base64Length -lt $ExportChunkThresholdBytes) {
                $normalisedEml = $emlBase64 -replace $Base64AllowedWhitespacePattern, ""
                try {
                    $smallBytes = [System.Convert]::FromBase64String($normalisedEml)
                } catch {
                    Write-ErrorResult `
                        -Action $action `
                        -ErrorCode "export_invalid_base64" `
                        -ErrorContext "FromBase64String" `
                        -Details @{ identity = $identity } `
                        -ErrorRecord $_
                }
                if ($smallBytes.Length -ne $decodedSize) {
                    Write-ErrorResult -Action $action -Message "Exported EML decoded size does not match its base64 metadata."
                }
                Write-SuccessResult @{
                    action          = "export"
                    identity        = $identity
                    eml             = $normalisedEml
                    runbook_version = $RunbookVersion
                }
                break
            }

            try {
                [System.GC]::Collect()
                Write-ChunkedExport `
                    -Base64 $emlBase64 `
                    -Identity $identity `
                    -Base64Length $payloadInfo.Base64Length `
                    -DecodedSize $decodedSize `
                    -HasWhitespace $payloadInfo.HasWhitespace
            } catch {
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "export_stream_failed" `
                    -ErrorContext "Write-ChunkedExport" `
                    -Details @{ identity = $identity } `
                    -ErrorRecord $_
            }
        }

        # --------------------------------------------------------------------
        # diagnose: read-only release environment and identity inspection
        # --------------------------------------------------------------------
        "diagnose" {
            $inspectedAt = [datetimeoffset]::UtcNow
            $rbacDiagnosticEvidence = $null
            try {
                $diagnosticMessages = @(
                    Get-QuarantineMessage `
                        -Identity $identity `
                        -ErrorAction Stop
                )
            } catch {
                $diagnosticDetails = @{
                    identity                = $identity
                    status                  = "inspection_failed"
                    inspected_at_utc        = $inspectedAt.ToString("o")
                    result_count            = 0
                    observed_identity       = ""
                    observed_release_status = ""
                    inspection_error        = (
                        Get-OriginalErrorMessage -ErrorRecord $_
                    )
                    handling                = "read_only"
                    include_rbac            = $includeRbac
                }
                Add-StaticDiagnosticEvidence -Data $diagnosticDetails
                $rbacDiagnosticEvidence = (
                    Get-QuarantineRbacDiagnosticEvidence
                )
                Add-RbacDiagnosticEvidence `
                    -Data $diagnosticDetails `
                    -Evidence $rbacDiagnosticEvidence
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "diagnostic_inspection_failed" `
                    -ErrorContext "Get-QuarantineMessage" `
                    -Details $diagnosticDetails `
                    -ErrorRecord $_
            }

            $diagnosticResult = @{
                action                  = "diagnose"
                identity                = $identity
                status                  = "inspected"
                inspected_at_utc        = $inspectedAt.ToString("o")
                result_count            = @($diagnosticMessages).Count
                observed_identity       = ""
                observed_release_status = ""
                inspection_error        = ""
                handling                = "read_only"
                include_rbac            = $includeRbac
            }
            if (@($diagnosticMessages).Count -eq 1) {
                $diagnosticResult.observed_identity = (
                    [string] $diagnosticMessages[0].Identity
                )
                $diagnosticResult.observed_release_status = (
                    [string] $diagnosticMessages[0].ReleaseStatus
                )
                if (-not (Test-QuarantineIdentityMatch `
                    -Left $diagnosticResult.observed_identity `
                    -Right $identity
                )) {
                    $diagnosticResult.inspection_error = (
                        "Get-QuarantineMessage returned a different identity."
                    )
                }
            } elseif (@($diagnosticMessages).Count -eq 0) {
                $diagnosticResult.inspection_error = (
                    "Get-QuarantineMessage returned no result."
                )
            } else {
                $diagnosticResult.inspection_error = (
                    "Get-QuarantineMessage returned " +
                    "$(@($diagnosticMessages).Count) results."
                )
            }
            Add-StaticDiagnosticEvidence `
                -Data $diagnosticResult `
                -DispositionAction "Release"
            $proxyEvidence = Get-ReleaseProxyDiagnosticEvidence
            foreach ($key in $proxyEvidence.Keys) {
                $diagnosticResult[$key] = $proxyEvidence[$key]
            }
            if ($diagnosticResult.inspection_error) {
                $rbacDiagnosticEvidence = (
                    Get-QuarantineRbacDiagnosticEvidence
                )
            } else {
                $rbacDiagnosticEvidence = (
                    Get-QuarantineRbacDiagnosticEvidence `
                        -IncludeTenantRbac:$includeRbac
                )
            }
            Add-RbacDiagnosticEvidence `
                -Data $diagnosticResult `
                -Evidence $rbacDiagnosticEvidence

            if ($diagnosticResult.inspection_error) {
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "diagnostic_inspection_unconfirmed" `
                    -Details $diagnosticResult `
                    -Message "Read-only quarantine inspection could not bind exactly one result to identity '$identity'. No release or deny cmdlet was executed."
            }
            if (
                $includeRbac -and
                $diagnosticResult.rbac_diagnostics_status -ne "complete"
            ) {
                $diagnosticResult.status = "inspection_incomplete"
                $missingCmdletText = (
                    [string[]] @($diagnosticResult.missing_cmdlets)
                ) -join ", "
                if (
                    $diagnosticResult.rbac_diagnostics_status -eq
                    "not_evaluated"
                ) {
                    Write-ErrorResult `
                        -Action $action `
                        -ErrorCode "diagnostic_rbac_not_evaluated" `
                        -Details $diagnosticResult `
                        -Message (
                            "Read-only quarantine identity inspection " +
                            "succeeded, but tenant RBAC was NOT EVALUATED. " +
                            "Required cmdlets missing from the current " +
                            "Exchange Online session: $missingCmdletText. " +
                            "Service-principal registration, Quarantine " +
                            "role presence, and role assignments are " +
                            "unknown. No release or deny cmdlet was executed."
                        )
                }
                $diagnosticRbacMessage = Get-PermissionEvidenceErrorMessage `
                    -Evidence $diagnosticResult `
                    -Fallback (
                        "Read-only quarantine identity inspection succeeded, " +
                        "but tenant RBAC evaluation was incomplete. No release " +
                        "or deny cmdlet was executed."
                    )
                Write-ErrorResult `
                    -Action $action `
                    -ErrorCode "diagnostic_rbac_partial" `
                    -Details $diagnosticResult `
                    -Message $diagnosticRbacMessage
            }
            Write-SuccessResult $diagnosticResult
        }

        # --------------------------------------------------------------------
        # reconcile: read the exact Exchange state without a disposition call
        # --------------------------------------------------------------------
        "reconcile" {
            # An empty, successful exact lookup is different from a thrown
            # Exchange error. Release/Deny continue to require a real row.
            $observation = Read-QuarantineStatus -Identity $identity -AllowMissing
            Write-SuccessResult @{
                action = "reconcile"
                identity = $identity
                observed_identity = $observation.ObservedIdentity
                observed_release_status = $observation.ObservedStatus
            }
        }

        # --------------------------------------------------------------------
        # release/deny: common safe workflow; exact Exchange invocation is
        # action-specific in Invoke-QuarantineDisposition. IRREVERSIBLE.
        # Reference: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/release-quarantinemessage
        # --------------------------------------------------------------------
        "release" {
            Invoke-RequestedDisposition -Action "release" -Identity $identity
        }
        "deny" {
            Invoke-RequestedDisposition -Action "deny" -Identity $identity
        }
    }

} catch {
    # The native PowerShell/Microsoft message is the primary error contract.
    # Stable metadata is additive and must never replace or rewrite it.
    Write-ErrorResult `
        -Action $action `
        -ErrorCode "runbook_unhandled_error" `
        -ErrorContext $action `
        -ErrorRecord $_

} finally {
    # Always disconnect; cleanup failure never changes the action result.
    $null = Close-ExchangeSessionBestEffort
}
