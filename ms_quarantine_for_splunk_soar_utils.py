# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
#
# MS Quarantine for Splunk SOAR - Azure Automation Utils
# ===============================================
# Handles all HTTP communication:
#   - Azure AD token acquisition (client credentials)
#   - Webhook firing
#   - Job status polling
#   - Job output retrieval
#
# References:
#   Azure AD token: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
#   Automation Job API: https://learn.microsoft.com/en-us/rest/api/automation/job
#   Automation Webhook: https://learn.microsoft.com/en-us/azure/automation/automation-webhooks

import base64
import binascii
import hashlib
import json
import re
import time
from typing import Optional
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

import requests


def validate_webhook_url(value: str) -> str:
    """Require HTTPS without including the secret-bearing URL in errors."""
    message = "Asset configuration error: 'webhook_url' must be a valid HTTPS URL with a host."
    try:
        url = value.strip()
        parsed = urlsplit(url)
        _ = parsed.port  # Validate an explicitly supplied port as well.
        if parsed.scheme != "https" or not parsed.hostname or any(char.isspace() for char in parsed.netloc):
            raise ValueError(message)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(message) from None
    return url


def parse_strict_integer(value) -> int:
    """Accept integers and decimal integer strings, never lossy coercions."""
    if isinstance(value, bool):
        raise ValueError("Boolean values are not integers.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value.strip()):
        return int(value.strip())
    raise ValueError("Expected an integer or a decimal integer string.")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Azure AD token endpoint
AAD_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Azure Management API scope for Automation
MGMT_SCOPE = "https://management.azure.com/.default"

# Azure Management API base URL
MGMT_BASE = "https://management.azure.com"

# Automation Job API path template
# Reference: https://learn.microsoft.com/en-us/rest/api/automation/job/get
JOB_API_PATH = (
    "/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}"
    "/providers/Microsoft.Automation"
    "/automationAccounts/{automation_account}"
    "/jobs/{job_id}"
)

# Automation Job Output API path template
# Reference: https://learn.microsoft.com/en-us/rest/api/automation/job/get-output
JOB_OUTPUT_API_PATH = JOB_API_PATH + "/output"

# Automation Management API version
MGMT_API_VERSION = "2023-11-01"

# Job terminal states - polling stops on any of these
JOB_TERMINAL_STATES = {"Completed", "Failed", "Stopped", "Suspended", "Disconnected"}

# Job success state
JOB_SUCCESS_STATE = "Completed"

# Job states that indicate failure
JOB_FAILURE_STATES = {"Failed", "Stopped", "Suspended", "Disconnected"}

# EML field variants from PowerShell PascalCase serialisation
EML_FIELD_VARIANTS = ("eml", "Eml", "EML")

# Bounded list and chunked export contracts mirror runbook.ps1.
AZURE_STREAM_LIMIT_MESSAGE = "Stream size is more than 1 MB, upload canceled"
LIST_CHUNK_MODE = "list_chunk"
LIST_COMPLETE_MODE = "list_complete"
MAX_LIST_RESULT_COUNT = 1000
CHUNKED_EXPORT_MODE = "chunked"
CHUNKED_COMPLETE_MODE = "chunked_complete"
ERROR_CHUNK_MODE = "error_chunk"
ERROR_COMPLETE_MODE = "error_complete"
CHUNK_ENCODING = "base64"
MAX_CHUNK_COUNT = 200
MAX_ERROR_CHUNK_COUNT = 200
MAX_ERROR_ENVELOPE_BYTES = 40 * 1024 * 1024
MAX_ERROR_TEXT_CHARS = MAX_ERROR_ENVELOPE_BYTES
MAX_DECODED_EML_BYTES = 24 * 1024 * 1024
MAX_INLINE_DECODED_EML_BYTES = 10 * 1024 * 1024
MIN_SUPPORTED_RUNBOOK_VERSION = (3, 3, 4)
# First runbook that reports effective connection evidence.
CONNECTION_CONTRACT_RUNBOOK_VERSION = (3, 4, 1)
# First runbook that connects ONLY with the Automation Account's system-assigned
# Managed Identity and implements the read-only config_check action that proves
# it. Irreversible actions require it.
MANAGED_IDENTITY_ONLY_RUNBOOK_VERSION = (3, 4, 2)
EXCHANGE_CONFIG_CONTRACT = "exchange_connection_v1"
EXCHANGE_AUTH_METHOD = "ManagedIdentity"
EXCHANGE_SETTING_MAX_CHARS = 256
PRECONDITION_ERROR_CODE = "precondition_unconfirmed"
POSTCONDITION_ERROR_CODE = "postcondition_unconfirmed"
DISPOSITION_REJECTED_ERROR_CODE = "disposition_rejected"
DISPOSITION_CAPABILITY_ERROR_CODE = "disposition_capability_unconfirmed"
DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE = "diagnostic_rbac_not_evaluated"
DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE = "diagnostic_rbac_partial"
POSTCONDITION_VERIFICATION_METHOD = "Get-QuarantineMessage"
RELEASE_CONTRACT_ID = "identity_releasetoall"
DENY_CONTRACT_ID = "identities_actiontype_no_dummy"
MAX_DIAGNOSTIC_TEXT_CHARS = 2048
MAX_DIAGNOSTIC_TRACE_CHARS = 8192
MAX_DIAGNOSTIC_TRACE_RECORDS = 25
MAX_JWT_HEADER_SEGMENT_CHARS = 8 * 1024
MAX_RBAC_ROLE_GROUP_INSPECTIONS = 20
MAX_PERMISSION_QUERY_ERRORS = 20
MAX_PERMISSION_QUERY_ERROR_BYTES = 32 * 1024
MAX_MODULE_VERSION_CHARS = 64
MAX_BUILD_FIELD_CHARS = 128
MAX_RUNTIME_FIELD_CHARS = 1024
MAX_RUNBOOK_SETTING_CHARS = 512
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
BUILD_FIELD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
JWT_COMPACT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?!\.[A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
)

# Azure Management API throttling. Azure may return 429 when multiple SOAR
# actions poll Automation jobs concurrently. Treat this as transient and back
# off inside the action instead of failing the playbook immediately.
HTTP_TOO_MANY_REQUESTS = 429
MAX_THROTTLE_SLEEP_SECONDS = 30
MAX_PERSISTED_ERROR_CHARS = 2048


QUARANTINE_SELECTION_STATUSES = {
    "release_requested": "Requested",
    "needs_review": "NotReleased",
}
QUARANTINE_SELECTION_CONTRACT = "quarantine_selection_v1"


def normalize_quarantine_selection_mode(value=None) -> str:
    """Blank upgraded assets retain the original Requested-only behavior."""
    if value is None or value == "":
        return "release_requested"
    if not isinstance(value, str) or value not in QUARANTINE_SELECTION_STATUSES:
        raise ValueError("quarantine_selection_mode must be release_requested or needs_review.")
    return value


def normalize_exchange_connection_settings(organization=None) -> dict:
    """
    Build the Exchange connection settings sent with every webhook call.

    Exchange Online authentication is always the Automation Account's
    system-assigned Managed Identity, so ``auth_method`` is a constant and
    nothing from a stored asset can select another method. The optional
    organization (tenant domain) is validated for type, length and
    whitespace/control characters only; Exchange validates the tenant itself.
    A blank organization is omitted so the runbook falls back to its
    ExchangeOrganization Automation Variable.
    """
    settings = {"auth_method": EXCHANGE_AUTH_METHOD}
    if organization is not None and not isinstance(organization, str):
        raise ValueError("exchange_organization must be a string.")
    org = (organization or "").strip()
    if org:
        if len(org) > EXCHANGE_SETTING_MAX_CHARS or re.search(r"[\x00-\x20\x7f]", org):
            raise ValueError(
                "exchange_organization must be a single tenant value "
                "such as contoso.onmicrosoft.com (no whitespace or "
                "control characters, at most 256 characters). Exchange "
                "validates the tenant itself."
            )
        settings["organization"] = org
    return settings


def redact_sensitive_text(value, secrets=(), max_chars=MAX_PERSISTED_ERROR_CHARS):
    """Return credential-redacted text, optionally bounded by the caller."""
    text = str(value or "")
    candidates = []
    for secret in secrets:
        secret_text = str(secret or "")
        if not secret_text:
            continue
        candidates.extend(
            (
                secret_text,
                quote(secret_text, safe=""),
                quote_plus(secret_text),
            )
        )
    for candidate in sorted(set(candidates), key=len, reverse=True):
        if candidate:
            text = text.replace(candidate, "[REDACTED]")

    # An object-member prefix plus a quoted key/colon selects JSON syntax.
    # Backticks are literal there, not escapes for the following backslash or
    # closing quote. Redact this form before interpreting native diagnostics.
    text = re.sub(
        r'(?i)((?:\{|,)\s*"(?:authorization|set-cookie|cookie)"\s*:\s*")'
        r'(?:\\[^\r\n]|[^"\\\r\n]|\\(?=[\r\n]|$))*("|(?=[\r\n]|$))',
        r"\1[REDACTED]\2",
        text,
    )

    # Native diagnostics may quote the name or value, with doubled quotes,
    # backslash or PowerShell backtick escapes (not JSON string conventions).
    # An unterminated value ends at the physical line boundary (or input end),
    # so a malformed secret cannot leak or swallow the next diagnostic line.
    for delimiter in ('"', "'"):
        pattern = (
            r"""(?i)(["']?(?:authorization|set-cookie|cookie)["']?\s*[:=]\s*"""
            + delimiter
            + r")"
            + r"(?:[\\`][^\r\n]|"
            + delimiter * 2
            + r"|[^"
            + delimiter
            + r"\\`\r\n]|[\\`](?=[\r\n]|$))*"
            + "("
            + delimiter
            + r"|(?=[\r\n]|$))"
        )
        text = re.sub(pattern, r"\1[REDACTED]\2", text)

    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"""(?i)(authorization\s*[:=]\s*(?!bearer\b)(?:basic\s+)?)(?!["'\s])[^\s,;]+""",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?im)^(\s*(?:set-cookie|cookie)\s*:\s*)[^\r\n]*",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"""(?ix)
        (
            ["']?
            (?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|
               refresh[_ -]?token|client[_ -]?assertion|password|pwd|
               x-identity-header|identity_header)
            ["']?\s*[:=]\s*"
        )
        [^"\r\n]*
        (")
        """,
        r"\1[REDACTED]\2",
        text,
    )
    text = re.sub(
        r"""(?ix)
        (
            ["']?
            (?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|
               refresh[_ -]?token|client[_ -]?assertion|password|pwd|
               x-identity-header|identity_header)
            ["']?\s*[:=]\s*'
        )
        [^'\r\n]*
        (')
        """,
        r"\1[REDACTED]\2",
        text,
    )
    text = re.sub(
        r"(?i)((?:access[_ -]?token|client[_ -]?secret|webhook[_ -]?token|"
        r"refresh[_ -]?token|client[_ -]?assertion|password|pwd|"
        r"x-identity-header|identity_header)"
        r"\s*[:=]\s*)(?![\"'])[^\s,;&]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)([?&](?:token|sig|signature|code|client_secret|access_token|"
        r"refresh_token|client_assertion|password|pwd)=)"
        r"[^&\s\"']+",
        r"\1[REDACTED]",
        text,
    )

    def redact_jwt(match):
        candidate = match.group(0)
        header_segment = candidate.split(".", 1)[0]
        if len(header_segment) > MAX_JWT_HEADER_SEGMENT_CHARS:
            return "[REDACTED-JWT]"
        padded_header = header_segment + ("=" * (-len(header_segment) % 4))
        try:
            header = json.loads(base64.urlsafe_b64decode(padded_header).decode("utf-8"))
        except (
            binascii.Error,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            return match.group(0)
        if not isinstance(header, dict) or not isinstance(header.get("alg"), str):
            return match.group(0)
        if not header["alg"].strip():
            return match.group(0)
        return "[REDACTED-JWT]"

    text = JWT_COMPACT_RE.sub(redact_jwt, text)
    if max_chars is None:
        return text
    return text[: max(0, int(max_chars))]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AutomationError(Exception):
    """Raised when an Azure Automation operation fails."""

    pass


class TokenError(AutomationError):
    """Raised when Azure AD token acquisition fails."""

    pass


class WebhookError(AutomationError):
    """Raised when the webhook call fails."""

    pass


class JobTimeoutError(AutomationError):
    """Raised when job polling exceeds the configured timeout."""

    def __init__(
        self,
        message: str,
        job_id: str = "",
        last_status: str = "",
        phase: str = "status",
    ):
        super().__init__(message)
        self.job_id = job_id
        self.last_status = last_status
        self.phase = phase


class JobFailedError(AutomationError):
    """Raised when a job reaches a failure terminal state."""

    pass


class RunbookActionError(AutomationError):
    """Raised for a validated, structured failure reported by the runbook."""

    def __init__(self, message: str, result: dict):
        super().__init__(message)
        self.result = result


class ConnectionContractError(AutomationError):
    """The deployed runbook did not confirm the configured Exchange settings."""


class OversizedExportError(AutomationError):
    """Raised when an EML exceeds the cloud-sandbox safety cap."""

    def __init__(
        self,
        message: str,
        identity: str = "",
        decoded_size: Optional[int] = None,
        max_decoded_size: Optional[int] = None,
    ):
        super().__init__(message)
        self.identity = identity
        self.decoded_size = decoded_size
        self.max_decoded_size = max_decoded_size


# ---------------------------------------------------------------------------
# Utils class
# ---------------------------------------------------------------------------


class MSQuarantineForSplunkSOARUtils:
    """
    Handles all communication with Azure Automation on behalf of the connector.

    Flow for each action:
        1. fire_webhook()   → returns job_id
        2. poll_job()       → waits until terminal state
        3. get_job_output() → returns parsed JSON result from Write-Output
    """

    def __init__(
        self,
        webhook_url: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        automation_account: str,
        poll_interval: int = 5,
        poll_timeout: int = 600,
        retain_chunked_base64: bool = True,
        exchange_organization: Optional[str] = None,
        quarantine_selection_mode: Optional[str] = None,
    ):
        self._connection_settings = normalize_exchange_connection_settings(
            exchange_organization,
        )
        self.quarantine_selection_mode = normalize_quarantine_selection_mode(quarantine_selection_mode)
        self.selection_release_status = QUARANTINE_SELECTION_STATUSES[self.quarantine_selection_mode]
        self._connection_contract_verified = False
        self._webhook_url = validate_webhook_url(webhook_url)
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._automation_account = automation_account
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._retain_chunked_base64 = retain_chunked_base64

        self._session = requests.Session()
        self._mgmt_token = None  # cached for current action

    def new_poll_deadline(self) -> float:
        """Return one absolute deadline shared by job status and output."""
        return time.time() + self._poll_timeout

    def redact_sensitive_text(self, value, max_chars=MAX_PERSISTED_ERROR_CHARS):
        """Redact connector-owned credentials from one diagnostic string."""
        secrets = [self._client_secret, self._mgmt_token]
        webhook_url = str(self._webhook_url or "")
        if webhook_url:
            secrets.append(webhook_url)
            try:
                secrets.extend(
                    item_value
                    for _item_name, item_value in parse_qsl(
                        urlsplit(webhook_url).query,
                        keep_blank_values=False,
                    )
                    if item_value
                )
            except ValueError:
                pass
        return redact_sensitive_text(value, secrets, max_chars=max_chars)

    @staticmethod
    def _transport_error_message(context: str, exc: Exception) -> str:
        """Describe a transport failure without persisting its request URL."""
        return f"{context} ({type(exc).__name__})"

    def _throttle_delay(self, response, retry_count: int) -> float:
        """
        Return the sleep delay for an Azure 429 response.

        Azure usually sends Retry-After as seconds. If absent or invalid, use a
        bounded exponential backoff based on the configured poll interval.
        """
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(
                    max(float(retry_after), 0.0),
                    MAX_THROTTLE_SLEEP_SECONDS,
                )
            except (TypeError, ValueError):
                pass

        base_delay = max(float(self._poll_interval), 1.0)
        return min(
            base_delay * (2 ** min(retry_count, 4)),
            MAX_THROTTLE_SLEEP_SECONDS,
        )

    def _sleep_for_retry(self, delay: float, deadline: float) -> None:
        """Sleep without exceeding the polling deadline by more than needed."""
        remaining = max(deadline - time.time(), 0.0)
        time.sleep(min(delay, remaining))

    # -----------------------------------------------------------------------
    # Azure AD token
    # -----------------------------------------------------------------------

    def get_mgmt_token(self) -> str:
        """
        Acquire an Azure AD Bearer token for the Azure Management API
        using the client credentials (app-only) flow.

        Reference:
        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

        Returns:
            Bearer token string.

        Raises:
            TokenError on failure.
        """
        if self._mgmt_token:
            return self._mgmt_token

        url = AAD_TOKEN_URL.format(tenant_id=self._tenant_id)

        try:
            response = self._session.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": MGMT_SCOPE,
                },
                timeout=30,
                verify=True,
            )
        except requests.exceptions.RequestException as exc:
            raise TokenError(self._transport_error_message("Token request failed", exc)) from exc

        if not response.ok:
            try:
                detail = response.json().get("error_description", response.text)
            except Exception:
                detail = response.text[:500]
            detail = self.redact_sensitive_text(detail, max_chars=500)
            raise TokenError(f"Azure AD token request failed (HTTP {response.status_code}): {detail}")

        try:
            token = response.json().get("access_token")
        except Exception as exc:
            raise TokenError(
                self._transport_error_message(
                    "Failed to parse token response",
                    exc,
                )
            ) from exc

        if not token:
            raise TokenError("Azure AD response did not contain access_token")

        self._mgmt_token = token
        return token

    # -----------------------------------------------------------------------
    # Webhook
    # -----------------------------------------------------------------------

    def fire_webhook(
        self,
        action: str,
        identity: Optional[str] = None,
        page_size: Optional[int] = None,
        operation_action: Optional[str] = None,
        include_rbac: Optional[bool] = None,
    ) -> str:
        """
        POST to the Azure Automation webhook to start a runbook job.

        The webhook URL already contains the auth token as a query parameter -
        no additional auth header is needed.

        Reference:
        https://learn.microsoft.com/en-us/azure/automation/automation-webhooks

        Args:
            action:   One of: list, export, diagnose, release, deny.
            identity: Quarantine message identity (GUID1\\GUID2), required
                      for export, diagnose, release, deny.

        Returns:
            Job ID string.

        Raises:
            WebhookError on failure.
        """
        if self.quarantine_selection_mode != "release_requested" and action in {"list", "release", "deny"}:
            self.verify_connection_contract()
        body = {"action": action}
        if self.quarantine_selection_mode != "release_requested":
            body["quarantine_selection_mode"] = self.quarantine_selection_mode
        body.update(self._connection_settings)
        if identity:
            body["identity"] = identity
        if page_size is not None:
            body["page_size"] = page_size
        if operation_action is not None:
            body["operation_action"] = operation_action
        if include_rbac is not None:
            body["include_rbac"] = include_rbac

        try:
            response = self._session.post(
                self._webhook_url,
                json=body,
                timeout=30,
                verify=True,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise WebhookError(self._transport_error_message("Webhook request failed", exc)) from exc

        # requests treats 3xx as OK; reject before parsing even apparent JobIds.
        # WebhookError preserves the existing unknown-outcome/no-retry handling.
        if 300 <= response.status_code < 400:
            raise WebhookError(f"Webhook returned HTTP {response.status_code}; redirects are not followed. The submission outcome is unknown.")

        if not response.ok:
            if response.status_code == 404:
                raise WebhookError(
                    "Webhook returned HTTP 404. The webhook URL is invalid, "
                    "the webhook has expired, or it was deleted. Create a new "
                    "webhook on the runbook in the Azure Portal and update "
                    "webhook_url in the asset settings."
                )
            if response.status_code in (401, 403):
                raise WebhookError(
                    f"Webhook returned HTTP {response.status_code}. The webhook "
                    "token in the URL is invalid or expired. Create a new webhook "
                    "and update webhook_url."
                )
            raise WebhookError(f"Webhook returned HTTP {response.status_code}: {self.redact_sensitive_text(response.text, max_chars=500)}")

        try:
            data = response.json()
        except ValueError as exc:
            raise WebhookError(f"Webhook response is not valid JSON: {self.redact_sensitive_text(response.text, max_chars=200)}") from exc

        # Azure Automation webhook response: { "JobIds": ["<uuid>"] }
        job_ids = data.get("JobIds", [])
        if not job_ids:
            raise WebhookError(f"Webhook response did not contain JobIds: {self.redact_sensitive_text(data, max_chars=500)}")

        return job_ids[0]

    # -----------------------------------------------------------------------
    # Job polling
    # -----------------------------------------------------------------------

    def _job_url(self, job_id: str) -> str:
        """Build the Management API URL for a specific job."""
        path = JOB_API_PATH.format(
            subscription_id=self._subscription_id,
            resource_group=self._resource_group,
            automation_account=self._automation_account,
            job_id=job_id,
        )
        return f"{MGMT_BASE}{path}?api-version={MGMT_API_VERSION}"

    def _job_output_url(self, job_id: str) -> str:
        """Build the Management API URL for a job's output."""
        path = JOB_OUTPUT_API_PATH.format(
            subscription_id=self._subscription_id,
            resource_group=self._resource_group,
            automation_account=self._automation_account,
            job_id=job_id,
        )
        return f"{MGMT_BASE}{path}?api-version={MGMT_API_VERSION}"

    def _mgmt_headers(self) -> dict:
        """Return headers for Azure Management API requests."""
        return {
            "Authorization": f"Bearer {self.get_mgmt_token()}",
            "Content-Type": "application/json",
        }

    def poll_job(self, job_id: str, deadline: Optional[float] = None) -> str:
        """
        Poll the job status until it reaches a terminal state.

        Reference:
        https://learn.microsoft.com/en-us/rest/api/automation/job/get

        Args:
            job_id: Azure Automation Job ID.

        Returns:
            Terminal status string (e.g. "Completed").

        Raises:
            JobTimeoutError if poll_timeout is exceeded.
            JobFailedError  if the job reaches a failure state.
            AutomationError on HTTP errors.
        """
        url = self._job_url(job_id)
        if deadline is None:
            deadline = self.new_poll_deadline()
        token_refreshed = False
        last_transient_error = None
        last_status = ""
        throttle_retries = 0

        while time.time() < deadline:
            try:
                response = self._session.get(
                    url,
                    headers=self._mgmt_headers(),
                    timeout=15,
                    verify=True,
                )
            except requests.exceptions.RequestException as exc:
                # Transient network errors should not kill the whole action -
                # keep retrying within the deadline.
                last_transient_error = type(exc).__name__
                self._sleep_for_retry(self._poll_interval, deadline)
                continue

            if not response.ok:
                if response.status_code == HTTP_TOO_MANY_REQUESTS:
                    delay = self._throttle_delay(response, throttle_retries)
                    throttle_retries += 1
                    last_transient_error = AutomationError(f"Job status API returned HTTP 429 throttling response; retrying after {delay:g}s.")
                    self._sleep_for_retry(delay, deadline)
                    continue
                if response.status_code == 403:
                    raise AutomationError(
                        "Job status API returned HTTP 403 (AuthorizationFailed). "
                        "The App Registration is missing the 'Automation Job Operator' "
                        "role on the Automation Account. In the Azure Portal, go to the "
                        "Automation Account -> Access control (IAM) -> Add role assignment, "
                        "assign 'Automation Job Operator' to the App Registration "
                        "(azure_client_id), then wait 2-3 minutes for propagation."
                    )
                if response.status_code == 401:
                    # The cached token may have expired mid-poll. Refresh once.
                    if not token_refreshed:
                        self._mgmt_token = None
                        token_refreshed = True
                        continue
                    raise AutomationError(
                        "Job status API returned HTTP 401 even after refreshing the "
                        "Azure AD token. Check azure_client_id, azure_client_secret "
                        "and azure_tenant_id in the asset settings."
                    )
                if response.status_code == 404:
                    raise AutomationError(
                        "Job status API returned HTTP 404. Check azure_subscription_id, "
                        "azure_resource_group and azure_automation_account in the asset "
                        "settings - one of them does not match the actual Automation Account."
                    )
                raise AutomationError(
                    f"Job status API returned HTTP {response.status_code}: {self.redact_sensitive_text(response.text, max_chars=500)}"
                )

            try:
                properties = response.json()["properties"]
                status = properties["status"]
                last_status = status
            except (ValueError, KeyError) as exc:
                raise AutomationError(f"Unexpected job status response: {self.redact_sensitive_text(response.text, max_chars=200)}") from exc

            if status in JOB_TERMINAL_STATES:
                if status in JOB_FAILURE_STATES:
                    # Include the PowerShell exception from the job properties
                    # so the user does not have to open the Azure Portal.
                    exception_detail = properties.get("exception", "")
                    detail = f": {exception_detail}" if exception_detail else ""
                    raise JobFailedError(f"Job {job_id} reached failure state '{status}'{detail}")
                return status

            self._sleep_for_retry(self._poll_interval, deadline)

        timeout_detail = ""
        if last_transient_error is not None:
            timeout_detail = f" (repeated network errors during polling, last: {last_transient_error})"
        raise JobTimeoutError(
            f"Job {job_id} did not complete within {self._poll_timeout}s{timeout_detail}",
            job_id=job_id,
            last_status=last_status,
            phase="status",
        )

    def get_job_status(self, job_id: str, deadline: Optional[float] = None) -> dict:
        """
        Read the current Azure Automation job state once.

        This method never starts a webhook and never waits for the job to
        change state.  HTTP 429 and one stale-token 401 are retried because
        they do not change that read-only contract.
        """
        url = self._job_url(job_id)
        if deadline is None:
            deadline = self.new_poll_deadline()
        token_refreshed = False
        throttle_retries = 0

        while time.time() < deadline:
            try:
                response = self._session.get(
                    url,
                    headers=self._mgmt_headers(),
                    timeout=15,
                    verify=True,
                )
            except requests.exceptions.RequestException as exc:
                raise AutomationError(
                    self._transport_error_message(
                        "Job status request failed",
                        exc,
                    )
                ) from exc

            if response.status_code == HTTP_TOO_MANY_REQUESTS:
                delay = self._throttle_delay(response, throttle_retries)
                throttle_retries += 1
                self._sleep_for_retry(delay, deadline)
                continue
            if response.status_code == 401 and not token_refreshed:
                self._mgmt_token = None
                token_refreshed = True
                continue
            if response.status_code == 403:
                raise AutomationError(
                    "Job status API returned HTTP 403 (AuthorizationFailed). "
                    "The App Registration is missing the 'Automation Job Operator' "
                    "role on the Automation Account."
                )
            if response.status_code == 401:
                raise AutomationError(
                    "Job status API returned HTTP 401 even after refreshing the "
                    "Azure AD token. Check azure_client_id, azure_client_secret "
                    "and azure_tenant_id in the asset settings."
                )
            if response.status_code == 404:
                raise AutomationError("Job status API returned HTTP 404. Verify the Azure job ID and Automation Account coordinates.")
            if not response.ok:
                raise AutomationError(
                    f"Job status API returned HTTP {response.status_code}: {self.redact_sensitive_text(response.text, max_chars=500)}"
                )

            try:
                properties = response.json()["properties"]
                status = properties["status"]
            except (ValueError, KeyError, TypeError) as exc:
                raise AutomationError(f"Unexpected job status response: {self.redact_sensitive_text(response.text, max_chars=200)}") from exc

            if not isinstance(status, str) or not status:
                raise AutomationError("Unexpected job status response: properties.status must be a non-empty string.")
            return {
                "status": status,
                "exception": str(properties.get("exception", "") or ""),
            }

        raise JobTimeoutError(
            f"Job status for {job_id} was throttled by Azure Automation until the {self._poll_timeout}s polling timeout expired.",
            job_id=job_id,
            last_status="unknown",
            phase="reconcile_status",
        )

    # -----------------------------------------------------------------------
    # Job output
    # -----------------------------------------------------------------------

    def get_job_output(
        self,
        job_id: str,
        action: Optional[str] = None,
        deadline: Optional[float] = None,
    ) -> dict:
        """
        Retrieve and parse the job's Write-Output content.

        The public contract remains one parsed dict for every action. Legacy
        runbooks write one JSON object. Newer runbooks may write chunked export
        records; those are verified and normalised back to one export dict here.

        Reference:
        https://learn.microsoft.com/en-us/rest/api/automation/job/get-output

        Args:
            job_id: Azure Automation Job ID.

        Returns:
            Parsed dict from the runbook's Write-Output.

        Raises:
            AutomationError on HTTP errors or parse failure.
        """
        url = self._job_output_url(job_id)

        if deadline is None:
            deadline = self.new_poll_deadline()
        throttle_retries = 0

        while time.time() < deadline:
            try:
                response = self._session.get(
                    url,
                    headers=self._mgmt_headers(),
                    timeout=30,
                    verify=True,
                )
            except requests.exceptions.RequestException as exc:
                raise AutomationError(
                    self._transport_error_message(
                        "Job output request failed",
                        exc,
                    )
                ) from exc

            if response.status_code != HTTP_TOO_MANY_REQUESTS:
                break

            delay = self._throttle_delay(response, throttle_retries)
            throttle_retries += 1
            self._sleep_for_retry(delay, deadline)
        else:
            raise JobTimeoutError(
                f"Job output for {job_id} was throttled by Azure Automation until the {self._poll_timeout}s polling timeout expired.",
                job_id=job_id,
                last_status="Completed",
                phase="output",
            )

        if not response.ok:
            if response.status_code == 403:
                raise AutomationError(
                    "Job output API returned HTTP 403 (AuthorizationFailed). "
                    "The App Registration is missing the 'Automation Job Operator' "
                    "role on the Automation Account."
                )
            raise AutomationError(
                f"Job output API returned HTTP {response.status_code}: {self.redact_sensitive_text(response.text, max_chars=500)}"
            )

        raw = response.text.strip()
        if not raw:
            raise AutomationError(f"Job {job_id} produced no output. Check the runbook for errors.")

        self._raise_if_stream_limit(raw, action=action)

        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise AutomationError(f"Job output JSON must be an object. Got {type(parsed).__name__}.")
            if parsed.get("mode") in {
                LIST_CHUNK_MODE,
                LIST_COMPLETE_MODE,
                CHUNKED_EXPORT_MODE,
                CHUNKED_COMPLETE_MODE,
                ERROR_CHUNK_MODE,
                ERROR_COMPLETE_MODE,
            }:
                return self._parse_multiline_job_output(raw)
            return parsed
        except ValueError:
            return self._parse_multiline_job_output(raw)

    def _raise_if_stream_limit(self, raw: str, action: Optional[str] = None):
        """Surface Azure Automation's per-stream limit as an actionable error."""
        if AZURE_STREAM_LIMIT_MESSAGE in raw:
            if action == "list":
                raise AutomationError(
                    "Azure Automation rejected an oversized list output record. "
                    "Deploy the runbook version that supports bounded list chunks; "
                    "export chunking does not repair list output."
                )
            raise AutomationError(
                "Azure Automation job output exceeded the 1 MiB stream limit. "
                "Use the protocol minimum 3.3.4 runbook or newer for bounded list/chunked export "
                "protocol (recommended pair: App 3.7.4 / Runbook 3.4.5) and "
                "retry the action."
            )

    def _json_dict_lines(self, raw: str) -> list:
        """Return JSON object lines from mixed Automation output."""
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        return records

    def _parse_multiline_job_output(self, raw: str) -> dict:
        """
        Parse mixed Automation output.

        Non-JSON lines are treated as verbose/noise. Bounded list and chunked
        export records are reconstructed only when their completion trailer is
        present and every record passes the protocol checks.
        """
        records = self._json_dict_lines(raw)
        if not records:
            raise AutomationError(
                f"Could not parse job output as JSON. "
                "Raw output could not be parsed after secret redaction: "
                f"{self.redact_sensitive_text(raw, max_chars=500)}"
            )

        error_records = [record for record in records if record.get("mode") in {ERROR_CHUNK_MODE, ERROR_COMPLETE_MODE}]
        has_error_complete = any(record.get("mode") == ERROR_COMPLETE_MODE for record in error_records)
        has_error_chunk = any(record.get("mode") == ERROR_CHUNK_MODE for record in error_records)
        standalone_error_records = [
            record
            for record in records
            if record.get("error") is True
            and record.get("mode")
            not in {
                ERROR_CHUNK_MODE,
                ERROR_COMPLETE_MODE,
            }
        ]
        if (has_error_complete or has_error_chunk) and standalone_error_records:
            raise AutomationError("Chunked error output contains a second standalone error envelope.")
        if has_error_complete:
            return self._parse_chunked_error_records(error_records)
        if has_error_chunk:
            raise AutomationError("Chunked error output is incomplete: missing mode=error_complete trailer.")

        for record in records:
            if record.get("error"):
                return record

        list_records = [
            record for record in records if record.get("action") == "list" and record.get("mode") in {LIST_CHUNK_MODE, LIST_COMPLETE_MODE}
        ]
        has_list_complete = any(record.get("mode") == LIST_COMPLETE_MODE for record in list_records)
        has_list_chunk = any(record.get("mode") == LIST_CHUNK_MODE for record in list_records)
        if has_list_complete:
            return self._parse_chunked_list_records(list_records)
        if has_list_chunk:
            raise AutomationError("Chunked list output is incomplete: missing action=list mode=list_complete trailer.")

        chunk_records = [
            record
            for record in records
            if record.get("action") == "export" and record.get("mode") in {CHUNKED_EXPORT_MODE, CHUNKED_COMPLETE_MODE}
        ]

        has_chunked_complete = any(record.get("mode") == CHUNKED_COMPLETE_MODE for record in chunk_records)
        has_chunk = any(record.get("mode") == CHUNKED_EXPORT_MODE for record in chunk_records)

        if has_chunked_complete:
            return self._parse_chunked_export_records(chunk_records)

        if has_chunk:
            raise AutomationError("Chunked export output is incomplete: missing action=export mode=chunked_complete trailer.")

        # Legacy behaviour: verbose output before a single final JSON object.
        return records[-1]

    def _parse_chunked_error_records(self, records: list) -> dict:
        """Verify and restore one exact UTF-8 runbook error envelope."""
        complete_records = [record for record in records if record.get("mode") == ERROR_COMPLETE_MODE]
        if len(complete_records) != 1:
            raise AutomationError("Chunked error output must contain exactly one mode=error_complete trailer.")

        complete = complete_records[0]
        if complete.get("error") is not True:
            raise AutomationError("Chunked error trailer must declare error=true.")
        action = self._required_string(complete, "action", "chunked error trailer")
        encoding = self._required_string(complete, "encoding", "chunked error trailer")
        if encoding != CHUNK_ENCODING:
            raise AutomationError(f"Chunked error uses unsupported encoding '{encoding}'.")
        chunk_count = self._required_int(complete, "chunk_count", "chunked error trailer")
        payload_base64_length = self._required_int(complete, "payload_base64_length", "chunked error trailer")
        payload_utf8_bytes = self._required_int(complete, "payload_utf8_bytes", "chunked error trailer")
        expected_sha256 = self._required_string(complete, "payload_sha256", "chunked error trailer")
        runbook_version = self._validate_runbook_version(complete, "chunked error trailer")
        build_metadata = {
            "runbook_source_revision": complete["runbook_source_revision"],
            "runbook_build_id": complete["runbook_build_id"],
        }

        if chunk_count < 1 or chunk_count > MAX_ERROR_CHUNK_COUNT:
            raise AutomationError(f"Chunked error chunk_count must be between 1 and {MAX_ERROR_CHUNK_COUNT}.")
        if payload_utf8_bytes < 1 or payload_utf8_bytes > MAX_ERROR_ENVELOPE_BYTES:
            raise AutomationError("Chunked error payload_utf8_bytes exceeds the supported error-envelope limit.")
        max_base64_length = ((MAX_ERROR_ENVELOPE_BYTES + 2) // 3) * 4
        if payload_base64_length < 1 or payload_base64_length > max_base64_length:
            raise AutomationError("Chunked error payload_base64_length exceeds the supported error-envelope limit.")
        if not SHA256_HEX_RE.match(expected_sha256):
            raise AutomationError("Chunked error payload_sha256 must be lowercase 64-character hex.")

        chunks = [record for record in records if record.get("mode") == ERROR_CHUNK_MODE]
        if len(chunks) != chunk_count:
            raise AutomationError(f"Chunked error expected {chunk_count} chunk(s), got {len(chunks)}.")

        indexed_chunks = {}
        for chunk in chunks:
            if chunk.get("error") is not True:
                raise AutomationError("Chunked error record must declare error=true.")
            if self._required_string(chunk, "action", "error chunk") != action:
                raise AutomationError("Chunked error action mismatch.")
            if self._required_string(chunk, "encoding", "error chunk") != CHUNK_ENCODING:
                raise AutomationError("Chunked error record uses an unsupported encoding.")
            chunk_version = self._validate_runbook_version(chunk, "chunked error record")
            if chunk_version != runbook_version or any(chunk.get(field) != value for field, value in build_metadata.items()):
                raise AutomationError("Chunked error runbook build metadata mismatch.")
            if self._required_int(chunk, "chunk_count", "error chunk") != chunk_count:
                raise AutomationError("Chunked error chunk_count mismatch.")
            idx = self._required_int(chunk, "chunk_index", "error chunk")
            if idx < 0 or idx >= chunk_count:
                raise AutomationError(f"Chunked error chunk_index {idx} is out of range.")
            if idx in indexed_chunks:
                raise AutomationError(f"Chunked error contains duplicate chunk_index {idx}.")
            indexed_chunks[idx] = self._required_string(chunk, "payload_chunk", "error chunk")

        missing = [idx for idx in range(chunk_count) if idx not in indexed_chunks]
        if missing:
            raise AutomationError("Chunked error is missing chunk_index value(s): " + ", ".join(str(idx) for idx in missing))

        encoded = "".join(indexed_chunks[idx] for idx in range(chunk_count))
        if len(encoded) != payload_base64_length:
            raise AutomationError(f"Chunked error payload_base64_length mismatch: expected {payload_base64_length}, got {len(encoded)}.")
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AutomationError("Chunked error payload is not valid base64.") from exc
        if len(payload) != payload_utf8_bytes:
            raise AutomationError(f"Chunked error payload_utf8_bytes mismatch: expected {payload_utf8_bytes}, got {len(payload)}.")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise AutomationError("Chunked error payload_sha256 mismatch after reassembly.")
        try:
            restored = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AutomationError("Chunked error payload is not a UTF-8 JSON object.") from exc
        if not isinstance(restored, dict) or restored.get("error") is not True:
            raise AutomationError("Chunked error payload must restore an object with error=true.")
        if restored.get("action") != action:
            raise AutomationError("Restored chunked error action mismatch.")
        if restored.get("mode") is not None:
            raise AutomationError("Restored chunked error envelope must not contain a mode.")
        if restored.get("runbook_version") != runbook_version or any(restored.get(field) != value for field, value in build_metadata.items()):
            raise AutomationError("Restored chunked error runbook build metadata mismatch.")
        return restored

    def _parse_chunked_list_records(self, records: list) -> dict:
        """Validate bounded list records and normalise them to one list result."""
        complete_records = [record for record in records if record.get("action") == "list" and record.get("mode") == LIST_COMPLETE_MODE]
        if len(complete_records) != 1:
            raise AutomationError("Chunked list output must contain exactly one action=list mode=list_complete trailer.")

        complete = complete_records[0]
        chunk_count = self._required_int(complete, "chunk_count", "chunked list trailer")
        expected_count = self._required_int(complete, "count", "chunked list trailer")
        runbook_version = self._validate_runbook_version(complete, "chunked list trailer")
        self._validate_selection_evidence(complete)
        selection_metadata = {
            key: complete[key]
            for key in (
                "quarantine_selection_mode",
                "quarantine_selection_contract",
                "selection_release_status",
            )
            if key in complete
        }
        build_metadata = {
            "runbook_source_revision": complete["runbook_source_revision"],
            "runbook_build_id": complete["runbook_build_id"],
        }

        if chunk_count < 1 or chunk_count > MAX_LIST_RESULT_COUNT:
            raise AutomationError(f"Chunked list chunk_count must be between 1 and {MAX_LIST_RESULT_COUNT}.")
        if expected_count < 1 or expected_count > MAX_LIST_RESULT_COUNT:
            raise AutomationError(f"Chunked list count must be between 1 and {MAX_LIST_RESULT_COUNT}.")

        chunks = [record for record in records if record.get("action") == "list" and record.get("mode") == LIST_CHUNK_MODE]
        if len(chunks) != chunk_count:
            raise AutomationError(f"Chunked list expected {chunk_count} chunk(s), got {len(chunks)}.")

        indexed_chunks = {}
        for chunk in chunks:
            self._validate_selection_evidence(chunk)
            chunk_version = self._validate_runbook_version(chunk, "chunked list record")
            if chunk_version != runbook_version:
                raise AutomationError("Chunked list runbook_version mismatch.")
            if any(chunk.get(field) != value for field, value in build_metadata.items()):
                raise AutomationError("Chunked list runbook build metadata mismatch.")

            idx = self._required_int(chunk, "chunk_index", "chunked list record")
            if idx < 0 or idx >= chunk_count:
                raise AutomationError(f"Chunked list chunk_index {idx} is out of range.")
            if idx in indexed_chunks:
                raise AutomationError(f"Chunked list contains duplicate chunk_index {idx}.")

            messages = chunk.get("messages")
            if not isinstance(messages, list) or not messages:
                raise AutomationError("Chunked list record messages must be a non-empty array.")
            if any(not isinstance(message, dict) for message in messages):
                raise AutomationError("Chunked list record messages must contain only objects.")
            indexed_chunks[idx] = messages

        missing = [idx for idx in range(chunk_count) if idx not in indexed_chunks]
        if missing:
            raise AutomationError("Chunked list is missing chunk_index value(s): " + ", ".join(str(idx) for idx in missing))

        messages = []
        for idx in range(chunk_count):
            messages.extend(indexed_chunks[idx])
        if len(messages) != expected_count:
            raise AutomationError(f"Chunked list count mismatch: expected {expected_count}, got {len(messages)}.")

        return {
            "action": "list",
            "count": expected_count,
            "messages": messages,
            "runbook_version": runbook_version,
            **build_metadata,
            **selection_metadata,
        }

    def _parse_chunked_export_records(self, records: list) -> dict:
        """Validate and normalise chunked export output to one export dict."""
        complete_records = [record for record in records if record.get("action") == "export" and record.get("mode") == CHUNKED_COMPLETE_MODE]
        if len(complete_records) != 1:
            raise AutomationError("Chunked export output must contain exactly one action=export mode=chunked_complete trailer.")

        complete = complete_records[0]
        identity = self._required_string(complete, "identity", "chunked trailer")
        chunk_count = self._required_int(complete, "chunk_count", "chunked trailer")
        eml_base64_length = self._required_int(complete, "eml_base64_length", "chunked trailer")
        decoded_size = self._required_int(complete, "decoded_size", "chunked trailer")
        expected_sha256 = self._required_string(complete, "sha256", "chunked trailer")
        runbook_version = self._validate_runbook_version(complete, "chunked trailer")
        build_metadata = {
            "runbook_source_revision": complete["runbook_source_revision"],
            "runbook_build_id": complete["runbook_build_id"],
        }

        if chunk_count < 1:
            raise AutomationError("Chunked export chunk_count must be at least 1.")
        if chunk_count > MAX_CHUNK_COUNT:
            raise AutomationError(f"Chunked export chunk_count {chunk_count} exceeds the supported maximum of {MAX_CHUNK_COUNT}.")
        if decoded_size < 0:
            raise AutomationError("Chunked export decoded_size must not be negative.")
        if decoded_size > MAX_DECODED_EML_BYTES:
            raise AutomationError(
                f"Chunked export decoded EML size {decoded_size} bytes exceeds the supported maximum of {MAX_DECODED_EML_BYTES} bytes."
            )
        if self._retain_chunked_base64 and decoded_size > MAX_INLINE_DECODED_EML_BYTES:
            raise AutomationError(
                f"Inline export is limited to {MAX_INLINE_DECODED_EML_BYTES} decoded bytes. Set export_mode=vault for larger EML files."
            )
        max_base64_length = ((MAX_DECODED_EML_BYTES + 2) // 3) * 4
        if eml_base64_length > max_base64_length:
            raise AutomationError(f"Chunked export base64 length {eml_base64_length} exceeds the maximum possible length {max_base64_length}.")
        if not SHA256_HEX_RE.match(expected_sha256):
            raise AutomationError("Chunked export trailer sha256 must be lowercase 64-character hex.")
        chunks = [record for record in records if record.get("action") == "export" and record.get("mode") == CHUNKED_EXPORT_MODE]
        if len(chunks) != chunk_count:
            raise AutomationError(f"Chunked export expected {chunk_count} chunk(s), got {len(chunks)}.")

        indexed_chunks = {}
        for chunk in chunks:
            chunk_version = self._validate_runbook_version(chunk, "chunked export record")
            if chunk_version != runbook_version or any(chunk.get(field) != value for field, value in build_metadata.items()):
                raise AutomationError("Chunked export runbook build metadata mismatch.")
            if self._required_string(chunk, "identity", "chunk") != identity:
                raise AutomationError("Chunked export identity mismatch.")

            encoding = self._required_string(chunk, "encoding", "chunk")
            if encoding != CHUNK_ENCODING:
                raise AutomationError(f"Chunked export uses unsupported encoding '{encoding}'.")

            idx = self._required_int(chunk, "chunk_index", "chunk")
            record_chunk_count = self._required_int(chunk, "chunk_count", "chunk")
            if record_chunk_count != chunk_count:
                raise AutomationError("Chunked export chunk_count mismatch.")
            if idx < 0 or idx >= chunk_count:
                raise AutomationError(f"Chunked export chunk_index {idx} is out of range.")
            if idx in indexed_chunks:
                raise AutomationError(f"Chunked export contains duplicate chunk_index {idx}.")

            indexed_chunks[idx] = self._required_string(chunk, "eml_chunk", "chunk")

        missing = [idx for idx in range(chunk_count) if idx not in indexed_chunks]
        if missing:
            raise AutomationError("Chunked export is missing chunk_index value(s): " + ", ".join(str(idx) for idx in missing))

        actual_base64_length = sum(len(indexed_chunks[idx]) for idx in range(chunk_count))
        if actual_base64_length != eml_base64_length:
            raise AutomationError(f"Chunked export eml_base64_length mismatch: expected {eml_base64_length}, got {actual_base64_length}.")

        eml_bytes = bytearray()
        sha256 = hashlib.sha256()
        for idx in range(chunk_count):
            encoded_chunk = indexed_chunks[idx]
            if len(encoded_chunk) % 4 != 0:
                raise AutomationError(f"Chunked export chunk_index {idx} length is not divisible by four.")
            try:
                decoded_chunk = base64.b64decode(encoded_chunk, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise AutomationError(f"Chunked export produced invalid base64 EML in chunk_index {idx}: {exc}") from exc
            eml_bytes.extend(decoded_chunk)
            sha256.update(decoded_chunk)

        if len(eml_bytes) != decoded_size:
            raise AutomationError(f"Chunked export decoded_size mismatch: expected {decoded_size}, got {len(eml_bytes)}.")

        actual_sha256 = sha256.hexdigest()
        if actual_sha256 != expected_sha256:
            raise AutomationError("Chunked export sha256 mismatch after reassembly.")

        result = {
            "action": "export",
            "mode": CHUNKED_EXPORT_MODE,
            "identity": identity,
            "chunk_count": chunk_count,
            "eml_base64_length": eml_base64_length,
            "decoded_size": len(eml_bytes),
            "sha256": actual_sha256,
            "runbook_version": runbook_version,
            **build_metadata,
            "_eml_bytes": eml_bytes,
        }
        if self._retain_chunked_base64:
            result["eml"] = "".join(indexed_chunks[idx] for idx in range(chunk_count))
        return result

    def _required_string(self, data: dict, key: str, where: str) -> str:
        val = data.get(key)
        if val is None:
            raise AutomationError(f"{where} missing required field '{key}'.")
        val = str(val)
        if val == "":
            raise AutomationError(f"{where} field '{key}' is empty.")
        return val

    def _required_int(self, data: dict, key: str, where: str) -> int:
        val = data.get(key)
        if isinstance(val, bool) or val is None:
            raise AutomationError(f"{where} missing numeric field '{key}'.")
        try:
            return parse_strict_integer(val)
        except (TypeError, ValueError) as exc:
            raise AutomationError(f"{where} field '{key}' is not numeric.") from exc

    @staticmethod
    def _canonical_quarantine_identity(value):
        """Return strict GUID\\GUID identity in case-insensitive form."""
        if not isinstance(value, str) or len(value) > 73:
            return None
        parts = value.split("\\")
        if len(parts) != 2 or not all(GUID_RE.fullmatch(part) for part in parts):
            return None
        return "\\".join(part.lower() for part in parts)

    @classmethod
    def _quarantine_identities_match(cls, left, right) -> bool:
        canonical_left = cls._canonical_quarantine_identity(left)
        canonical_right = cls._canonical_quarantine_identity(right)
        return bool(canonical_left and canonical_right and canonical_left == canonical_right)

    # -----------------------------------------------------------------------
    # Combined: run a full action
    # -----------------------------------------------------------------------

    def run_action(
        self,
        action: str,
        identity: Optional[str] = None,
        page_size: Optional[int] = None,
        operation_action: Optional[str] = None,
        include_rbac: Optional[bool] = None,
    ) -> dict:
        """
        Execute a full action cycle: webhook → poll → output.

        Args:
            action:    One of: list, export, diagnose, release, deny.
            identity:  Required for export, diagnose, release, deny.
            page_size: Optional max number of messages for the list action.

        Returns:
            Parsed JSON dict from the runbook's Write-Output.

        Raises:
            WebhookError, JobTimeoutError, JobFailedError, AutomationError.
        """
        job_id = self.fire_webhook(
            action,
            identity,
            page_size,
            operation_action=operation_action,
            include_rbac=include_rbac,
        )
        return self.wait_for_action_result(
            job_id,
            action,
            identity,
            requested_include_rbac=include_rbac,
            requested_operation_action=operation_action,
        )

    def wait_for_action_result(
        self,
        job_id: str,
        action: str,
        identity: Optional[str] = None,
        requested_include_rbac: Optional[bool] = None,
        requested_operation_action: Optional[str] = None,
    ) -> dict:
        """
        Wait for and validate a job that has already been started.

        Separating webhook creation from completion lets the connector persist
        the Azure job ID before it waits on an irreversible release or deny.
        """
        deadline = self.new_poll_deadline()
        try:
            self.poll_job(job_id, deadline=deadline)
        except JobFailedError as job_error:
            # Runbook 3.1.3 and older can emit a structured application error
            # and then exit non-zero. Azure may preserve that output even when
            # the job state is Failed. Read and validate it before falling
            # back to the transport-level job failure.
            try:
                failed_result = self.get_job_output(
                    job_id,
                    action=action,
                    deadline=deadline,
                )
            except AutomationError as output_error:
                raise JobFailedError(f"{job_error}; structured job output was unavailable: {output_error}") from job_error

            if isinstance(failed_result, dict) and failed_result.get("error") is True:
                self._validate_runbook_result(
                    failed_result,
                    requested_action=action,
                    requested_identity=identity,
                    requested_include_rbac=requested_include_rbac,
                    requested_operation_action=requested_operation_action,
                )
                self._raise_for_runbook_error(
                    failed_result,
                    requested_action=action,
                    requested_identity=identity,
                )
            raise job_error

        result = self.get_job_output(
            job_id,
            action=action,
            deadline=deadline,
        )
        self._validate_runbook_result(
            result,
            requested_action=action,
            requested_identity=identity,
            requested_include_rbac=requested_include_rbac,
            requested_operation_action=requested_operation_action,
        )
        self._raise_for_runbook_error(
            result,
            requested_action=action,
            requested_identity=identity,
        )
        return result

    def get_validated_job_output(
        self,
        job_id: str,
        action: str,
        identity: Optional[str] = None,
        deadline: Optional[float] = None,
    ) -> dict:
        """Read and validate an existing job output without firing a webhook."""
        result = self.get_job_output(
            job_id,
            action=action,
            deadline=deadline,
        )
        self._validate_runbook_result(
            result,
            requested_action=action,
            requested_identity=identity,
        )
        self._raise_for_runbook_error(
            result,
            requested_action=action,
            requested_identity=identity,
        )
        return result

    def verify_connection_contract(self) -> dict:
        """
        Read-only check that the deployed runbook connects to Exchange Online
        with its Managed Identity and applies the configured organization.

        It performs no Exchange connection and no mailbox/quarantine write and
        must succeed before any irreversible webhook is sent. A runbook older
        than 3.4.2 (which answers "Unknown action" or may still offer other
        sign-in modes) therefore never receives a release/deny.
        """
        if self._connection_contract_verified:
            return dict(self._connection_settings)
        try:
            result = self.run_action("config_check")
        except AutomationError as exc:
            required_version = "3.4.3" if self.quarantine_selection_mode == "needs_review" else "3.4.2"
            raise ConnectionContractError(
                "The deployed runbook could not confirm the Managed "
                "Identity-only Exchange connection and selected mode, so "
                "no irreversible action was sent and no subsequent list "
                f"was sent. Publish Runbook {required_version} or newer (protocol "
                "minimum; recommended App 3.7.4 / Runbook 3.4.5) to the same "
                "Automation Account first; older runbooks answer 'Unknown "
                "action' or may still support other sign-in modes. Cause: "
                f"{self.redact_sensitive_text(exc)}"
            ) from exc

        mismatches = []
        if result.get("exchange_auth_method") != EXCHANGE_AUTH_METHOD or result.get("exchange_auth_method_source") != "webhook":
            mismatches.append("auth_method")
        requested_org = self._connection_settings.get("organization")
        expected_org_source = "webhook" if requested_org else ("automation_variable")
        if (requested_org and result.get("exchange_organization") != requested_org) or result.get(
            "exchange_organization_source"
        ) != expected_org_source:
            mismatches.append("organization")
        if mismatches:
            raise ConnectionContractError(
                "The runbook reports different effective Exchange settings "
                f"than sent ({', '.join(mismatches)}); no irreversible "
                "action was sent."
            )
        self._connection_contract_verified = True
        return result

    @staticmethod
    def _runbook_version_tuple(source: dict):
        version = source.get("runbook_version") if isinstance(source, dict) else None
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version) if isinstance(version, str) else None
        return tuple(int(part) for part in match.groups()) if match else None

    @staticmethod
    def _reject_credential_evidence(source: dict, where: str) -> None:
        """A Managed-Identity-only runbook never reports credential evidence."""
        for field in ("exchange_credential_name", "exchange_credential_source"):
            if field in source:
                raise AutomationError(
                    "Runbook protocol error: "
                    f"{where} reports unsupported credential evidence "
                    f"('{field}'); Exchange authentication is "
                    "ManagedIdentity only."
                )

    def _validate_selection_evidence(self, result: dict) -> None:
        if self.quarantine_selection_mode == "release_requested":
            # Pairing with the original 3.4.2 remains supported for this mode.
            if "quarantine_selection_mode" not in result:
                return
        if (
            result.get("quarantine_selection_contract") != QUARANTINE_SELECTION_CONTRACT
            or result.get("quarantine_selection_mode") != self.quarantine_selection_mode
            or result.get("selection_release_status") != self.selection_release_status
        ):
            raise AutomationError(
                "Runbook quarantine selection contract mismatch with the "
                f"current asset mode '{self.quarantine_selection_mode}'. "
                "When reconciling an existing operation, restore its original "
                "asset selection mode first; a newer runbook does not change "
                "stored job output. For new operations, verify protocol minimum "
                "Runbook 3.4.3 or newer and matching mode; recommended pair: "
                "App 3.7.4 / Runbook 3.4.5. No selection is inferred."
            )

    def _validate_config_check_result(self, result: dict) -> None:
        """Validate the read-only connection contract report."""
        version = self._validate_runbook_version(result, "config_check result")
        if self._runbook_version_tuple(result) < MANAGED_IDENTITY_ONLY_RUNBOOK_VERSION:
            raise AutomationError(
                "Runbook protocol error: config_check result comes from "
                f"runbook {version}; the Managed Identity-only Exchange "
                "connection requires Runbook 3.4.2 or newer (protocol minimum; "
                "recommended pair: App 3.7.4 / Runbook 3.4.5)."
            )
        if result.get("status") != "verified" or result.get("config_contract") != EXCHANGE_CONFIG_CONTRACT:
            raise AutomationError(f"Runbook protocol error: config_check result lacks config_contract={EXCHANGE_CONFIG_CONTRACT}.")
        for field in (
            "exchange_auth_method",
            "exchange_auth_method_source",
            "exchange_organization",
            "exchange_organization_source",
        ):
            value = result.get(field)
            if not isinstance(value, str) or len(value) > MAX_RUNBOOK_SETTING_CHARS:
                raise AutomationError(f"Runbook protocol error: config_check result requires bounded string field '{field}'.")
        self._validate_selection_evidence(result)
        self._reject_credential_evidence(result, "config_check result")
        if result.get("exchange_auth_method") != EXCHANGE_AUTH_METHOD:
            raise AutomationError(
                "Runbook protocol error: config_check result does not report ManagedIdentity as the Exchange authentication method."
            )

    def _validate_runbook_version(self, result: dict, where: str) -> str:
        """Require a semantic runbook version at or above the app minimum."""
        runbook_version = self._required_string(result, "runbook_version", where)
        version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", runbook_version)
        if not version_match:
            raise AutomationError(f"{where} runbook_version must use semantic versioning.")

        version_tuple = tuple(int(part) for part in version_match.groups())
        if version_tuple < MIN_SUPPORTED_RUNBOOK_VERSION:
            required = ".".join(str(part) for part in MIN_SUPPORTED_RUNBOOK_VERSION)
            raise AutomationError(
                f"{where} requires runbook {required} or newer; received {runbook_version}. Deploy the app and runbook together."
            )
        for field in ("runbook_source_revision", "runbook_build_id"):
            value = self._required_string(result, field, where)
            if len(value) > MAX_BUILD_FIELD_CHARS or not BUILD_FIELD_RE.match(value):
                raise AutomationError(f"{where} field '{field}' has an invalid build identifier.")
        return runbook_version

    @staticmethod
    def _supports_connection_contract(source: dict) -> bool:
        version = MSQuarantineForSplunkSOARUtils._runbook_version_tuple(source)
        return bool(version and version >= CONNECTION_CONTRACT_RUNBOOK_VERSION)

    @staticmethod
    def _validate_connection_evidence(source: dict, where: str, require_disconnect: bool = False) -> None:
        """Validate the bounded, non-secret effective connection settings."""
        if source.get("exchange_auth_method") != EXCHANGE_AUTH_METHOD:
            raise AutomationError(f"Runbook protocol error: {where} does not report exchange_auth_method={EXCHANGE_AUTH_METHOD}.")
        managed_identity_only = (
            MSQuarantineForSplunkSOARUtils._runbook_version_tuple(source) or (0, 0, 0)
        ) >= MANAGED_IDENTITY_ONLY_RUNBOOK_VERSION
        if managed_identity_only:
            MSQuarantineForSplunkSOARUtils._reject_credential_evidence(source, where)
        allowed_method_sources = {"webhook", "default"}
        if not managed_identity_only:
            allowed_method_sources.add("automation_variable")
        allowed_sources = {
            "exchange_auth_method_source": allowed_method_sources,
            "exchange_organization_source": {"webhook", "automation_variable"},
        }
        for field, allowed in allowed_sources.items():
            if source.get(field) not in allowed:
                raise AutomationError(f"Runbook protocol error: {where} has an invalid '{field}'.")
        organization = source.get("exchange_organization")
        if not isinstance(organization, str) or not organization or len(organization) > MAX_RUNBOOK_SETTING_CHARS:
            raise AutomationError(f"Runbook protocol error: {where} requires bounded non-empty string field 'exchange_organization'.")
        for field in (
            "exchange_connection_metadata",
            "exchange_connection_metadata_error",
        ):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_ERROR_TEXT_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
        if "exchange_disconnect_status" in source or require_disconnect:
            disconnect_error = source.get("exchange_disconnect_error")
            if source.get("exchange_disconnect_status") not in {"completed", "failed"} or (
                not isinstance(disconnect_error, str) or len(disconnect_error) > MAX_ERROR_TEXT_CHARS
            ):
                raise AutomationError(f"Runbook protocol error: {where} has invalid Exchange disconnect evidence.")

    @staticmethod
    def _validate_static_diagnostics(
        source: dict,
        where: str,
        requested_action: str = "release",
        connection_contract: Optional[bool] = None,
    ) -> None:
        """Validate bounded, non-secret build/runtime/cmdlet metadata."""
        if connection_contract is None:
            connection_contract = MSQuarantineForSplunkSOARUtils._supports_connection_contract(source)
        if not isinstance(source, dict):
            raise AutomationError(f"Runbook protocol error: {where} diagnostics must be an object.")

        required_values = {
            "runbook_source_revision": MAX_BUILD_FIELD_CHARS,
            "runbook_build_id": MAX_BUILD_FIELD_CHARS,
            "powershell_version": 64,
            "powershell_edition": 32,
            "exchange_auth_method": 32,
            "exchange_online_management_version": MAX_MODULE_VERSION_CHARS,
            "cmdlet_name": 128,
            "cmdlet_contract_id": 128,
            "cmdlet_expected_argument_names": 128,
            "cmdlet_parameter_names": MAX_DIAGNOSTIC_TEXT_CHARS,
        }
        for field, max_chars in required_values.items():
            value = source.get(field)
            if not isinstance(value, str) or not value or len(value) > max_chars:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded non-empty string field '{field}'.")

        if source.get("exchange_auth_method") != EXCHANGE_AUTH_METHOD:
            raise AutomationError(f"Runbook protocol error: {where} does not report exchange_auth_method={EXCHANGE_AUTH_METHOD}.")

        for field in (
            "powershell_platform",
            "powershell_os",
            "exchange_online_management_path",
            "cmdlet_module_name",
            "cmdlet_module_version",
            "cmdlet_command_type",
            "cmdlet_default_parameter_set",
            "cmdlet_parameter_sets",
        ):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_RUNTIME_FIELD_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
        for field in ("cmdlet_metadata_error",):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_ERROR_TEXT_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} has an invalid exact error field '{field}'.")

        if connection_contract:
            MSQuarantineForSplunkSOARUtils._validate_connection_evidence(source, where)

        if requested_action == "deny":
            expected_contract_id = DENY_CONTRACT_ID
            expected_argument_names = {"Identities", "ActionType"}
            required_parameter_names = {
                "Identities",
                "ActionType",
                "ErrorAction",
            }
        else:
            expected_contract_id = RELEASE_CONTRACT_ID
            expected_argument_names = {"Identity", "ReleaseToAll"}
            required_parameter_names = {
                "Identity",
                "ReleaseToAll",
                "ErrorAction",
            }

        if source.get("cmdlet_contract_id") != expected_contract_id:
            raise AutomationError(f"Runbook protocol error: {where} has an unexpected cmdlet_contract_id.")
        supplied_argument_names = {item.strip() for item in source.get("cmdlet_expected_argument_names", "").split(",") if item.strip()}
        if supplied_argument_names != expected_argument_names:
            raise AutomationError(f"Runbook protocol error: {where} has unexpected disposition argument names.")
        parameter_names = {item.strip() for item in source.get("cmdlet_parameter_names", "").split(",") if item.strip()}
        if not required_parameter_names <= parameter_names:
            raise AutomationError(f"Runbook protocol error: {where} lacks the required effective parameter names.")
        if not source.get("cmdlet_parameter_sets") and not source.get("cmdlet_metadata_error"):
            raise AutomationError(f"Runbook protocol error: {where} requires cmdlet parameter-set metadata or an error.")

    @staticmethod
    def _validate_rbac_diagnostics(source: dict, where: str) -> None:
        """Validate bounded read-only tenant RBAC and identity evidence."""
        if source.get("permission_queries_read_only") is not True:
            raise AutomationError(f"Runbook protocol error: {where} must declare permission queries as read-only.")

        rbac_included = source.get("rbac_included")
        if not isinstance(rbac_included, bool):
            raise AutomationError(f"Runbook protocol error: {where} requires boolean field 'rbac_included'.")

        status = source.get("rbac_diagnostics_status")
        if status not in {
            "complete",
            "partial",
            "not_evaluated",
            "not_requested",
        }:
            raise AutomationError(f"Runbook protocol error: {where} has an invalid rbac_diagnostics_status.")
        claims_status = source.get("managed_identity_claims_status")
        if rbac_included and claims_status not in {
            "resolved",
            "incomplete",
            "unavailable",
            "not_applicable",
        }:
            raise AutomationError(f"Runbook protocol error: {where} has an invalid managed_identity_claims_status.")

        bounded_strings = {
            "rbac_diagnostics_reason": 128,
            "read_roles": MAX_DIAGNOSTIC_TEXT_CHARS,
            "export_roles": MAX_DIAGNOSTIC_TEXT_CHARS,
            "release_to_all_roles": MAX_DIAGNOSTIC_TEXT_CHARS,
            "release_deny_roles": MAX_DIAGNOSTIC_TEXT_CHARS,
            "quarantine_role_groups": MAX_DIAGNOSTIC_TEXT_CHARS,
            "matched_quarantine_role_groups": MAX_DIAGNOSTIC_TEXT_CHARS,
            "managed_identity_app_id": 128,
            "managed_identity_object_id": 128,
            "registered_service_principal_identity": 512,
            "registered_service_principal_app_id": 128,
            "registered_service_principal_object_id": 128,
        }
        for field, max_chars in bounded_strings.items():
            value = source.get(field, "")
            if not isinstance(value, str) or len(value) > max_chars:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
        if "managed_identity_resource_id" in source:
            raise AutomationError(f"Runbook protocol error: {where} must not persist managed_identity_resource_id.")

        empty_contracts = source.get("rbac_empty_contracts")
        allowed_empty_contracts = {
            "read_roles",
            "export_roles",
            "release_to_all_roles",
            "release_deny_roles",
            "quarantine_role",
        }
        if (
            not isinstance(empty_contracts, list)
            or not all(isinstance(value, str) and value in allowed_empty_contracts for value in empty_contracts)
            or len(empty_contracts) != len(set(empty_contracts))
        ):
            raise AutomationError(f"Runbook protocol error: {where} has invalid rbac_empty_contracts evidence.")

        required_cmdlets = [
            "Get-ManagementRole",
            "Get-ManagementRoleEntry",
            "Get-ServicePrincipal",
            "Get-ManagementRoleAssignment",
            "Get-RoleGroupMember",
        ]
        command_lists = {}
        for field in (
            "rbac_required_cmdlets",
            "rbac_available_cmdlets",
            "missing_cmdlets",
        ):
            values = source.get(field)
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value and len(value) <= 128 for value in values)
                or len(values) != len(set(values))
            ):
                raise AutomationError(f"Runbook protocol error: {where} has invalid command list '{field}'.")
            command_lists[field] = values
        if command_lists["rbac_required_cmdlets"] != required_cmdlets:
            raise AutomationError(f"Runbook protocol error: {where} does not declare the required RBAC cmdlet set.")
        if (set(command_lists["rbac_available_cmdlets"]) & set(command_lists["missing_cmdlets"])) or (
            set(command_lists["rbac_available_cmdlets"]) | set(command_lists["missing_cmdlets"])
        ) != set(required_cmdlets):
            raise AutomationError(f"Runbook protocol error: {where} has inconsistent RBAC cmdlet availability.")
        missing_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("missing_cmdlet_count"))
        if missing_count != len(command_lists["missing_cmdlets"]):
            raise AutomationError(f"Runbook protocol error: {where} has an invalid missing_cmdlet_count.")

        nullable_boolean_fields = (
            "quarantine_role_present",
            "service_principal_registered",
            "role_group_membership_evaluated",
            "quarantine_group_membership_confirmed",
            "quarantine_administrator_membership_confirmed",
            "role_assignment_matches_identity",
        )
        for field in nullable_boolean_fields:
            if source.get(field) is not None and not isinstance(source.get(field), bool):
                raise AutomationError(f"Runbook protocol error: {where} requires boolean or null field '{field}'.")

        role_group_total_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("quarantine_role_group_total_count"))
        role_group_inspected_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("quarantine_role_group_inspected_count"))
        role_group_inspection_truncated = source.get("quarantine_role_group_inspection_truncated")
        if (
            role_group_total_count is None
            or role_group_total_count < 0
            or role_group_inspected_count is None
            or role_group_inspected_count < 0
            or role_group_inspected_count > role_group_total_count
            or role_group_inspected_count > MAX_RBAC_ROLE_GROUP_INSPECTIONS
            or not isinstance(role_group_inspection_truncated, bool)
            or role_group_inspection_truncated != (role_group_inspected_count < role_group_total_count)
        ):
            raise AutomationError(f"Runbook protocol error: {where} has invalid role-group inspection counts.")
        if role_group_inspection_truncated and any(
            source.get(field) is False
            for field in (
                "quarantine_group_membership_confirmed",
                "quarantine_administrator_membership_confirmed",
                "role_assignment_matches_identity",
            )
        ):
            raise AutomationError(
                f"Runbook protocol error: {where} claims definitive negative RBAC evidence after truncating role-group inspection."
            )

        error_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("permission_query_error_count"))
        retained_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("permission_query_error_retained_count"))
        dropped_count = MSQuarantineForSplunkSOARUtils._optional_int(source.get("permission_query_error_dropped_count"))
        errors_truncated = source.get("permission_query_errors_truncated")
        if any(value is None or value < 0 for value in (error_count, retained_count, dropped_count)) or not isinstance(errors_truncated, bool):
            raise AutomationError(f"Runbook protocol error: {where} has invalid permission-query error counts.")
        errors = source.get("permission_query_errors")
        if not isinstance(errors, list):
            raise AutomationError(f"Runbook protocol error: {where} permission_query_errors must be an array.")
        if (
            len(errors) != retained_count
            or error_count != retained_count + dropped_count
            or errors_truncated != (dropped_count > 0)
            or len(errors) > MAX_PERMISSION_QUERY_ERRORS
            or len(
                json.dumps(
                    errors,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            > MAX_PERMISSION_QUERY_ERROR_BYTES
        ):
            raise AutomationError(f"Runbook protocol error: {where} permission-query error count does not match.")
        for record in errors:
            if not isinstance(record, dict):
                raise AutomationError(f"Runbook protocol error: {where} permission-query errors must be objects.")
            for field, max_chars in (
                ("query", 128),
                ("error", MAX_DIAGNOSTIC_TEXT_CHARS),
                ("exception_type", 256),
            ):
                value = record.get(field)
                if not isinstance(value, str) or len(value) > max_chars:
                    raise AutomationError(f"Runbook protocol error: {where} has an invalid permission error '{field}'.")
            cmdlet = record.get("cmdlet")
            if cmdlet is not None and (not isinstance(cmdlet, str) or not cmdlet or len(cmdlet) > 128):
                raise AutomationError(f"Runbook protocol error: {where} has an invalid permission error 'cmdlet'.")

        if status == "not_requested":
            if (
                rbac_included
                or source.get("rbac_diagnostics_reason") != "tenant_rbac_opt_in_required"
                or error_count != 0
                or empty_contracts
                or claims_status not in {None, ""}
                or source.get("managed_identity_app_id", "")
                or source.get("managed_identity_object_id", "")
                or role_group_total_count != 0
                or role_group_inspected_count != 0
                or role_group_inspection_truncated
                or any(source.get(field) is not None for field in nullable_boolean_fields)
            ):
                raise AutomationError(f"Runbook protocol error: {where} has inconsistent not-requested RBAC evidence.")
        elif not rbac_included:
            raise AutomationError(f"Runbook protocol error: {where} reports tenant RBAC evidence without opt-in.")
        elif status == "complete":
            if error_count != 0 or missing_count != 0 or empty_contracts or role_group_inspection_truncated:
                raise AutomationError(f"Runbook protocol error: {where} claims complete RBAC diagnostics with gaps.")
            if any(source.get(field) is None for field in nullable_boolean_fields):
                raise AutomationError(f"Runbook protocol error: {where} claims complete RBAC diagnostics with unknowns.")
        elif status == "not_evaluated":
            if (
                missing_count == 0
                or source.get("rbac_diagnostics_reason") != "required_cmdlets_unavailable_in_current_exchange_session"
                or role_group_total_count != 0
                or role_group_inspected_count != 0
                or role_group_inspection_truncated
                or any(source.get(field) is not None for field in nullable_boolean_fields)
            ):
                raise AutomationError(f"Runbook protocol error: {where} has inconsistent not-evaluated RBAC evidence.")
        elif error_count == 0 and not (
            (source.get("rbac_diagnostics_reason") == "no_role_contracts_visible" and empty_contracts)
            or (source.get("rbac_diagnostics_reason") == "role_group_inspection_truncated" and role_group_inspection_truncated)
        ):
            raise AutomationError(f"Runbook protocol error: {where} claims partial RBAC diagnostics without a gap.")
        if claims_status == "resolved":
            for field in (
                "managed_identity_app_id",
                "managed_identity_object_id",
            ):
                if not GUID_RE.match(source.get(field, "")):
                    raise AutomationError(f"Runbook protocol error: {where} has invalid resolved identity field '{field}'.")

        membership = source.get("quarantine_group_membership_confirmed")
        assignment_matches = source.get("role_assignment_matches_identity")
        if source.get("quarantine_role_groups") != source.get("matched_quarantine_role_groups"):
            raise AutomationError(f"Runbook protocol error: {where} exposes unmatched role-group names.")
        if source.get("service_principal_registered"):
            for field in (
                "registered_service_principal_app_id",
                "registered_service_principal_object_id",
            ):
                if not GUID_RE.match(source.get(field, "")):
                    raise AutomationError(f"Runbook protocol error: {where} registers a service principal without a valid '{field}'.")
        if membership and (not source["role_group_membership_evaluated"] or not source["matched_quarantine_role_groups"]):
            raise AutomationError(f"Runbook protocol error: {where} confirms membership without supporting evidence.")
        if assignment_matches and not (membership or source.get("service_principal_registered") or claims_status == "resolved"):
            raise AutomationError(f"Runbook protocol error: {where} confirms an assignment without identity evidence.")
        if source.get("quarantine_administrator_membership_confirmed") and (
            not membership or "Quarantine Administrator" not in source["matched_quarantine_role_groups"]
        ):
            raise AutomationError(f"Runbook protocol error: {where} has inconsistent Quarantine Administrator evidence.")

    @staticmethod
    def _validate_diagnostic_trace(value, field: str, where: str) -> list:
        if not isinstance(value, str) or len(value) > MAX_DIAGNOSTIC_TRACE_CHARS:
            raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
        if value == "":
            return []
        try:
            trace = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise AutomationError(f"Runbook protocol error: {where} field '{field}' is not valid JSON.") from exc
        if not isinstance(trace, list) or len(trace) > MAX_DIAGNOSTIC_TRACE_RECORDS:
            raise AutomationError(
                f"Runbook protocol error: {where} field '{field}' must contain at most {MAX_DIAGNOSTIC_TRACE_RECORDS} records."
            )
        if not all(isinstance(record, dict) for record in trace):
            raise AutomationError(f"Runbook protocol error: {where} field '{field}' must contain objects.")
        return trace

    @staticmethod
    def _validate_irreversible_diagnostics(
        source: dict,
        where: str,
        requested_action: str,
        connection_contract: Optional[bool] = None,
    ) -> None:
        """Require bounded module/cmdlet evidence for disposition attempts."""
        if connection_contract is None:
            connection_contract = MSQuarantineForSplunkSOARUtils._supports_connection_contract(source)
        if not isinstance(source, dict):
            raise AutomationError(f"Runbook protocol error: {where} diagnostics must be an object.")

        MSQuarantineForSplunkSOARUtils._validate_static_diagnostics(
            source,
            where,
            requested_action,
            connection_contract,
        )
        module_version = source.get("exchange_online_management_version")
        if not isinstance(module_version, str) or not module_version or len(module_version) > MAX_MODULE_VERSION_CHARS:
            raise AutomationError(f"Runbook protocol error: {where} requires a bounded exchange_online_management_version string.")

        for field in (
            "cmdlet_warning",
            "cmdlet_information",
            "cmdlet_verbose",
            "cmdlet_error",
        ):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_ERROR_TEXT_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")

        if not isinstance(source.get("cmdlet_executed"), bool):
            raise AutomationError(f"Runbook protocol error: {where} requires boolean field 'cmdlet_executed'.")
        duration = MSQuarantineForSplunkSOARUtils._optional_int(source.get("cmdlet_duration_ms"))
        if duration is None or duration < 0:
            raise AutomationError(f"Runbook protocol error: {where} requires non-negative cmdlet_duration_ms.")

        for field in (
            "cmdlet_started_at_utc",
            "cmdlet_completed_at_utc",
            "cmdlet_fully_qualified_error_id",
            "cmdlet_error_category",
            "cmdlet_error_reason",
            "cmdlet_error_target_name",
            "cmdlet_error_target_type",
            "cmdlet_exception_type",
            "cmdlet_exception_hresult",
            "cmdlet_http_status_code",
            "cmdlet_request_id",
            "cmdlet_correlation_id",
            "cmdlet_server_timestamp",
        ):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_DIAGNOSTIC_TEXT_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
        for field in ("cmdlet_error_details", "cmdlet_inner_exception"):
            value = source.get(field)
            if not isinstance(value, str) or len(value) > MAX_ERROR_TEXT_CHARS:
                raise AutomationError(f"Runbook protocol error: {where} has an invalid exact error field '{field}'.")

        if connection_contract:
            attempted = source.get("cmdlet_invocation_attempted")
            if not isinstance(attempted, bool):
                raise AutomationError(f"Runbook protocol error: {where} requires boolean field 'cmdlet_invocation_attempted'.")
            for field in (
                "cmdlet_invocation_form",
                "cmdlet_error_position",
                "cmdlet_script_stack_trace",
            ):
                value = source.get(field)
                if not isinstance(value, str) or len(value) > MAX_ERROR_TEXT_CHARS:
                    raise AutomationError(f"Runbook protocol error: {where} requires bounded string field '{field}'.")
            if source["cmdlet_executed"] and not attempted:
                raise AutomationError(f"Runbook protocol error: {where} executed a cmdlet that was never invoked.")
        else:
            attempted = source["cmdlet_executed"]

        if attempted:
            if not source.get("cmdlet_started_at_utc") or not source.get("cmdlet_completed_at_utc"):
                raise AutomationError(f"Runbook protocol error: {where} invoked a cmdlet without UTC timing evidence.")
        elif source.get("cmdlet_started_at_utc") or source.get("cmdlet_completed_at_utc") or duration != 0:
            raise AutomationError(f"Runbook protocol error: {where} claims timing for a cmdlet that was not invoked.")

    def _validate_runbook_result(
        self,
        result: dict,
        requested_action: str,
        requested_identity: Optional[str] = None,
        requested_include_rbac: Optional[bool] = None,
        requested_operation_action: Optional[str] = None,
    ) -> None:
        """Validate envelopes using GUID semantics, not wire identity casing."""
        if not isinstance(result, dict):
            raise AutomationError("Runbook protocol error: final output must be a JSON object.")

        self._validate_runbook_version(result, "Runbook result")
        if requested_action in {"list", "release", "deny", "config_check"}:
            self._validate_selection_evidence(result)
        if requested_action in {"release", "deny"} and self._runbook_version_tuple(result) < MANAGED_IDENTITY_ONLY_RUNBOOK_VERSION:
            raise AutomationError(
                "Runbook protocol error: release/deny requires Runbook "
                "3.4.2 or newer (Managed Identity-only Exchange "
                f"connection); received {result.get('runbook_version')}. "
                "This is the protocol minimum; recommended pair: App 3.7.4 / Runbook 3.4.5."
            )

        response_action = result.get("action")
        if response_action != requested_action:
            raise AutomationError(
                f"Runbook protocol error: response action '{response_action}' does not match requested action '{requested_action}'."
            )

        error_value = result.get("error")
        if error_value is not None and not isinstance(error_value, bool):
            raise AutomationError("Runbook protocol error: field 'error' must be a boolean.")

        if requested_action == "reconcile" and requested_operation_action is not None:
            evidence = result.get("details") if error_value is True else result
            if (
                requested_operation_action not in {"release", "deny"}
                or not isinstance(evidence, dict)
                or evidence.get("operation_action") != requested_operation_action
            ):
                raise AutomationError("Runbook protocol error: reconciliation operation_action does not match the requested operation_action.")

        if requested_action in {"release", "deny"} and error_value is True:
            details = result.get("details")
            response_identity = details.get("identity") if isinstance(details, dict) else None
            if not self._quarantine_identities_match(response_identity, requested_identity):
                raise AutomationError(
                    "Runbook protocol error: structured irreversible-action error identity does not match the requested identity."
                )
            if result.get("error_code") in {
                PRECONDITION_ERROR_CODE,
                POSTCONDITION_ERROR_CODE,
                DISPOSITION_REJECTED_ERROR_CODE,
                DISPOSITION_CAPABILITY_ERROR_CODE,
                "exchange_cmdlet_failed",
            }:
                self._validate_irreversible_diagnostics(
                    details,
                    f"{result.get('error_code')} result",
                    requested_action,
                )

        if (
            requested_action == "diagnose"
            and error_value is True
            and result.get("error_code")
            in {
                "diagnostic_inspection_failed",
                "diagnostic_inspection_unconfirmed",
                DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
                DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
            }
        ):
            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: diagnostic failure requires an object in field 'details'.")
            if not self._quarantine_identities_match(details.get("identity"), requested_identity):
                raise AutomationError("Runbook protocol error: diagnostic failure identity does not match the requested identity.")
            self._validate_static_diagnostics(
                details,
                "diagnostic failure result",
            )
            self._validate_rbac_diagnostics(
                details,
                "diagnostic failure result",
            )
            if requested_include_rbac is not None and details.get("include_rbac") is not requested_include_rbac:
                raise AutomationError("Runbook protocol error: diagnostic failure RBAC opt-in does not match the request.")

        if (
            requested_action
            in {
                "export",
                "diagnose",
                "reconcile",
                "release",
                "deny",
            }
            and error_value is not True
        ):
            response_identity = result.get("identity")
            if not isinstance(response_identity, str) or not self._quarantine_identities_match(response_identity, requested_identity):
                raise AutomationError("Runbook protocol error: response identity does not match the requested identity.")

        if requested_action == "config_check" and error_value is not True:
            self._validate_config_check_result(result)

        if requested_action == "reconcile" and error_value is not True:
            operation_action = result.get("operation_action")
            if operation_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: reconcile result requires operation_action=release or deny.")
            self._validate_irreversible_diagnostics(
                result,
                "successful reconcile result",
                operation_action,
            )
            expected_release_status = "Released" if operation_action == "release" else "Denied"
            if (
                result.get("status")
                not in {
                    "confirmed_success",
                    "confirmed_failed",
                    "outcome_unknown",
                }
                or result.get("handling")
                not in {
                    "no_retry_needed",
                    "retry_requires_new_operation",
                    "reconcile_before_retry",
                }
                or result.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD
                or result.get("expected_release_status") != expected_release_status
                or not self._quarantine_identities_match(
                    result.get("observed_identity"),
                    requested_identity,
                )
                or not isinstance(
                    result.get("observed_release_status"),
                    str,
                )
                or self._optional_int(result.get("verification_attempts")) != 1
                or result.get("cmdlet_executed") is not False
            ):
                raise AutomationError("Runbook protocol error: reconcile result does not prove one exact read-only Exchange status observation.")
            status = result.get("status")
            handling = result.get("handling")
            observed_status = result.get("observed_release_status")
            if status == "confirmed_success" and (handling != "no_retry_needed" or observed_status.lower() != expected_release_status.lower()):
                raise AutomationError(
                    "Runbook protocol error: successful reconcile result does not match the expected terminal Exchange status."
                )
            opposite_status = "Denied" if operation_action == "release" else "Released"
            if status == "confirmed_failed" and (
                handling != "retry_requires_new_operation" or observed_status.lower() != opposite_status.lower()
            ):
                raise AutomationError("Runbook protocol error: failed reconcile result does not prove the opposite terminal Exchange status.")
            if status == "outcome_unknown" and (handling != "reconcile_before_retry" or observed_status.lower() in {"released", "denied"}):
                raise AutomationError("Runbook protocol error: unknown reconcile result has an inconsistent Exchange status or handling value.")
            trace = self._validate_diagnostic_trace(
                result.get("postcondition_trace"),
                "postcondition_trace",
                "successful reconcile result",
            )
            if (
                len(trace) != 1
                or trace[0].get("attempt") != 1
                or trace[0].get("result_count") != 1
                or not self._quarantine_identities_match(
                    trace[0].get("observed_identity"),
                    requested_identity,
                )
                or trace[0].get("observed_release_status") != observed_status
                or trace[0].get("exact_identity_match") is not True
                or trace[0].get("error") != ""
            ):
                raise AutomationError(
                    "Runbook protocol error: reconcile result trace does not prove one exact, error-free identity-bound status read."
                )

        if requested_action == "diagnose" and error_value is not True:
            self._validate_static_diagnostics(
                result,
                "successful diagnose result",
            )
            self._validate_rbac_diagnostics(
                result,
                "successful diagnose result",
            )
            include_rbac = result.get("include_rbac")
            if not isinstance(include_rbac, bool):
                raise AutomationError("Runbook protocol error: successful diagnose result must declare boolean include_rbac.")
            if requested_include_rbac is not None and include_rbac is not requested_include_rbac:
                raise AutomationError("Runbook protocol error: successful diagnose result RBAC opt-in does not match the request.")
            expected_rbac_status = "complete" if include_rbac else "not_requested"
            if result.get("rbac_included") is not include_rbac or result.get("rbac_diagnostics_status") != expected_rbac_status:
                raise AutomationError("Runbook protocol error: successful diagnose result has an inconsistent RBAC opt-in/result contract.")
            if (
                result.get("status") != "inspected"
                or result.get("handling") != "read_only"
                or self._optional_int(result.get("result_count")) != 1
                or not self._quarantine_identities_match(
                    result.get("observed_identity"),
                    requested_identity,
                )
                or not isinstance(
                    result.get("observed_release_status"),
                    str,
                )
                or not result.get("observed_release_status")
                or result.get("inspection_error") != ""
                or not isinstance(result.get("inspected_at_utc"), str)
                or not result.get("inspected_at_utc")
            ):
                raise AutomationError("Runbook protocol error: successful diagnose result does not prove one exact read-only identity snapshot.")

        if requested_action in {"release", "deny"} and error_value is not True:
            expected_business_status = "released" if requested_action == "release" else "denied"
            expected_release_status = "Released" if requested_action == "release" else "Denied"
            observed_release_status = result.get("observed_release_status")
            observed_identity = result.get("observed_identity")
            observed_status_history = result.get("observed_release_status_history")
            verification_attempts = self._optional_int(result.get("verification_attempts"))

            self._validate_irreversible_diagnostics(
                result,
                f"successful {requested_action} result",
                requested_action,
            )
            if self._supports_connection_contract(result):
                self._validate_connection_evidence(
                    result,
                    f"successful {requested_action} result",
                    require_disconnect=result.get("idempotent") is not True,
                )
            idempotent_status = f"already_{expected_business_status}"
            is_idempotent = result.get("status") == idempotent_status
            if result.get("status") not in {
                expected_business_status,
                idempotent_status,
            }:
                raise AutomationError(
                    "Runbook protocol error: successful "
                    f"{requested_action} result must declare "
                    f"status={expected_business_status} or "
                    f"status={idempotent_status}."
                )
            if is_idempotent:
                if (
                    result.get("idempotent") is not True
                    or result.get("cmdlet_executed") is not False
                    or result.get("handling") != "no_retry_needed"
                ):
                    raise AutomationError(
                        "Runbook protocol error: an already-achieved "
                        "disposition must declare idempotent=true, "
                        "cmdlet_executed=false, and handling=no_retry_needed."
                    )
            else:
                invoked = (
                    result.get("cmdlet_invocation_attempted") is True
                    if self._supports_connection_contract(result)
                    else result.get("cmdlet_executed") is True
                )
                if result.get("idempotent") not in (None, False) or not invoked:
                    raise AutomationError(
                        "Runbook protocol error: a newly executed disposition "
                        "must declare an attempted cmdlet invocation and must "
                        "not claim idempotent success."
                    )
            if result.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD:
                raise AutomationError(
                    "Runbook protocol error: successful release/deny result "
                    "must declare verification_method="
                    f"{POSTCONDITION_VERIFICATION_METHOD}."
                )
            if result.get("expected_release_status") != expected_release_status:
                raise AutomationError(
                    f"Runbook protocol error: successful {requested_action} result has an invalid expected Exchange release status."
                )
            if not isinstance(observed_release_status, str) or observed_release_status.lower() != expected_release_status.lower():
                raise AutomationError(
                    "Runbook protocol error: successful "
                    f"{requested_action} result lacks the confirmed Exchange "
                    f"ReleaseStatus={expected_release_status} postcondition."
                )
            if verification_attempts is None or verification_attempts < 1:
                raise AutomationError(
                    "Runbook protocol error: successful release/deny result must declare a positive verification_attempts value."
                )
            if not self._quarantine_identities_match(
                observed_identity,
                requested_identity,
            ):
                raise AutomationError(
                    "Runbook protocol error: successful release/deny result observed_identity does not match the requested identity."
                )
            if (
                not isinstance(observed_status_history, str)
                or not observed_status_history
                or observed_status_history.split(" -> ")[-1].lower() != expected_release_status.lower()
            ):
                raise AutomationError(
                    "Runbook protocol error: successful release/deny result "
                    "must retain a status history ending in the confirmed "
                    f"ReleaseStatus={expected_release_status}."
                )
            if not isinstance(result.get("last_verification_error"), str):
                raise AutomationError("Runbook protocol error: successful release/deny result requires a string last_verification_error.")
            self._validate_diagnostic_trace(
                result.get("precondition_trace"),
                "precondition_trace",
                f"successful {requested_action} result",
            )
            self._validate_diagnostic_trace(
                result.get("postcondition_trace"),
                "postcondition_trace",
                f"successful {requested_action} result",
            )
            if not result.get("precondition_trace"):
                raise AutomationError("Runbook protocol error: successful release/deny result requires a precondition trace.")
            if is_idempotent and result.get("postcondition_trace"):
                raise AutomationError("Runbook protocol error: idempotent success must not claim a postcondition trace after a skipped cmdlet.")
            if not is_idempotent and not result.get("postcondition_trace"):
                raise AutomationError("Runbook protocol error: executed release/deny success requires a postcondition trace.")

    def _raise_for_runbook_error(
        self,
        result: dict,
        requested_action: str,
        requested_identity: Optional[str] = None,
    ) -> None:
        """Validate and raise a structured application error from the runbook."""
        if not isinstance(result, dict):
            return

        error_value = result.get("error")
        if error_value is None or error_value is False:
            return
        if error_value is not True:
            raise AutomationError("Runbook protocol error: field 'error' must be a boolean.")

        response_action = result.get("action")
        if response_action != requested_action:
            raise AutomationError(
                f"Runbook protocol error: structured error action '{response_action}' does not match requested action '{requested_action}'."
            )

        if result.get("error_code") == PRECONDITION_ERROR_CODE:
            if requested_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: precondition_unconfirmed is valid only for release and deny.")

            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: precondition_unconfirmed requires an object in field 'details'.")
            if not self._quarantine_identities_match(details.get("identity"), requested_identity):
                raise AutomationError("Runbook protocol error: precondition_unconfirmed identity does not match the requested identity.")
            if details.get("expected_release_status") != self.selection_release_status:
                raise AutomationError(
                    f"Runbook protocol error: precondition_unconfirmed must expect ReleaseStatus={self.selection_release_status}."
                )
            if details.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD:
                raise AutomationError(
                    f"Runbook protocol error: precondition_unconfirmed must declare verification_method={POSTCONDITION_VERIFICATION_METHOD}."
                )
            if details.get("handling") != "manual_review":
                raise AutomationError("Runbook protocol error: precondition_unconfirmed must declare handling=manual_review.")
            if self._optional_int(details.get("verification_attempts")) != 1:
                raise AutomationError("Runbook protocol error: precondition_unconfirmed must declare exactly one verification attempt.")
            for field in (
                "observed_release_status",
                "observed_identity",
                "observed_release_status_history",
                "last_verification_error",
            ):
                if not isinstance(details.get(field), str):
                    raise AutomationError(f"Runbook protocol error: precondition_unconfirmed requires string field '{field}'.")
            self._validate_diagnostic_trace(
                details.get("precondition_trace"),
                "precondition_trace",
                "precondition_unconfirmed result",
            )
            self._validate_diagnostic_trace(
                details.get("postcondition_trace"),
                "postcondition_trace",
                "precondition_unconfirmed result",
            )
            if details.get("postcondition_trace") != "":
                raise AutomationError("Runbook protocol error: precondition_unconfirmed must not contain a postcondition trace.")

            message = result.get("message")
            if not isinstance(message, str) or not message:
                message = "Exchange disposition precondition was not confirmed."
            raise RunbookActionError(
                message,
                result=result,
            )

        if result.get("error_code") == POSTCONDITION_ERROR_CODE:
            if requested_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed is valid only for release and deny.")

            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires an object in field 'details'.")

            expected_release_status = "Released" if requested_action == "release" else "Denied"
            response_identity = details.get("identity")
            observed_release_status = details.get("observed_release_status")
            observed_identity = details.get("observed_identity")
            observed_status_history = details.get("observed_release_status_history")
            verification_attempts = self._optional_int(details.get("verification_attempts"))

            if not self._quarantine_identities_match(response_identity, requested_identity):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed identity does not match the requested identity.")
            if details.get("expected_release_status") != expected_release_status:
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed has an invalid expected Exchange release status.")
            if not isinstance(observed_release_status, str):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires a string observed_release_status.")
            if details.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD:
                raise AutomationError(
                    f"Runbook protocol error: postcondition_unconfirmed must declare verification_method={POSTCONDITION_VERIFICATION_METHOD}."
                )
            if verification_attempts is None or verification_attempts < 1:
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed must declare a positive verification_attempts value.")
            if details.get("handling") != "reconcile_before_retry":
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed must declare handling=reconcile_before_retry.")
            if not isinstance(observed_identity, str):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires a string observed_identity.")
            if not isinstance(observed_status_history, str):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires a string observed_release_status_history.")
            if not isinstance(
                details.get("last_verification_error"),
                str,
            ):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires a string last_verification_error.")
            self._validate_diagnostic_trace(
                details.get("precondition_trace"),
                "precondition_trace",
                "postcondition_unconfirmed result",
            )
            self._validate_diagnostic_trace(
                details.get("postcondition_trace"),
                "postcondition_trace",
                "postcondition_unconfirmed result",
            )
            if not details.get("precondition_trace") or not details.get("postcondition_trace"):
                raise AutomationError("Runbook protocol error: postcondition_unconfirmed requires both precondition and postcondition traces.")

            message = result.get("message")
            if not isinstance(message, str) or not message:
                message = "Exchange postcondition could not be confirmed."
            raise RunbookActionError(
                message,
                result=result,
            )

        if result.get("error_code") == DISPOSITION_REJECTED_ERROR_CODE:
            if requested_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: disposition_rejected is valid only for release and deny.")
            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: disposition_rejected requires an object in field 'details'.")
            expected_release_status = "Released" if requested_action == "release" else "Denied"
            if not self._quarantine_identities_match(details.get("identity"), requested_identity):
                raise AutomationError("Runbook protocol error: disposition_rejected identity does not match the requested identity.")
            if details.get("expected_release_status") != expected_release_status:
                raise AutomationError("Runbook protocol error: disposition_rejected has an invalid expected Exchange release status.")
            if details.get("observed_release_status") != self.selection_release_status:
                raise AutomationError(
                    f"Runbook protocol error: disposition_rejected requires the exact unchanged ReleaseStatus={self.selection_release_status}."
                )
            if not self._quarantine_identities_match(
                details.get("observed_identity"),
                requested_identity,
            ):
                raise AutomationError("Runbook protocol error: disposition_rejected requires an exact observed_identity match.")
            if details.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD:
                raise AutomationError(
                    f"Runbook protocol error: disposition_rejected must declare verification_method={POSTCONDITION_VERIFICATION_METHOD}."
                )
            verification_attempts = self._optional_int(details.get("verification_attempts"))
            if verification_attempts is None or verification_attempts < 3 or verification_attempts > 20:
                raise AutomationError(
                    "Runbook protocol error: disposition_rejected must declare between three and twenty bounded verification attempts."
                )
            if details.get("handling") != "manual_review":
                raise AutomationError("Runbook protocol error: disposition_rejected must declare handling=manual_review.")
            if details.get("last_verification_error") != "":
                raise AutomationError("Runbook protocol error: disposition_rejected cannot contain a postcondition read error.")
            if details.get("observed_release_status_history") != self.selection_release_status:
                raise AutomationError(
                    f"Runbook protocol error: disposition_rejected requires an unchanged {self.selection_release_status} status history."
                )
            self._validate_diagnostic_trace(
                details.get("precondition_trace"),
                "precondition_trace",
                "disposition_rejected result",
            )
            postcondition_trace = self._validate_diagnostic_trace(
                details.get("postcondition_trace"),
                "postcondition_trace",
                "disposition_rejected result",
            )
            if not details.get("precondition_trace") or not details.get("postcondition_trace"):
                raise AutomationError("Runbook protocol error: disposition_rejected requires both precondition and postcondition traces.")
            if len(postcondition_trace) != verification_attempts or any(
                record.get("attempt") != attempt
                or record.get("result_count") != 1
                or not self._quarantine_identities_match(
                    record.get("observed_identity"),
                    requested_identity,
                )
                or record.get("observed_release_status") != self.selection_release_status
                or record.get("exact_identity_match") is not True
                or record.get("error") != ""
                for attempt, record in enumerate(
                    postcondition_trace,
                    start=1,
                )
            ):
                raise AutomationError(
                    "Runbook protocol error: disposition_rejected requires "
                    f"the declared number of exact, error-free {self.selection_release_status} "
                    "status reads."
                )
            if not any(
                details.get(field)
                for field in (
                    "cmdlet_error",
                    "cmdlet_fully_qualified_error_id",
                    "cmdlet_error_category",
                    "cmdlet_error_details",
                )
            ):
                raise AutomationError("Runbook protocol error: disposition_rejected requires structured cmdlet rejection evidence.")
            message = result.get("message")
            if not isinstance(message, str) or not message:
                message = "Exchange rejected the disposition operation."
            raise RunbookActionError(
                message,
                result=result,
            )

        if result.get("error_code") == DISPOSITION_CAPABILITY_ERROR_CODE:
            if requested_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: disposition_capability_unconfirmed is valid only for release and deny.")
            details = result.get("details")
            if (
                not isinstance(details, dict)
                or not self._quarantine_identities_match(details.get("identity"), requested_identity)
                or details.get("cmdlet_executed") is not False
                or details.get("cmdlet_capability_status") != "unconfirmed"
                or not details.get("cmdlet_capability_error")
                or details.get("handling") != "manual_review"
            ):
                raise AutomationError("Runbook protocol error: capability failure lacks fail-closed runtime evidence.")
            message = result.get("message")
            if not isinstance(message, str) or not message:
                message = "Disposition command capability was not confirmed."
            raise RunbookActionError(
                message,
                result=result,
            )

        if result.get("error_code") == "reconciliation_inspection_unconfirmed":
            if requested_action != "reconcile":
                raise AutomationError("Runbook protocol error: read-only reconciliation failure is valid only for action=reconcile.")
            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: reconciliation failure requires an object in field 'details'.")
            operation_action = details.get("operation_action")
            if operation_action not in {"release", "deny"}:
                raise AutomationError("Runbook protocol error: reconciliation failure requires operation_action=release or deny.")
            self._validate_irreversible_diagnostics(
                details,
                "read-only reconciliation failure",
                operation_action,
            )
            expected_release_status = "Released" if operation_action == "release" else "Denied"
            if (
                not self._quarantine_identities_match(details.get("identity"), requested_identity)
                or details.get("status") != "outcome_unknown"
                or details.get("handling") != "reconcile_before_retry"
                or details.get("expected_release_status") != expected_release_status
                or details.get("verification_method") != POSTCONDITION_VERIFICATION_METHOD
                or self._optional_int(details.get("verification_attempts")) != 1
                or details.get("cmdlet_executed") is not False
                or details.get("precondition_trace") != ""
                or not isinstance(details.get("observed_identity"), str)
                or not isinstance(
                    details.get("observed_release_status"),
                    str,
                )
                or not isinstance(
                    details.get("observed_release_status_history"),
                    str,
                )
                or not isinstance(details.get("last_verification_error"), str)
                or not details.get("last_verification_error")
            ):
                raise AutomationError("Runbook protocol error: reconciliation failure lacks one fail-closed read-only status observation.")
            trace = self._validate_diagnostic_trace(
                details.get("postcondition_trace"),
                "postcondition_trace",
                "read-only reconciliation failure",
            )
            if len(trace) != 1 or trace[0].get("attempt") != 1 or trace[0].get("exact_identity_match") is True:
                raise AutomationError(
                    "Runbook protocol error: reconciliation failure trace does not prove one unconfirmed read-only observation."
                )
            message = result.get("message")
            if not isinstance(message, str) or not message:
                message = "Read-only reconciliation could not confirm status."
            raise RunbookActionError(
                message,
                result=result,
            )

        if result.get("error_code") == "exchange_cmdlet_failed":
            details = result.get("details")
            if not isinstance(details, dict) or details.get("handling") != "retry_requires_new_operation":
                raise AutomationError("Runbook protocol error: exchange_cmdlet_failed must declare handling=retry_requires_new_operation.")
        if result.get("error_code") == "export_oversized":
            if requested_action != "export":
                raise AutomationError("Runbook protocol error: export_oversized is valid only for the export action.")

            details = result.get("details")
            if not isinstance(details, dict):
                raise AutomationError("Runbook protocol error: export_oversized requires an object in field 'details'.")

            response_identity = details.get("identity")
            decoded_size = self._optional_int(details.get("decoded_size"))
            max_decoded_size = self._optional_int(details.get("max_decoded_size"))
            handling = details.get("handling")

            if (
                not isinstance(response_identity, str)
                or not response_identity
                or not self._quarantine_identities_match(response_identity, requested_identity)
            ):
                raise AutomationError("Runbook protocol error: export_oversized identity does not match the requested identity.")
            if decoded_size is None or max_decoded_size is None or max_decoded_size < 0 or decoded_size <= max_decoded_size:
                raise AutomationError("Runbook protocol error: export_oversized sizes are missing or inconsistent.")
            if handling != "fail_closed":
                raise AutomationError("Runbook protocol error: export_oversized must declare handling=fail_closed.")

            raise OversizedExportError(
                result.get("message", "Export exceeds safety cap."),
                identity=response_identity,
                decoded_size=decoded_size,
                max_decoded_size=max_decoded_size,
            )

        message = result.get("message")
        if not isinstance(message, str) or not message:
            message = "unknown error"
        raise RunbookActionError(
            message,
            result=result,
        )

    @staticmethod
    def _optional_int(value):
        """Return an integer for structured error metadata, otherwise None."""
        if isinstance(value, bool) or value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    # -----------------------------------------------------------------------
    # EML helpers
    # -----------------------------------------------------------------------

    def extract_eml(self, data: dict) -> str:
        """
        Extract the base64 EML field from the runbook output, tolerating
        PowerShell's PascalCase 'Eml' and normalised lowercase 'eml'.

        Reference:
        https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/export-quarantinemessage
        """
        for key in EML_FIELD_VARIANTS:
            if key in data:
                val = data[key]
                if isinstance(val, dict):
                    return str(val.get("value", ""))
                return str(val) if val is not None else ""
        return ""
