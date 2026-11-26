# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
#
# MS Defender Quarantine Manager - Azure Automation Utils
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
from concurrent.futures import Future, wait
from email.utils import parsedate_to_datetime
from threading import Event, Thread
from types import SimpleNamespace
from typing import Optional
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit
from uuid import uuid4

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
CHUNK_ENCODING = "base64"
PROTECTED_READ_ACTIONS = {"list", "export"}
PROTECTED_OUTPUT_MODE = "msq-protected-v1"
MAX_PROTECTED_RECORD_CHARS = 1024 * 1024
MAX_CHUNK_COUNT = 200
MAX_DECODED_EML_BYTES = 24 * 1024 * 1024
# A full export incurs two Base64 expansions (EML and encrypted records),
# plus record framing. Keep headroom over its ~43 MiB wire size.
MAX_JOB_OUTPUT_BYTES = 64 * 1024 * 1024
JOB_OUTPUT_READ_BYTES = 64 * 1024
MAX_INLINE_DECODED_EML_BYTES = 10 * 1024 * 1024
EXCHANGE_AUTH_METHOD = "ManagedIdentity"
EXCHANGE_SETTING_MAX_CHARS = 256
DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE = "diagnostic_rbac_not_evaluated"
DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE = "diagnostic_rbac_partial"
MAX_DIAGNOSTIC_TEXT_CHARS = 2048
MAX_DIAGNOSTIC_TRACE_CHARS = 8192
MAX_DIAGNOSTIC_TRACE_RECORDS = 25
MAX_JWT_HEADER_SEGMENT_CHARS = 8 * 1024
MAX_RBAC_ROLE_GROUP_INSPECTIONS = 20
MAX_PERMISSION_QUERY_ERRORS = 20
MAX_PERMISSION_QUERY_ERROR_BYTES = 32 * 1024
MAX_MODULE_VERSION_CHARS = 64
MAX_RUNTIME_FIELD_CHARS = 1024
MAX_RUNBOOK_SETTING_CHARS = 512
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
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


class JobSubmissionRejected(AutomationError):
    """Azure explicitly rejected authorization before starting a job."""


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

    def __init__(self, message, job_id="", last_status="", exception=""):
        super().__init__(message)
        self.job_id = job_id
        self.last_status = last_status
        self.exception = exception


class RunbookActionError(AutomationError):
    """Raised for a validated, structured failure reported by the runbook."""

    def __init__(self, message: str, result: dict):
        super().__init__(message)
        self.result = result


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


class _AzureSession(requests.Session):
    def resolve_redirects(self, response, request, **kwargs):
        # Requests still tries to populate Response.next when redirects are
        # disabled, consuming the body. Streamed output must not do that.
        if kwargs.get("yield_requests") and kwargs.get("stream"):
            return iter(())
        return super().resolve_redirects(response, request, **kwargs)


class MSQuarantineForSplunkSOARUtils:
    """
    Handles all communication with Azure Automation on behalf of the connector.

    Flow for each action:
        1. start_job()      → returns job_id
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
        progress_callback=None,
        *,
        runbook_name: Optional[str] = None,
    ):
        self._connection_settings = normalize_exchange_connection_settings(
            exchange_organization,
        )
        self.selection_release_status = "Requested"
        self._webhook_url = validate_webhook_url(webhook_url) if runbook_name is None else None
        if runbook_name is not None:
            if not GUID_RE.fullmatch(subscription_id):
                raise ValueError("Azure subscription ID must be a UUID for REST job start.")
            if not re.fullmatch(r"[\w().-]{1,90}", resource_group) or resource_group.endswith("."):
                raise ValueError("Azure resource group name is invalid for REST job start.")
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{4,48}[A-Za-z0-9]", automation_account):
                raise ValueError("Azure Automation Account name is invalid for REST job start.")
        self._runbook_name = runbook_name
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._automation_account = automation_account
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._retain_chunked_base64 = retain_chunked_base64
        # Native connector callback, accepting one human-readable string.
        self.progress_callback = progress_callback
        self._next_progress_at = 0.0

        self._session = _AzureSession()
        self._mgmt_token = None  # cached for current action

    def new_poll_deadline(self) -> float:
        """Return one absolute deadline shared by job status and output."""
        return time.monotonic() + self._poll_timeout

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
        """Honor Retry-After (seconds or HTTP date), limited only by the deadline."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
                if 0 <= delay < float("inf"):
                    return delay
            except (TypeError, ValueError):
                try:
                    return max(parsedate_to_datetime(retry_after).timestamp() - time.time(), 0.0)
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(
            max(float(self._poll_interval), 1.0) * (2 ** min(retry_count, 4)),
            MAX_THROTTLE_SLEEP_SECONDS,
        )

    def _progress(self, message):
        """Report through native SOAR progress at most once every 30 seconds."""
        now = time.monotonic()
        if self.progress_callback is not None and now >= self._next_progress_at:
            self._next_progress_at = now + 30
            try:
                self.progress_callback(message)
            except Exception:
                # A progress/UI failure must not change an Azure action outcome.
                pass

    def _sleep_for_retry(self, delay: float, deadline: float, message=None) -> None:
        """Wait in progress-sized intervals without extending the job deadline."""
        end = min(time.monotonic() + delay, deadline)
        while time.monotonic() < end:
            if message:
                self._progress(message)
            time.sleep(max(0.0, min(30.0, end - time.monotonic())))

    # -----------------------------------------------------------------------
    # Azure AD token
    # -----------------------------------------------------------------------

    def get_mgmt_token(self, timeout=30) -> str:
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
                timeout=timeout,
                verify=True,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise TokenError(self._transport_error_message("Token request failed", exc)) from exc

        if 300 <= response.status_code < 400:
            raise TokenError(f"Azure AD token request returned HTTP {response.status_code}; redirects are not followed.")

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

    def _job_input(self, action, identity, page_size, include_rbac, output_public_key):
        body = {"action": action}
        if action in PROTECTED_READ_ACTIONS:
            if not output_public_key:
                raise AutomationError("Protected list/export requires a per-job public key.")
            body = {"action": f"protected_{action}_v1", "output_public_key": output_public_key}
        body.update(self._connection_settings)
        if identity:
            body["identity"] = identity
        if page_size is not None:
            body["page_size"] = page_size
        if include_rbac is not None:
            body["include_rbac"] = include_rbac
        return body

    def start_job(self, action, identity=None, page_size=None, include_rbac=None, *, output_public_key=None):
        """Submit once through the configured transport without fallback."""
        if self._runbook_name is None:
            if output_public_key is not None:
                return self.fire_webhook(action, identity, page_size, output_public_key=output_public_key)
            return self.fire_webhook(action, identity, page_size, include_rbac=include_rbac)
        body = self._job_input(action, identity, page_size, include_rbac, output_public_key)
        headers = self._mgmt_headers()
        job_id = str(uuid4())
        url = self._job_url(job_id, api_version="2024-10-23")
        try:
            with self._session.put(
                url,
                headers=headers,
                json={"properties": {"runbook": {"name": self._runbook_name}, "parameters": {"RequestJson": json.dumps(body)}}},
                timeout=30,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code in (401, 403):
                    raise JobSubmissionRejected(
                        f"Azure refused REST job submission (HTTP {response.status_code}). Check the Entra app registration and its job-start permission."
                    )
                if response.status_code not in (200, 201, 202):
                    raise AutomationError(f"Azure REST job submission returned HTTP {response.status_code}. Check job history before retrying.")
        except requests.exceptions.RequestException:
            error = AutomationError("Azure REST job submission could not be confirmed. Check job history before retrying.")
            error.job_id = job_id
            raise error from None
        except JobSubmissionRejected:
            raise
        except AutomationError as error:
            error.job_id = job_id
            raise
        return job_id

    def fire_webhook(
        self,
        action: str,
        identity: Optional[str] = None,
        page_size: Optional[int] = None,
        include_rbac: Optional[bool] = None,
        *,
        output_public_key: Optional[str] = None,
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
        body = self._job_input(action, identity, page_size, include_rbac, output_public_key)

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
        job_ids = data.get("JobIds", []) if isinstance(data, dict) else []
        if not isinstance(job_ids, list) or len(job_ids) != 1 or not isinstance(job_ids[0], str) or not GUID_RE.fullmatch(job_ids[0]):
            raise WebhookError(f"Webhook response did not contain JobIds: {self.redact_sensitive_text(data, max_chars=500)}")

        return job_ids[0]

    # -----------------------------------------------------------------------
    # Job polling
    # -----------------------------------------------------------------------

    def _job_path(self, job_id: str, template: str) -> str:
        return template.format(
            subscription_id=quote(self._subscription_id, safe=""),
            resource_group=quote(self._resource_group, safe=""),
            automation_account=quote(self._automation_account, safe=""),
            job_id=quote(job_id, safe=""),
        )

    def _job_url(self, job_id: str, *, api_version: str = MGMT_API_VERSION) -> str:
        """Build the Management API URL for a specific job."""
        return f"{MGMT_BASE}{self._job_path(job_id, JOB_API_PATH)}?api-version={api_version}"

    def _job_output_url(self, job_id: str) -> str:
        """Build the Management API URL for a job's output."""
        return f"{MGMT_BASE}{self._job_path(job_id, JOB_OUTPUT_API_PATH)}?api-version={MGMT_API_VERSION}"

    def _mgmt_headers(self, deadline=None) -> dict:
        """Return headers, including any token acquisition in the wait budget."""
        timeout = 30 if deadline is None else min(30, max(0.001, deadline - time.monotonic()))
        return {
            "Authorization": f"Bearer {self.get_mgmt_token(timeout=timeout)}",
            "Content-Type": "application/json",
        }

    def _read_job_response(self, job_id, phase, deadline, last_status=""):
        """Retry only transient reads; never resubmit the writing webhook."""
        output = phase == "output"
        url = self._job_output_url(job_id) if output else self._job_url(job_id)
        token_refreshed = False
        retries = 0
        last_error = ""
        while time.monotonic() < deadline:
            self._progress(f"Waiting for Azure Automation job {job_id} ({phase}, {last_status or 'pending'}).")
            headers = self._mgmt_headers(deadline)
            if output:
                # The byte ceiling must not rely on the inflater's behavior.
                headers["Accept-Encoding"] = "identity"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            response = None
            try:
                response = self._session.get(
                    url,
                    headers=headers,
                    timeout=min(30 if output else 15, remaining),
                    verify=True,
                    allow_redirects=False,
                    stream=output,
                )
                if output and time.monotonic() >= deadline:
                    self._job_timeout(job_id, phase, last_status)
                if response.status_code == 401 and not token_refreshed:
                    self._mgmt_token = None
                    token_refreshed = True
                    continue
                if response.status_code in {408, 429, 500, 502, 503, 504}:
                    last_error = f"Job {phase} API returned HTTP {response.status_code}"
                    delay = self._throttle_delay(response, retries)
                    retries += 1
                elif not 200 <= response.status_code < 300:
                    message = f"Job {job_id} {phase} API returned HTTP {response.status_code}"
                    if not output:
                        message += f": {self.redact_sensitive_text(response.text, max_chars=500)}"
                    raise AutomationError(message)
                elif output:
                    output_response, response = response, None
                    body = self._read_output_until_deadline(output_response, deadline, job_id, last_status)
                    return SimpleNamespace(text=body)
                else:
                    return response
            except requests.exceptions.RequestException as exc:
                last_error = self._transport_error_message("Transient job read failure", exc)
                delay = max(float(self._poll_interval), 1.0)
            finally:
                if output and getattr(response, "raw", None) is not None:
                    response.close()
            self._sleep_for_retry(delay, deadline, f"Waiting for Azure Automation job {job_id}; {last_error}.")
        self._job_timeout(job_id, phase, last_status, last_error)

    def _read_output_until_deadline(self, response, deadline, job_id, last_status):
        # Requests' read timeout is an inactivity timeout, not a wall-clock
        # budget. The download worker owns the stream and never invokes SOAR
        # callbacks or starts a retry. The caller can release its action lock
        # even if the current socket read cannot be interrupted.
        if getattr(response, "raw", None) is None:
            return self._read_output_body(response, deadline, job_id, last_status)
        done = Future()
        abandoned = Event()

        def download():
            try:
                try:
                    body = self._read_output_body(response, deadline, job_id, last_status, abandoned)
                finally:
                    response.close()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                done.set_exception(exc)
            else:
                done.set_result(body)

        try:
            Thread(target=download, name="azure-job-output", daemon=True).start()
        except BaseException:
            response.close()
            raise
        try:
            while (remaining := deadline - time.monotonic()) > 0:
                if wait([done], timeout=min(5, remaining)).done:
                    if time.monotonic() < deadline:
                        return done.result()
                    break
                if time.monotonic() < deadline:
                    self._progress(f"Waiting for Azure Automation job {job_id} output.")
            self._job_timeout(job_id, "output", last_status)
        finally:
            abandoned.set()

    def _read_output_body(self, response, deadline, job_id, last_status, abandoned=None):
        """Buffer only bounded, uncompressed bytes while the job budget remains."""
        encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
        if encoding not in {"", "identity"}:
            raise AutomationError("Azure job output returned an unsupported HTTP content encoding.")
        limit = MAX_JOB_OUTPUT_BYTES
        oversized = f"Azure job output exceeded the {limit}-byte download limit."
        length = response.headers.get("Content-Length", "").strip()
        if length.isascii() and length.isdecimal():
            # Compare decimal strings to avoid converting untrusted giant integers.
            digits = length.lstrip("0")
            bound = str(limit)
            if (len(digits), digits) > (len(bound), bound):
                raise AutomationError(oversized)
        if (abandoned is not None and abandoned.is_set()) or time.monotonic() >= deadline:
            self._job_timeout(job_id, "output", last_status)
        body = bytearray()
        # An adapter can also return a response with already-buffered content.
        if getattr(response, "raw", None) is not None:
            chunks = response.iter_content(JOB_OUTPUT_READ_BYTES)
        else:
            cached = getattr(response, "content", None)
            chunks = (cached if cached is not None else response.text.encode("utf-8"),)
        for chunk in chunks:
            if (abandoned is not None and abandoned.is_set()) or time.monotonic() >= deadline:
                self._job_timeout(job_id, "output", last_status)
            if len(body) + len(chunk) > limit:
                raise AutomationError(oversized)
            body.extend(chunk)
            if abandoned is not None and abandoned.is_set():
                self._job_timeout(job_id, "output", last_status)
        if time.monotonic() >= deadline:
            self._job_timeout(job_id, "output", last_status)
        try:
            return body.decode(getattr(response, "encoding", None) or "utf-8-sig", errors="replace")
        except LookupError:
            return body.decode("utf-8-sig", errors="replace")

    def _job_timeout(self, job_id, phase, last_status, detail=""):
        raise JobTimeoutError(
            f"Job {job_id} did not finish {phase} within the {self._poll_timeout}s wait budget. "
            "The outcome is unknown; Azure has not been stopped. Check the job in Azure "
            "before consciously starting a new action." + (f" Last read error: {detail}" if detail else ""),
            job_id=job_id,
            last_status=last_status,
            phase=phase,
        )

    def poll_job(self, job_id: str, deadline: Optional[float] = None) -> str:
        """Wait through nonterminal Azure states within one job/output deadline."""
        if deadline is None:
            deadline = self.new_poll_deadline()
        last_status = ""
        while time.monotonic() < deadline:
            response = self._read_job_response(job_id, "status", deadline, last_status)
            try:
                properties = response.json()["properties"]
                status = properties["status"]
                if not isinstance(status, str) or not status:
                    raise ValueError("missing status")
            except (ValueError, KeyError, TypeError) as exc:
                raise AutomationError(f"Unexpected job status response: {self.redact_sensitive_text(response.text, max_chars=200)}") from exc
            last_status = status
            if status in JOB_FAILURE_STATES:
                exception = properties.get("exception", "")
                raise JobFailedError(
                    f"Job {job_id} reached failure state '{status}'" + (f": {exception}" if exception else ""),
                    job_id=job_id,
                    last_status=status,
                    exception=exception,
                )
            if status == JOB_SUCCESS_STATE:
                return status
            self._sleep_for_retry(
                self._poll_interval,
                deadline,
                f"Waiting for Azure Automation job {job_id} ({status}).",
            )
        self._job_timeout(job_id, "status", last_status)

    # -----------------------------------------------------------------------
    # Job output
    # -----------------------------------------------------------------------

    def get_job_output(
        self,
        job_id: str,
        action: str,
        deadline: Optional[float] = None,
        *,
        output_private_key=None,
    ) -> dict:
        """
        Retrieve and parse the job's Write-Output content.

        List and export require authenticated job records. The other actions
        return one JSON object. Chunked records are verified and reassembled.

        Reference:
        https://learn.microsoft.com/en-us/rest/api/automation/job/get-output

        Args:
            job_id: Azure Automation Job ID.
            action: Expected action, which determines wire protection.

        Returns:
            Parsed dict from the runbook's Write-Output.

        Raises:
            AutomationError on HTTP errors or parse failure.
        """
        if action not in {"list", "export", "release", "deny", "reconcile", "diagnose"}:
            raise AutomationError("Job output requires a known expected action.")
        if deadline is None:
            deadline = self.new_poll_deadline()
        while time.monotonic() < deadline:
            response = self._read_job_response(job_id, "output", deadline, "Completed")
            raw = response.text.strip()
            if raw:
                break
            self._sleep_for_retry(
                max(float(self._poll_interval), 1.0),
                deadline,
                f"Waiting for Azure Automation job {job_id} output.",
            )
        else:
            self._job_timeout(job_id, "output", "Completed", "No output available")

        self._raise_if_stream_limit(raw, action=action)
        if action in PROTECTED_READ_ACTIONS:
            raw = self._decrypt_job_records(raw, action, output_private_key)

        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise AutomationError(f"Job output JSON must be an object. Got {type(parsed).__name__}.")
            mode = self._validated_job_record_mode(parsed)
            if mode in {
                LIST_CHUNK_MODE,
                LIST_COMPLETE_MODE,
                CHUNKED_EXPORT_MODE,
                CHUNKED_COMPLETE_MODE,
            }:
                return self._parse_multiline_job_output(raw)
            return parsed
        except ValueError:
            return self._parse_multiline_job_output(raw)

    @staticmethod
    def _decrypt_job_records(raw: str, action: str, private_key) -> str:
        """Accept only a complete, ordered protected response, or a setup error."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            # Early key/runtime/input errors can precede cipher setup. Never
            # propagate their arbitrary text, and never accept plaintext data.
            plain_error = json.loads(raw) if len(raw) < 16384 else None
        except ValueError:
            plain_error = None
        if isinstance(plain_error, dict) and plain_error.get("error") is True:
            raise AutomationError("Protected output was not initialized. Check the paired runbook and its PowerShell runtime.")
        if private_key is None:
            raise AutomationError("Protected output has no matching job key.")

        decrypted = []
        cipher = None
        final = False
        max_records = MAX_LIST_RESULT_COUNT + 1 if action == "list" else MAX_CHUNK_COUNT + 1
        try:
            for index, line in enumerate(raw.split("\n")):
                if final or index >= max_records or len(line) >= MAX_PROTECTED_RECORD_CHARS:
                    raise ValueError
                record = json.loads(line)
                if (
                    not isinstance(record, dict)
                    or record.get("mode") != PROTECTED_OUTPUT_MODE
                    or type(record.get("index")) is not int
                    or record["index"] != index
                    or type(record.get("final")) is not bool
                    or ("wrapped_key" in record) != (index == 0)
                ):
                    raise ValueError
                if index == 0:
                    key = private_key.decrypt(
                        base64.b64decode(record["wrapped_key"], validate=True),
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                    )
                    if len(key) != 32:
                        raise ValueError
                    cipher = AESGCM(key)
                final = record["final"]
                nonce = base64.b64decode(record["nonce"], validate=True)
                tag = base64.b64decode(record["tag"], validate=True)
                if len(nonce) != 12 or len(tag) != 16:
                    raise ValueError
                aad = f"{PROTECTED_OUTPUT_MODE}:{action}:{index}:{int(final)}".encode("ascii")
                ciphertext = base64.b64decode(record["ciphertext"], validate=True)
                decrypted.append(cipher.decrypt(nonce, ciphertext + tag, aad).decode("utf-8"))
            if not final:
                raise ValueError
        except (ValueError, TypeError, KeyError, InvalidTag) as exc:
            raise AutomationError("Protected job output is invalid or incomplete.") from None
        return "\n".join(decrypted)

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
                "Azure Automation job output exceeded the 1 MiB stream limit. Use bounded list/chunked export transport in the runbook."
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

    @staticmethod
    def _validated_job_record_mode(record):
        mode = record.get("mode")
        if "mode" in record and not isinstance(mode, str):
            raise AutomationError("Runbook protocol error: field 'mode' must be a string.")
        return mode

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

        for record in records:
            self._validated_job_record_mode(record)
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

    def _parse_chunked_list_records(self, records: list) -> dict:
        """Validate bounded list records and normalise them to one list result."""
        complete_records = [record for record in records if record.get("action") == "list" and record.get("mode") == LIST_COMPLETE_MODE]
        if len(complete_records) != 1:
            raise AutomationError("Chunked list output must contain exactly one action=list mode=list_complete trailer.")

        complete = complete_records[0]
        chunk_count = self._required_int(complete, "chunk_count", "chunked list trailer")
        expected_count = self._required_int(complete, "count", "chunked list trailer")
        metadata = {key: complete[key] for key in ("runbook_version", "runbook_source_revision", "runbook_build_id") if key in complete}

        if chunk_count < 1 or chunk_count > MAX_LIST_RESULT_COUNT:
            raise AutomationError(f"Chunked list chunk_count must be between 1 and {MAX_LIST_RESULT_COUNT}.")
        if expected_count < 1 or expected_count > MAX_LIST_RESULT_COUNT:
            raise AutomationError(f"Chunked list count must be between 1 and {MAX_LIST_RESULT_COUNT}.")

        chunks = [record for record in records if record.get("action") == "list" and record.get("mode") == LIST_CHUNK_MODE]
        if len(chunks) != chunk_count:
            raise AutomationError(f"Chunked list expected {chunk_count} chunk(s), got {len(chunks)}.")

        indexed_chunks = {}
        for chunk in chunks:
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
            **metadata,
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
        metadata = {key: complete[key] for key in ("runbook_version", "runbook_source_revision", "runbook_build_id") if key in complete}

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
            **metadata,
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
        include_rbac: Optional[bool] = None,
        *,
        validate_result=None,
    ) -> dict:
        """Submit exactly one job, then wait for its result."""
        if action not in PROTECTED_READ_ACTIONS:
            job_id = self.start_job(action, identity, page_size, include_rbac=include_rbac)
            return self.wait_for_action_result(job_id, action, identity, validate_result=validate_result)
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = base64.b64encode(
                private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode("ascii")
        except (ImportError, ValueError) as exc:
            raise AutomationError("Protected output cryptography is unavailable; no job was started.") from exc
        job_id = self.start_job(action, identity, page_size, output_public_key=public_key)
        return self.wait_for_action_result(
            job_id,
            action,
            identity,
            output_private_key=private_key,
            validate_result=validate_result,
        )

    def wait_for_action_result(
        self,
        job_id: str,
        action: str,
        identity: Optional[str] = None,
        requested_include_rbac: Optional[bool] = None,
        *,
        output_private_key=None,
        validate_result=None,
    ) -> dict:
        """Wait for the normal job and output using one shared deadline.

        Failed Azure jobs are returned as failures with their original exception;
        their output is never read to reconstruct a different outcome.
        """
        deadline = self.new_poll_deadline()
        self._next_progress_at = 0.0
        last_status = ""
        try:
            last_status = self.poll_job(job_id, deadline=deadline)
            kwargs = {"output_private_key": output_private_key} if action in PROTECTED_READ_ACTIONS else {}
            result = self.get_job_output(job_id, action=action, deadline=deadline, **kwargs)
            self._validate_runbook_result(result, action, identity)
            self._raise_for_runbook_error(result, action, identity)
            if validate_result is not None:
                validate_result(result)
            return result
        except AutomationError as exc:
            # Preserve the known job on every failure, including bad output
            # and runbook errors reached through native import's run_action.
            exc.job_id = job_id
            if not getattr(exc, "last_status", ""):
                exc.last_status = last_status
            raise

    def _validate_runbook_result(
        self,
        result: dict,
        requested_action: str,
        requested_identity: Optional[str] = None,
        requested_include_rbac: Optional[bool] = None,
    ) -> None:
        """Check action/identity and business result, not implementation evidence."""
        if not isinstance(result, dict):
            raise AutomationError("Runbook protocol error: final output must be a JSON object.")
        if result.get("action") != requested_action:
            raise AutomationError("Runbook protocol error: response action does not match requested action.")
        if "error" in result and not isinstance(result["error"], bool):
            raise AutomationError("Runbook protocol error: field 'error' must be a boolean.")
        is_error = result.get("error") is True
        context = result.get("context", result.get("details", {}))
        context = context if isinstance(context, dict) else {}
        response_identity = result.get("identity", context.get("identity") if is_error else None)
        if requested_identity is not None and not self._quarantine_identities_match(response_identity, requested_identity):
            raise AutomationError("Runbook protocol error: response identity does not match the requested identity.")
        if is_error:
            if not isinstance(result.get("message"), str) or not result["message"]:
                raise AutomationError("Runbook protocol error: error result requires a message.")
            return
        if requested_action in {"release", "deny"}:
            expected = "released" if requested_action == "release" else "denied"
            status = result.get("status")
            if not isinstance(status, str) or status not in {expected, f"already_{expected}"}:
                raise AutomationError(f"Runbook protocol error: successful {requested_action} requires status={expected} or already_{expected}.")
            if not self._quarantine_identities_match(result.get("observed_identity"), requested_identity):
                raise AutomationError("Runbook protocol error: observed_identity does not match requested identity.")
            observed = result.get("observed_release_status")
            if not isinstance(observed, str) or observed.lower() != expected:
                raise AutomationError(
                    f"Runbook protocol error: successful {requested_action} lacks confirmed Exchange ReleaseStatus={expected.title()}."
                )
        elif requested_action == "list":
            if "messages" not in result or not isinstance(result["messages"], (list, dict)):
                raise AutomationError("Runbook protocol error: list requires messages.")
        elif requested_action == "export":
            if not result.get("_eml_bytes") and not self.extract_eml(result):
                raise AutomationError("Runbook protocol error: export requires EML content.")
        elif requested_action == "reconcile":
            if not self._quarantine_identities_match(result.get("observed_identity"), requested_identity):
                raise AutomationError("Runbook protocol error: observed_identity does not match requested identity.")
            release_status = result.get("observed_release_status", result.get("release_status"))
            if not isinstance(release_status, str) or not release_status:
                raise AutomationError("Runbook protocol error: reconcile requires release_status.")
        # Manual diagnose details remain optional observations, not a proof matrix.

    def _raise_for_runbook_error(
        self,
        result: dict,
        requested_action: str,
        requested_identity: Optional[str] = None,
    ) -> None:
        if result.get("error") is not True:
            return
        self._validate_runbook_result(result, requested_action, requested_identity)
        if result.get("error_code", result.get("code")) == "export_oversized":
            details = result.get("context", result.get("details", {}))
            details = details if isinstance(details, dict) else {}
            if requested_action != "export":
                raise AutomationError("Runbook protocol error: export_oversized is only valid for export.")
            # Sizes are useful when supplied, but native errors need no evidence envelope.
            sizes = {}
            for key in ("decoded_size", "max_decoded_size"):
                try:
                    sizes[key] = parse_strict_integer(details.get(key, result.get(key)))
                except (TypeError, ValueError):
                    sizes[key] = None
            raise OversizedExportError(result["message"], identity=requested_identity, **sizes)
        # Keep native code/context/PowerShell fields intact on the exception.
        raise RunbookActionError(result["message"], result=result)

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
