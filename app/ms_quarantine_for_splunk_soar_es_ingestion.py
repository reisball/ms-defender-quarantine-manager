# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Native ES ingestion for the existing App-Wizard connector.

Wire contract: splunk-soar-sdk 6.1.5 abstract.SOARClient and Finding models.
No SDK runtime dependency, decorator batching, or additional stored credentials.
"""

import hashlib
import ipaddress
import json
from urllib.parse import quote, urljoin, urlsplit

import requests

from ms_quarantine_for_splunk_soar_utils import MAX_DECODED_EML_BYTES, AutomationError
from ms_quarantine_for_splunk_soar_ingestion import (
    _parse_mime_mail, _mail_files_from_parsed, _MimeStructureLimit,
)

ES_MAX_JSON_BYTES = 2 * 1024 * 1024


class ESSubmissionRejected(AutomationError):
    """Definitive HTTP rejection, safe for the caller to clear submit intent.

    A response body is deliberately not retained. Network errors, invalid/lost
    responses, 5xx and ambiguous 408/425/429/499 never use this exception.
    """

    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"SOAR ES transport rejected request: HTTP {status_code}.")


def _platform_transport_policy():
    """Read the actual platform policy, not asset/runtime TLS overrides.

    SDK 6.1.5 delegates these settings to phantom_common.install_info.
    Without that module use certificate verification, not its SDK test shim's
    insecure fallback.
    """
    try:
        from phantom_common.install_info import (
            get_verify_ssl_setting, is_onprem_broker_install,
        )
    except ImportError:
        return True, False
    verify = get_verify_ssl_setting()
    broker = is_onprem_broker_install()
    if type(verify) is not bool or type(broker) is not bool:
        raise AutomationError("SOAR platform TLS/install policy is malformed.")
    return verify, broker


class NativeESClient:
    """Use the ephemeral native action-run session, never an asset API token.

    Native SOAR only. Automation Broker is unsupported: SDK 6.1.5 requires
    api_proxy routing plus RPC Bearer/WebSocket ph-auth-token and
    PsaasImpersonationToken headers, which this native adapter does not implement.
    Honor the platform verification policy; its native 127.0.0.1 endpoint has
    the SDK's narrowly scoped TLS exception (not localhost/arbitrary hosts).
    """

    def __init__(self, runtime, base_url):
        verify, broker = _platform_transport_policy()
        if broker or runtime.get("broker_ph_auth_token"):
            raise AutomationError(
                "ES adapter requires native SOAR execution; Automation Broker "
                "api_proxy authentication is unsupported."
            )
        token = runtime.get("user_session_token")
        basic = runtime.get("soar_auth") or {}
        if not token and basic.get("phantom_url"):
            base_url = basic["phantom_url"]
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise AutomationError("ES adapter requires a trusted HTTPS SOAR base URL.")
        if not token and not (basic.get("username") and basic.get("password")):
            raise AutomationError(
                "ES adapter requires the native action-run user session."
            )
        # SDK AppClient._create_client grants its exception only to the
        # native IPv4 loopback host and configured port. Requests below never
        # follow redirects automatically and cannot leave this fixed origin.
        self._verify_tls = verify and parsed.hostname != "127.0.0.1"
        self.base_url = base_url.rstrip("/")
        self._server_version = None
        self._download_origin = None
        self.session = requests.Session()
        if token:
            self.session.cookies.set("sessionid", token)
        response = self._request("GET", "/login")
        self.session.cookies.update(response.cookies)
        # An authenticated /login may redirect to the UI before setting CSRF.
        # Follow only same-origin HTTPS locations, never redirect credentials.
        for _ in range(3):
            if not response.is_redirect:
                break
            location = urljoin(
                self.base_url + "/login", response.headers.get("Location", "")
            )
            target = urlsplit(location)
            if (target.scheme, target.netloc) != (parsed.scheme, parsed.netloc):
                raise AutomationError(
                    "SOAR login redirected outside its trusted origin."
                )
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            response = self._request("GET", path, allow_login_redirect=True)
            self.session.cookies.update(response.cookies)
        if response.is_redirect:
            raise AutomationError("SOAR login exceeded its redirect limit.")
        csrf = self.session.cookies.get("csrftoken") or response.cookies.get(
            "csrftoken"
        )
        if not csrf:
            raise AutomationError("SOAR session did not supply a CSRF token.")
        self.session.headers.update(
            {"X-CSRFToken": csrf, "Referer": self.base_url + "/"}
        )
        if not token:
            login_response = self._request(
                "POST",
                "/login",
                data={
                    "username": basic["username"],
                    "password": basic["password"],
                    "csrfmiddlewaretoken": csrf,
                },
            )
            self.session.cookies.update(login_response.cookies)
            if not self.session.cookies.get("sessionid"):
                raise AutomationError(
                    "Native SOAR runtime login did not establish a session."
                )
            csrf = self.session.cookies.get("csrftoken") or csrf
            self.session.headers["X-CSRFToken"] = csrf

    def _request(self, method, path, allow_login_redirect=False, **kwargs):
        # Prevent callers from widening the loopback TLS exception or changing
        # transport policy; all API paths must remain relative to this origin.
        if (not isinstance(path, str) or not path.startswith("/")
                or path.startswith("//") or urlsplit(path).netloc
                or any(key in kwargs for key in ("verify", "allow_redirects", "timeout"))):
            raise AutomationError("SOAR ES request must use a fixed-origin API path.")
        try:
            response = self.session.request(
                method,
                self.base_url + path,
                timeout=30,
                verify=self._verify_tls,
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            # Exception text can contain cookies/URLs; never surface it.
            raise AutomationError(
                "SOAR ES transport failed: " + type(exc).__name__
            ) from None
        if 400 <= response.status_code < 500 and response.status_code not in {408, 425, 429, 499}:
            raise ESSubmissionRejected(response.status_code)
        if response.status_code >= 400 or (
            response.is_redirect and path != "/login" and not allow_login_redirect
        ):
            raise AutomationError(
                f"SOAR ES transport returned HTTP {response.status_code}."
            )
        return response

    def _public_download_origin(self):
        """Resolve analyst-facing links independently of authenticated transport."""
        if self._download_origin is not None:
            return self._download_origin
        origin = self.request("GET", "/rest/system_info").get("base_url")
        error = "SOAR system_info did not supply a valid external HTTPS download origin."
        if (not isinstance(origin, str) or not origin
                or any(char.isspace() or ord(char) < 32 for char in origin)
                or "\\" in origin):
            raise AutomationError(error)
        try:
            parsed = urlsplit(origin)
            port = parsed.port
            host = parsed.hostname
            if (parsed.scheme != "https" or not host
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                    or "?" in origin or "#" in origin or "%" in host
                    or port == 0):
                raise ValueError
            host = host.rstrip(".").lower()
            if host == "localhost" or host.endswith(".localhost"):
                raise ValueError
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                # Private service DNS is valid; resolution is not needed here.
                if (not host or host.split(".")[-1].isdigit()
                        or host.lower().startswith("0x") or any(
                    not (char.isascii() and (char.isalnum() or char in ".-"))
                    for char in host
                )):
                    raise ValueError
            else:
                address = getattr(address, "ipv4_mapped", None) or address
                if (address.is_loopback or address.is_unspecified
                        or address.is_link_local or address.is_multicast):
                    raise ValueError
        except ValueError:
            raise AutomationError(error) from None
        self._download_origin = origin.rstrip("/")
        return self._download_origin

    def _prepare_download_links(self, prepared):
        """Rebase only generated Vault URLs; never send session auth there."""
        email_records = [
            finding["email"] for finding in prepared.get("findings", [])
            if isinstance(finding.get("email"), dict)
            and (finding["email"].get("attachments")
                 or finding["email"].get("raw_email_link"))
        ]
        if not email_records:
            return
        origin = self._public_download_origin()
        prefix = self.base_url + "/rest/download_attachment?vault_id="

        def external_link(link):
            if not isinstance(link, str) or not link.startswith(prefix):
                raise AutomationError("ES mail download link is not a generated Vault URL.")
            return origin + link[len(self.base_url):]

        for email in email_records:
            for attachment in email.get("attachments", []):
                attachment["url"] = external_link(attachment.get("url"))
            if email.get("raw_email_link"):
                email["raw_email_link"] = external_link(email["raw_email_link"])

    def prepare_bulk_payload(self, payload):
        """Complete fallible version/schema work before marking a submission."""
        prepared = json.loads(json.dumps(payload))
        self._prepare_download_links(prepared)
        if prepared.get("findings"):
            # SOAR 8.6's live backend predates the SDK 6.1.5 mapping shape.
            # Keep the SDK model internally, adapting only the native wire.
            if self._server_version is None:
                version = self.request("GET", "/rest/version").get("version")
                if not isinstance(version, str) or not version:
                    raise AutomationError("Could not identify the SOAR ES backend version.")
                self._server_version = version
            if self._server_version.split(".")[:2] == ["8", "6"]:
                for finding in prepared["findings"]:
                    fields = finding.get("additional_fields")
                    if isinstance(fields, dict):
                        finding["additional_fields"] = [
                            {"name": name, "value": value if isinstance(value, str)
                             else json.dumps(value, sort_keys=True)}
                            for name, value in fields.items()
                        ]
        return prepared

    def request(self, method, path, **kwargs):
        response = self._request(method, path, **kwargs)
        try:
            result = response.json()
        except ValueError:
            raise AutomationError("SOAR ES transport returned invalid JSON.") from None
        if not isinstance(result, dict):
            raise AutomationError("SOAR ES transport returned a non-object response.")
        return result


def _validated_drilldowns(ingest):
    """Validate SDK Finding drilldown structures before any Vault uploads."""
    result = {}
    for setting, required in (
        ("es_drilldown_searches", ("name", "search", "earliest", "latest")),
        ("es_drilldown_dashboards", ("app", "dashboard_id", "name")),
    ):
        value = ingest.get(setting)
        if value is None:
            continue
        if not isinstance(value, list):
            raise AutomationError("Invalid ES drilldown list: " + setting)
        for entry in value:
            if not isinstance(entry, dict) or any(
                not isinstance(entry.get(key), str) or not entry[key].strip()
                for key in required
            ):
                raise AutomationError("Invalid ES drilldown fields: " + setting)
            if setting == "es_drilldown_dashboards" and entry.get("tokens") is not None:
                tokens = entry["tokens"]
                if not isinstance(tokens, list) or any(
                    not isinstance(token, dict)
                    or not isinstance(token.get("name"), str)
                    or not token["name"].strip()
                    or not isinstance(token.get("value"), str)
                    for token in tokens
                ):
                    raise AutomationError("Invalid ES drilldown dashboard tokens.")
        result[setting.removeprefix("es_")] = value
    return result


def _outer_body_part(mail):
    """Select an outer body, never a file or attached message's descendants."""
    if mail.get_content_disposition() == "attachment" or mail.get_filename():
        return None
    kind = mail.get_content_type()
    if kind in {"text/plain", "text/html"}:
        return mail
    # message/rfc822 is multipart to the parser but is not the outer body.
    if mail.get_content_maintype() != "multipart":
        return None
    parts = list(mail.iter_parts())
    if kind == "multipart/related":
        start = mail.get_param("start")
        root = next((p for p in parts if p.get("Content-ID") == start), None) if start else None
        parts = [root if root is not None else parts[0]] if parts else []
    best = None
    for part in parts:
        candidate = _outer_body_part(part)
        if candidate is not None:
            if candidate.get_content_type() == "text/plain":
                return candidate
            if best is None:
                best = candidate
    return best


def build_finding(
    message, eml_bytes, identity, work_item_id, source_id, ingest, upload, base_url
):
    """Build the SDK Finding wire shape. Upload must confirm *every* file."""
    if not eml_bytes or len(eml_bytes) > MAX_DECODED_EML_BYTES:
        raise AutomationError(
            "ES ingestion requires a complete EML within the 24 MiB export limit."
        )
    try:
        mail = _parse_mime_mail(eml_bytes)
    except _MimeStructureLimit:
        raise
    except Exception:  # noqa: BLE001 -- parser failures must not submit incomplete mail
        raise AutomationError("Could not parse the exported EML.") from None
    if not mail.keys():
        raise AutomationError("Exported EML has no mail headers.")
    if not isinstance(eml_bytes, bytes):
        raise AutomationError("Missing or oversized EML; import not published.")
    attachments = _mail_files_from_parsed(mail)
    return _build_finding_from_parsed(
        message, eml_bytes, identity, work_item_id, source_id, ingest,
        upload, base_url, mail, attachments,
    )


def _build_finding_from_parsed(
    message, eml_bytes, identity, work_item_id, source_id, ingest, upload,
    base_url, mail, attachments,
):
    """Project a tree already validated by the shared intake parser."""
    files = [("original.eml", eml_bytes, True)] + [
        (name, content, False) for name, content in attachments
    ]
    body = ""
    part = _outer_body_part(mail)
    if part is not None:
        content = part.get_payload(decode=True) or b""
        try:
            body = content.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            body = content.decode("utf-8", errors="replace")
    # Preserve duplicate RFC headers as arrays; the raw message is authoritative.
    headers = {}
    for key, value in mail.items():
        key = key.lower()
        value = str(value)[:8192]
        if key in headers:
            if not isinstance(headers[key], list):
                headers[key] = [headers[key]]
            headers[key].append(value)
        else:
            headers[key] = value
    raw_headers = headers
    # Match extras.email.EmailData.to_dict used by the reference connectors.
    # ES uses normalized underscore keys; retain exact RFC header names too.
    headers = {"email_id": identity, "raw_headers": raw_headers}
    for field, rfc_name in {
        "from": "from",
        "to": "to",
        "cc": "cc",
        "bcc": "bcc",
        "subject": "subject",
        "date": "date",
        "message_id": "message-id",
        "reply_to": "reply-to",
        "content_type": "content-type",
        "x_mailer": "x-mailer",
        "x_priority": "x-priority",
    }.items():
        value = raw_headers.get(rfc_name)
        if value:
            headers[field] = ", ".join(value) if isinstance(value, list) else value
    received = raw_headers.get("received")
    if received:
        headers["received"] = received if isinstance(received, list) else [received]
    finding = {
        "rule_title": (
            "Quarantine release request: "
            + str(message.get("Subject") or mail.get("Subject") or identity)
        )[:240],
        "rule_description": "Microsoft Defender quarantine message; original EML attached.",
        "security_domain": ingest["es_security_domain"],
        "urgency": ingest.get("es_urgency"),
        "investigation_type": ingest.get("es_investigation_type"),
        "run_threat_analysis": ingest.get("es_run_threat_analysis", False),
        "launch_automation": ingest.get("es_launch_automation", False),
        "finding_source": ingest.get("_finding_source", "MS Quarantine for Splunk SOAR"),
        "additional_fields": {
            "quarantine_identity": identity,
            "work_item_id": work_item_id,
            "source_data_identifier": source_id,
            "quarantine": dict(message),
            "eml_sha256": hashlib.sha256(eml_bytes).hexdigest(),
        },
        "email": {"headers": headers, "body": body[:256000], "attachments": []},
    }
    finding = {key: value for key, value in finding.items() if value is not None}
    finding.update(_validated_drilldowns(ingest))
    # Bound the complete JSON before any uploads or remote finding creation.
    if len(json.dumps(finding).encode("utf-8")) > ES_MAX_JSON_BYTES:
        raise AutomationError("Finding metadata exceeds the ES JSON safety budget.")
    for name, content, raw in files:
        vault_id = upload(name, content)
        if not isinstance(vault_id, str) or not vault_id:
            raise AutomationError(
                "ES mail attachment was not confirmed in the SOAR Vault."
            )
        link = (
            base_url.rstrip("/")
            + "/rest/download_attachment?vault_id="
            + quote(vault_id, safe="")
        )
        finding["email"]["attachments"].append(
            {"filename": name, "filesize": len(content), "url": link}
        )
        if raw:
            finding["email"]["raw_email_link"] = link
    return finding

