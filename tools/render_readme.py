#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Render self-contained distributable help from the shipped manifest."""

import argparse
import json
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def render(manifest):
    def code(value):
        return "<code>" + escape(str(value)) + "</code>"

    rows = []
    for key, spec in sorted(manifest["configuration"].items(), key=lambda item: item[1].get("order", 999)):
        default = json.dumps(spec["default"]) if "default" in spec else "not set"
        desc = escape(spec["description"])
        if spec.get("value_list"):
            desc += " Choices: " + ", ".join(code(v) for v in spec["value_list"]) + "."
        rows.append(
            "<tr><td>"
            + code(key)
            + "</td><td>"
            + ("yes" if spec.get("required") else "no")
            + "</td><td>"
            + code(default)
            + "</td><td>"
            + desc
            + "</td></tr>"
        )
    actions = []
    for action in manifest["actions"]:
        params = []
        for key, spec in sorted(action.get("parameters", {}).items(), key=lambda item: item[1].get("order", 999)):
            desc = escape(spec.get("description", ""))
            if spec.get("value_list"):
                desc += " Choices: " + ", ".join(code(v) for v in spec["value_list"]) + "."
            params.append("<li>" + code(key) + " (" + ("required" if spec.get("required") else "optional") + "): " + desc + "</li>")
        actions.append(
            "<h3>"
            + escape(action["action"])
            + "</h3><p>"
            + escape(action.get("description", ""))
            + "</p>"
            + ("<ul>" + "".join(params) + "</ul>" if params else "<p>No parameters.</p>")
        )
    title = escape(manifest["name"]) + " " + escape(manifest["app_version"])
    return (
        """<!--
Copyright 2026 Kai Seidenschnur
Licensed under the Apache License, Version 2.0.
-->
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>"""
        + title
        + """</title></head>
<body>
<h1>"""
        + title
        + """</h1>
<p>Publisher: """
        + escape(manifest["publisher"])
        + """. Copyright 2026 Kai Seidenschnur.
Apache-2.0; see the included <a href="LICENSE">LICENSE</a>.</p>
<h2>Overview</h2>
<p>Import Microsoft Defender quarantined email into Splunk SOAR or Enterprise
Security through Azure Automation. Each message includes its original email,
attachments and selected metadata. Importing a message does not release or deny it.</p>
<p>This distribution has its own app UUID and package identity. It does not
convert assets belonging to another app. Configure one ingesting asset per tenant;
pause previous intake before a controlled replacement.</p>
<h2>Requirements and setup</h2>
<ol>
<li>Deploy the companion Azure Automation Runbook 3.4.5 separately. Enable the
Automation Account's system-assigned Managed Identity and install the
ExchangeOnlineManagement module in its PowerShell runtime.</li>
<li>Grant the Managed Identity <code>Exchange.ManageAsApp</code> and the
Exchange/Defender permissions for the quarantine actions you intend to use.
Exchange sign-in uses Managed Identity, not the asset's client secret.</li>
<li>Create a runbook webhook. Enter its direct HTTPS URL and the Automation
Account coordinates in the asset. Configure a separate App Registration with
Automation Job Operator access on that account for reading Azure job status
and output. Enter its tenant ID, client ID and client secret value.</li>
<li>Set the Exchange tenant domain in the asset or in the Automation Variable
<code>ExchangeOrganization</code>; the asset value takes precedence.</li>
<li>Use one ingesting asset per tenant. Select the source mode and target before
starting intake. Configure the container label and schedule in Ingest Settings;
disable the schedule to pause automatic imports. Use Poll Now for a manual import. For ES, use the native ES ingest settings
and register the five additional fields below.</li>
<li>Configure the analysis playbook's asset bindings, analyst/approver settings,
notification recipients, portal links and routing label before activation.
For SOAR, start analysis from the completed mail's ready artifact.</li>
</ol>
<p>Native email import requires authenticated local SOAR REST access, including
when importing into SOAR rather than ES. Automation Broker is not supported;
The connector has been piloted successfully on Splunk SOAR Cloud.</p>
<h2>Email import</h2>
<p><code>on_poll_max_containers</code> is a maximum of simultaneously unresolved
Microsoft quarantine identities, configurable 1–50 and default 10. It is not a
per-poll increment. The app checks tracked IDs read-only; exact
<code>Released</code> or <code>Denied</code> frees slots. It fills free slots from
the existing first 50 source-status candidates. Missing IDs, errors, other
statuses and analysis completion do not free slots. An empty import does not
prove an empty backlog; no pagination or stable ordering is promised.</p>
<p>Selection <code>release_requested</code> means Microsoft <code>Requested</code>;
<code>needs_review</code> means <code>NotReleased</code>. Needs review is explicit
opt-in and may process mail without a recipient request. Check your tenant's Deny eligibility before using it with NotReleased messages. A mail intentionally left unchanged can occupy
a slot indefinitely.</p>
<p>Original email and attachments are saved automatically to the container's
Vault. Selected mail fields are always added as artifacts, using the chosen
combined/separate layout.
All preparation suppresses automation. SOAR publishes a final
ready artifact only after preparation; use its <code>ingestionReady=true</code>,
<code>quarantineIdentity</code> and original-mail <code>vaultId</code>.
ES uses the configured native threat-analysis and automation settings instead;
publication acceptance does not prove that an analysis workflow finished.</p>
<h2>Native ES prerequisites</h2>
<p>Register <code>quarantine_identity</code>, <code>work_item_id</code>,
<code>source_data_identifier</code>, <code>quarantine</code> and
<code>eml_sha256</code> as accepted additional fields in the target ES environment.
The app does not register them. Configure a valid security domain; urgency and
investigation type are optional native settings. Analyst download links use the
validated external HTTPS base URL from SOAR system information. Test their
reachability and mail/attachment rendering from the analyst interface. ES is a
lossy projection: the outer message body prefers plain text, then HTML;
attachment-marked parts, file-named parts and attached-message descendants are
excluded. Related MIME uses its declared root (or first part). Header values are limited to 8192 characters
and body to 256000 characters. The 2 MiB metadata check precedes attachment-link
entries and is not a complete final-request size guarantee. The original EML in
Vault remains authoritative.</p>
<h2>Configuration</h2>
<p>Configure the Azure connection, email selection and active-message limit,
selected mail fields, and advanced job settings below. The ingest schedule is
set in SOAR/ES Ingest Settings; the Azure polling interval and timeout monitor
individual Azure jobs, not the mail-import schedule.</p>
<p>The SOAR URL override applies to both SOAR and ES email import. Azure
connections require HTTPS and certificate verification; webhook redirects are
not followed. Configure the platform's trusted CA store for private certificates.</p>
<table><thead><tr><th>Field</th><th>Required</th><th>Default</th><th>Description</th></tr></thead><tbody>
"""
        + "\n".join(rows)
        + """
</tbody></table>
<h2>Available actions</h2>
<p>Release and Deny run only when invoked by an operator or playbook. The app
confirms the resulting Microsoft status before reporting a successful disposition.</p>
"""
        + "\n".join(actions)
        + """
<h2>Maintenance and removal</h2>
<p>Back up the app, asset configuration and app state using the platform backup
procedure. Stop ingestion and dependent automation before removing the app.
Resolve pending operations before restoring a backup; do not clear state to
restart processing or resubmit an operation with an unknown outcome.</p>
<h2>Failures and recovery</h2>
<p>Retryable preparation and definitive publication rejection can retry on a later
poll. Timeout, lost or mismatched receipt, server failure and unknown acceptance
remain <code>publishing</code>; no blind resubmission. Deterministic MIME/size
failures remain <code>blocked</code>. Use <b>recover quarantine ingestion</b> with
an exact identity and an evidence-based operator note. Retry preparation only
after its underlying problem is fixed; confirm published only after independently
verifying the existing exact artifact/finding and workflow. Recovery does not
free a Microsoft-status-controlled slot or dispatch analysis by itself.</p>
<ul><li><code>retry_preparation</code> is allowed only from <code>blocked</code>,
<code>reserved</code>, <code>preparing</code> or <code>ready</code>. It resets to
<code>preparing</code> with a bound container, otherwise <code>reserved</code>;
a later poll resumes preparation. It cannot reset publishing or published items.</li>
<li><code>confirm_published</code> is allowed only from <code>publishing</code>.
Verify the existing exact ready artifact or ES finding, linked container and
native automation execution independently, and record evidence in the required
operator note. This operator assertion marks <code>published</code> without
sending another submission; the app does not verify that evidence itself.</li></ul>
<p>For uncertain Release/Deny outcomes use read-only reconciliation before any
new write. A genuine Microsoft error is not proof that no effect occurred.
No polling operation calls Release/Deny.</p>
<h2>Limits and data handling</h2>
<p>EML cap: 24 MiB. MIME limits: 200 parts, nesting depth 30, 100 attachments,
48 MiB combined decoded attachments. Native ledger cap: 1000 records; active
items are not evicted. Terminal retention is configurable 1–365 days, default
30. Retention expiry can allow reappearing source records to be admitted again;
there is no global exactly-once guarantee. A 600-second between-call poll budget
defers remaining work; one in-flight operation may run longer.</p>
<p>Mail and attachments may contain sensitive content or malware. Original mail
travels from Exchange through Azure Automation to SOAR/Vault; ES receives finding
metadata and mail/file links. Apply platform permissions, retention and handling
policies to jobs, Vault, state and evidence. No credentials are stored in this
help. Do not include message bodies, tokens or webhook URLs in support reports.</p>
<h2>Troubleshooting and support</h2>
<p>If an action fails, record the app and runbook versions, SOAR/ES versions,
selection mode, action error and Azure job ID. Check the job output and use
read-only reconciliation for an uncertain disposition. Do not include client
secrets, webhook tokens or message contents in support reports.</p>
</body></html>
"""
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(json.loads((ROOT / "ms_quarantine_for_splunk_soar.json").read_text()))
    path = ROOT / "readme.html"
    if args.check:
        if not path.exists() or path.read_text() != expected:
            parser.error("readme.html is missing or differs from the manifest-backed generator")
    else:
        path.write_text(expected)


if __name__ == "__main__":
    main()
