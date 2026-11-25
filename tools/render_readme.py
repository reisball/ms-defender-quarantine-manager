#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Render self-contained distributable help from the shipped manifest."""
import argparse
from html import escape
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def render(manifest):
    def code(value):
        return "<code>" + escape(str(value)) + "</code>"

    rows = []
    for key, spec in sorted(manifest["configuration"].items(),
                            key=lambda item: item[1].get("order", 999)):
        default = json.dumps(spec["default"]) if "default" in spec else "not set"
        desc = escape(spec["description"])
        if spec.get("value_list"):
            desc += " Choices: " + ", ".join(code(v) for v in spec["value_list"]) + "."
        rows.append("<tr><td>" + code(key) + "</td><td>"
                    + ("yes" if spec.get("required") else "no") + "</td><td>"
                    + code(default) + "</td><td>" + desc + "</td></tr>")
    actions = []
    for action in manifest["actions"]:
        params = []
        for key, spec in sorted(action.get("parameters", {}).items(),
                                key=lambda item: item[1].get("order", 999)):
            desc = escape(spec.get("description", ""))
            if spec.get("value_list"):
                desc += " Choices: " + ", ".join(code(v) for v in spec["value_list"]) + "."
            params.append("<li>" + code(key) + " ("
                          + ("required" if spec.get("required") else "optional")
                          + "): " + desc + "</li>")
        actions.append("<h3>" + escape(action["action"]) + "</h3><p>"
                       + escape(action.get("description", "")) + "</p>"
                       + ("<ul>" + "".join(params) + "</ul>" if params else "<p>No parameters.</p>"))
    title = escape(manifest["name"]) + " " + escape(manifest["app_version"])
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>""" + title + """</title></head>
<body>
<h1>""" + title + """</h1>
<p>Publisher: """ + escape(manifest["publisher"]) + """. Copyright 2026 Kai Seidenschnur.
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
<li>Deploy the companion Azure Automation Runbook """ + escape(manifest["app_version"]) + """ separately. Enable the
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
<li>Use one ingesting asset per tenant. Select the target before starting
Requested-only intake. Configure the container label and schedule in Ingest Settings;
disable the schedule to pause automatic imports. Use Poll Now for a manual import. For ES, use the native ES ingest settings
and register the five additional fields below.</li>
<li>Configure the analysis playbook's asset bindings, analyst/approver settings,
notification recipients, portal links and routing label before activation.
Publish and confirm the matching runbook first, install the matching app, then activate its compatible playbook.
For combined-layout SOAR, start analysis from the completed mail's single email artifact.</li>
</ol>
<p>Native email import requires authenticated local SOAR REST access, including
when importing into SOAR rather than ES. Automation Broker is not supported. The manifest minimum is SOAR 8.5.0
with Python 3.9/3.13 runtimes; use the runtime supported by your platform.
SOAR 8.7 and later use Python 3.13.</p>
<h2>Email import</h2>
<p><code>on_poll_max_containers</code> is a maximum of simultaneously unresolved
Microsoft quarantine identities, configurable 1–50 and default 10. It is not a
per-poll increment. The app checks tracked IDs read-only; exact
<code>Released</code> or <code>Denied</code> frees slots. It fills free slots from
the first 50 candidates with status <code>Requested</code>. Missing IDs, errors, other
statuses and analysis completion do not free slots. An empty import does not
prove an empty backlog; no pagination or stable ordering is promised.</p>
<p>Intake imports only Microsoft <code>Requested</code> messages: mail with a
recipient release request. There is no source-mode selector; obsolete asset
settings are ignored. Existing intake scopes containing <code>needs_review</code>
are normalized without deleting records or changing tenant/organization/target
scope. Published references are retained and successful imports are not
republished. Older pending or unconfirmed attempts are not automatically replayed.
They require a deliberate Poll Now retry and must appear as <code>Requested</code>
in the first 50 candidates. Microsoft-status checks continue for tracked identities. A mail left unchanged can occupy a slot indefinitely. Failed imports also hold
their slot; retrying one does not consume an additional slot.</p>
<h3>SOAR events</h3>
<p>New SOAR events are named after the email subject, without a prefix;
mail without a subject uses <code>[No subject]</code>.</p>
<p>Original email and attachments are saved automatically to the container's
Vault. In the combined SOAR layout, exactly one email artifact is saved last,
after all uploads, with native <code>run_automation=true</code> outside CEF.
Its <code>vaultId</code> always references the original EML; <code>senderAddress</code>
and <code>recipientAddress</code> always come from Microsoft's quarantine-list
values, not RFC Sender or delivery headers. These fields have no selection controls;
old false settings cannot suppress them. Existing optional selections extend the
same artifact; unavailable optional headers are omitted. With all optional fields
off, the three required fields still produce one usable artifact.</p>
<p>The email artifact is named after the email subject (<code>No subject</code> if
absent). Read identity from <code>container:data.quarantine_identity</code> and
subject from <code>container:name</code>. No separate Request, Original-EML,
Ready, technical or attachment email artifacts are created in this layout,
and no <code>ingestionReady</code> flag is required. Vault files and platform file
metadata remain available. Historical events are not rewritten.</p>
<p>Update existing playbooks that require Ready/Request artifacts together with
the producer before activation: remove those readiness/correlation gates and map
analyzers directly to the single artifact's <code>vaultId</code>, Release/Deny to
the event identity, and prompt context to the fields above. Preserve decisions,
approvals and other business flow. These consumer mappings are unchanged by the import/disposition simplification.
This app does not update or activate playbooks.</p>
<p>The separate-field SOAR layout retains its existing behavior. Internal EML
export and chunked transport are unchanged. Separate layout still uses a final Ready artifact; legacy
stored field selections remain readable. ES uses its configured native
threat-analysis and automation settings unchanged. Publication acceptance does
not prove that an analysis workflow finished.</p>
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
<p>Configure the Azure connection, active-message limit, selected mail fields
and advanced job settings below. The ingest schedule is
set in SOAR/ES Ingest Settings; the Azure polling interval and timeout monitor
individual Azure jobs, not the mail-import schedule.</p>
<p>The SOAR URL override applies to both SOAR and ES email import. Azure
connections require HTTPS and certificate verification; webhook redirects are
not followed. Configure the platform's trusted CA store for private certificates.</p>
<table><thead><tr><th>Field</th><th>Required</th><th>Default</th><th>Description</th></tr></thead><tbody>
""" + "\n".join(rows) + """
</tbody></table>
<h2>Available actions</h2>
<p>Release and Deny run only when invoked by an operator or playbook. The app
submits one Azure job, waits for its output and returns a native ActionResult.
The runbook checks the exact identity and requires Microsoft <code>Requested</code>
or an already matching terminal status. Release uses
<code>Release-QuarantineMessage -Identity &lt;id&gt; -ReleaseToAll -Confirm:$false -ErrorAction Stop</code>;
Deny adds <code>-ActionType Deny</code> to that same command. No extra configuration-check
job or diagnostic proof is required before normal actions.</p>
<p>After a successful command, the runbook allows up to seven status reads,
ten seconds apart, for Exchange to report <code>Released</code> or <code>Denied</code>.
A command error remains an error; later status reads do not reconstruct success.
The default Azure job/output wait remains 600 seconds with 5-second status
polling. Existing whole-second ranges are 600–3600 for timeout and 1–60 for
polling. Transient reads can retry within one deadline, respecting Retry-After;
the writing webhook is never automatically retried.</p>
""" + "\n".join(actions) + """
<h2>Maintenance and removal</h2>
<p>Back up the app, asset configuration and app state using the platform backup
procedure. Stop ingestion and dependent automation before removing the app.
Inspect unresolved job and import outcomes before restoring a backup; do not
clear state to restart processing. Preserve the existing ingest scope and native
references. An upgrade does not automatically replay older pending work.</p>
<h2>Failures and deliberate retries</h2>
<p>Import is synchronous: export mail, prepare container and files, then publish
complete input. A small identity/result record retains the outcome and native
references; there is no background recovery workflow. Scheduled polls skip
failed or interrupted identities. A failed import is not a successful import.</p>
<p>Inspect the action error and any existing native container, Vault files, final
email artifact (Ready artifact in separate layout) or ES finding. Correct the
reported problem, then use native <b>Poll Now</b> for a fresh attempt of failed
identities still present in the first 50 <code>Requested</code> candidates.
There is no new retry parameter. Poll Now can also admit new messages within its
normal count and active-message limit. Successful retained identities remain
deduplicated, and a newly failed attempt is not retried again within that poll.</p>
<p>Native container, Vault, artifact and ES calls are not one exactly-once
transaction. If an ES response is lost, a finding may already exist; a fresh
attempt can duplicate it. Inspect native evidence before deciding to retry.</p>
<p>For Release/Deny failures, read the actual Azure/Exchange error and known
<code>azure_job_id</code> in the native ActionResult. A timeout means the result
is unknown; it does not cancel Azure. Inspect the original job and output in
Azure Automation. If the webhook response was lost without a job ID, inspect
Azure job history before a new action. Do not infer a root cause from missing
output. The app does not automatically replay or resume the action.</p>
<p>A consciously started new disposition is allowed after an old uncertainty;
there is no persistent disposition registry or manual operation ID. Each new
action performs fresh validation. Use <b>inspect release environment</b> for
optional read-only identity/runtime diagnosis; enable its optional RBAC
inspection only when needed, not as a normal business prerequisite.</p>
<h2>Limits and data handling</h2>
<p>EML cap: 24 MiB. MIME limits: 200 parts, nesting depth 30, 100 attachments,
48 MiB combined decoded attachments. Import record cap: 1000 records; active
items are not evicted. Terminal retention is configurable 1–365 days, default
30. Retention expiry can allow reappearing source records to be admitted again;
there is no global exactly-once guarantee. Scheduled polls use a 600-second
between-call work budget. Poll Now always checks tracked statuses before intake,
even with a paused schedule: status checks and imports each receive a separate
600-second work budget. This is not a ten-minute total action timeout; one
in-flight operation may run longer than its phase budget. Failed
attempts still require deliberate Poll Now, not a later scheduled retry.</p>
<p>Mail and attachments may contain sensitive content or malware. Original mail
travels from Exchange through Azure Automation to SOAR/Vault; ES receives finding
metadata and mail/file links. Apply platform permissions, retention and handling
policies to jobs, Vault, state and evidence. No credentials are stored in this
help. Do not include message bodies, tokens or webhook URLs in support reports.</p>
<h2>Troubleshooting and support</h2>
<p>If an action fails, record the app and runbook versions, SOAR/ES versions,
actual action error and known Azure job ID. Check the job output and, if needed,
use optional manual inspection for the current Microsoft status. A successful
local test or publication receipt does not establish downstream execution or
customer production acceptance. Do not include client
secrets, webhook tokens or message contents in support reports.</p>
</body></html>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(json.loads((ROOT / "app" / "ms_quarantine_for_splunk_soar.json").read_text()))
    path = ROOT / "app" / "readme.html"
    if args.check:
        if not path.exists() or path.read_text() != expected:
            parser.error("readme.html is missing or differs from the manifest-backed generator")
    else:
        path.write_text(expected)


if __name__ == "__main__":
    main()
