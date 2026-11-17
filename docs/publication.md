# Publication and package contents

[Documentation index](README.md).

## Source and versions

This source line keeps **App 3.7.4 / Runbook 3.4.5** with a newly assigned app UUID and package identity. Product versions are deliberately retained. This is a separate SOAR app, not an in-place replacement identified by an earlier app UUID. Action names, wire fields, persisted state schemas and opaque deduplication IDs remain data contracts; changing the app identity does not migrate assets or state.

For a fresh repository, export only the reviewed current tree. Do not copy the private repository's `.git` directory, remotes, hidden credentials, local artifacts or history. Keep the original repository as a separate private archive. Initialize and commit the new tree before building release artifacts so the build metadata names the new public source commit.

Private deployment evidence belongs in the private project record, not in a public test report. A clean snapshot scan says nothing about the original repository's history.

## Distribution boundaries

| Artifact | Contents |
|---|---|
| App TGZ | One `ms-quarantine-for-splunk-soar/` directory and eleven runtime files |
| Separate runbook | Versioned `runbook.ps1` companion, deployed to Azure separately |
| Source tree | Code, tests, development tools and public documentation |

The app's eleven files are the manifest, connector, utilities, SOAR ingestion, ES ingestion, `__init__.py`, two logos, generated `readme.html`, `LICENSE`, and `NOTICE`. Tests, Markdown, playbooks and the runbook are excluded from the app TGZ.

Playbooks, historical playbook fixtures and proprietary platform sources are not part of this repository. Analysis workflows are configured and validated separately.

## Before creating a public release

1. Review the current tracked tree for secrets, real deployment addresses, private links, personal test data, stale generated receipts and unintended files.
1. Check versions, generated help, runbook fingerprint, relative documentation links and the intended package allowlist.
1. Run the applicable app/runbook Python and PowerShell checks. Record exact candidate results and unavailable gates separately.
1. Build twice from the same committed runtime bytes and compare outputs. Verify archive members and checksums.
1. Select the public repository destination, default branch and license settings explicitly. Configure private vulnerability reporting if offered; do not claim it is enabled before checking.
1. Run the prepared GitHub Actions workflow on that repository and inspect actual results. Configure repository protections appropriate to the maintenance model.
1. Publish source and release artifacts only after reviewing the final destination and content.

Local preparation does not create a GitHub repository, transfer history, publish a release or deploy either component. Passing offline tests is not tenant or end-to-end acceptance.

## Community submission handoff

The repository prepares a community-supported submission; it does not submit or publish on behalf of the owner. Record the reviewed commit, hosted CI result, independent review and release checksums. Include the separate Azure runbook and setup guide with the handoff, not inside the app TGZ.

The native SOAR Cloud pilot is confirmed. Automation Broker remains unsupported; a successful pilot is not a certification for every version or tenant. The two upstream GUID/name/package registry entries remain onboarding work. All other technical findings must be resolved before handoff. See [CI boundaries](ci.md#technical-readiness-versus-upstream-registration).
