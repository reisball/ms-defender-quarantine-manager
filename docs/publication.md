# Publication and package contents

[Documentation index](README.md).

## Source and versions

This source line uses **App 3.7.4 / Runbook 3.7.4** with a newly assigned app UUID and package identity. App and runbook share one release version from 3.7.4 onward. This is a separate SOAR app, not an in-place replacement identified by an earlier app UUID. Action names, wire fields, persisted state schemas and opaque deduplication IDs remain data contracts; changing the app identity does not migrate assets or state.

The current simplification does not increment those version labels or establish a new published release. Select a unique release version before customer package handover; do not distribute different runtime bytes as though they were the existing release. Local verification is not evidence of a customer installation. Handover order is: publish and confirm the matching runbook, install the matching app, then activate its compatible playbook.

For a fresh repository, export only the reviewed current tree. Do not copy the private repository's `.git` directory, remotes, hidden credentials, local artifacts or history. Keep the original repository as a separate private archive. Initialize and commit the new tree before building release artifacts so the build metadata names the new public source commit.

Private deployment evidence belongs in the private project record, not in a public test report. A clean snapshot scan says nothing about the original repository's history.

The [canonical compatibility matrix](compatibility.md) distinguishes the original 3.7.4 source baseline from the unreleased candidate with unchanged labels. Use its source-qualified pairs, evidence scope and upgrade requirements when selecting artifacts; version equality alone is not compatibility evidence.

## Distribution boundaries

| Artifact | Contents |
|---|---|
| App TGZ | One `ms-quarantine-for-splunk-soar/` directory and ten runtime files |
| Separate runbook | Versioned `runbook.ps1` companion, deployed to Azure separately |
| Source tree | Code, tests, development tools and public documentation |

The app's ten files are the manifest, connector, utilities, SOAR ingestion, ES ingestion, `__init__.py`, two logos, generated `readme.html`, and `LICENSE`. Tests, Markdown, playbooks and the runbook are excluded from the app TGZ.

In a source checkout, the runtime files live in `app/`, while `LICENSE` remains at the repository root. The builder places those files directly under `ms-quarantine-for-splunk-soar/` in the TGZ; it does not include an `app/` directory. The separate runbook artifact is built from `runbook/runbook.ps1`. These source paths do not change the downloadable artifact filenames: `ms-quarantine-for-splunk-soar-3.7.4.tgz` and `ms-quarantine-for-splunk-soar-runbook-3.7.4.ps1`.

Playbooks, historical playbook fixtures and proprietary platform sources are not part of this repository. Analysis workflows are configured and validated separately.

## Before creating a public release

1. Review the current tracked tree for secrets, real deployment addresses, private links, personal test data, stale generated receipts and unintended files.
2. Check versions, generated help, runbook fingerprint, relative documentation links and the intended package allowlist. Review and update the [compatibility matrix](compatibility.md#maintaining-the-matrix) for the exact app/runbook pair, including component-only changes; record evidence, restrictions and any required counterpart upgrade.
3. Run the applicable app/runbook Python and PowerShell checks. Record exact candidate results and unavailable gates separately.
4. Build twice from the same committed runtime bytes and compare outputs. Verify archive members and checksums.
5. Select the public repository destination, default branch and license settings explicitly. Configure private vulnerability reporting if offered; do not claim it is enabled before checking.
6. Run the prepared GitHub Actions workflow on that repository and inspect actual results. Configure repository protections appropriate to the maintenance model.
7. Publish source and release artifacts only after reviewing the final destination and content.

Local preparation does not create a GitHub repository, transfer history, publish a release or deploy either component. Passing offline tests is not tenant or end-to-end acceptance.
