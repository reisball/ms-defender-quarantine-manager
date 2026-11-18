# Changelog

Versions below describe source changes, not a guarantee of deployment or tenant acceptance. App and Azure runbook are separate artifacts. Starting with 3.7.4, both use the same version and are versioned together. Changes are listed separately; an unchanged component is marked **No changes**. The initial runbook alignment from 3.4.5 to 3.7.4 changes version metadata only.

## 3.7.4 — current source, unreleased

### App

- Name new SOAR containers/events after the email subject without a prefix, using `[No subject]` when absent; keep artifact names and ES finding titles unchanged.
- Name the configurable combined email overview artifact after the email subject, without a prefix; keep field selections and other artifact names unchanged.
- Remove the redundant Email import checkbox and app-level polling gate. Native Ingest Settings and Poll Now control invocation.
- Ignore stored `enable_on_poll_ingestion` values without rewriting asset state.
- Preserve ES target validation, selection modes, active-message limits and the paired runbook.
- Update installed help and user guides for external users.
- Prepare public documentation and GitHub CI with the explicitly renamed MS Quarantine for Splunk SOAR identity, a new UUID, package/module names and matching runbook build provenance. The repository distributes only the app and companion runbook, with their documentation and tests; playbooks are not included.

### Runbook

- No changes.

## App 3.7.3 / Runbook 3.4.5 — webhook transport

- Require a valid HTTPS webhook URL at asset initialization and utility construction without echoing token-bearing URLs in errors.
- Reject webhook redirects before accepting a job ID. Preserve unknown-outcome handling and no automatic Release/Deny retry.
- Keep the runbook, action parameters, mail limits and polling behavior unchanged.

## App 3.7.2 / Runbook 3.4.5 — audit corrections

- Preserve requested-operation binding and newer confirmed reconciliation evidence across restart-safe refreshes.
- Redact quoted diagnostic headers in Python and PowerShell; bound optional success diagnostics and preserve unknown RBAC evidence.
- Schedule existing preparation and status work fairly without changing slot ownership or discovery.
- Include previously omitted MIME container attachments without renumbering existing files; enforce structure limits during parsing.
- Verify release-input provenance and normalize staging modes.
- Declare existing result summaries and reject lossy configuration numbers while retaining integral floats.
- Clarify native compatibility and inactive example bindings.

## App 3.7.1 / Runbook 3.4.4 — asset UI cleanup

- Remove legacy export-mode and metadata-enable controls while preserving stored values for compatibility.
- Native import always uses Vault transport; normalize verified chunked bytes before MIME validation.
- Group connection, import, mail-field and advanced settings consistently.
- Remove the public legacy worker-update action. Complete old callbacks on the preceding app before upgrading.

## App 3.7.0 / Runbook 3.4.4 — native ingestion

- Add a persistent app-owned window shared by native SOAR/ES intake: default ten unresolved identities per asset. Only confirmed Microsoft `Released`/`Denied` observations free slots.
- Prepare the original EML, attachments, hashes and selected metadata before publishing automation or a finding; suppress preparation-time automation.
- Persist publication intent and expose uncertain acceptance without blind resubmission.
- Remove public List/Get actions; older analysis workflows require migration.
- Add audited ingestion recovery and durable preparation/status cursors.
- Preserve bounded first-page discovery, record retention, migration guards, exact source-status checks and reconciliation.
- Use authenticated native SOAR REST and platform TLS policy; document unsupported Automation Broker execution and unverified SOAR Cloud compatibility.
- Require registration of ES additional fields and verify external Vault drilldowns.
- Ship deterministic allowlisted packages with generated self-contained HTML help and the license.
- Bound and redact runbook diagnostics while retaining execution and postcondition evidence.

## Earlier source versions — condensed history

| Version pair | Main change |
|---|---|
| App 3.5.9 / Runbook 3.4.3 | Validate identities and count/output boundaries; cap manual and native discovery results. |
| App 3.5.8 / Runbook 3.4.3 | Add paired `release_requested` / `needs_review` selection, handshake and exact source-status checks. |
| App 3.5.7 / Runbook 3.4.2 | Make Exchange sign-in Managed Identity only; reject unsupported authentication before Exchange access. |
| App 3.5.6 | Clarify the separate Azure-job and Exchange authentication layers in asset settings. |
| App 3.5.5 / Runbook 3.4.1 | Remove the synthetic capability-binding gate in favor of real command invocation and native errors. |
| App 3.5.4 / Runbook 3.4.0 | Refactor runbook diagnostics for readability. |
| App 3.5.4 / Runbook 3.3.4 | Remove disposition-time RBAC introspection as an execution prerequisite; retain opt-in read-only diagnostics. |

The [retired capability-binding design](docs/history/release-deny-binding.md) explains why that historical mechanism must not be restored as a current gate. Older private commit/issue and deployment records are not reproduced as public release evidence.

## Acceptance boundaries

Offline tests, deterministic archives and editor checks prove different properties. Positive native mail/Vault/automation/ES execution, analyzer behavior, notification delivery and Exchange tenant eligibility require the [deployment checklist](docs/validation.md). In particular, Deny of `NotReleased` is not guaranteed for every tenant.
