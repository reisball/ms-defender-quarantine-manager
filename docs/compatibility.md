# App and runbook compatibility

[Documentation index](README.md).

This is the canonical compatibility matrix for the SOAR app and the separately deployed Azure Automation runbook. Both components use one shared release version, including releases that change only one component. Matching labels alone do not establish compatibility, and unlisted combinations are **not verified**.

## Status and evidence

- **Supported**: the specified pair has documented interface compatibility and validation evidence, subject to its stated restrictions. This is not a claim that every customer environment has passed acceptance.
- **Incompatible**: a documented contract mismatch prevents using the pair unchanged; follow the stated upgrade requirement.
- **Not verified**: evidence is insufficient to establish compatibility. This is neither supported nor proven incompatible.

The initial baseline is the source at [9e1b188](https://github.com/reisball/ms-quarantine-for-splunk-soar/tree/9e1b188af842f2cf3bb0bd53171bb0ba70f1a21a), as recorded in [Issue #16](https://github.com/reisball/ms-quarantine-for-splunk-soar/issues/16): its manifest `app_version`, runbook version header and `$RunbookVersion` all read `3.7.4`. These checks establish source-version alignment only, not runtime compatibility or live end-to-end acceptance.

The unreleased candidate at [1832021](https://github.com/reisball/ms-quarantine-for-splunk-soar/tree/1832021e6a52af9f95e7db5e94b331c7957e5b04) still carries those labels but has different runtime bytes and contracts. It is preparation for the planned Version 4, not a published Version 4 release or an assigned release version. Neither source identity below establishes a currently installed customer version. Offline [CI and contract checks](ci.md) and [deployment acceptance](validation.md) have distinct scopes; no customer acceptance is established for this candidate by this matrix.

## Matrix

| App version / source | Runbook version / source | Compatibility status | Restrictions / upgrade requirements |
|---|---|---|---|
| 3.7.4 at `9e1b188` (initial baseline) | 3.7.4 at `9e1b188` | Not verified | Source-version alignment is recorded above. No broader historical range or runtime acceptance is asserted. Do not substitute the later candidate merely because its labels also read 3.7.4. |
| 3.7.4 label at `1832021` (unreleased candidate) | 3.7.4 label at `1832021` | Not verified | Use exact candidate provenance for validation. Before customer handover, assign a unique shared release version, validate that pair and coordinate the changed consumers described below. These labels do not identify a new distributable release. |

Cross-pairing either baseline component with the other candidate component is not verified. No older/newer counterpart or version range is supported by inference from these two rows.

Both source snapshots use app UUID `2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e`; that identity and the repeated version labels do not distinguish their runtime bytes. Compare the artifact's source commit and checksums, plus the runbook source fingerprint/build ID, not filenames or version strings alone. An app with an earlier, different UUID is a separate identity; installing this app does not migrate its assets or state.

## Upgrade decisions

1. Identify the installed app and published runbook by version **and source/artifact identity**, then locate the intended target pair above. Treat unknown provenance or an unlisted pair as not verified. There is currently no supported row that justifies retaining an older runbook with the candidate app.
2. Review the target's restrictions. Deploy the matching runbook when updating the app unless an explicit supported matrix entry permits retaining the installed counterpart. Even unchanged runbook behavior does not by itself establish cross-version compatibility. Validate an unreleased pair before treating it as supported; do not hand over different runtime bytes under the existing release label.
3. Coordinate the consumer and state transition. The candidate removes the app's `recover_quarantine_ingestion` and `reconcile_quarantine_operation` actions and manual operation IDs, uses Requested-only intake and changes the combined-layout playbook input to one email artifact plus event identity. Existing consumers of removed actions or Ready/Request artifacts must be updated before activation. Follow [ingestion migration and input mappings](ingestion.md#updating-an-existing-playbook-consumer) and [failed-import handling](ingestion.md#failed-imports-and-poll-now); preserve tracked state and publication references. Pause previous intake before changing an ingesting asset and keep one ingesting asset per tenant.
4. Follow [installation](installation.md) and [publication](publication.md): publish and confirm the matching Azure runbook first, install the matching SOAR app second, then activate the compatible playbook. App installation never deploys the runbook. Perform [environment acceptance](validation.md) on the exact pair and validate the separately maintained playbook; local checks do not prove either live path.

## Maintaining the matrix

Review this file whenever either component changes and with every shared release/version change. Add or revise only evidence-backed pairs or explicitly bounded ranges, with source/release identity, restrictions and validation scope. If a contract change requires a newer counterpart, record its minimum compatible version and upgrade order once that version is assigned. Retain the source-qualified baseline so unchanged labels cannot hide different bytes.

Use **not verified** where evidence is missing and **incompatible** only for a documented mismatch. Record earlier-runbook compatibility only when both interface review and validation evidence support it. Follow the [contribution and release workflow](../CONTRIBUTING.md#shared-release-version); component change summaries belong in the existing release notes, not a second changelog here.
