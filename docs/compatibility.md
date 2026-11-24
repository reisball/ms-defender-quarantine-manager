# App and runbook compatibility

[Back to README](../README.md)

The SOAR app and the Azure runbook share one release version. Matching version labels alone do not prove compatibility, and any combination not listed here is **not verified**.

| Status | Meaning |
|---|---|
| Supported | Documented interface compatibility and validation evidence, subject to the listed restrictions. This does not mean every customer environment has passed acceptance. |
| Incompatible | A documented contract mismatch. Follow the listed upgrade requirement. |
| Not verified | Not enough evidence. This is neither supported nor proven incompatible. |

## Matrix

| App | Runbook | Status | Restrictions |
|---|---|---|---|
| 3.7.4 at [`9e1b188`](https://github.com/reisball/ms-quarantine-for-splunk-soar/tree/9e1b188af842f2cf3bb0bd53171bb0ba70f1a21a) (baseline) | 3.7.4 at `9e1b188` | Not verified | Only source-version alignment is recorded ([#16](https://github.com/reisball/ms-quarantine-for-splunk-soar/issues/16)). Do not substitute the later candidate because its labels also read 3.7.4. |
| 3.7.4 label at [`1832021`](https://github.com/reisball/ms-quarantine-for-splunk-soar/tree/1832021e6a52af9f95e7db5e94b331c7957e5b04) (unreleased 4.0 candidate) | 3.7.4 label at `1832021` | Not verified | Assign a unique release version and validate the pair before handover. Update playbook consumers first (see below). |

Mixing a component from one row with the other row's counterpart is not verified.

Both rows use app UUID `2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e` and the same version labels, so identify a build by its source commit, archive checksum and runbook fingerprint, not by its filename. No customer acceptance has been recorded for either row.

## Upgrade steps

1. Identify the installed app and published runbook by version **and** source commit or checksum. Treat unknown provenance as not verified.
2. Always deploy the matching runbook with the app. No current row allows keeping an older runbook.
3. Before upgrading to the candidate, update dependent playbooks. The candidate:
   - removes the `recover_quarantine_ingestion` and `reconcile_quarantine_operation` actions and manual operation IDs;
   - imports `Requested` messages only;
   - gives combined-layout playbooks one email artifact plus the event's quarantine identity instead of the Ready/Request artifacts. See [updating a playbook](ingestion.md#updating-an-existing-playbook).
4. Pause the previous intake before changing an ingesting asset, and keep one ingesting asset per tenant.
5. Follow the [install order](installation.md#install-order), then run the [deployment checklist](validation.md) on the exact pair.
