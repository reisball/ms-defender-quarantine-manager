# Deployment checklist

[Back to README](../README.md)

Run these checks with controlled test messages before enabling regular intake. Release and Deny change real quarantine state, so use only messages approved for that. Record which app/runbook build (source commit or checksum) you tested.

## Before the first import

- [ ] Runbook published first, matching app installed second ([install order](installation.md#install-order)); package checksums verified.
- [ ] Native SOAR execution (no Automation Broker).
- [ ] Azure job access (App Registration) and Exchange permissions (Managed Identity) verified separately.
- [ ] One ingesting asset per tenant, with a small active-message limit.
- [ ] ES only: [additional fields](ingestion.md#enterprise-security) registered, security domain set, external HTTPS SOAR URL verified.
- [ ] Playbook assets, approver, label and routing configured; only the intended automation enabled.

## Import

| Check | Expected result |
|---|---|
| **test connectivity** | Succeeds |
| Poll Now with one `Requested` message | Original EML, attachments and metadata are complete, then the event is published |
| Combined layout | Exactly one email artifact, saved last, starts the configured playbook |
| `NotReleased` message | Not imported |
| Repeated poll | An already imported message is not imported again |
| Original and attachment downloads | Content matches the test message and analysts can open it |
| Limit reached | Imported and failed unresolved messages share the limit; analysis completion alone frees nothing |
| Failed import, then Poll Now | Scheduled polls skip it; Poll Now retries it in its existing slot |

## Release and Deny

| Check | Expected result |
|---|---|
| Approved Release / Deny | One Azure job; result confirms `Released` / `Denied` |
| Delayed Exchange status | Up to seven status reads allow the change to appear |
| Azure or Exchange failure | The actual error and job ID are returned |
| Timeout | Reported as unknown; nothing is retried automatically |

Successful publication does not prove that downstream analysis worked. Verify the playbook run separately. Keep raw mail and credentials out of shared test reports.
