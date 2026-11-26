# App and runbook compatibility

[Back to README](../README.md)

The SOAR app and the Azure runbook share one release version. Matching version labels alone do not prove compatibility, and any combination not listed here is **not verified**.

| Status | Meaning |
|---|---|
| Supported | Documented interface compatibility and validation evidence, subject to the listed restrictions. This does not mean every customer environment has passed acceptance. |
| Incompatible | A documented contract mismatch. Use the matching app and runbook. |
| Not verified | Not enough evidence. This is neither supported nor proven incompatible. |

## Version pair

| SOAR app | Azure runbook | Validation scope |
|---|---|---|
| 1.1.0 | 1.1.0 | Intended release pair. Build and contract checks are not evidence of a live deployment or end-to-end acceptance. |

Use the matching runbook and app from the same build. The app installer does not update the runbook in Azure. Other pairings are not verified.

**Test connectivity** warns if the installed app and the runbook report different
release versions or if either version is unavailable. A warning does not change the
connectivity result. Compare the separately reported runbook build ID with the
`$RunbookBuildId` in the shipped runbook. Matching version labels are not proof
that the builds match.

## First installation

Create a new asset, follow the [install order](installation.md#install-order), and
run the [deployment checklist](validation.md) on the exact app/runbook pair.
