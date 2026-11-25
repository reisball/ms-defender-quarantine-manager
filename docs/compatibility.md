# App and runbook compatibility

[Back to README](../README.md)

The SOAR app and the Azure runbook share one release version. Matching version labels alone do not prove compatibility, and any combination not listed here is **not verified**.

| Status | Meaning |
|---|---|
| Supported | Documented interface compatibility and validation evidence, subject to the listed restrictions. This does not mean every customer environment has passed acceptance. |
| Incompatible | A documented contract mismatch. Follow the listed upgrade requirement. |
| Not verified | Not enough evidence. This is neither supported nor proven incompatible. |

## Version pair

| SOAR app | Azure runbook | Validation scope |
|---|---|---|
| 1.0.0 | 1.0.0 | Intended release pair. Build and contract checks are not evidence of a live deployment or end-to-end acceptance. |

Use the matching runbook and app from the same build. The app installer does not update the runbook in Azure. Other pairings are not verified.

**Test connectivity** warns if the installed app and the runbook report different
release versions or if either version is unavailable. A warning does not change the
connectivity result. Compare the separately reported runbook build ID with the
`$RunbookBuildId` in the shipped runbook. Matching version labels are not proof
that the builds match.

## Install or replace an internal build

1. Pause any existing intake for the tenant. Do not run two ingesting assets for the same tenant.
2. If you are replacing an internal build, identify its app UUID and follow the [asset and migration guidance](installation.md#4-install-the-app-and-create-an-asset). No in-place update from an internal build is assumed.
3. Check existing playbooks against the [SOAR playbook input contract](ingestion.md#updating-an-existing-playbook) before enabling automation.
4. Follow the [install order](installation.md#install-order), then run the [deployment checklist](validation.md) on the exact pair.
