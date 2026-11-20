# Example playbooks

[Documentation index](../docs/README.md)

These examples are separate from the SOAR app package. Importing the app does not install or activate a playbook.

| Example | Purpose |
|---|---|
| [Native SAA quarantine workflow](MS_Quarantine_SAA_Example/README.md) | Analyze the original email with Splunk Attack Analyzer, release below an example score of 30, otherwise request an analyst decision, and close only after a successful quarantine action. |

Each example directory contains its native JSON/Python export pair and instructions for packaging, importing, mapping assets and approvers, and validating the workflow. Templates ship inactive with placeholder configuration; do not activate one before completing its environment-specific checks.

The [compatibility matrix](../docs/compatibility.md) describes the app/runbook source pairs. Verification of a playbook is separate from app/runbook compatibility and deployment acceptance.
