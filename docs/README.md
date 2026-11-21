# Documentation

Start with [installation](installation.md), then validate the configured workflow with [controlled messages](validation.md).

## Operate the connector

| Need | Read |
|---|---|
| App/runbook pairing, evidence and upgrade requirements | [Compatibility matrix](compatibility.md) |
| Prerequisites, identities, runbook and asset setup | [Installation](installation.md) |
| Import window, actions, limits and deliberate retries | [Operations](operations.md) |
| SOAR/ES ingestion contracts and migration | [Email ingestion](ingestion.md) |
| Azure job and Exchange diagnostics | [Troubleshooting](troubleshooting.md) |
| Native analysis workflows, import and configuration | [Example playbooks](../examples/README.md) |
| Environment acceptance | [Deployment checklist](validation.md) |
| Controlled Azure-only validation | [Azure validation](azure-validation.md) |
| TLS, credentials and quarantined content | [Security](security.md) |
| Attachment extraction and parser boundaries | [MIME limits](mime-limits.md) |

## Develop and distribute

- [Contributing](../CONTRIBUTING.md)
- [CI and build checks](ci.md)
- [Publication and package contents](publication.md)
- [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases)
- [Generated installed help](../app/readme.html)

## Historical design

[Retired Release/Deny capability binding](history/release-deny-binding.md) explains a removed mechanism. It is not a current configuration or execution requirement. Private deployment receipts, customer bindings and internal issue history are not part of these public manuals.
