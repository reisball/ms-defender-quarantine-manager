# Security policy

## Reporting a vulnerability

Do not publish credentials, quarantine content or an exploitable deployment configuration in an issue.

If the repository offers **Security → Report a vulnerability**, use that private reporting flow. If private reporting is unavailable, open an issue asking for a private contact channel without vulnerability details. Wait for a private channel before sharing the reproduction.

Include affected versions, expected and observed behavior, impact, and a minimal synthetic reproduction. Remove webhook tokens, client secrets, tenant identifiers and original mail.

## Maintenance scope

The current source line is App 3.7.4 with Runbook 3.7.4. Older versions do not have a guaranteed backport policy. There is no guaranteed response time or commercial support SLA.

A source release, an offline test result and acceptance on a particular SOAR/Azure/Exchange deployment are different evidence. Follow the [deployment checklist](docs/validation.md) for your environment.

## Operating safely

See [security and data handling](docs/security.md) for identity boundaries, TLS, message handling and uncertain disposition outcomes.
