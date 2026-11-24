# Contributing

Discuss substantial changes in an issue first. Keep each pull request focused and link its issue. Setup, checks and the release process are in [Development and release](docs/development.md).

## Change expectations

- Cover changed behavior and its failure paths with tests. Keep code, tests and documentation consistent.
- Preserve the app UUID. Change app and runbook versions together.
- Edit the help generator and its inputs, not the generated `app/readme.html`.
- Keep Exchange sign-in Managed Identity only; the Azure job-read credentials are a separate layer.
- Preserve TLS verification, the source-status checks, the exact Release/Deny invocations, postcondition reads and the no-automatic-retry rule for writes. Do not add a synthetic capability probe before a real Exchange command.
- Use synthetic mail and reserved example domains. Never commit credentials, webhook URLs, tenant exports, raw quarantined messages or environment-specific bindings.
- In the pull request, describe the checks you actually ran and any remaining limitations.

Contributions are submitted under the [Apache-2.0 license](LICENSE). Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
