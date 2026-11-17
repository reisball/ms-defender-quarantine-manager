# Contributing

Discuss substantial changes in an issue first. Describe the problem, intended behavior and acceptance criteria; keep each pull request focused and link its issue.

## Development

Use a local virtual environment and the bounded dependency ranges in `requirements-dev.txt`; this file is not a lockfile.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
```

See [CI and build checks](docs/ci.md) for the Python matrix, complete PowerShell contracts and deterministic app/runbook packaging. Offline checks and successful package creation do not replace [deployment validation](docs/validation.md).

## Change expectations

- Cover changed behavior and relevant failure paths. Keep runtime code, tests and operating documentation consistent.
- Preserve the app UUID. Coordinate app/runbook compatibility and version changes explicitly.
- Edit the help generator and its inputs, not generated `readme.html`; regenerate and check the result.
- Keep Exchange sign-in Managed Identity only. Azure job-read credentials are a different authentication layer.
- Preserve TLS verification, selected-source-status checks, exact Release/Deny invocation shapes, postcondition reads and reconciliation before retry. Do not introduce a synthetic capability probe as a prerequisite to a real Exchange command.
- Use synthetic mail and reserved example domains. Never commit credentials, token-bearing webhook URLs, tenant exports or raw quarantined messages.
- Keep environment bindings and private operational receipts outside the public source tree.
- Describe checks actually run and remaining limitations in the pull request. A test plan is not a test result.

Contributions are submitted under the repository's [Apache-2.0 license](LICENSE). Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public reproduction containing sensitive data.
