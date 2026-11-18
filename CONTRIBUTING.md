# Contributing

Discuss substantial changes in an issue first. Describe the problem, intended behavior and acceptance criteria; keep each pull request focused and link its issue.

## Repository layout

| Path | Purpose |
|---|---|
| `app/` | SOAR runtime modules, manifest, logos and generated installed help |
| `runbook/runbook.ps1` | Azure Automation runbook source, deployed separately from the app |
| `tests/python/` | Python tests for runtime behavior and packaging |
| `tests/powershell/` | PowerShell runbook contract tests |
| `tools/` | Help generation, runbook stamping, compatibility checks and release tooling |
| `docs/` | Public operating and development guides, including historical design notes |

Repository metadata, dependency and test configuration, and `LICENSE` remain at the root. Source directories are not release archive paths; see [package contents](docs/publication.md).

## Development

Run the following commands from the repository root. Use a local virtual environment and the bounded dependency ranges in `requirements-dev.txt`; this file is not a lockfile.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q tests/python/
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
```

See [CI and build checks](docs/ci.md) for the Python matrix, complete PowerShell contracts and deterministic app/runbook packaging. Offline checks and successful package creation do not replace [deployment validation](docs/validation.md).

## Shared release version

App and runbook use one release version, even when only one component changes. The manifest's `app_version` in `app/ms_quarantine_for_splunk_soar.json` is authoritative. After changing it, synchronize the runbook version and fingerprint, regenerate installed help, then check both:

```bash
python3 tools/stamp_runbook.py --write
python3 tools/render_readme.py
python3 tools/stamp_runbook.py --check
python3 tools/render_readme.py --check
```

Starting with 3.7.5, publish release notes in [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases); do not maintain a separate changelog file. Earlier changelog history is not migrated.

Build each release's notes from the merged pull requests included since the preceding release. For 3.7.5, use the changes collected after the existing 3.7.4 baseline. GitHub-generated notes may serve as a draft; edit them into a concise, user-facing summary. Use separate `App` and `Runbook` sections and write `No changes` for an unchanged component. Verify the notes against the actual release diff.

Collect changes through issues and pull requests while preparing a release. Update both component versions together when preparing the agreed release; merging a pull request does not itself publish a release.

## Change expectations

- Cover changed behavior and relevant failure paths. Keep runtime code, tests and operating documentation consistent.
- Preserve the app UUID. Coordinate app/runbook compatibility and version changes explicitly.
- Edit the help generator and its inputs, not generated `app/readme.html`; regenerate and check the result.
- Keep Exchange sign-in Managed Identity only. Azure job-read credentials are a different authentication layer.
- Preserve TLS verification, selected-source-status checks, exact Release/Deny invocation shapes, postcondition reads and reconciliation before retry. Do not introduce a synthetic capability probe as a prerequisite to a real Exchange command.
- Use synthetic mail and reserved example domains. Never commit credentials, token-bearing webhook URLs, tenant exports or raw quarantined messages.
- Keep environment bindings and private operational receipts outside the public source tree.
- Describe checks actually run and remaining limitations in the pull request. A test plan is not a test result.

Contributions are submitted under the repository's [Apache-2.0 license](LICENSE). Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public reproduction containing sensitive data.
