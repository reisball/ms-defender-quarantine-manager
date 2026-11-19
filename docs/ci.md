# Development, CI and builds

[Documentation index](README.md).

## Python checks

Run commands from the repository root. Use Python 3.9 and 3.13, matching the configured matrix. The legacy app uses platform-provided dependencies at runtime; `requirements-dev.txt` is for development only and contains version ranges, not a lockfile.

```bash
python -m pip install -r requirements-dev.txt
python -m json.tool app/ms_quarantine_for_splunk_soar.json >/dev/null
python -m compileall -q app/ms_quarantine_for_splunk_soar_connector.py app/ms_quarantine_for_splunk_soar_utils.py app/ms_quarantine_for_splunk_soar_ingestion.py app/ms_quarantine_for_splunk_soar_es_ingestion.py
python -m pytest -q tests/python/
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
python tools/check_mime_parser_compat.py
```

The pytest suite in `tests/python/` covers the connector, Requested-only intake, recovery and packaging. It uses synthetic API/SDK inputs. This repository does not include playbooks, playbook fixtures or platform-source-dependent playbook tests.

## GitHub Actions and PowerShell

[GitHub workflow](../.github/workflows/ci.yml) runs the Python matrix and, on Python 3.13, the complete PowerShell contract sequence. The Python 3.9 job uses `ubuntu-22.04`, where `setup-python` provides a compatible build; Python 3.13 uses `ubuntu-latest`. PowerShell is provided by the GitHub-hosted Ubuntu runner and checked before use. Actions are pinned to immutable commits and the workflow has read-only repository permission.

The PowerShell scripts live in `tests/powershell/` and exercise `runbook/runbook.ps1`. The PowerShell sequence includes inline assertions and parameter variants for export/base64/list/error transport, Managed Identity and rejected legacy authentication, Release/Deny preconditions and postconditions, read-only diagnostics/RBAC, and quarantine status filtering. Running one script or only pytest does not replace the sequence.

The [Gitea workflow](../.gitea/workflows/ci.yml) is retained as the original CI definition; GitHub does not execute it. A local check of the GitHub workflow is not evidence of a successful hosted run. Inspect the exact candidate's Actions results before publishing a release.

## Deterministic release kit

Required tools: Git, Bash, Python, GNU tar/gzip, jq and sha256sum.

```bash
tools/build_release.sh
```

The builder verifies generated help and matches every staged runtime byte against a real source commit. Commit changes before building; a history-free source export must first be initialized and committed in its new repository. Do not disable the provenance check.

The default output is `dist/`. Run the builder into two separate output directories with identical source commit/time inputs and compare archive checksums when changing packaging. See [publication](publication.md) for the allowlist and separate runbook artifact.

## Deployment acceptance

Offline tests and package integrity do not establish native SOAR/Azure/Exchange acceptance. Perform positive and negative integration tests on the exact configured app/runbook pair in an authorized environment. Check import, Vault contents, downstream automation and Microsoft postconditions separately.

Analysis and approval workflows are configured outside this repository. Their successful execution must be validated separately from app installation and ingestion receipts.
