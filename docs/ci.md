# Development, CI and builds

[Documentation index](README.md).

## Python checks

Use Python 3.9 and 3.13, matching the configured matrix. The legacy app uses platform-provided dependencies at runtime; `requirements-dev.txt` is for development only and contains version ranges, not a lockfile.

```bash
python -m pip install -r requirements-dev.txt
python -m json.tool ms_quarantine_for_splunk_soar.json >/dev/null
python -m compileall -q ms_quarantine_for_splunk_soar_connector.py ms_quarantine_for_splunk_soar_utils.py ms_quarantine_for_splunk_soar_ingestion.py ms_quarantine_for_splunk_soar_es_ingestion.py
python -m pytest -q
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
python tools/check_mime_parser_compat.py
```

The default pytest suite covers the connector, ingestion, selection, recovery and packaging. It uses synthetic API/SDK inputs. This repository does not include playbooks, playbook fixtures or platform-source-dependent playbook tests.

## GitHub Actions and PowerShell

[GitHub workflow](../.github/workflows/ci.yml) runs the Python matrix and, on Python 3.13, the complete PowerShell contract sequence. PowerShell is provided by the GitHub-hosted Ubuntu runner and checked before use. Actions are pinned to immutable commits and the workflow has read-only repository permission.

The PowerShell sequence includes inline assertions and parameter variants for export/base64/list/error transport, Managed Identity and rejected legacy authentication, Release/Deny preconditions and postconditions, read-only diagnostics/RBAC, and selection modes. Running one script or only pytest does not replace the sequence.

The [Gitea workflow](../.gitea/workflows/ci.yml) is retained as the original CI definition; GitHub does not execute it. A local check of the GitHub workflow is not evidence of a successful hosted run. Inspect the exact candidate's Actions results before publishing a release.

## Upstream SOAR preparation gates

The separate Python 3.13 quality job runs the official SOAR hook families pinned in
[.pre-commit-config.yaml](../.pre-commit-config.yaml): Ruff, djLint, SOAR App Linter,
mdformat, Semgrep, detect-secrets and dev-cicd-tools. Python 3.9 tests use Ubuntu
24.04 because the newer default runner does not provide that interpreter.

```bash
python3.13 -m pip install pre-commit==4.5.1
pre-commit run --all-files --show-diff-on-failure
```

Run development tools in a dedicated environment outside the source tree, or an
isolated container. Hooks can modify source; inspect the diff and rerun until the
working tree is stable. Tool repository revisions are pinned; transitive Python
dependencies and Semgrep's `p/python` rules remain upstream-managed, not a fully
locked toolchain. Runtime dependencies are platform-provided, so there is no dummy
`requirements.txt` or dependency wheel bundle. The dependency packager correctly
reports no matching files until real bundled dependencies are introduced.

### Technical readiness versus upstream registration

The static wrapper runs **every** upstream static check against a temporary copy of
tracked source. Only the exact “GUID and app not listed” and “GUID and app package
name not listed” responses are classified as **registration pending**. GUID/name
collisions, missing checks, execution errors, source auto-fixes and all other
failures remain blocking. The report preserves every original result and upstream
exit code. Set `SOAR_CHECK_REPORT` to save the JSON report outside the source tree.

A passing pre-submission job is **not** a wholly passing upstream acceptance run.
The existing UUID, package and publisher must be registered during onboarding;
never change them to bypass these checks. In the dev-cicd-tools hook environment,
`python tools/soar_checks.py static-strict` also fails on pending registration.
Upstream compilation, packaging, review and platform validation are separate gates.

### Documentation, attribution and scoped findings

Edit [manual_readme_content.md](../manual_readme_content.md), not the generated
root README. The official `build-docs` generator combines that manual with the
manifest. Our wrapper replaces only its exact known Splunk ownership footer with
Kai Seidenschnur's ownership statement and fails if that template changes. The
upstream generator/template remains attributable to Splunk under its own license;
this adaptation does not transfer ownership of its template. The copyright hook
also receives `--copyright "Kai Seidenschnur"` explicitly.

The independent HTML renderer continues to own `readme.html`; djLint validates it
but does not reformat that generated file. Keep its copyright header and generated
content consistent with `python tools/render_readme.py --check`.

SOAR App Linter runs with dependency installation enabled, without `--no-deps`, at
upstream's error severity. It operates on a disposable tracked-source snapshot so
its `.venv`, package markers and Pylint configuration cannot alter the checkout.
Warning-level filesystem findings are not an error-level certification; native
state locks and temporary Vault files remain necessary. No broad runtime lint or
security exclusions are used. Local annotations identify synthetic negative-test
credentials, dynamic platform mocks and non-security IOC hash fingerprints.

Keep unreleased entries in `release_notes/unreleased.md` using the upstream format.
The generated `NOTICE` is distributed in the app TGZ; Markdown sources and release
notes remain in the source repository.

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
