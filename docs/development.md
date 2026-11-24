# Development and release

[Back to README](../README.md) · [Contributing](../CONTRIBUTING.md)

## Repository layout

| Path | Purpose |
|---|---|
| `app/` | SOAR runtime modules, manifest, logos and generated `readme.html` |
| `runbook/runbook.ps1` | Azure Automation runbook, released as a separate artifact |
| `examples/` | Example playbooks, not part of the app package |
| `tests/python/`, `tests/powershell/` | Python tests and PowerShell runbook contract tests |
| `tools/` | Help generation, runbook stamping, MIME parser check and release builder |

## Checks

Run from the repository root with Python 3.9 and 3.13. `requirements-dev.txt` holds development-only version ranges, not a lockfile; at runtime the app uses platform-provided dependencies.

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m json.tool app/ms_quarantine_for_splunk_soar.json >/dev/null
python -m pytest -q tests/python/
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
python tools/check_mime_parser_compat.py
```

The [GitHub workflow](../.github/workflows/ci.yml) runs this on both Python versions and, on 3.13, the full PowerShell contract sequence in `tests/powershell/`. Running a single PowerShell script does not replace the sequence. The [Gitea workflow](../.gitea/workflows/ci.yml) is the original CI definition and is not run by GitHub.

The MIME parser overrides CPython's private `BytesFeedParser._new_message` hook and reads `_msgstack` to enforce the node and depth limits before allocation. Re-run `tools/check_mime_parser_compat.py` and the MIME tests when adding a Python runtime.

## Versions and release notes

App and runbook share one version, even when only one changes. `app_version` in `app/ms_quarantine_for_splunk_soar.json` is authoritative. After changing it:

```bash
python3 tools/stamp_runbook.py --write
python3 tools/render_readme.py
python3 tools/stamp_runbook.py --check
python3 tools/render_readme.py --check
```

Edit `tools/render_readme.py` or the manifest, never the generated `app/readme.html`. Never change the app UUID.

Publish release notes in [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases), not a changelog file. Write them from the merged pull requests since the previous release, with separate `App` and `Runbook` sections (`No changes` if unchanged), and check them against the release diff.

With every version change, update the [compatibility matrix](compatibility.md). Add only pairs backed by evidence, with source identity, validation scope and restrictions. Use **not verified** when evidence is missing and **incompatible** only for a documented mismatch. Keep the source-qualified baseline rows.

## Building the release kit

Requires Git, Bash, Python, GNU tar/gzip, jq and sha256sum.

```bash
tools/build_release.sh
```

The builder checks generated help and verifies that every staged runtime byte comes from a committed source revision, so commit first and do not disable this check. Output goes to `dist/`. When packaging changes, build twice from the same commit and compare checksums.

| Artifact | Contents |
|---|---|
| `ms-quarantine-for-splunk-soar-<version>.tgz` | One `ms-quarantine-for-splunk-soar/` directory with ten files: manifest, connector, utils, SOAR ingestion, ES ingestion, `__init__.py`, two logos, `readme.html`, `LICENSE` |
| `ms-quarantine-for-splunk-soar-runbook-<version>.ps1` | Stamped `runbook/runbook.ps1` |

Tests, Markdown, the runbook and example playbooks are not in the app archive. The SAA example is packaged separately as described in [its README](../examples/MS_Quarantine_SAA_Example/README.md#import-and-configure).

## Before publishing a release

1. Review the tracked tree for secrets, real deployment addresses, private links and personal test data.
2. Check versions, generated help, runbook fingerprint, documentation links and the compatibility matrix.
3. Run all Python and PowerShell checks and inspect the hosted Actions run for the exact commit.
4. Build twice, compare checksums and check the archive contents.
5. For 4.0, record the documentation review in [#25](https://github.com/reisball/ms-quarantine-for-splunk-soar/issues/25) before publishing.

Offline tests and a clean build do not prove that a live SOAR, Azure or Exchange deployment works. That requires the [deployment checklist](validation.md) on the exact pair.

## Pending: Azure sandbox size validation

The 24 MiB EML cap is conservative because local tests cannot measure memory in the Azure Automation Cloud Sandbox (400 MB limit). Validate it in a **non-production** Automation Account using the internal read-only runbook `export` operation. Downstream automation must be disabled, and no fixture may be released or denied.

| Fixture (decoded bytes) | Expected |
|---|---|
| 24,602,271 (known production case) | Job `Completed`; 129 chunks of 256,000 base64 characters; matching SHA-256 and Vault download |
| 25,165,824 (exactly 24 MiB) | Job `Completed`; 132 chunks; matching SHA-256; peak memory leaves a documented reserve below 400 MB, repeated with cold and warm module starts |
| 25,165,825 (cap + 1) | `error_code=export_oversized`, `handling=fail_closed`, `max_decoded_size=25165824`; no Vault import; message stays failed and holds its slot |
| Failed or suspended job | Reported as a transport/job failure, not as oversized |

For each run, record the app/runbook versions and commit, the PowerShell runtime and module versions, the job ID and timestamps, the size, chunk count and SHA-256, and peak memory if available. Never record webhook URLs, tokens or mail content. Keep 24 MiB only if the exact-boundary runs stay below the limit with a reserve. Otherwise, propose a lower cap or a Hybrid Runbook Worker approach. Attach sanitized evidence to [#18](https://github.com/reisball/ms-quarantine-for-splunk-soar/issues/18).
