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

Run from the repository root with Python 3.9 and 3.13. `requirements-dev.txt` holds development-only version ranges, not a lockfile; the release builder verifies the runtime wheels against the manifest and wheel lock.

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m json.tool app/ms_quarantine_for_splunk_soar.json >/dev/null
python -m pytest -q tests/python/
python tools/render_readme.py --check
python tools/stamp_runbook.py --check
python tools/check_mime_parser_compat.py
```

The [GitHub workflow](../.github/workflows/ci.yml) runs this on both Python versions and, on 3.13, the full PowerShell contract sequence in `tests/powershell/`. Running a single PowerShell script does not replace the sequence.

The MIME parser overrides CPython's private `BytesFeedParser._new_message` hook and reads `_msgstack` to enforce the node and depth limits before allocation. Re-run `tools/check_mime_parser_compat.py` and the MIME tests when adding a Python runtime.

## Splunk SOAR community submission

Keep the repository layout above. The upstream legacy connector tooling expects
the app manifest and source at the checkout root. The submission checker builds
the pinned release package and projects its contents into a disposable app
root; it does not move files in this repository or put the Azure runbook into
the SOAR package.

Run the checks from a committed checkout. Both tooling environments use
Python 3.13, separately from the app runtime and from each other: the app linter
requires Pydantic 1; the static/doc hooks use a SOAR SDK requiring Pydantic 2.

```bash
(
    set -e
    # Use uv 0.13.10 and pre-commit 4.5.1, as in CI.
    tooling=$(mktemp -d /tmp/msqsoar-tools.XXXXXX)
    for tool in hooks lint; do
        uv venv --python 3.13 "$tooling/$tool"
        uv pip sync --python "$tooling/$tool/bin/python" \
            --build-constraints tools/soar-tooling/build-constraints.txt \
            "tools/soar-tooling/$tool.txt"
    done
    python tools/soar_checks.py quality
    (
        export PATH="$tooling/hooks/bin:$PATH"
        python tools/soar_checks.py copyright
        SOAR_CHECK_REPORT="$tooling/static.json" python tools/soar_checks.py static
        python tools/soar_checks.py docs
        python tools/soar_checks.py notes
    )
    (PATH="$tooling/lint/bin:$PATH" python tools/soar_checks.py lint)
    python3 tools/render_notice.py --check
)
```

The lock inputs pin upstream Git commits, and the corresponding `.txt` files
pin the resolved Python 3.13 dependencies. The build constraints also pin
the isolated build dependencies of the Git-based tools. When updating tools, regenerate with
`uv pip compile --python-version 3.13 --build-constraints tools/soar-tooling/build-constraints.txt tools/soar-tooling/<tool>.in -o tools/soar-tooling/<tool>.txt`,
then test both environments independently.

The pinned quality hooks run on the packaged app and its submission Markdown,
not against the release builder or the separate Azure runbook. They check Ruff
lint/formatting, JSON/YAML, HTML lint, the manual Markdown fragment, Semgrep's
live Python registry rules, merge markers and secrets. The hook revisions and
quality settings are taken from the selected source commit; Semgrep's remote
`p/python` rule content can change independently of its executable. The
template's Conventional Commits hook is a commit-message hook, not a gate on
GitHub's generated merge commit. The maintained README keeps its GitHub tables;
the upstream Markdown formatter without GFM would turn them into prose.
The docs hook generates an upstream README in scratch space, not over this
repository's maintained README. HTML is linted but not reformatted by the hook:
`tools/render_readme.py` owns its exact bytes. The copyright audit runs on a
copy with the actual owner as an explicit argument; it is a manual
submission check because the upstream updater uses the calendar year.
Do not run the unmodified legacy template's dependency/NOTICE generation on
this layout: it assumes a root `requirements.txt` and would replace the NOTICE
for the bundled wheels. The linter checks errors and uses a disposable
app copy seeded with the pinned tooling and the exact bundled Python 3.13
wheels; upstream dependency checks stay enabled. The static report retains raw
results; upstream reads the live registries when available and can fall back
to bundled snapshots. `static-strict` additionally fails if registration is
pending. A non-strict pass is not upstream acceptance or native SOAR validation.

NOTICE is generated from license text in the exact hash-locked runtime wheels
for both app interpreters, plus pinned notices for the bundled OpenSSL, libffi and Rust components.
The Rust notice records source checksums and distinguishes the all-target
cryptography lockfile from the Linux standard-library dependency set. NOTICE
excludes SOAR tooling and platform-provided dependencies.
When wheels change, review their bundled license files and native components,
update the wheel lock, and run `python3 tools/render_notice.py`.

See the [SOAR contribution guide](https://github.com/splunk-soar-connectors/.github/blob/main/.github/CONTRIBUTING.md)
for the repository request, required hooks and upstream pull request process.

## Versions and release notes

App and runbook share one version, even when only one changes. `app_version` in `app/ms_quarantine_for_splunk_soar.json` is authoritative. After changing it:

```bash
python3 tools/stamp_runbook.py --write
python3 tools/render_readme.py
python3 tools/stamp_runbook.py --check
python3 tools/render_readme.py --check
```

Edit `tools/render_readme.py` or the manifest, never the generated `app/readme.html`. Never change the app UUID.

Publish release notes in [GitHub Releases](https://github.com/reisball/ms-defender-quarantine-manager/releases), not a changelog file. Write them from the merged pull requests since the previous release, with separate `App` and `Runbook` sections (`No changes` if unchanged), and check them against the release diff.

With every version change, update the [compatibility matrix](compatibility.md). Add only pairs backed by evidence, with source identity, validation scope and restrictions. Use **not verified** when evidence is missing and **incompatible** only for a documented mismatch. Keep the source-qualified baseline rows.

## Building the release kit

Requires Git, Bash, Python, GNU tar/gzip, jq and sha256sum.

```bash
tools/build_release.sh
```

The builder checks generated help and verifies that every staged runtime byte comes from a committed source revision, so commit first and do not disable this check. Output goes to `dist/`. When packaging changes, build twice from the same commit and compare checksums.

| Artifact | Contents |
|---|---|
| `ms-defender-quarantine-manager-<version>.tgz` | One `ms-quarantine-for-splunk-soar/` directory with runtime modules, the manifest, icons, `readme.html`, `LICENSE`, `NOTICE` and the six pinned runtime wheels |
| `ms-defender-quarantine-manager-runbook-<version>.ps1` | Stamped `runbook/runbook.ps1` |

Tests, Markdown, the runbook and example playbooks are not in the app archive. The SAA example is packaged separately as described in [its README](../examples/MS_Quarantine_SAA_Example/README.md#import-and-configure).

## Before publishing a release

1. Review the tracked tree for secrets, real deployment addresses, private links and personal test data.
2. Check versions, generated help, runbook fingerprint, documentation links and the compatibility matrix.
3. Run all Python and PowerShell checks and inspect the hosted Actions run for the exact commit.
4. Build twice, compare checksums and check the archive contents.
5. Review the user documentation against the exact release candidate before publishing.

Offline tests and a clean build do not prove that a live SOAR, Azure or Exchange deployment works. That requires the [deployment checklist](validation.md) on the exact pair.

## Pending: Azure sandbox size validation

The 24 MiB EML cap is conservative because local tests cannot measure memory in the Azure Automation Cloud Sandbox (400 MB limit). Validate it in a **non-production** Automation Account using the internal read-only runbook `export` operation. Downstream automation must be disabled, and no fixture may be released or denied.

| Fixture (decoded bytes) | Expected |
|---|---|
| 24,602,271 (known production case) | Job `Completed`; 129 chunks of 256,000 base64 characters; matching SHA-256 and Vault download |
| 25,165,824 (exactly 24 MiB) | Job `Completed`; 132 encrypted chunks plus the final record; matching SHA-256 after SOAR decryption; peak memory leaves a documented reserve below 400 MB, repeated with cold and warm module starts |
| 25,165,825 (cap + 1) | `error_code=export_oversized`, `handling=fail_closed`, `max_decoded_size=25165824`; no Vault import; message stays failed and holds its slot |
| Failed or suspended job | Reported as a transport/job failure, not as oversized |

Verify all Azure job streams contain no readable EML, the aggregate Job Output API returns the full encrypted stream, and the installed SOAR package decrypts it on the supported interpreter. Use synthetic mail.

For each run, record the app/runbook versions and commit, the PowerShell runtime and module versions, the job ID and timestamps, the size, chunk count and SHA-256, and peak memory if available. Never record webhook URLs, tokens or mail content. Keep 24 MiB only if the exact-boundary runs stay below the limit with a reserve. Otherwise, propose a lower cap or a Hybrid Runbook Worker approach. Attach sanitized evidence to [#18](https://github.com/reisball/ms-defender-quarantine-manager/issues/18).

## SDK candidate (#42)

Build and test the Python 3.13 SDK project from a clean staging directory:

```sh
scratch=$(mktemp -d)
python3 tools/stage_sdk.py "$scratch/project"
(cd "$scratch/project" && uv run --locked --python 3.13 python -m pytest -q tests)
bash tools/build_sdk.sh "$scratch/ms-defender-quarantine-manager-1.0.0-sdk.tgz"
```

The SDK project pins `splunk-soar-sdk` 8.0.2 and shares the transport, bounded
MIME parsing, and intake logic with the regression suite. The SDK build does
not modify the separately deployed Azure runbook. The SDK packager selects
runtime wheels; the build generates NOTICE from those exact wheels and checks
that the final archive bundles the same wheel inventory. These commands do not
perform a SOAR installation, contact Azure, or publish a release.

SOAR intake and SOAR-proxied ES findings use acknowledged SDK client calls
instead of decorator buffering because automation must follow the final Vault
upload and a stored publication checkpoint. The progress log reports the
counts; the SDK poll wrappers supply their own final action status message.
