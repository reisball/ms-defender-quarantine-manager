# Development and release

[Back to README](../README.md) · [Contributing](../CONTRIBUTING.md)

## Repository layout

| Path | Purpose |
|---|---|
| `sdk_app/` | SDK app project, lockfile, runtime source and SDK tests |
| `app/` | Shared transport, MIME and ingestion modules; legacy connector retained as a regression fixture |
| `runbook/runbook.ps1` | Azure Automation runbook, released as a separate artifact |
| `examples/` | Example playbooks, not part of the app package |
| `tests/python/`, `tests/powershell/` | Python tests and PowerShell runbook contract tests |
| `tools/` | Help generation, runbook stamping, MIME parser check and release builder |

## Checks

Run from the repository root with Python 3.13 and uv 0.13.10, as in CI.
`requirements-dev.txt` is for the shared and legacy regression tests only.
The SDK project uses the locked SDK 8.0.2 environment in `sdk_app/uv.lock`.

```bash
python3.13 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-dev.txt uv==0.13.10
python -m pytest -q tests/python/
python tools/check_mime_parser_compat.py
scratch=$(mktemp -d)
python tools/stage_sdk.py "$scratch/project"
(cd "$scratch/project" && uv run --locked --python 3.13 python -m pytest -q tests)
```

The [GitHub workflow](../.github/workflows/ci.yml) runs both suites plus the full
PowerShell contract sequence in `tests/powershell/`. Running a single PowerShell
script does not replace the sequence.

The MIME parser overrides CPython's private `BytesFeedParser._new_message` hook and reads `_msgstack` to enforce the node and depth limits before allocation. Re-run `tools/check_mime_parser_compat.py` and the MIME tests when adding a Python runtime.

## Legacy reference checks and SDK submission

The retained legacy-only upstream hooks expect a flat classic connector at
the checkout root. CI still runs them against a separately built historical
reference projection via `tools/build_legacy_reference.sh`. They are not the
release pipeline, do not validate the SDK package for upstream submission,
and do not imply support for a classic installation or upgrade. SDK release
checks instead exercise the locked SDK tests and validate its generated
manifest and wheel archive. Upstream SDK submission and SOAR installation
remain separate validation steps.

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

The pinned legacy quality hooks run on the historical reference and its submission Markdown,
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

The historical reference NOTICE is generated from its own hash-locked wheels
plus pinned notices for OpenSSL, libffi and Rust components.
The Rust notice records source checksums and distinguishes the all-target
cryptography lockfile from the Linux standard-library dependency set. NOTICE
excludes SOAR tooling and platform-provided dependencies.
When wheels change, review their bundled license files and native components,
update the wheel lock, and run `python3 tools/render_notice.py`.

See the [SOAR contribution guide](https://github.com/splunk-soar-connectors/.github/blob/main/.github/CONTRIBUTING.md)
for the repository request, required hooks and upstream pull request process.

## Versions and release notes

App and runbook share one version, even when only one changes. The version in
`sdk_app/pyproject.toml` is authoritative for the SDK artifact. Update it and
refresh `sdk_app/uv.lock`, then generate the new SDK manifest and use it to
stamp and check the runbook:

```bash
scratch=$(mktemp -d)
tools/build_sdk.sh "$scratch/app.tgz"
tar -xOzf "$scratch/app.tgz" 'MS Defender Quarantine Manager/manifest.json' > "$scratch/manifest.json"
python tools/stamp_runbook.py --manifest "$scratch/manifest.json" --write --check
```

The legacy fixture has a separate manifest and generated help. If the shared
runbook version changes while those historical gates remain active, align the
fixture version as well and run `python tools/render_readme.py`. Do not change
the app UUID.

Publish release notes in [GitHub Releases](https://github.com/reisball/ms-defender-quarantine-manager/releases), not a changelog file. Write them from the merged pull requests since the previous release, with separate `App` and `Runbook` sections (`No changes` if unchanged), and check them against the release diff.

With every version change, update the [compatibility matrix](compatibility.md). Add only pairs backed by evidence, with source identity, validation scope and restrictions. Use **not verified** when evidence is missing and **incompatible** only for a documented mismatch. Keep the source-qualified baseline rows.

## Building the release kit

Requires Git, Bash, Python 3.13, uv 0.13.10, GNU tar, jq and sha256sum.
The SDK packager needs access to the locked upstream wheel and sdist URLs.

```bash
tools/build_release.sh
```

The release builder checks SDK runtime inputs and the companion runbook against
the selected committed revision (HEAD by default), verifies the generated SDK
manifest and exact wheel set, and verifies the runbook fingerprint before
moving any artifacts into `dist/`.

The SDK's wall-clock manifest timestamp, tar metadata, and gzip timestamp
are normalized to `SOURCE_DATE_EPOCH` (HEAD's commit time by default). The locked
`red-black-tree-mod` sdist currently builds a pure-Python wheel whose ZIP entry
timestamps differ between builds; only that wheel's ZIP metadata is
normalized. Its contents (including RECORD) are unchanged, and every
downloaded wheel keeps its original lock-verified bytes. Compare all outputs
from two isolated builds with the same source, tools and epoch; byte identity
across arbitrary Python, zlib or SDK toolchains is not asserted.

NOTICE inventories the final wheel hashes, includes the wheel license files,
and lists native components declared in the shipped SBOMs. It includes the
libffi license for the statically linked CFFI Linux wheels, and the OpenSSL
4.0.3 license for the version reported by both cryptography wheels. The latter
is copied from the [upstream OpenSSL release commit](https://github.com/openssl/openssl/blob/af1775b60dfa141a4ad762585052cabeb9f37e9e/LICENSE.txt)
(SHA-256 `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`).
A dependency update that changes these assumptions needs notice review.

| Artifact | Contents |
|---|---|
| `ms-defender-quarantine-manager-<version>.tgz` | One `MS Defender Quarantine Manager/` directory with SDK runtime modules, generated `manifest.json`, template, icons, in-app documentation, `LICENSE`, `NOTICE`, and locked SDK dependency wheels |
| `ms-defender-quarantine-manager-runbook-<version>.ps1` | Stamped `runbook/runbook.ps1` |

Tests, repository-only documentation, the runbook and example playbooks are not in the app archive. The SAA example is packaged separately as described in [its README](../examples/MS_Quarantine_SAA_Example/README.md#import-and-configure).

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

## SDK runtime boundary

SOAR intake and SOAR-proxied ES findings use acknowledged SDK client calls
instead of decorator buffering because automation must follow the final Vault
upload and a stored publication checkpoint. The actions use the SDK dispatcher
with structured summaries rather than the fixed-result poll and connectivity
decorators. Intake requires a native authenticated SOAR session. It keeps an
encrypted per-asset ledger in the SDK state directory, separate from deferred
action state, and verifies each checkpoint from disk before publication.
The local fixture tests exercise restart and missing-write behavior; storage
and Vault behavior on an installed SOAR instance still need native validation.
