"""Release-builder regressions using local disposable Git repositories only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
APP = "ms-quarantine-for-splunk-soar"
APP_INPUTS = (
    "__init__.py", "LICENSE", "readme.html", "ms_quarantine_for_splunk_soar.json",
    "ms_quarantine_for_splunk_soar_connector.py", "ms_quarantine_for_splunk_soar_utils.py",
    "ms_quarantine_for_splunk_soar_ingestion.py", "ms_quarantine_for_splunk_soar_es_ingestion.py",
    "ms_quarantine_for_splunk_soar.svg", "ms_quarantine_for_splunk_soar_dark.svg",
)
# Source layout differs from the intentionally flat installable package.
APP_SOURCES = {name: name if name == "LICENSE" else f"app/{name}" for name in APP_INPUTS}
RUNBOOK_SOURCE = "runbook/runbook.ps1"
EPOCH = "1700000000"


def run(repo, *args, env=None, binary=False):
    env = dict(os.environ if env is None else env)
    # Never let caller Git bindings redirect fixture commands into a real repo.
    env = {key: value for key, value in env.items()
           if not key.startswith("GIT_") or key in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")}
    if args[0] == "git":
        args = ("git", f"--git-dir={repo / '.git'}", f"--work-tree={repo}",
                "-c", "user.name=Build regression",
                "-c", "user.email=build-test@example.invalid",
                "-c", "commit.gpgsign=false", *args[1:])
    return subprocess.run(args, cwd=repo, env=env, text=not binary, capture_output=True)


def git(repo, *args):
    result = run(repo, "git", *args)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def git_bytes(repo, *args):
    result = run(repo, "git", *args, binary=True)
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    for name in (*APP_SOURCES.values(), RUNBOOK_SOURCE, "tools/build_release.sh",
                 "tools/render_readme.py", "tools/stamp_runbook.py"):
        dest = repo / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    (repo / "README.md").write_text("Repository documentation\n")
    (repo / "test_example.py").write_text("# Repository-only test\n")
    git(repo, "init", "-q")
    assert (repo / ".git").is_dir()
    assert Path(git(repo, "rev-parse", "--show-toplevel")) == repo
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "Build inputs")
    return repo


def build(repo, output, *, commit=None, epoch=EPOCH, mask="022", locale="C", extra_env=None):
    env = os.environ.copy()
    env.pop("SOURCE_COMMIT", None)
    env.pop("SOURCE_DATE_EPOCH", None)
    if commit is not None:
        env["SOURCE_COMMIT"] = commit
    if epoch is not None:
        env["SOURCE_DATE_EPOCH"] = epoch
    env["LC_ALL"] = locale
    env.update(extra_env or {})
    return run(repo, "bash", "-c", 'umask "$1"; bash tools/build_release.sh "$2"',
               "build-test", mask, str(output), env=env)


def assert_success(result):
    assert result.returncode == 0, result.stdout + result.stderr


def output_bytes(output):
    return {path.name: path.read_bytes() for path in output.iterdir()}


def successful_release(repo, output):
    assert_success(build(repo, output))
    result = output_bytes(output)
    assert len(result) == 4
    return result


def assert_rejected_unchanged(repo, output, previous, **kwargs):
    result = build(repo, output, **kwargs)
    assert result.returncode != 0, "Mismatching source was accepted"
    assert output_bytes(output) == previous
    return result


@pytest.mark.parametrize("name", APP_INPUTS)
def test_every_packaged_input_mismatch_preserves_previous_release(source, tmp_path, name):
    output = tmp_path / "release"
    previous = successful_release(source, output)
    # Whitespace keeps JSON valid and changes bytes, not runtime semantics.
    with (source / APP_SOURCES[name]).open("ab") as stream:
        stream.write(b"\n")
    assert_rejected_unchanged(source, output, previous)


def test_staged_app_change_preserves_previous_release(source, tmp_path):
    output = tmp_path / "release"
    previous = successful_release(source, output)
    name = "ms_quarantine_for_splunk_soar_utils.py"
    with (source / APP_SOURCES[name]).open("ab") as stream:
        stream.write(b"\n# staged regression\n")
    git(source, "add", APP_SOURCES[name])
    assert_rejected_unchanged(source, output, previous)


def test_restamped_changed_runbook_preserves_previous_release(source, tmp_path):
    output = tmp_path / "release"
    previous = successful_release(source, output)
    with (source / RUNBOOK_SOURCE).open("ab") as stream:
        stream.write(b"\n# changed but internally valid companion\n")
    assert_success(run(source, "python3", "tools/stamp_runbook.py", "--write"))
    result = assert_rejected_unchanged(source, output, previous)
    assert "runbook.ps1" in result.stderr


@pytest.mark.parametrize("kind", ("unknown", "blob", "different-inputs"))
def test_invalid_or_mismatching_override_preserves_previous_release(source, tmp_path, kind):
    output = tmp_path / "release"
    previous = successful_release(source, output)
    if kind == "unknown":
        override = "0" * 40
    elif kind == "blob":
        override = git(source, "rev-parse", "HEAD:LICENSE")
    else:
        (source / "LICENSE").write_text("Different committed bytes\n")
        git(source, "add", "LICENSE")
        git(source, "commit", "-qm", "Different source")
        override = git(source, "rev-parse", "HEAD")
        git(source, "checkout", "HEAD^", "--", "LICENSE")
    assert_rejected_unchanged(source, output, previous, commit=override)


@pytest.mark.parametrize("poison_git", [False, True])
def test_valid_override_resolves_commit_and_keeps_unrelated_changes_allowed(source, tmp_path, monkeypatch, poison_git):
    if poison_git:
        monkeypatch.setenv("GIT_DIR", "/nonexistent/ms_quarantine_for_splunk_soar-fixture-gitdir")
        monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent/ms_quarantine_for_splunk_soar-fixture-worktree")
    original = git(source, "rev-parse", "HEAD")
    (source / "README.md").write_text("New documentation revision\n")
    git(source, "add", "README.md")
    git(source, "commit", "-qm", "Docs only")
    assert original != git(source, "rev-parse", "HEAD")
    (source / "README.md").write_text("Dirty unrelated documentation\n")
    (source / "test_example.py").write_text("# Staged unrelated test change\n")
    git(source, "add", "test_example.py")
    output = source / "untracked-build-output"
    output.mkdir()
    (output / "user-note").write_text("Not a package member\n")
    # Short refs are resolved to the immutable full commit id.
    assert_success(build(source, output, commit=original[:12]))
    metadata = json.loads((output / "BUILD_METADATA.json").read_text())
    assert metadata["source_commit"] == original
    assert metadata["source_date_epoch"] == int(EPOCH)
    assert (output / "user-note").read_text() == "Not a package member\n"
    with tarfile.open(next(output.glob("*.tgz"))) as archive:
        assert set(archive.getnames()) == {APP, *(f"{APP}/{name}" for name in APP_INPUTS)}
        for name in APP_INPUTS:
            expected = git_bytes(source, "show", f"{original}:{APP_SOURCES[name]}")
            assert archive.extractfile(f"{APP}/{name}").read() == expected
    expected_runbook = git_bytes(source, "show", f"{original}:{RUNBOOK_SOURCE}")
    assert next(output.glob("*.ps1")).read_bytes() == expected_runbook
    assert_success(run(output, "sha256sum", "-c", "SHA256SUMS"))


def test_default_epoch_still_uses_head_with_an_older_identical_input_commit(source, tmp_path):
    original = git(source, "rev-parse", "HEAD")
    (source / "README.md").write_text("Docs-only commit with distinct timestamp\n")
    git(source, "add", "README.md")
    env = dict(os.environ, GIT_AUTHOR_DATE="1800000000 +0000", GIT_COMMITTER_DATE="1800000000 +0000")
    assert_success(run(source, "git", "commit", "-qm", "Later docs", env=env))
    output = tmp_path / "release"
    assert_success(build(source, output, commit=original, epoch=None))
    metadata = json.loads((output / "BUILD_METADATA.json").read_text())
    assert metadata["source_date_epoch"] == 1800000000
    assert metadata["source_commit"] == original


@pytest.mark.parametrize("name", ("ms_quarantine_for_splunk_soar_utils.py", "runbook.ps1"))
def test_staged_bytes_are_verified_not_only_worktree_bytes(source, tmp_path, name):
    output = tmp_path / "release"
    previous = successful_release(source, output)
    # Simulate corruption during copying; clean checkout bytes alone cannot prove
    # that the staged package corresponds to the claimed commit.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_cp = shutil.which("cp")
    shim = bin_dir / "cp"
    shim.write_text(
        "#!/usr/bin/env bash\nset -e\n"
        f'"{real_cp}" "$@"\n'
        'if [[ "${@: -1}" == */' + name + ' ]]; then\n'
        '    printf "\\n# corrupted staged copy\\n" >> "${@: -1}"\nfi\n'
    )
    shim.chmod(0o755)
    result = assert_rejected_unchanged(
        source, output, previous,
        extra_env={"PATH": f"{bin_dir}:{os.environ['PATH']}"},
    )
    assert name in result.stderr


def test_umask_and_locale_reproducibility_preserves_source_and_output_modes(source, tmp_path):
    locales = subprocess.check_output(["locale", "-a"], text=True).splitlines()
    utf8 = next((name for name in locales if name.lower() in ("c.utf8", "c.utf-8")), "C")
    source.chmod(0o750)
    (source / "LICENSE").chmod(0o600)
    source_modes = {p: p.stat().st_mode for p in (source, *(source / n for n in APP_SOURCES.values()), source / RUNBOOK_SOURCE)}
    outputs = []
    for index, (mask, locale) in enumerate((("022", "C"), ("077", "C"), ("022", utf8), ("077", utf8))):
        output = tmp_path / f"build-{index}"
        output.mkdir(mode=0o700)
        assert_success(build(source, output, mask=mask, locale=locale))
        assert output.stat().st_mode & 0o777 == 0o700
        assert {p: p.stat().st_mode for p in source_modes} == source_modes
        outputs.append(output_bytes(output))
        with tarfile.open(next(output.glob("*.tgz"))) as archive:
            for member in archive.getmembers():
                assert member.mode == (0o755 if member.isdir() else 0o644)
                assert member.uid == member.gid == 0
                assert member.mtime == int(EPOCH)
    hashes = [{name: hashlib.sha256(data).hexdigest() for name, data in files.items()} for files in outputs]
    assert all(hashes[0] == other for other in hashes[1:])
