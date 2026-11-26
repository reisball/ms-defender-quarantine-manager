"""Offline SDK packaging regressions. CI also builds the real distribution twice."""

import gzip
import io
import json
import sys
import tarfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import render_sdk_notice as packaging
import stage_sdk

EPOCH = 1700000000


def wheel(files, *, year=2024):
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        for path, data in files.items():
            archive.writestr(ZipInfo(path, (year, 1, 1, 0, 0, 0)), data)
    return output.getvalue()


def local_entries():
    prefix = "red_black_tree_mod-1.22.dist-info/"
    return {
        "red_black_dict_mod.py": b"# dict\n",
        "red_black_set_mod.py": b"# set\n",
        prefix + "licenses/COPYING": b"Text",
        prefix + "METADATA": b"Name: red-black-tree-mod\nVersion: 1.22\n",
        prefix + "WHEEL": b"Root-Is-Purelib: true\nTag: py3-none-any\n",
        prefix + "top_level.txt": b"red_black_dict_mod\n",
        prefix + "RECORD": b"source bytes unchanged\n",
    }


def test_local_wheel_metadata_only_normalization():
    files = local_entries()
    a = packaging.normalize_local_wheel(wheel(files, year=2024))
    b = packaging.normalize_local_wheel(
        wheel(dict(reversed(list(files.items()))), year=2025)
    )
    assert a == b
    with ZipFile(io.BytesIO(a)) as result:
        assert {name: result.read(name) for name in result.namelist()} == files

    with pytest.raises(ValueError, match="layout changed"):
        packaging.normalize_local_wheel(wheel({**files, "unexpected.so": b"binary"}))


def crypto_wheel(*, openssl="4.0.3"):
    prefix = "cryptography-50.0.2.dist-info/"
    files = {
        prefix + "METADATA": b"Name: cryptography\nVersion: 50.0.2\n",
        prefix + "licenses/LICENSE": b"Wheel license",
        prefix + "sboms/sbom.json": json.dumps(
            {"components": [{"name": "openssl", "version": openssl}]}
        ),
        prefix + "sboms/cryptography-rust.cyclonedx.json": json.dumps(
            {
                "components": [
                    {
                        "name": "rust-component",
                        "version": "1",
                        "licenses": [{"expression": "MIT"}],
                    }
                ]
            }
        ),
    }
    return wheel(files)


def fixture_tar(path, files, *, reverse=False):
    with tarfile.open(path, "w:gz") as archive:
        for relative, data in sorted(files.items(), reverse=reverse):
            record = tarfile.TarInfo(f"{packaging.APP}/{relative}")
            record.mode = 0o777 if reverse else 0o640
            record.mtime = EPOCH + int(reverse)
            record.size = len(data)
            archive.addfile(record, io.BytesIO(data))


def test_archive_normalization_and_notice(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    package_one, package_two, final_one, final_two = (
        tmp_path / name for name in ("a", "b", "a.tgz", "b.tgz")
    )
    # Exercise normalization independently of the real lock/manifest gate below.
    monkeypatch.setattr(
        packaging, "validate", lambda files, *_: json.loads(files["manifest.json"])
    )
    local = "wheels/shared/" + packaging.LOCAL_WHEEL
    crypto = "wheels/shared/cryptography-50.0.2-cp311-abi3-manylinux_2_28_x86_64.whl"
    original_crypto = crypto_wheel()
    files = {
        local: wheel(local_entries(), year=2024),
        crypto: original_crypto,
        "manifest.json": b'{"utctime_updated":"wall time one","configuration":{"z":{},"a":{}}}',
        "src/app.py": b"pass\n",
    }
    fixture_tar(package_one, files)
    files[local] = wheel(local_entries(), year=2025)
    files["manifest.json"] = (
        b'{"utctime_updated":"wall time two","configuration":{"z":{},"a":{}}}'
    )
    fixture_tar(package_two, files, reverse=True)
    packaging.normalize_package(package_one, final_one, project, EPOCH)
    packaging.normalize_package(package_two, final_two, project, EPOCH)
    assert final_one.read_bytes() == final_two.read_bytes()
    assert int.from_bytes(final_one.read_bytes()[4:8], "little") == EPOCH
    assert gzip.decompress(final_one.read_bytes())
    packaged = packaging.files_of(final_one)
    assert list(json.loads(packaged["manifest.json"])["configuration"]) == ["z", "a"]
    assert packaged[crypto] == original_crypto
    assert b"=== OpenSSL 4.0.3" in packaged["NOTICE"]
    assert b"rust-component / 1 / MIT" in packaged["NOTICE"]
    assert packaging.sha(packaged[local]).encode() in packaged["NOTICE"]
    with tarfile.open(final_one) as archive:
        assert archive.getmembers()[0].name == packaging.APP
        assert archive.getmembers()[0].isdir()
        for member in archive:
            assert (member.mode, member.uid, member.gid, member.mtime) == (
                0o755 if member.isdir() else 0o644,
                0,
                0,
                EPOCH,
            )


def test_unknown_openssl_requires_notice_review():
    with pytest.raises(ValueError, match="OpenSSL 0.0.0 needs"):
        packaging.render_notice(
            {"wheels/shared/cryptography.whl": crypto_wheel(openssl="0.0.0")}
        )


def test_non_sdk_manifest_fails_before_publish(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n')
    with pytest.raises(ValueError, match="generated manifest appid"):
        packaging.validate({"manifest.json": b'{"python_version":"3.9"}'}, tmp_path)


def test_traversal_rejected(tmp_path):
    archive = tmp_path / "bad.tgz"
    fixture_tar(archive, {"../outside": b"no"})
    with pytest.raises(ValueError, match="Unexpected SDK archive path"):
        packaging.files_of(archive)


def test_sdk_stage_copies_shared_sources_and_generates_version(tmp_path):
    destination = tmp_path / "project"
    stage_sdk.stage(destination, None)
    assert (destination / "uv.lock").read_bytes() == (
        stage_sdk.PROJECT / "uv.lock"
    ).read_bytes()
    assert (destination / "tests/test_sdk_runtime.py").is_file()
    assert (destination / "src/version.py").read_text().startswith("APP_VERSION = ")
    surface = (
        destination / "src/ms_quarantine_for_splunk_soar_ingestion.py"
    ).read_text()
    assert "from .ms_quarantine_for_splunk_soar_" in surface
    assert not any(path.name == "__pycache__" for path in destination.rglob("*"))


def test_default_release_uses_sdk_manifest_and_keeps_companion_separate(
    tmp_path, monkeypatch
):
    from test_build_release import ROOT, assert_success, git, run

    repo = tmp_path / "source"
    output = tmp_path / "release"
    for path in (
        "tools/build_release.sh",
        "tools/stamp_runbook.py",
        "runbook/runbook.ps1",
    ):
        dest = repo / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((ROOT / path).read_bytes())
    # Stub only the independently tested SDK compiler; use the real release
    # wrapper, SDK-shaped manifest, source provenance, fingerprint and checksums.
    manifest = {
        "appid": packaging.APP_ID,
        "app_version": "1.0.0",
        "main_module": "src.app:app",
    }
    fixture_tar(
        repo / "sdk-fixture.tgz", {"manifest.json": json.dumps(manifest).encode()}
    )
    (repo / "tools/build_sdk.sh").write_text(
        '#!/usr/bin/env bash\nset -eu\ntest "$2" = "$(git rev-parse HEAD)"\ncp sdk-fixture.tgz "$1"\n'
    )
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "SDK release wrapper fixture")
    monkeypatch.delenv("SOURCE_COMMIT", raising=False)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(EPOCH))
    assert_success(run(repo, "bash", "tools/build_release.sh", str(output)))
    package = output / "ms-defender-quarantine-manager-1.0.0.tgz"
    companion = output / "ms-defender-quarantine-manager-runbook-1.0.0.ps1"
    assert package.read_bytes() == (repo / "sdk-fixture.tgz").read_bytes()
    assert companion.read_bytes() == (repo / "runbook/runbook.ps1").read_bytes()
    assert set(packaging.files_of(package)) == {"manifest.json"}
    metadata = json.loads((output / "BUILD_METADATA.json").read_bytes())
    assert metadata["source_commit"] == git(repo, "rev-parse", "HEAD")
    assert metadata["app_version"] == metadata["runbook_version"] == "1.0.0"
    assert_success(run(output, "sha256sum", "-c", "SHA256SUMS"))

    previous = {p.name: p.read_bytes() for p in output.iterdir()}
    (repo / "runbook/runbook.ps1").write_bytes(
        companion.read_bytes() + b"# local change\n"
    )
    refused = run(repo, "bash", "tools/build_release.sh", str(output))
    assert refused.returncode != 0
    assert "Source provenance mismatch: runbook/runbook.ps1" in refused.stderr
    assert {p.name: p.read_bytes() for p in output.iterdir()} == previous
