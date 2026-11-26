#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Validate and normalize the SDK archive, and generate NOTICE from shipped wheels."""

import argparse
import gzip
import hashlib
import io
import json
import re
import stat
import tarfile
import tomllib
from datetime import UTC, datetime
from email import message_from_bytes
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from stage_sdk import source_bytes

COPYING = re.compile(
    r"(?:LICEN[CS]E|COPYING|NOTICE|AUTHORS)(?:[._-].*)?", re.IGNORECASE
)
NOTICES = Path(__file__).resolve().parent / "soar-tooling/notices"
APP = "MS Defender Quarantine Manager"
APP_ID = "2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e"
# SDK 8.0.2 verifies the sdist against uv.lock, then builds it locally.
LOCAL_WHEEL = "red_black_tree_mod-1.22-py3-none-any.whl"
OPENSSL_LICENSES = {"4.0.3": "openssl-4.0.3.txt"}
RUST_NOTICES = {
    "cryptography": (
        "cryptography-sdk-rust.txt",
        "sboms/cryptography-rust.cyclonedx.json",
    ),
    "pydantic-core": (
        "pydantic-core-sdk-rust.txt",
        "sboms/pydantic-core.cyclonedx.json",
    ),
}


def check_rust_notice(text: str, wheel: str, digest: str, components: list) -> None:
    reviewed_wheels = re.findall(
        r"^Wheel SHA-256: ([0-9a-f]{64})  (\S+)$", text, re.MULTILINE
    )
    if (digest, wheel) not in reviewed_wheels:
        raise ValueError(f"Review Rust attribution for {wheel}")
    reviewed_crates = set(
        re.findall(
            r"^(\S+) (\S+) \(.*\)\nhttps://static\.crates\.io/[^\n]+\nSHA-256: ([0-9a-f]{64})$",
            text,
            re.MULTILINE,
        )
    )
    registry = []
    for component in components:
        purl = component.get("purl", "")
        if purl.startswith("pkg:cargo/") and "?download_url=file:" in purl:
            continue  # first-party path crate, covered by wheel licensing
        checksums = [
            h["content"] for h in component.get("hashes", []) if h["alg"] == "SHA-256"
        ]
        if (
            len(checksums) != 1
            or (component["name"], component["version"], checksums[0])
            not in reviewed_crates
        ):
            raise ValueError(
                f"Review source attribution for {component['name']} in {wheel}"
            )
        registry.append(component["name"])
    if not registry:
        raise ValueError(f"No Cargo registry inventory in {wheel}")


def files_of(package: Path) -> dict:
    files = {}
    seen = set()
    with tarfile.open(package, "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != member.name
                or not path.parts
                or path.parts[0] != APP
                or member.name in seen
            ):
                raise ValueError(f"Unexpected SDK archive path: {member.name}")
            seen.add(member.name)
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) < 2:
                raise ValueError(f"Unexpected SDK archive member: {member.name}")
            files[path.relative_to(APP).as_posix()] = archive.extractfile(member).read()
    return files


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_local_wheel(data: bytes) -> bytes:
    """Change only ZIP metadata of the known pure-Python source-built wheel."""
    buf = io.BytesIO()
    with ZipFile(io.BytesIO(data)) as source, ZipFile(buf, "w") as target:
        names = source.namelist()
        allowed = {
            "red_black_dict_mod.py",
            "red_black_set_mod.py",
            *(
                f"red_black_tree_mod-1.22.dist-info/{name}"
                for name in (
                    "licenses/COPYING",
                    "METADATA",
                    "WHEEL",
                    "top_level.txt",
                    "RECORD",
                )
            ),
        }
        if len(names) != len(allowed) or set(names) != allowed:
            raise ValueError(
                "Source-built wheel layout changed; review the pinned sdist"
            )
        if b"Root-Is-Purelib: true" not in source.read(
            "red_black_tree_mod-1.22.dist-info/WHEEL"
        ):
            raise ValueError("Source-built wheel is no longer pure Python")
        for name in sorted(names):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            target.writestr(
                info, source.read(name), compress_type=ZIP_DEFLATED, compresslevel=9
            )
    return buf.getvalue()


def render_notice(files: dict, commit: str | None = None) -> str:
    header = APP + "\nThird-party notices for the bundled SDK wheels."
    notices = {}
    inventory = []
    native = []
    openssl_versions = set()
    bundled_libffi = False
    rust_notices = {}
    for path, data in sorted(files.items()):
        if not path.endswith(".whl"):
            continue
        wheel = Path(path).name
        digest = sha(data)
        inventory.append(f"{wheel}: sha256:{digest}")
        with ZipFile(io.BytesIO(data)) as contents:
            (metadata_path,) = (
                n
                for n in contents.namelist()
                if n.endswith(".dist-info/METADATA") and n.count("/") == 1
            )
            meta = message_from_bytes(contents.read(metadata_path))
            dist_info = metadata_path.removesuffix("METADATA")
            texts = tuple(
                (n, contents.read(n).decode("utf-8").strip())
                for n in sorted(contents.namelist())
                if not n.endswith("/") and COPYING.fullmatch(Path(n).name)
            )
            if not texts:
                raise ValueError(f"No bundled license text in {wheel}")
            name = f"{meta['Name']} {meta['Version']}"
            for filename, content in texts:
                notices.setdefault(name, {})[(Path(filename).name, content)] = None

            sboms = {}
            for n in sorted(contents.namelist()):
                if n.startswith(dist_info + "sboms/") and n.endswith(".json"):
                    sboms[n.removeprefix(dist_info)] = json.loads(contents.read(n))[
                        "components"
                    ]
            dist_name = meta["Name"].lower().replace("_", "-")
            if dist_name == "cryptography":
                (openssl,) = [
                    c["version"]
                    for c in sboms["sboms/sbom.json"]
                    if c["name"] == "openssl"
                ]
                if openssl not in OPENSSL_LICENSES:
                    raise ValueError(
                        f"OpenSSL {openssl} needs a reviewed license notice"
                    )
                openssl_versions.add(openssl)
            if dist_name in RUST_NOTICES:
                filename, sbom = RUST_NOTICES[dist_name]
                if dist_name not in rust_notices:
                    rust_notices[dist_name] = (
                        source_bytes(NOTICES / filename, commit).decode("utf-8").strip()
                    )
                check_rust_notice(
                    rust_notices[dist_name], wheel, digest, sboms.get(sbom, [])
                )
            if dist_name == "cffi":
                if meta["Version"] != "2.1.1" or "manylinux" not in wheel:
                    raise ValueError(f"Review libffi attribution for {wheel}")
                bundled_libffi = True
                native.append(f"{wheel}: statically linked libffi (see license below)")
            for sbom, components in sboms.items():
                rows = [
                    " / ".join(
                        [
                            c["name"],
                            c.get("version", "unspecified"),
                            " OR ".join(
                                item.get("expression")
                                or item["license"].get("id")
                                or item["license"]["name"]
                                for item in c.get("licenses", [])
                            )
                            or "license not specified in SBOM",
                        ]
                    )
                    for c in components
                ]
                native.append(f"{wheel} [{sbom}]\n" + "\n".join(sorted(rows)))

    if not inventory:
        raise ValueError("No SDK wheels found.")
    blocks = [header, "Bundled wheels:\n" + "\n".join(inventory)]
    for name, texts in sorted(notices.items()):
        blocks.append(
            f"=== {name} ===\n"
            + "\n\n".join(f"--- {file} ---\n{body}" for file, body in sorted(texts))
        )
    if native:
        blocks.append(
            "=== Native component disclosures (from wheel SBOMs where supplied) ===\n"
            + "\n\n".join(native)
        )
    for version in sorted(openssl_versions):
        license_text = (
            source_bytes(NOTICES / OPENSSL_LICENSES[version], commit)
            .decode("utf-8")
            .strip()
        )
        blocks.append(
            f"=== OpenSSL {version} (bundled in cryptography) ===\n" + license_text
        )
    if bundled_libffi:
        license_text = (
            source_bytes(NOTICES / "libffi-3.4.6.txt", commit).decode("utf-8").strip()
        )
        blocks.append("=== libffi (bundled in CFFI Linux wheels) ===\n" + license_text)
    for dist_name, notice in sorted(rust_notices.items()):
        blocks.append(f"=== {dist_name} Rust native license notices ===\n" + notice)
    return "\n\n".join(blocks) + "\n"


def validate(files: dict, project: Path) -> dict:
    project_data = tomllib.loads(
        (project / "pyproject.toml").read_text(encoding="utf-8")
    )
    manifest = json.loads(files["manifest.json"])
    required = {
        "appid": APP_ID,
        "main_module": "src.app:app",
        "app_version": project_data["project"]["version"],
        "python_version": "3.13",
        "min_phantom_version": "8.7.0",
        "supports_es_polling": True,
        "packaged_by": "splunk-soar-sdk 8.0.2",
    }
    for key, value in required.items():
        if manifest.get(key) != value:
            raise ValueError(
                f"Unexpected generated manifest {key}: {manifest.get(key)!r}"
            )
    if {key for key in manifest if re.fullmatch(r"pip\d+_dependencies", key)} != {
        "pip313_dependencies",
        "pip315_dependencies",
    } or manifest["pip315_dependencies"] != {"wheel": []}:
        raise ValueError("Only Python 3.13 may have packaged dependencies")
    actions = [action["identifier"] for action in manifest["actions"]]
    if actions != [
        "test_connectivity",
        "on_poll",
        "on_es_poll",
        "deny_quarantine_release",
        "release_quarantine_message",
        "inspect_release_environment",
    ]:
        raise ValueError(f"Unexpected SDK action order: {actions}")

    declared = set()
    entries = manifest["pip313_dependencies"]["wheel"]
    modules = [entry["module"] for entry in entries]
    if len(set(modules)) != len(entries) or not {
        "splunk-soar-sdk",
        "cryptography",
    }.issubset(modules):
        raise ValueError(
            "Missing SDK runtime dependency or duplicate module in manifest"
        )
    for entry in entries:
        for key in ("input_file", "input_file_aarch64"):
            path = entry[key]
            if not re.fullmatch(r"wheels/shared/[A-Za-z0-9_.-]+\.whl", path):
                raise ValueError(f"Invalid manifest wheel path: {path}")
            if not Path(path).name.startswith(entry["module"].replace("-", "_") + "-"):
                raise ValueError(f"Wheel module mismatch: {entry['module']} / {path}")
            declared.add(path)
    if declared != {name for name in files if name.endswith(".whl")}:
        raise ValueError("SDK archive wheels do not match the generated manifest")

    lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    hashes = {
        entry["url"].rsplit("/", 1)[-1]: entry["hash"]
        for package in lock["package"]
        for entry in package.get("wheels", [])
    }
    for path in declared:
        name = Path(path).name
        if name != LOCAL_WHEEL and hashes.get(name) != f"sha256:{sha(files[path])}":
            raise ValueError(f"SDK wheel does not match uv.lock: {name}")
    if f"wheels/shared/{LOCAL_WHEEL}" not in declared:
        raise ValueError("Review the allowlist for source-built SDK wheels")

    expected = {"LICENSE", "README.md", manifest["logo"], manifest["logo_dark"]}
    for directory in ("src", "templates", "release_notes"):
        expected.update(
            p.relative_to(project).as_posix()
            for p in (project / directory).rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and (directory != "src" or p.suffix == ".py")
        )
    if (
        set(files)
        - {"manifest.json", "NOTICE", "templates/base/base_template.html"}
        - declared
        != (expected - {"templates/base/base_template.html"})
        or "templates/base/base_template.html" not in files
    ):
        raise ValueError("Unexpected/missing SDK archive members")
    for name in expected:
        if files[name] != (project / name).read_bytes():
            raise ValueError(f"SDK archive differs from staged {name}")
    return manifest


def normalize_package(
    package: Path, output: Path, project: Path, epoch: int, commit: str | None = None
) -> None:
    files = files_of(package)
    manifest = validate(files, project)
    # The SDK writes wall-clock utctime_updated independently of SOURCE_DATE_EPOCH.
    manifest["utctime_updated"] = (
        datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")
    )
    files["manifest.json"] = (json.dumps(manifest, indent=4) + "\n").encode()
    path = f"wheels/shared/{LOCAL_WHEEL}"
    files[path] = normalize_local_wheel(files[path])
    files["NOTICE"] = render_notice(files, commit).encode()

    dirs = {APP}
    for name in files:
        dirs.update(
            str(parent)
            for parent in PurePosixPath(f"{APP}/{name}").parents
            if parent.parts
        )
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as target,
    ):
        for name in sorted(dirs):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode, member.mtime = 0o755, epoch
            target.addfile(member)
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(f"{APP}/{name}")
            member.mode, member.mtime, member.size = 0o644, epoch, len(data)
            target.addfile(member, io.BytesIO(data))
    if files_of(output) != files:
        raise ValueError("Packaged file bytes do not match verified SDK payload.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--package-output", action="store_true")
    parser.add_argument("--project", type=Path)
    parser.add_argument("--epoch", type=int)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    if args.package_output:
        if args.project is None or args.epoch is None:
            parser.error("--package-output requires --project and --epoch")
        normalize_package(
            args.package, args.output, args.project, args.epoch, args.source_commit
        )
    else:
        args.output.write_text(render_notice(files_of(args.package)), encoding="utf-8")


if __name__ == "__main__":
    main()
