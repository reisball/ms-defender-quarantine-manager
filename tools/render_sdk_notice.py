#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Emit the notices of the exact wheels selected by the SDK packager."""

import argparse
import hashlib
import io
import re
import tarfile
from email import message_from_bytes
from pathlib import Path
from zipfile import ZipFile

COPYING = re.compile(r"(?:LICEN[CS]E|COPYING|NOTICE|AUTHORS)(?:[._-].*)?", re.I)


def render(package: Path) -> str:
    header = "MS Defender Quarantine Manager\nThird-party notices for the bundled SDK wheels."
    notices = {}
    inventory = []
    with tarfile.open(package, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if not member.isfile() or not member.name.endswith(".whl"):
                continue
            data = archive.extractfile(member).read()
            wheel = Path(member.name).name
            digest = hashlib.sha256(data).hexdigest()
            inventory.append(f"{wheel}: sha256:{digest}")
            with ZipFile(io.BytesIO(data)) as contents:
                (metadata_path,) = (
                    n
                    for n in contents.namelist()
                    if n.endswith(".dist-info/METADATA") and n.count("/") == 1
                )
                meta = message_from_bytes(contents.read(metadata_path))
                texts = tuple(
                    (n, contents.read(n).decode("utf-8").strip())
                    for n in sorted(contents.namelist())
                    if not n.endswith("/") and COPYING.fullmatch(Path(n).name)
                )
                if not texts:
                    raise ValueError(f"No bundled license text in {wheel}")
                name = f"{meta['Name']} {meta['Version']}"
                for path, content in texts:
                    notices.setdefault(name, {})[(Path(path).name, content)] = None
    if not inventory:
        raise ValueError("No SDK wheels found.")
    blocks = [header, "Bundled wheels:\n" + "\n".join(inventory)]
    for name, texts in sorted(notices.items()):
        blocks.append(
            f"=== {name} ===\n"
            + "\n\n".join(f"--- {file} ---\n{body}" for file, body in sorted(texts))
        )
    return "\n\n".join(blocks) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--package-output", action="store_true")
    args = parser.parse_args()
    notice = render(args.package)
    if not args.package_output:
        args.output.write_text(notice, encoding="utf-8")
        return

    data = notice.encode("utf-8")
    with (
        tarfile.open(args.package, "r:gz") as source,
        tarfile.open(args.output, "w:gz") as target,
    ):
        manifests = [
            m
            for m in source.getmembers()
            if m.name.count("/") == 1 and m.name.endswith("/manifest.json")
        ]
        (manifest,) = manifests
        name = manifest.name.removesuffix("manifest.json") + "NOTICE"
        for member in source.getmembers():
            if member.name != name:
                target.addfile(
                    member, source.extractfile(member) if member.isfile() else None
                )
        record = tarfile.TarInfo(name)
        record.mode = 0o644
        record.size = len(data)
        target.addfile(record, io.BytesIO(data))
    with tarfile.open(args.output, "r:gz") as archive:
        if archive.extractfile(name).read() != data or render(args.output) != notice:
            raise ValueError("Packaged NOTICE does not match the bundled wheels.")


if __name__ == "__main__":
    main()
