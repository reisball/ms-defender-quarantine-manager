#!/usr/bin/env python3
"""Render distribution notices from the hash-locked runtime wheels."""
import argparse
from email import message_from_bytes
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def license_text(data):
    # Keep the legal text intact while normalizing trailing whitespace.
    return "\n".join(line.rstrip() for line in data.decode("utf-8").splitlines()).rstrip()


def render(app, lock):
    blocks = [
        "MS Defender Quarantine Manager\nCopyright 2026 Kai Seidenschnur",
        "Third-party notices for the bundled SOAR runtime wheels (both Python versions).",
    ]
    for relative, entry in sorted(lock["wheels"].items()):
        wheel = app / relative
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"Wheel SHA-256 mismatch: {relative}")
        with ZipFile(wheel) as archive:
            metadata_path, = (name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            prefix = metadata_path.removesuffix("METADATA")
            metadata = message_from_bytes(archive.read(metadata_path))
            paths = [
                name for name in archive.namelist()
                if name.startswith(prefix) and re.fullmatch(
                    r"(?:licenses/)?(?:LICENSE|COPYING|NOTICE|AUTHORS)(?:[._-][^/]+)?",
                    name[len(prefix):], re.IGNORECASE
                )
            ]
            if not paths:
                raise ValueError(f"No license texts in {relative}")
            license_name = metadata["License-Expression"] or metadata["License"] or "See license text"
            blocks.append(
                f"=== {metadata['Name']} {metadata['Version']} ===\n"
                f"Wheel: {relative}\nSource: {entry['url']}\nLicense: {license_name}"
            )
            for name in sorted(paths):
                blocks.append(f"--- {name[len(prefix):]} ---\n" + license_text(archive.read(name)))

    for source in lock.get("native_notices", []):
        notice = ROOT / "tools/soar-tooling/notices" / source["file"]
        data = notice.read_bytes()
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError(f"Native notice SHA-256 mismatch: {notice.name}")
        build_sources = "".join(f"Build source: {url}\n" for url in source.get("build_sources", []))
        blocks.append(f"=== {source['component']} ===\nSource: {source['url']}\n" + build_sources + license_text(data))
    return ("\n\n".join(blocks) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    app = ROOT / "app"
    lock = json.loads((ROOT / "tools/wheel-lock.json").read_bytes())
    output = render(app, lock)
    notice = app / "NOTICE"
    if args.check:
        if not notice.exists() or notice.read_bytes() != output:
            parser.exit(1, "app/NOTICE is out of date; run python tools/render_notice.py\n")
    else:
        notice.write_bytes(output)


if __name__ == "__main__":
    main()
