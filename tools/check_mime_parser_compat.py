#!/usr/bin/env python3
# Copyright (c) 2026 Kai Seidenschnur
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Stdlib-only MIME compatibility probe; stubs unrelated SOAR imports, no network.

Run with each supported Python. --benchmark baseline|bounded measures the same
50,000-part input in a fresh process; peak RSS includes interpreter/import costs.
"""

import argparse
import hashlib
import json
import resource
import sys
import time
import types
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path


def load_parser():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    # These synthetic modules deliberately supply only the members this probe needs.
    phantom = types.ModuleType("phantom")
    phantom.app = types.ModuleType("phantom.app")
    action_result = types.ModuleType("phantom.action_result")
    action_result.ActionResult = object
    sys.modules.update({"phantom": phantom, "phantom.app": phantom.app, "phantom.action_result": action_result})  # pylint: disable=no-member
    utils = types.ModuleType("ms_quarantine_for_splunk_soar_utils")
    utils.AutomationError = type("AutomationError", (Exception,), {})
    utils.OversizedExportError = type("OversizedExportError", (utils.AutomationError,), {})  # pylint: disable=no-member
    utils.MAX_DECODED_EML_BYTES = 24 * 1024 * 1024
    sys.modules[utils.__name__] = utils  # pylint: disable=no-member
    import ms_quarantine_for_splunk_soar_ingestion

    return ms_quarantine_for_splunk_soar_ingestion


def wide(n):
    return (
        b"Subject: wide\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        + b"--x\r\nContent-Type: text/plain\r\n\r\nz\r\n" * n
        + b"--x--\r\n"
    )


def deep(n):
    root = current = EmailMessage()
    root["Subject"] = "deep"
    for _ in range(n):
        current.make_mixed()
        child = EmailMessage()
        current.attach(child)
        current = child
    current.set_content("leaf")
    return root.as_bytes()


def corpus():
    root = EmailMessage()
    root["Subject"] = "Grüße"
    root["Received"] = "first"
    root["Received"] = "second"
    root.set_content("outer body")
    root.add_attachment(b"\x00\xffbinary", maintype="application", subtype="octet-stream", filename="ä.bin")
    result = [root.as_bytes(), wide(199), deep(30)]
    for subtype in ("rfc822", "global"):
        attached = EmailMessage()
        attached["Subject"] = "attached"
        attached.set_content("nested")
        wrapper = EmailMessage()
        wrapper.set_type("message/" + subtype)
        wrapper.set_payload([attached])
        wrapper["Content-Disposition"] = 'attachment; filename="nested.eml"'
        root.attach(wrapper)
        result.append(root.as_bytes())
    result.extend(
        [
            b"Subject: split\r\nX-Long: " + b"x" * 8200 + b"\r\n folded\r\n\r\n" + "Grüße".encode(),
            b"Subject: digest\nContent-Type: multipart/digest; boundary=d\n\n--d\n\nSubject: nested\n\nbody\n--d--\n",
            b"Subject: report\nContent-Type: message/delivery-status\n\nReporting-MTA: dns; test\n\nAction: failed\n",
        ]
    )
    return result


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--benchmark", choices=["baseline", "bounded"])
    mode = args.parse_args().benchmark
    m = load_parser()
    if mode:
        data = wide(50000)
        start = time.perf_counter()
        nodes = 0
        if mode == "baseline":
            mail = BytesParser(policy=policy.default).parsebytes(data)
            nodes = sum(1 for _ in mail.walk())
        else:
            parser = m._BoundedMimeParser()
            try:
                for offset in range(0, len(data), 8192):
                    parser.feed(data[offset : offset + 8192])
                parser.close()
            except m.AutomationError:
                pass
            nodes = parser._created_parts
            assert nodes == 200
        print(
            json.dumps(
                {
                    "python": sys.version.split()[0],
                    "mode": mode,
                    "fixture_bytes": len(data),
                    "constructed_nodes": nodes,
                    "elapsed_seconds": time.perf_counter() - start,
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                }
            )
        )
        return
    checks = 0
    for data in corpus():
        reference = BytesParser(policy=policy.default).parsebytes(data)
        for chunk in (1, 7, 8192):
            parser = m._BoundedMimeParser()
            for offset in range(0, len(data), chunk):
                parser.feed(data[offset : offset + chunk])
            actual = parser.close()
            assert actual.as_bytes(policy=policy.default) == reference.as_bytes(policy=policy.default)
            assert [[type(d).__name__ for d in p.defects] for p in actual.walk()] == [
                [type(d).__name__ for d in p.defects] for p in reference.walk()
            ]
            try:
                expected_files = m._mail_files_from_parsed(reference)
            except m.AutomationError:
                try:
                    m._mail_files_from_parsed(actual)
                except m.AutomationError:
                    pass
                else:
                    raise AssertionError("Defect acceptance changed")
            else:
                assert m._mail_files_from_parsed(actual) == expected_files
            checks += 1
    for data in (wide(200), deep(31)):
        parser = m._BoundedMimeParser()
        try:
            parser.feed(data)
            parser.close()
        except m.AutomationError:
            assert parser._created_parts <= 200
            assert len(parser._msgstack) <= 31
        else:
            raise AssertionError("Oversized MIME structure accepted")
        checks += 1
    print(
        json.dumps(
            {
                "python": sys.version.split()[0],
                "checks": checks,
                "status": "passed",
                "source_sha256": hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
