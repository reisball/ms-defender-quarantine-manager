"""Missing MIME containers are appended without renumbering old Vault files."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
from unittest.mock import Mock

import pytest
if __package__:
    from .test_native_ingestion import setup, candidate, sample_mail
else:
    from test_native_ingestion import setup, candidate, sample_mail
from ms_quarantine_for_splunk_soar_ingestion import mail_files
from ms_quarantine_for_splunk_soar_utils import AutomationError


def attached_fixture(kind="global"):
    outer = EmailMessage()
    outer["Subject"] = "outer"
    outer.set_content("ordinary outer body")
    outer.add_attachment(b"BEFORE", maintype="application", subtype="octet-stream", filename="before.bin")
    child = EmailMessage()
    child["Subject"] = "Grüße"
    child.set_content("embedded body")
    child.add_attachment(b"INNER", maintype="application", subtype="octet-stream", filename="inner.bin")
    if kind == "global":
        wrapper = EmailMessage()
        wrapper.set_type("message/global")
        wrapper["Content-Disposition"] = 'attachment; filename="international.eml"'
        wrapper.set_payload([child])
    else:
        wrapper = child
        wrapper["Content-Disposition"] = 'attachment; filename="bundle.mime"'
    outer.attach(wrapper)
    outer.add_attachment(b"AFTER", maintype="application", subtype="octet-stream", filename="after.bin")
    return outer.as_bytes()


OLD_FILES = [("001_before.bin", b"BEFORE"), ("002_inner.bin", b"INNER"), ("003_after.bin", b"AFTER")]


@pytest.mark.parametrize("kind", ["global", "multipart"])
def test_missing_containers_follow_unchanged_legacy_files(kind):
    eml = attached_fixture(kind)
    files = mail_files(eml)
    assert files[:3] == OLD_FILES
    assert len(files) == 4
    assert files[3][0] == ("004_international.eml" if kind == "global" else "004_bundle.mime")
    part = BytesParser(policy=policy.default).parsebytes(eml).get_payload()[2]
    expected = (part.get_payload()[0] if kind == "global" else part).as_bytes(policy=policy.default)
    assert files[3][1] == expected


@pytest.mark.parametrize("count", [99, 100])
def test_new_container_obeys_existing_total_attachment_limit(count):
    outer = EmailMessage()
    outer["Subject"] = "bounded"
    outer.set_content("body")
    for index in range(count):
        outer.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=str(index))
    inner = EmailMessage()
    inner["Subject"] = "attached"
    inner.set_content("inner")
    wrapper = EmailMessage()
    wrapper.set_type("message/global")
    wrapper["Content-Disposition"] = 'attachment; filename="grüße.eml"'
    wrapper.set_payload([inner])
    outer.attach(wrapper)
    if count == 99:
        files = mail_files(outer.as_bytes())
        assert len(files) == 100
        assert files[-1][0] == "100_grüße.eml"
    else:
        with pytest.raises(AutomationError, match="attachment count"):
            mail_files(outer.as_bytes())


def test_normal_multipart_body_does_not_become_an_attachment():
    assert mail_files(sample_mail()) == [
        ("001_same.bin", b"ATTACHMENT ONE"), ("002_same.bin", b"ATTACHMENT TWO"),
    ]


@pytest.mark.parametrize("kind", ["global", "multipart"])
def test_containers_nested_in_rfc822_are_not_extracted_twice(kind):
    child = BytesParser(policy=policy.default).parsebytes(attached_fixture(kind))
    outer = EmailMessage()
    outer["Subject"] = "outermost"
    outer.set_content("outermost body")
    outer.add_attachment(child)
    files = mail_files(outer.as_bytes())
    assert len(files) == 1
    assert files[0][1] == child.as_bytes(policy=policy.default)


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("kind", ["global", "multipart"])
def test_partial_legacy_vault_map_survives_restart(tmp_path, target, kind):
    eml = attached_fixture(kind)
    c = setup(tmp_path, target)
    c._ingest_settings()
    c._ingest_reserve([candidate(1)], 10, 1)
    key, row = next(iter(c._ingest_records().items()))
    original = c._safe_filename(row["identity"])
    old_files = [(original, eml)] + OLD_FILES
    vaults = {str(i): {"vault_id": "legacy-" + str(i), "file_name": name,
                       "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
              for i, (name, content) in enumerate(old_files)}
    c._ingest_update(key, phase="preparing", container_id=77, files=vaults,
                     eml_sha256=hashlib.sha256(eml).hexdigest())
    resumed = setup(tmp_path, target)
    resumed.eml = eml
    resumed._ingest_settings()
    resumed._store_in_vault = Mock(return_value=(True, {"vault_id": "new-container-file"}))
    prepared = resumed._ingest_prepare(key, resumed._ingest_records()[key])
    assert prepared["phase"] == "ready"
    assert prepared["attachment_count"] == 4
    assert {key: prepared["files"][key] for key in vaults} == vaults
    assert prepared["files"]["4"]["vault_id"] == "new-container-file"
    assert resumed._store_in_vault.call_count == 1
    assert not any(event[0] in {"container", "publish", "es_publish"} for event in resumed.events)
