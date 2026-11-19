"""MIME extraction order and complete native Vault publication."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest
if __package__:
    from .test_native_ingestion import setup, poll, t, sample_mail
else:
    from test_native_ingestion import setup, poll, t, sample_mail
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
def test_all_mime_containers_reach_vault_before_synchronous_publication(tmp_path, target, kind):
    c = setup(tmp_path, target, limit=1)
    c.eml = attached_fixture(kind)
    t.VAULT_ADDS.clear()
    expected = [(c._safe_filename(c.candidates[0]["Identity"].lower()), c.eml)] + mail_files(c.eml)

    def assert_complete():
        assert [(v["file_name"], v["content"]) for v in t.VAULT_ADDS] == expected
        assert len({v["container"] for v in t.VAULT_ADDS}) == 1

    if target == "es":
        def publish(method, path, **kwargs):
            assert_complete()
            assert (method, path) == ("POST", "/rest/enterprise_security/findings/bulk_create")
            payload = kwargs["json"]
            assert len(payload["findings"][0]["email"]["attachments"]) == len(expected)
            return {"status": "success", "created": 1, "failed": 0, "errors": [],
                    "container_ids": payload["container_ids"], "findings": ["mime-finding"]}
        c._ingest_es_client_instance.request.side_effect = publish
    else:
        save = c.save_artifact
        def publish(artifact):
            if artifact["run_automation"]:
                assert_complete()
            return save(artifact)
        c.save_artifact = publish

    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert_complete()
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "completed"
    assert "files" not in row
    # Restart deduplicates completion; it does not resume old file checkpoints.
    restarted = setup(tmp_path, target, limit=1)
    assert poll(restarted)[0] == t.APP_SUCCESS
    assert not restarted.events
    assert_complete()
