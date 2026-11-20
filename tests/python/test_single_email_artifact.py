"""Issue #5: one complete native combined artifact, using synthetic backends."""
from email.message import EmailMessage

import pytest

from test_native_ingestion import setup, poll, t


def optional_fields_off():
    return {key: False for key in t.ARTIFACT_FIELD_CONFIG_KEYS.values()}


@pytest.mark.parametrize("attachments", [False, True])
@pytest.mark.parametrize("legacy_required_fields", [False, True])
def test_combined_import_publishes_one_artifact_after_vault(
        tmp_path, attachments, legacy_required_fields):
    config = optional_fields_off()
    for field in ("sender_address", "recipient_address", "vault_id"):
        config["artifact_field_" + field] = legacy_required_fields
    c = setup(tmp_path, limit=1, config_overrides=config)
    if not attachments:
        mail = EmailMessage()
        mail["Subject"] = "Subject without selected display fields"
        mail["Sender"] = "rfc-sender@example.test"
        mail["Delivered-To"] = "rfc-recipient@example.test"
        mail.set_content("Body")
        c.eml = mail.as_bytes()
    c.candidates[0]["SenderAddress"] = "microsoft-sender@example.test"
    c.candidates[0]["RecipientAddress"] = "microsoft-recipient@example.test"
    t.VAULT_ADDS.clear()
    original = c.save_artifact
    def publish(artifact):
        assert len(t.VAULT_ADDS) == (3 if attachments else 1)
        assert t.VAULT_ADDS[0]["content"] == c.eml
        assert artifact["run_automation"] is True
        return original(artifact)
    c.save_artifact = publish
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(c._saved_containers) == 1
    container = c._saved_containers[0]["container"]
    assert container["artifacts"] == []
    assert container["run_automation"] is False
    assert container["data"]["quarantine_identity"] == c.candidates[0]["Identity"]
    assert len(c.artifacts) == 1
    artifact = next(iter(c.artifacts.values()))
    row = next(iter(c._ingest_records().values()))
    assert artifact["cef"] == {
        "vaultId": t.VAULT_ADDS[0]["vault_id"],
        "senderAddress": "microsoft-sender@example.test",
        "recipientAddress": "microsoft-recipient@example.test",
    }
    assert artifact["name"] == ("Synthetic quarantine" if attachments
                                else "Subject without selected display fields")
    assert row["email_artifact_id"]
    assert "ready_artifact_id" not in row
    assert row["missing_artifact_fields"] == []
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c.artifacts) == 1
    assert len(t.VAULT_ADDS) == (3 if attachments else 1)
    assert [event[0] for event in c.events].count("publish") == 1


def test_selected_optional_fields_extend_same_artifact_without_overwriting_context(tmp_path):
    config = optional_fields_off()
    config.update(artifact_field_from=True, artifact_field_quarantine_identity=True,
                  artifact_field_received_date=True)
    c = setup(tmp_path, limit=1, config_overrides=config)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(c.artifacts) == 1
    cef = next(iter(c.artifacts.values()))["cef"]
    assert cef["fromEmail"] == "sender@example.test"
    assert cef["quarantineIdentity"] == c.candidates[0]["Identity"]
    assert cef["senderAddress"] == c.candidates[0]["SenderAddress"]
    assert cef["recipientAddress"] == c.candidates[0]["RecipientAddress"]
    assert "emailSubject" not in cef
    assert not {"workItemId", "ingestionReady", "attachmentCount", "isOriginalEmail"} & cef.keys()
    assert next(iter(c._ingest_records().values()))["missing_artifact_fields"] == ["received_date"]


def test_missing_optional_headers_still_publish_required_fields_with_subject_fallback(tmp_path):
    c = setup(tmp_path, limit=1)
    mail = EmailMessage()
    mail["X-Test"] = "No selectable headers"
    mail.set_content("Body")
    c.eml = mail.as_bytes()
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    artifact = next(iter(c.artifacts.values()))
    assert len(c.artifacts) == 1
    assert artifact["name"] == "No subject"
    assert set(artifact["cef"]) == {"vaultId", "senderAddress", "recipientAddress"}


def test_partial_vault_failure_never_creates_email_artifact_or_starts_automation(tmp_path):
    c = setup(tmp_path, limit=1)
    store = c._store_in_vault
    calls = []
    def fail_attachment(content, *args, **kwargs):
        calls.append(content)
        if len(calls) == 2:
            return False, "Synthetic attachment upload failure"
        return store(content, *args, **kwargs)
    c._store_in_vault = fail_attachment
    assert poll(c)[0] == t.APP_ERROR
    assert c._saved_containers[0]["container"]["artifacts"] == []
    assert not c.artifacts
    assert not any(event[0] == "publish" for event in c.events)
    c._store_in_vault = store
    assert poll(c)[0] == t.APP_SUCCESS
    assert not c.artifacts
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == len(c.artifacts) == 1


def test_definite_publication_rejection_requires_fresh_explicit_attempt(tmp_path):
    c = setup(tmp_path, limit=1)
    original = c.save_artifact
    c.save_artifact = lambda artifact: (t.APP_ERROR, "Synthetic rejection", None)
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    assert "email_artifact" not in row
    assert "files" not in row
    c.save_artifact = original
    exports = sum(action == "export" for action, _, _ in c.calls)
    assert poll(c)[0] == t.APP_SUCCESS
    assert not c.artifacts
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert sum(action == "export" for action, _, _ in c.calls) == exports + 1
    assert len(c.artifacts) == 1


def test_separate_layout_retains_existing_artifact_contract(tmp_path):
    c = setup(tmp_path, limit=1, config_overrides={"artifact_layout": "separate"})
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert c._saved_containers[0]["container"]["artifacts"][0]["name"] == "Quarantine release request"
    assert len([a for a in c.artifacts.values() if "isOriginalEmail" in a["cef"]]) == 3
    ready = [a for a in c.artifacts.values() if a["run_automation"]]
    assert len(ready) == 1
    assert ready[0]["cef"]["ingestionReady"] is True
    assert next(iter(c._ingest_records().values()))["ready_artifact_id"]
