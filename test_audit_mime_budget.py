"""Bound the tree during parsing, with exact same-runtime MIME semantics."""
from email import policy
from email.feedparser import FeedParser
from email.parser import BytesParser
import pytest

if __package__:
    from .test_native_ingestion import sample_mail, ES, candidate, setup, poll
    from .test_ingestion_review_guards import deep_mail
    from .test_audit_mime_attachments import attached_fixture
else:
    from test_native_ingestion import sample_mail, ES, candidate, setup, poll
    from test_ingestion_review_guards import deep_mail
    from test_audit_mime_attachments import attached_fixture
from ms_quarantine_for_splunk_soar_ingestion import (
    mail_files, MAX_MIME_PARTS, MAX_MIME_DEPTH, _BoundedMimeParser,
    _mail_files_from_parsed,
)
from ms_quarantine_for_splunk_soar_es_ingestion import build_finding
from ms_quarantine_for_splunk_soar_utils import AutomationError


def instrument(monkeypatch):
    observed = []
    original = FeedParser._new_message
    def counted(self):
        observed.append(len(self._msgstack))
        return original(self)
    monkeypatch.setattr(FeedParser, "_new_message", counted)
    return observed


def wide_fixture(count):
    return (b"Subject: wide\nContent-Type: multipart/mixed; boundary=x\n\n"
            + b"--x\nContent-Type: text/plain\n\nz\n" * count + b"--x--\n")


@pytest.mark.parametrize("eml", [wide_fixture(5000), deep_mail(31)], ids=["wide", "deep"])
def test_forbidden_nodes_are_not_constructed(monkeypatch, eml):
    observed = instrument(monkeypatch)
    with pytest.raises(AutomationError, match="MIME structure limits"):
        mail_files(eml)
    assert len(observed) <= MAX_MIME_PARTS
    assert max(observed) <= MAX_MIME_DEPTH


def test_es_standalone_keeps_immutable_input_contract():
    with pytest.raises(AutomationError, match="Missing or oversized EML"):
        build_finding(candidate(1), bytearray(sample_mail()), candidate(1)["Identity"],
                      "work", "source", ES, lambda name, data: name, "https://soar.test")


def test_public_es_projection_builds_only_one_tree(monkeypatch):
    eml = sample_mail()
    expected_count = len(list(BytesParser(policy=policy.default).parsebytes(eml).walk()))
    observed = instrument(monkeypatch)
    finding = build_finding(candidate(1), eml, candidate(1)["Identity"],
                            "work", "source", ES, lambda name, data: name, "https://soar.test")
    assert len(observed) == expected_count
    assert finding["email"]["body"].strip() == "Synthetic body"
    assert len(finding["email"]["attachments"]) == 3


@pytest.mark.parametrize("chunk", [1, 7, 8192])
@pytest.mark.parametrize("fixture", [sample_mail, attached_fixture, lambda: attached_fixture("multipart"),
                                    lambda: deep_mail(30), lambda: wide_fixture(199)],
                         ids=["ordinary", "global", "multipart-attachment", "deep-boundary", "wide-boundary"])
def test_chunked_parser_keeps_standard_policy_bytes_and_defects(chunk, fixture):
    eml = fixture()
    reference = BytesParser(policy=policy.default).parsebytes(eml)
    parser = _BoundedMimeParser()
    for offset in range(0, len(eml), chunk):
        parser.feed(eml[offset:offset + chunk])
    actual = parser.close()
    assert actual.as_bytes(policy=policy.default) == reference.as_bytes(policy=policy.default)
    assert [[type(d) for d in part.defects] for part in actual.walk()] == [
        [type(d) for d in part.defects] for part in reference.walk()]
    assert _mail_files_from_parsed(actual) == _mail_files_from_parsed(reference)


@pytest.mark.parametrize("target", ["soar", "es"])
def test_structure_rejection_retains_slot_without_side_effects(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    c.eml = wide_fixture(5000)
    _, ar = poll(c)
    assert ar.get_summary()["active_messages"] == 1
    row = next(iter(c._ingest_records().values()))
    assert row["phase"] == "blocked"
    assert not c.events
    assert len([call for call in c.calls if call[0] == "export"]) == 1
    poll(c)
    assert len([call for call in c.calls if call[0] == "export"]) == 1
    assert not c.events
