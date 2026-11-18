"""Outer-message MIME body regressions, synthetic input only."""
from email.message import EmailMessage
import pytest

if __package__:
    from . import test_connector as t
else:
    import test_connector as t
from ms_quarantine_for_splunk_soar_es_ingestion import build_finding


def finding(mail):
    uploads = []
    def upload(name, content):
        uploads.append((name, content))
        return "synthetic-vault"
    result = build_finding({}, mail.as_bytes(), t.IDENTITY, "work", "source",
                           {"es_security_domain": "threat"}, upload,
                           "https://soar.example.test")
    assert uploads[0][1] == mail.as_bytes()
    return result["email"]["body"]


@pytest.mark.parametrize("kind", ["attachment", "filename", "attached_message", "attached_multipart"])
def test_attachment_or_descendant_never_becomes_outer_body(kind):
    mail = EmailMessage()
    mail["Subject"] = "Outer"
    mail.make_mixed()
    decoy = EmailMessage()
    decoy.set_content("DECOY attachment text")
    if kind == "attachment":
        decoy["Content-Disposition"] = "attachment"
    elif kind == "filename":
        decoy.set_param("name", "text.txt", header="Content-Type")
    elif kind == "attached_message":
        wrapper = EmailMessage()
        wrapper.add_attachment(decoy)
        decoy = wrapper.get_payload()[0]
    else:
        wrapper = EmailMessage()
        wrapper.make_mixed()
        wrapper["Content-Disposition"] = "attachment"
        wrapper.attach(decoy)
        decoy = wrapper
    mail.attach(decoy)
    body = EmailMessage()
    body.set_content("REAL outer body")
    mail.attach(body)
    assert finding(mail).strip() == "REAL outer body"


def test_plain_alternative_preferred_to_html():
    mail = EmailMessage()
    mail["Subject"] = "Alternative"
    mail.set_content("<p>HTML</p>", subtype="html")
    mail.add_alternative("PLAIN", subtype="plain")
    assert finding(mail).strip() == "PLAIN"


def test_related_uses_declared_root_not_text_resource():
    mail = EmailMessage()
    mail["Subject"] = "Related"
    mail.make_related()
    resource = EmailMessage()
    resource.set_content("RESOURCE")
    resource["Content-ID"] = "<resource>"
    body = EmailMessage()
    body.set_content("<p>REAL HTML</p>", subtype="html")
    body["Content-ID"] = "<body>"
    mail.attach(resource)
    mail.attach(body)
    mail.set_param("start", "<body>")
    assert finding(mail).strip() == "<p>REAL HTML</p>"


def test_attachment_only_mail_has_empty_body():
    mail = EmailMessage()
    mail["Subject"] = "Attachment only"
    mail.set_content("DECOY")
    mail["Content-Disposition"] = "attachment"
    assert finding(mail) == ""
