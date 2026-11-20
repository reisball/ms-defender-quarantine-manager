"""Distributable-help contracts: offline, no SOAR/Azure calls."""
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = ROOT / "app"


def generator():
    spec = importlib.util.spec_from_file_location("ms_quarantine_for_splunk_soar_render_help", ROOT / "tools/render_readme.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HelpParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.forbidden = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe", "object", "embed"}:
            self.forbidden.append(tag)
        for key, value in attrs:
            if key in {"href", "src"}:
                self.links.append(value)
            if key.lower().startswith("on"):
                self.forbidden.append(key)

    def handle_data(self, data):
        self.text.append(data)


def test_shipped_help_matches_current_manifest_and_required_fields():
    manifest = json.loads((APP_DIR / "ms_quarantine_for_splunk_soar.json").read_text())
    help_text = (APP_DIR / "readme.html").read_text()
    assert help_text == generator().render(manifest)
    parsed = HelpParser()
    parsed.feed(help_text)
    prose = " ".join(parsed.text)
    assert manifest["app_version"] in prose
    assert manifest["publisher"] in prose
    for key in manifest["configuration"]:
        assert key in prose
    for action in manifest["actions"]:
        assert action["action"] in prose
        for param, spec in action.get("parameters", {}).items():
            assert param in prose
            for choice in spec.get("value_list", []):
                assert str(choice) in prose
    assert not parsed.forbidden


def test_installed_help_has_no_unshipped_local_dependencies():
    parser = HelpParser()
    parser.feed((APP_DIR / "readme.html").read_text())
    for link in parser.links:
        if link.startswith(("https://", "#")):
            continue
        assert link == "LICENSE", link
        assert (ROOT / link).is_file()


def test_help_check_detects_missing_or_stale_file(tmp_path, monkeypatch):
    mod = generator()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["render_readme.py", "--check"])
    source = APP_DIR / "ms_quarantine_for_splunk_soar.json"
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / source.name).write_bytes(source.read_bytes())
    try:
        mod.main()
    except SystemExit as result:
        assert result.code == 2
    else:
        raise AssertionError("Missing installed help was not rejected")
    (tmp_path / "app" / "readme.html").write_text("obsolete help")
    try:
        mod.main()
    except SystemExit as result:
        assert result.code == 2
    else:
        raise AssertionError("Stale installed help was not rejected")


def test_installed_parameter_help_no_longer_directs_removed_action():
    manifest = json.loads((APP_DIR / "ms_quarantine_for_splunk_soar.json").read_text())
    for identifier in ["release_quarantine_message", "deny_quarantine_release"]:
        action = next(a for a in manifest["actions"] if a["identifier"] == identifier)
        assert "list quarantine requests" not in action["parameters"]["identity"]["description"]
        assert "container:data.quarantine_identity" in action["parameters"]["identity"]["description"]
        assert "ready artifact" not in action["parameters"]["identity"]["description"]
        assert "operation_id" not in action["parameters"]


def test_regenerated_help_escapes_manifest_prose():
    manifest = json.loads((APP_DIR / "ms_quarantine_for_splunk_soar.json").read_text())
    manifest["publisher"] = '<script>not executable</script> & "quoted"'
    rendered = generator().render(manifest)
    parsed = HelpParser()
    parsed.feed(rendered)
    assert not parsed.forbidden
    assert manifest["publisher"] in "".join(parsed.text)


def test_help_explains_automatic_files_and_no_legacy_ui_controls():
    manifest = json.loads((APP_DIR / "ms_quarantine_for_splunk_soar.json").read_text())
    rendered = generator().render(manifest)
    parsed = HelpParser()
    parsed.feed(rendered)
    prose = " ".join(parsed.text)
    assert "Original email and attachments are saved automatically" in prose
    assert "exactly one email artifact" in prose
    assert "separate-field SOAR layout" in prose
    assert "These fields have no selection controls" in prose
    assert "container:data.quarantine_identity" in prose
    assert "Purpose and validation status" not in prose
    assert "artifacts/ms_quarantine_for_splunk_soar-" not in prose
    assert "legacy worker-update callbacks" not in prose
    assert "enable_on_poll_ingestion" not in prose
    assert "update quarantine work item" not in prose
    for group in ("Connection", "Email import", "Mail fields", "Advanced"):
        assert group in prose


def test_new_product_identity_and_packaged_entrypoints():
    from uuid import UUID
    manifest = json.loads((APP_DIR / "ms_quarantine_for_splunk_soar.json").read_text())
    assert manifest["name"] == "MS Quarantine for Splunk SOAR"
    assert manifest["package_name"] == "phantom_ms_quarantine_for_splunk_soar"
    assert UUID(manifest["appid"]).version == 4
    assert len(manifest["app_version"].split(".")) == 3
    assert all(part.isdigit() for part in manifest["app_version"].split("."))
    for field in ("main_module", "logo", "logo_dark"):
        assert manifest[field].startswith("ms_quarantine_for_splunk_soar")
        assert (APP_DIR / manifest[field]).is_file()
