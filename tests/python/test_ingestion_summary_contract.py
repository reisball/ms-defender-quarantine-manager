"""Compare real handler summaries with the public manifest, using synthetic IO."""
import json
from pathlib import Path

import pytest

if __package__:
    from . import test_native_ingestion as native
else:
    import test_native_ingestion as native

t = native.t
POLL_ACTIONS = [("on_poll", "soar"), ("on_poll", "es"), ("on_es_poll", "es")]
POLL_KEYS = {
    "candidates", "containers_created", "messages_published", "ingestion_enabled",
    "active_messages", "active_limit", "ingest_target", "requested_containers",
    "terminal_observed", "errors", "candidate_window", "results_may_be_truncated", "failed_imports",
}


def check_summary(identifier, ar, expected_keys):
    manifest = json.loads((Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text())
    action = next(a for a in manifest["actions"] if a["identifier"] == identifier)
    fields = {o["data_path"]: o["data_type"] for o in action["output"]}
    assert len(fields) == len(action["output"]), "Duplicate output declarations"
    summary = ar.get_summary()
    assert set(summary) == expected_keys
    for key, value in summary.items():
        declared = fields["action_result.summary." + key]
        # bool is an int subclass; a numeric counter must not accept bool.
        assert type(value) in {
            "numeric": (int, float), "boolean": (bool,), "string": (str,)
        }[declared], (key, value, declared)
    return summary


def invoke(c, identifier, param=None):
    ar = t.patch_ar(c)
    c._action_id = identifier
    return c.handle_action(param or {}), ar


@pytest.mark.parametrize("identifier,target", POLL_ACTIONS)
def test_poll_success_and_terminal_readback(tmp_path, identifier, target):
    c = native.setup(tmp_path, target, limit=2)
    status, ar = invoke(c, identifier)
    assert status == t.APP_SUCCESS, ar.get_message()
    summary = check_summary(identifier, ar, POLL_KEYS)
    assert summary["messages_published"] == summary["containers_created"] == 2
    assert summary["active_messages"] == summary["active_limit"] == 2
    assert summary["ingest_target"] == target
    assert summary["ingestion_enabled"] is True
    assert summary["errors"] == summary["terminal_observed"] == 0
    identity = next(iter(c._ingest_records().values()))["identity"]
    c.observed[identity] = "Released"
    status, ar = invoke(c, identifier)
    assert status == t.APP_SUCCESS, ar.get_message()
    summary = check_summary(identifier, ar, POLL_KEYS)
    assert summary["terminal_observed"] == 1
    assert summary["messages_published"] == 1


@pytest.mark.parametrize("identifier,target", POLL_ACTIONS)
def test_partial_failure_keeps_real_counts(tmp_path, identifier, target):
    c = native.setup(tmp_path, target, limit=2)
    original = c._ingest_publish
    calls = []
    def publish(key, row):
        calls.append(key)
        if len(calls) == 1:
            raise TimeoutError("synthetic publication interruption")
        return original(key, row)
    c._ingest_publish = publish
    status, ar = invoke(c, identifier)
    assert status == t.APP_ERROR
    summary = check_summary(identifier, ar, POLL_KEYS)
    assert summary["errors"] == 1
    assert summary["containers_created"] == summary["messages_published"] == 1
    assert summary["active_messages"] == 2


@pytest.mark.parametrize("identifier,target", POLL_ACTIONS)
def test_full_discovery_window_reports_truncation(tmp_path, identifier, target):
    c = native.setup(tmp_path, target, limit=1)
    c.candidates = [native.candidate(i) for i in range(1, 52)]
    status, ar = invoke(c, identifier)
    assert status == t.APP_SUCCESS, ar.get_message()
    summary = check_summary(identifier, ar, POLL_KEYS)
    assert summary["candidates"] == summary["candidate_window"] == 50
    assert summary["results_may_be_truncated"] is True


def test_empty_poll_reports_enabled_with_zero_measured_counts(tmp_path):
    c = native.setup(tmp_path)
    c.candidates = []
    status, ar = invoke(c, "on_poll")
    assert status == t.APP_SUCCESS
    summary = check_summary("on_poll", ar, POLL_KEYS)
    assert summary["ingestion_enabled"] is True
    assert summary["candidates"] == summary["containers_created"] == 0
    assert [action for action, _, _ in c.calls] == ["list"]


def test_es_requires_enabled_target_without_fabricated_summary(tmp_path):
    c = native.setup(tmp_path)
    status, ar = invoke(c, "on_es_poll")
    assert status == t.APP_ERROR
    check_summary("on_es_poll", ar, set())
    assert not c.calls


@pytest.mark.parametrize("identifier,target", POLL_ACTIONS)
def test_lock_rejection_has_no_measured_zeroes(tmp_path, identifier, target):
    c = native.setup(tmp_path, target)
    with c._ingest_poll_lock():
        status, ar = invoke(c, identifier)
    assert status == t.APP_ERROR
    check_summary(identifier, ar, set())
