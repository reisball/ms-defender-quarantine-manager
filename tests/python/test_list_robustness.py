"""List normalization retained for native intake, without the old public API."""
import json
import pytest
import requests_mock

from test_connector import (
    APP_ERROR, IDENTITY, ORG, AutomationError, build_metadata,
    dispatch_flow, make_connector, patch_ar, make_utils, chunked_list_output,
)

def row(**changes):
    return {"Identity": IDENTITY, "ReleaseStatus": "Requested", **changes}

def envelope(rows, **changes):
    return {"action": "list", "messages": rows, "count": len(rows), **changes}


@pytest.mark.parametrize("identity", [None, {}, [], ["bad"], True, 23, "", "bad", IDENTITY+"\n"])
def test_invalid_list_identity_rejected_before_any_native_writes(identity):
    c = make_connector()
    with pytest.raises(AutomationError, match="[Ii]dentity"):
        c._normalise_list_result(envelope([row(), row(Identity=identity)]))
    assert c._saved_containers == []


@pytest.mark.parametrize("handler", ["_handle_release_quarantine_message", "_handle_deny_quarantine_release"])
@pytest.mark.parametrize("identity", [None, {}, [], ["bad"], True, 23])
def test_direct_identity_type_rejected_without_any_http(handler, identity):
    c = make_connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        assert getattr(c, handler)({"identity": identity}) == APP_ERROR
        assert "identity" in ar.get_message().lower()
        assert ar.get_data() == []
        assert m.call_count == 0


@pytest.mark.parametrize("count", [True, False, 1.9, 1.0, float("inf"), "1.9", {}, []])
def test_noninteger_backend_count_rejected(count):
    with pytest.raises(AutomationError, match="count"):
        make_connector()._normalise_list_result(envelope([row()], count=count))


@pytest.mark.parametrize("count", [1, "1", " 1 ", "+1"])
def test_integer_count_compatibility(count):
    rows = make_connector()._normalise_list_result(envelope([row()], count=count))
    assert rows[0]["Identity"] == IDENTITY


def test_list_normalizes_optional_fields_and_recipient_arrays():
    result = make_connector()._normalise_list_result(envelope([
        row(RecipientAddress=["first@example.org", "second@example.org"]),
    ]))
    assert result == [dict(row(), SenderAddress="", RecipientAddress="first@example.org, second@example.org",
                           Subject="", Type="", ReceivedTime="", Expires="", PolicyName="")]


@pytest.mark.parametrize("messages,count", [(False, 0), (["bad"], 1), ([row()], 0),
                                          ([{}], 1), ([row(RecipientAddress={})], 1)])
def test_invalid_list_shape_or_count_is_rejected(messages, count):
    with pytest.raises(AutomationError):
        make_connector()._normalise_list_result(envelope([], messages=messages, count=count))


@pytest.mark.parametrize("messages", [None, []])
def test_empty_list_is_empty(messages):
    assert make_connector()._normalise_list_result(envelope([], messages=messages)) == []


def test_legacy_single_row_remains_supported_but_count_is_strict():
    c = make_connector()
    assert c._normalise_list_result(envelope([], messages=row(), count=1))[0]["Identity"] == IDENTITY
    with pytest.raises(AutomationError, match="count"):
        c._normalise_list_result(envelope([], messages=row(), count=True))


def test_poll_validates_entire_list_before_any_container():
    c = make_connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {"list": envelope([row(), row(Identity=None)])})
        assert c._handle_on_poll({}) == APP_ERROR
        assert c._saved_containers == []
        assert ar.get_data() == []
        assert [body["action"] for body in bodies] == ["protected_list_v1"]


@pytest.mark.parametrize("count", [True, 1.9, 1.0, float("inf"), "1.9"])
def test_chunked_list_count_is_not_lossily_coerced(count):
    records = [{"action": "list", "mode": "list_chunk", "chunk_index": 0,
                "messages": [row()], **build_metadata()},
               {"action": "list", "mode": "list_complete", "chunk_count": 1,
                "count": count, **build_metadata()}]
    with pytest.raises(AutomationError, match="count"):
        make_utils()._parse_multiline_job_output("\n".join(json.dumps(r) for r in records))
