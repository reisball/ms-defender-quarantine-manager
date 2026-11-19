"""Historical confirmation must not replace the current native error."""
from unittest.mock import Mock
import pytest
from test_connector import APP_ERROR, IDENTITY, JOB_ID, RunbookActionError, make_connector, patch_ar


@pytest.mark.parametrize("action,handler", [
    ("release", "_handle_release_quarantine_message"),
    ("deny", "_handle_deny_quarantine_release"),
])
def test_current_native_error_is_never_replaced_by_old_confirmation(action, handler):
    c = make_connector()
    ar = patch_ar(c)
    c.save_state({"irreversible_operations": {"old": {
        "identity": IDENTITY, "state": "confirmed", "action": action,
        "result": {"status": "released" if action == "release" else "denied"},
    }}})
    before = c.load_state()
    cause = {"action": action, "identity": IDENTITY, "error": True,
             "message": "Native Exchange error remains the current result",
             "context": {"RequestId": "request-42"}}
    c._utils.fire_webhook = Mock(return_value=JOB_ID)
    c._utils.wait_for_action_result = Mock(side_effect=RunbookActionError(
        cause["message"], result=cause))
    assert getattr(c, handler)({"identity": IDENTITY}) == APP_ERROR
    assert cause["message"] in ar.get_message()
    assert ar.get_data()[0]["context"] == cause["context"]
    assert c.load_state() == before
    c._utils.fire_webhook.assert_called_once_with(action, identity=IDENTITY)
