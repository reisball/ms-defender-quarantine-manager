"""Business guards retained after retiring durable claims and recovery."""
from unittest.mock import Mock
import pytest
from test_connector import IDENTITY, JOB_ID, AutomationError, RunbookActionError, make_utils


@pytest.mark.parametrize("action,status", [("release", "released"), ("deny", "denied")])
@pytest.mark.parametrize("already", [False, True])
@pytest.mark.parametrize("upper", [False, True])
def test_success_envelope_accepts_semantically_matching_guid_identity(action, status, already, upper):
    utils = make_utils()
    identity = IDENTITY.upper() if upper else IDENTITY.lower()
    output = {"action": action, "identity": identity,
              "status": ("already_" if already else "") + status,
              "observed_identity": identity, "observed_release_status": status.title()}
    utils.poll_job = Mock()
    utils.get_job_output = Mock(return_value=output)
    assert utils.wait_for_action_result(JOB_ID, action, IDENTITY) is output
    for key in ("identity", "observed_identity"):
        for foreign in (IDENTITY.replace("c14401cf", "a14401cf"), "not-a-guid", None):
            utils.get_job_output.return_value = dict(output, **{key: foreign})
            with pytest.raises(AutomationError):
                utils.wait_for_action_result(JOB_ID, action, IDENTITY)


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("location", ["identity", "context", "details"])
def test_native_error_retains_guid_identity_binding(action, location):
    utils = make_utils()
    output = {"action": action, "error": True, "message": "native failure"}
    if location == "identity":
        output["identity"] = IDENTITY.upper()
    else:
        output[location] = {"identity": IDENTITY.upper()}
    utils.poll_job = Mock()
    utils.get_job_output = Mock(return_value=output)
    with pytest.raises(RunbookActionError) as exc:
        utils.wait_for_action_result(JOB_ID, action, IDENTITY.lower())
    assert exc.value.result is output
    if location == "identity":
        output["identity"] = "foreign"
    else:
        output[location]["identity"] = "foreign"
    with pytest.raises(AutomationError) as exc:
        utils.wait_for_action_result(JOB_ID, action, IDENTITY)
    assert not isinstance(exc.value, RunbookActionError)


@pytest.mark.parametrize("field,value", [
    ("action", "deny"), ("status", "denied"), ("observed_release_status", "Requested"),
    ("error", "false"),
])
def test_success_rejects_wrong_action_status_or_error_type(field, value):
    output = {"action": "release", "identity": IDENTITY, "status": "released",
              "observed_identity": IDENTITY, "observed_release_status": "Released"}
    output[field] = value
    with pytest.raises(AutomationError):
        make_utils()._validate_runbook_result(output, "release", IDENTITY)
