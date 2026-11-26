"""Offline coverage for the two runbook start methods."""
import json
from unittest.mock import MagicMock, Mock

import pytest
import requests

from ms_quarantine_for_splunk_soar_utils import AutomationError, JobSubmissionRejected, MSQuarantineForSplunkSOARUtils, TokenError


def client(runbook_name=None, **overrides):
    return MSQuarantineForSplunkSOARUtils(
        "https://example.invalid/hook?token=fixture", "tenant", "client", "secret",
        runbook_name=runbook_name,
        **({"subscription_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "resource_group": "group", "automation_account": "automation"} | overrides),
    )


def test_webhook_is_default():
    azure = client()
    azure.fire_webhook = Mock(return_value="fixture-job")
    assert azure.start_job("deny", "identity") == "fixture-job"
    azure.fire_webhook.assert_called_once()


@pytest.mark.parametrize("status", [201, 302, 401, 403, None])
def test_arm_start_sends_one_request_and_never_falls_back(status):
    azure = client("published")
    azure.get_mgmt_token = Mock(return_value="credential")
    azure.fire_webhook = Mock()
    azure._session = MagicMock()
    put = azure._session.put
    if status is None:
        put.side_effect = requests.Timeout("sensitive provider detail")
    else:
        put.return_value.__enter__.return_value.status_code = status
    if status == 201:
        job_id = azure.start_job("list", output_public_key="public-key")
    else:
        with pytest.raises(JobSubmissionRejected if status in (401, 403) else AutomationError) as failure:
            azure.start_job("list", output_public_key="public-key")
        job_id = getattr(failure.value, "job_id", None)
        assert (job_id is None) == (status in (401, 403))
        assert "sensitive provider detail" not in str(failure.value)
    put.assert_called_once()
    azure.fire_webhook.assert_not_called()
    if job_id is not None:
        assert put.call_args.args[0].endswith(f"/jobs/{job_id}?api-version=2024-10-23")
    if status is not None:
        response = put.return_value.__enter__.return_value
        response.json.assert_not_called()
        put.return_value.__exit__.assert_called_once()
    args = put.call_args.kwargs
    assert args["allow_redirects"] is False
    assert args["stream"] is True
    assert args["headers"]["Authorization"] == "Bearer credential"
    props = args["json"]["properties"]
    assert props["runbook"] == {"name": "published"}
    assert json.loads(props["parameters"]["RequestJson"]) == {
        "action": "protected_list_v1", "output_public_key": "public-key", "auth_method": "ManagedIdentity",
    }


@pytest.mark.parametrize("field", ["subscription_id", "resource_group", "automation_account"])
def test_rest_requires_valid_resource_components(field):
    with pytest.raises(ValueError):
        client("published", **{field: "not a resource name"})


def test_oauth_requires_non_redirect_response():
    azure = client()
    azure._session = Mock()
    response = azure._session.post.return_value
    response.status_code = 307
    with pytest.raises(TokenError, match="redirects are not followed"):
        azure.get_mgmt_token()
    assert azure._session.post.call_args.kwargs["allow_redirects"] is False
    response.json.assert_not_called()
