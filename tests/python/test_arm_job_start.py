"""Offline coverage for the two runbook start methods."""
import json
from unittest.mock import MagicMock, Mock

import pytest
import requests

from ms_quarantine_for_splunk_soar_utils import AutomationError, MSQuarantineForSplunkSOARUtils


def client(runbook_name=None):
    return MSQuarantineForSplunkSOARUtils(
        "https://example.invalid/hook?token=fixture", "tenant", "client", "secret",
        "subscription", "group", "automation", runbook_name=runbook_name,
    )


def test_webhook_is_default():
    azure = client()
    azure.fire_webhook = Mock(return_value="fixture-job")
    assert azure.start_job("deny", "identity") == "fixture-job"
    azure.fire_webhook.assert_called_once()


@pytest.mark.parametrize("status", [201, 302, 403, None])
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
        with pytest.raises(AutomationError) as failure:
            azure.start_job("list", output_public_key="public-key")
        job_id = failure.value.job_id
        assert "sensitive provider detail" not in str(failure.value)
    put.assert_called_once()
    azure.fire_webhook.assert_not_called()
    assert put.call_args.args[0].endswith(f"/jobs/{job_id}?api-version=2024-10-23")
    args = put.call_args.kwargs
    assert args["allow_redirects"] is False
    assert args["headers"]["Authorization"] == "Bearer credential"
    props = args["json"]["properties"]
    assert props["runbook"] == {"name": "published"}
    assert json.loads(props["parameters"]["RequestJson"]) == {
        "action": "protected_list_v1", "output_public_key": "public-key", "auth_method": "ManagedIdentity",
    }
