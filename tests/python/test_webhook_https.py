"""Webhook transport regressions for #116; all HTTP stays in requests-mock."""
from unittest.mock import Mock

import pytest

if __package__:
    from . import test_connector as t
else:
    import test_connector as t


INVALID_URLS = [
    "http://example.invalid/webhooks?token=private-marker",
    "//example.invalid/webhooks?token=private-marker",
    "https:///webhooks?token=private-marker",
    "https://[broken/webhooks?token=private-marker",
    "https://example.invalid:bad/webhooks?token=private-marker",
]


@pytest.mark.parametrize("url", INVALID_URLS)
def test_asset_rejects_invalid_webhook_without_request(url):
    connector = t.MSQuarantineForSplunkSOARConnector()
    connector._config = {**t.base_asset_config(), "webhook_url": url}
    connector.set_status = Mock(return_value=t.APP_ERROR)
    with t.req_mock.Mocker() as mock:
        assert connector.initialize() == t.APP_ERROR
        assert not mock.called
    message = connector.set_status.call_args.args[1]
    assert "HTTPS" in message
    assert "private-marker" not in message
    assert url not in message


@pytest.mark.parametrize("url", INVALID_URLS)
def test_direct_utility_rejects_invalid_webhook(url):
    with t.req_mock.Mocker() as mock:
        with pytest.raises(ValueError, match="HTTPS") as exc:
            t.make_utils(webhook_url=url)
        assert not mock.called
    assert "private-marker" not in str(exc.value)


@pytest.mark.parametrize("url", [
    t.WEBHOOK_URL,
    "https://relay.example.invalid:8443/webhook?token=synthetic",
    "HTTPS://example.invalid/webhook",
])
def test_valid_https_keeps_job_and_payload_contract(url):
    connector = t.make_connector(config_overrides={"webhook_url": url})
    with t.req_mock.Mocker() as mock:
        mock.post(url, status_code=202, json={"JobIds": [t.JOB_ID]})
        assert connector._utils.fire_webhook("list", page_size=2, output_public_key="fixture-public-key") == t.JOB_ID
        assert mock.call_count == 1
        assert mock.last_request.json()["page_size"] == 2
        assert mock.last_request.verify  # True or the configured CA bundle.


@pytest.mark.parametrize("code", [301, 302, 303, 304, 307, 308])
@pytest.mark.parametrize("target", [
    "http://other.invalid/webhook?token=redirect-private-marker",
    "https://other.invalid/webhook?token=redirect-private-marker",
    "/other-webhook?token=redirect-private-marker",
])
def test_redirect_is_rejected_even_with_job_ids_and_never_followed(code, target):
    utils = t.make_utils()
    with t.req_mock.Mocker() as mock:
        # A real requests Session executes its normal redirect machinery;
        # the adapter intercepts both original and possible follow-up requests.
        mock.register_uri(t.req_mock.ANY, t.req_mock.ANY,
                          json={"JobIds": [t.JOB_ID]})
        mock.post(t.WEBHOOK_URL, status_code=code,
                  headers={"Location": target}, json={"JobIds": [t.JOB_ID]})
        with pytest.raises(t.WebhookError, match=f"HTTP {code}") as exc:
            utils.fire_webhook("release", identity=t.IDENTITY)
        assert mock.call_count == 1
        assert mock.last_request.method == "POST"
    assert "redirect-private-marker" not in str(exc.value)
    assert "abc123" not in str(exc.value)


@pytest.mark.parametrize("handler", [
    "_handle_release_quarantine_message",
    "_handle_deny_quarantine_release",
])
def test_redirect_is_not_retried_but_new_action_after_restart_is_allowed(handler, tmp_path):
    state = tmp_path / "state.json"
    params = {"identity": t.IDENTITY}
    for _ in range(2):
        connector = t.make_connector(state_path=state)
        result = t.patch_ar(connector)
        with t.req_mock.Mocker() as mock:
            mock.post(t.WEBHOOK_URL, status_code=307,
                      headers={"Location": "https://other.invalid/webhook"})
            assert getattr(connector, handler)(params) == t.APP_ERROR
            assert mock.call_count == 1
        assert "HTTP 307" in result.get_message()
        assert "state" not in result.get_data()[0]
        assert result.get_data()[0]["error"] is True
