"""Public ingestion recovery wiring and SOAR numeric limit compatibility."""
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

if __package__:
    from . import test_connector as t
else:
    import test_connector as t

from ms_quarantine_for_splunk_soar_utils import AutomationError, parse_strict_integer


def test_public_ingestion_recovery_is_removed():
    manifest = json.loads((Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text())
    assert "recover_quarantine_ingestion" not in {a["identifier"] for a in manifest["actions"]}
    assert not hasattr(t.MSQuarantineForSplunkSOARConnector, "_handle_ingest_recovery")


@pytest.mark.parametrize("value, expected", [(1.0, 1), (10.0, 10), (50.0, 50)])
def test_asset_poll_limit_accepts_whole_number_float(tmp_path, value, expected):
    connector = t.make_connector(
        state_path=tmp_path / "state.json",
        config_overrides={"on_poll_max_containers": value})
    assert connector._on_poll_max_containers == expected
    assert type(connector._on_poll_max_containers) is int


@pytest.mark.parametrize("value", [True, False, 1.5, 49.9, float("nan"),
                                       float("inf"), float("-inf"), 0.0, 51.0])
def test_asset_poll_limit_rejects_invalid_numbers(tmp_path, value):
    connector = t.MSQuarantineForSplunkSOARConnector()
    connector._state_file_path = str(tmp_path / "state.json")
    connector._config = dict(t.base_asset_config(), on_poll_max_containers=value)
    assert connector.initialize() == t.APP_ERROR


@pytest.mark.parametrize("value, expected", [(1.0, 1), (10.0, 10), (50.0, 50),
                                              (99.0, 50), (0.0, 10), (-1.0, 10)])
def test_poll_now_limit_accepts_whole_number_float(tmp_path, value, expected):
    connector = t.make_connector(state_path=tmp_path / "state.json")
    connector._is_poll_now = True
    actual = connector._on_poll_container_limit({"container_count": value})
    assert actual == expected
    assert type(actual) is int


@pytest.mark.parametrize("value", [True, False, 1.5, 49.9, float("nan"),
                                       float("inf"), float("-inf")])
def test_poll_now_limit_rejects_invalid_numbers(tmp_path, value):
    connector = t.make_connector(state_path=tmp_path / "state.json")
    connector._is_poll_now = True
    with pytest.raises(AutomationError, match="must be an integer"):
        connector._on_poll_container_limit({"container_count": value})


def test_whole_float_compatibility_does_not_relax_shared_integer_parser():
    with pytest.raises(ValueError):
        parse_strict_integer(10.0)
