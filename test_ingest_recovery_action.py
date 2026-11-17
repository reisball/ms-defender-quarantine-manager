# Copyright (c) 2026 Kai Seidenschnur
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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


def test_recovery_action_manifest_contract():
    manifest = json.loads(Path(__file__).with_name("ms_quarantine_for_splunk_soar.json").read_text())
    actions = [a for a in manifest["actions"] if a["identifier"] == "recover_quarantine_ingestion"]
    assert len(actions) == 1
    action = actions[0]
    assert action["action"] == "recover quarantine ingestion"
    assert action["read_only"] is False
    params = action["parameters"]
    assert set(params) == {"identity", "resolution", "operator_note"}
    assert all(p["required"] for p in params.values())
    assert params["identity"]["data_type"] == "string"
    assert params["operator_note"]["data_type"] == "string"
    assert params["resolution"]["value_list"] == ["retry_preparation", "confirm_published"]


@pytest.mark.parametrize("resolution", ["retry_preparation", "confirm_published"])
def test_recovery_dispatches_original_parameters(tmp_path, resolution):
    connector = t.make_connector(state_path=tmp_path / "state.json")
    connector._action_id = "recover_quarantine_ingestion"
    connector._handle_ingest_recovery = Mock(return_value=t.APP_SUCCESS)
    param = {"identity": t.IDENTITY, "resolution": resolution, "operator_note": "Verified synthetic recovery evidence"}
    assert connector.handle_action(param) == t.APP_SUCCESS
    connector._handle_ingest_recovery.assert_called_once_with(param)
    assert connector._handle_ingest_recovery.call_args.args[0] is param


@pytest.mark.parametrize("value, expected", [(1.0, 1), (10.0, 10), (50.0, 50)])
def test_asset_poll_limit_accepts_whole_number_float(tmp_path, value, expected):
    connector = t.make_connector(state_path=tmp_path / "state.json", config_overrides={"on_poll_max_containers": value})
    assert connector._on_poll_max_containers == expected
    assert type(connector._on_poll_max_containers) is int


@pytest.mark.parametrize("value", [True, False, 1.5, 49.9, float("nan"), float("inf"), float("-inf"), 0.0, 51.0])
def test_asset_poll_limit_rejects_invalid_numbers(tmp_path, value):
    connector = t.MSQuarantineForSplunkSOARConnector()
    connector._state_file_path = str(tmp_path / "state.json")
    connector._config = dict(t.base_asset_config(), on_poll_max_containers=value)
    assert connector.initialize() == t.APP_ERROR


@pytest.mark.parametrize("value, expected", [(1.0, 1), (10.0, 10), (50.0, 50), (99.0, 50), (0.0, 10), (-1.0, 10)])
def test_poll_now_limit_accepts_whole_number_float(tmp_path, value, expected):
    connector = t.make_connector(state_path=tmp_path / "state.json")
    connector._is_poll_now = True
    actual = connector._on_poll_container_limit({"container_count": value})
    assert actual == expected
    assert type(actual) is int


@pytest.mark.parametrize("value", [True, False, 1.5, 49.9, float("nan"), float("inf"), float("-inf")])
def test_poll_now_limit_rejects_invalid_numbers(tmp_path, value):
    connector = t.make_connector(state_path=tmp_path / "state.json")
    connector._is_poll_now = True
    with pytest.raises(AutomationError, match="must be an integer"):
        connector._on_poll_container_limit({"container_count": value})


def test_whole_float_compatibility_does_not_relax_shared_integer_parser():
    with pytest.raises(ValueError):
        parse_strict_integer(10.0)
