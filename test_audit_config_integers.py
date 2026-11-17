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
"""Numeric SOAR config stays lossless; no network or live asset changes."""

import pytest


if __package__:
    from . import test_connector as t
else:
    import test_connector as t

FIELDS = [
    ("poll_interval_seconds", "_poll_interval", 1, 60, 5),
    ("poll_timeout_seconds", "_poll_timeout", 600, 3600, 600),
    ("worker_terminal_retention_days", "_worker_terminal_retention_days", 1, 365, 30),
]


@pytest.mark.parametrize("field,attr,low,high,default", FIELDS)
@pytest.mark.parametrize("value", [True, False, 1.9, 600.5, float("nan"), float("inf"), float("-inf"), "1.9", "abc"])
def test_invalid_config_numbers_are_controlled_errors(field, attr, low, high, default, value):
    c = t.MSQuarantineForSplunkSOARConnector()
    c._config = t.base_asset_config()
    c._config[field] = value
    assert c.initialize() == t.APP_ERROR


@pytest.mark.parametrize("field,attr,low,high,default", FIELDS)
def test_existing_lossless_values_and_limits_remain_valid(field, attr, low, high, default):
    for value in [low, high, default, float(default), str(default), " +" + str(default) + " "]:
        c = t.MSQuarantineForSplunkSOARConnector()
        c._config = t.base_asset_config()
        c._config[field] = value
        assert c.initialize() == t.APP_SUCCESS
        # Actual config is forwarded into the Azure helper for intervals.
        if field.startswith("poll_"):
            assert getattr(c._utils, attr) == int(value)
        else:
            assert getattr(c, attr) == int(value)
    for value in [low - 1, high + 1]:
        c = t.MSQuarantineForSplunkSOARConnector()
        c._config = t.base_asset_config()
        c._config[field] = value
        assert c.initialize() == t.APP_ERROR
