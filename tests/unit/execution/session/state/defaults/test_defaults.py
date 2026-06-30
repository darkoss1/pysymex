"""Tests for execution-session default factory ownership."""

from __future__ import annotations

from collections import OrderedDict

from pysymex._internal.execution.session.state.defaults.detectors import (
    default_detector_query_cache,
)
from pysymex._internal.execution.session.state.defaults.phase import (
    default_phase_counts,
    default_phase_timers,
)
from pysymex._internal.execution.session.state.defaults.results import default_issues
from pysymex._internal.execution.session.state.defaults.snapshots import default_snapshot_mapping


def test_state_defaults_return_fresh_mutable_collections() -> None:
    first_issues = default_issues()
    second_issues = default_issues()
    assert first_issues == []
    assert second_issues == []
    assert first_issues is not second_issues

    first_mapping = default_snapshot_mapping()
    second_mapping = default_snapshot_mapping()
    first_mapping["value"] = object()
    assert "value" not in second_mapping

    first_cache = default_detector_query_cache()
    second_cache = default_detector_query_cache()
    assert isinstance(first_cache, OrderedDict)
    assert isinstance(second_cache, OrderedDict)
    assert first_cache is not second_cache


def test_phase_default_schemas_remain_fixed() -> None:
    assert default_phase_timers() == {
        "execute_step": 0.0,
        "process_execution_result": 0.0,
        "path_feasibility": 0.0,
    }
    assert default_phase_counts() == {
        "execute_step": 0,
        "process_execution_result": 0,
        "path_feasibility": 0,
    }
