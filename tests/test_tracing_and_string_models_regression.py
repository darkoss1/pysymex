"""Regression tests for tracing config serialization and string model coupling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import z3

from pysymex.analysis.path_manager import ExplorationStrategy
from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue
from pysymex.models.strings import StrCountModel, StrSplitModel
from pysymex.tracing.schemas import TracerConfig
from pysymex.tracing.tracer import ExecutionTracer


class _MockState:
    def __init__(self, pc: int) -> None:
        self.pc = pc


def test_start_session_normalizes_non_scalar_config_snapshot(tmp_path: Path):
    tracer = ExecutionTracer(
        TracerConfig(
            enabled=True,
            output_dir=str(tmp_path),
        )
    )

    trace_path = tracer.start_session(
        func_name="fn",
        signature_str="(x: int)",
        initial_args={"x": "int"},
        config_snapshot={
            "strategy": ExplorationStrategy.CHTD_NATIVE,
            "symbolic_args": {},
            "thresholds": [1, 2, 3],
            "none": None,
        },
        source_file="dummy.py",
    )
    tracer.end_session()

    import gzip
    with gzip.open(trace_path, "rt", encoding="utf-8") as f:
        line = f.readline()
    event = json.loads(line)
    cfg = event["tracer_config"]

    assert isinstance(cfg["strategy"], str)
    assert cfg["symbolic_args"] == "{}"
    assert cfg["thresholds"] == "[1, 2, 3]"
    assert cfg["none"] is None


def test_count_equals_one_forces_split_len_at_least_two_for_non_empty_separator():
    state = _MockState(pc=10)
    original, original_constraint = SymbolicString.symbolic("s")
    sep = SymbolicString.from_const("/")

    count_model = StrCountModel()
    split_model = StrSplitModel()

    count_result = count_model.apply([original, sep], {}, cast("Any", state))
    split_result = split_model.apply([original, sep], {}, cast("Any", _MockState(pc=11)))

    assert isinstance(count_result.value, SymbolicValue)
    assert isinstance(split_result.value, SymbolicList)

    solver = z3.Solver()
    solver.add(original_constraint)
    solver.add(*count_result.constraints)
    solver.add(*split_result.constraints)

    solver.add(count_result.value.is_int)
    solver.add(count_result.value.z3_int == 1)

    # Regression: this used to be SAT due to weak count/split coupling.
    solver.push()
    solver.add(split_result.value.z3_len == 1)
    assert solver.check() == z3.unsat
    solver.pop()

    solver.add(split_result.value.z3_len >= 2)
    assert solver.check() == z3.sat
