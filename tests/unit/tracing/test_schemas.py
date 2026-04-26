from __future__ import annotations

import os

from pydantic import TypeAdapter

from pysymex.tracing.schemas import StepDeltaEvent, TracerConfig


def test_tracer_config_from_env_truthy() -> None:
    old_trace = os.environ.get("PY_SYMEX_TRACE")
    old_comp = os.environ.get("PY_SYMEX_TRACE_COMPRESSION")
    try:
        os.environ["PY_SYMEX_TRACE"] = "true"
        os.environ["PY_SYMEX_TRACE_COMPRESSION"] = "9"
        cfg = TracerConfig.from_env(output_dir="out")
        assert cfg.enabled is True
        assert cfg.compression_level == 9
        assert cfg.output_dir == "out"
    finally:
        if old_trace is None:
            os.environ.pop("PY_SYMEX_TRACE", None)
        else:
            os.environ["PY_SYMEX_TRACE"] = old_trace
        if old_comp is None:
            os.environ.pop("PY_SYMEX_TRACE_COMPRESSION", None)
        else:
            os.environ["PY_SYMEX_TRACE_COMPRESSION"] = old_comp


def test_trace_event_union_round_trip_for_step_event() -> None:
    adapter: TypeAdapter[StepDeltaEvent] = TypeAdapter(StepDeltaEvent)
    event = StepDeltaEvent(seq=7, path_id=2, pc=9, opcode="LOAD_CONST")
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, StepDeltaEvent)
    assert parsed.event_type == "step"
    assert parsed.seq == 7
