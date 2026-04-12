from __future__ import annotations

from pathlib import Path

from pysymex.tracing.analyzer import FilterPipeline, build_parser, build_pipeline, stream_events


def test_filter_pipeline_add_and_matches() -> None:
    pipeline = FilterPipeline()
    pipeline.add(lambda event: event.get("event_type") == "step")
    pipeline.add(lambda event: event.get("pc") == 3)

    assert pipeline.matches({"event_type": "step", "pc": 3}) is True
    assert pipeline.matches({"event_type": "solve", "pc": 3}) is False


def test_stream_events_skips_malformed_json(tmp_path: Path) -> None:
    trace_file = tmp_path / "trace.jsonl"
    trace_file.write_text('{"event_type":"step","seq":1}\nnot-json\n', encoding="utf-8")

    rows = list(stream_events(str(trace_file)))
    assert len(rows) == 1
    assert rows[0][1]["event_type"] == "step"


def test_build_pipeline_from_parser_filters_by_event_type() -> None:
    parser = build_parser()
    args = parser.parse_args(["--event-type", "step"])
    pipeline = build_pipeline(args)

    assert pipeline.matches({"event_type": "step"}) is True
    assert pipeline.matches({"event_type": "issue"}) is False

