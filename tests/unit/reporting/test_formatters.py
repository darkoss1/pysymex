from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pysymex.reporting.formatters import JSONFormatter, MarkdownFormatter, TextFormatter, format_result


@dataclass
class _IssueKind:
    name: str


@dataclass
class _Issue:
    kind: _IssueKind
    message: str
    line_number: int | None = None
    function_name: str = "f"
    pc: int = 0
    constraints: list[object] = field(default_factory=lambda: [])

    def get_counterexample(self) -> dict[str, object] | None:
        return {"x": 0}


@dataclass
class _Result:
    source_file: str = "mod.py"
    function_name: str = "f"
    paths_explored: int = 2
    paths_completed: int = 1
    paths_pruned: int = 1
    coverage: set[int] = field(default_factory=lambda: {1, 2, 3})
    total_time_seconds: float = 0.1
    issues: list[_Issue] = field(default_factory=lambda: [_Issue(_IssueKind("TYPE_ERROR"), "bad", 7)])


def test_text_and_json_formatter_emit_expected_fields() -> None:
    result = _Result()
    typed_result = cast("Any", result)
    text = TextFormatter(color=False).format(typed_result)
    payload = json.loads(JSONFormatter().format(typed_result))

    assert "PySyMex" in text
    assert payload["function"]["name"] == "f"
    assert payload["summary"]["total_issues"] == 1


def test_markdown_and_format_result_dispatch(tmp_path: Path) -> None:
    result = _Result()
    typed_result = cast("Any", result)
    md = MarkdownFormatter().format(typed_result)
    fallback = format_result(typed_result, format_type="unknown")
    out = tmp_path / "report.txt"
    TextFormatter().save(typed_result, str(out))

    assert "# PySyMex - Symbolic Execution Report" in md
    assert "PySyMex" in fallback
    assert out.exists()

