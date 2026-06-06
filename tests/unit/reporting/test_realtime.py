from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from pysymex.reporting.realtime import (
    GlobalState,
    HTML_TEMPLATE,
    RealtimeVisualizationPlugin,
    global_state,
    run_realtime_scan,
)
from pysymex.reporting.realtime.execution import execute_realtime_file
from pysymex.scanner.file import scan_file
from pysymex.scanner.types import ScanResult


class _Engine:
    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}

    def register_hook(self, name: str, handler: object) -> None:
        self.hooks[name] = handler


def _ignore_server_shutdown(server: object) -> None:
    pass


def _degraded_realtime_result(*args: object, **kwargs: object) -> ScanResult:
    _ = args
    _ = kwargs
    return ScanResult(
        file_path="degraded.py",
        timestamp="now",
        degraded_passes=["solver_unknown_detector_query"],
    )


def test_global_state_get_json_contains_expected_keys() -> None:
    state = GlobalState()
    payload = json.loads(state.get_json())
    assert "nodes" in payload
    assert "stats" in payload
    assert payload["graph_revision"] == 0
    assert payload["node_count"] == 0


def test_global_state_omits_unchanged_graph_payload() -> None:
    state = GlobalState()
    with state.lock:
        state.replace_graph(
            [{"id": "root", "label": "root", "type": "dir", "status": "pending"}],
            [],
        )
        revision = state.graph_revision

    payload = json.loads(state.get_json(client_graph_revision=revision))

    assert payload["graph_unchanged"] is True
    assert payload["graph_revision"] == revision
    assert payload["node_count"] == 1
    assert "nodes" not in payload
    assert "edges" not in payload

    skipped = json.loads(state.get_json(include_graph=False))
    assert skipped["graph_unchanged"] is True
    assert "nodes" not in skipped
    assert "edges" not in skipped


def test_realtime_template_renders_live_scan_data_as_text() -> None:
    assert ".innerHTML" not in HTML_TEMPLATE
    assert ".textContent" in HTML_TEMPLATE
    assert "Statistics" in HTML_TEMPLATE
    assert "Detected Issues" in HTML_TEMPLATE
    assert "MAX_RENDERED_GRAPH_NODES" in HTML_TEMPLATE
    assert "graph_revision" in HTML_TEMPLATE
    assert "skip_graph=1" in HTML_TEMPLATE
    assert 'id="g-pause"' in HTML_TEMPLATE


def test_realtime_plugin_registers_pre_step_hook() -> None:
    plugin = RealtimeVisualizationPlugin()
    hooks = plugin.get_hooks()
    assert "pre_step" in hooks

    engine = _Engine()
    plugin.activate(cast("Any", engine))
    assert "pre_step" in engine.hooks


def test_execute_realtime_file_delegates_policy_to_canonical_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "delegated.py"
    target.write_text("def target(value: int) -> int:\n    return value\n", encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_scan_file(file_path: object, **kwargs: object) -> ScanResult:
        observed["file_path"] = file_path
        observed.update(kwargs)
        return ScanResult(file_path=str(file_path), timestamp="now")

    monkeypatch.setattr("pysymex.reporting.realtime.execution.scan_file", fake_scan_file)
    plugin = RealtimeVisualizationPlugin(sleep_ms=0)

    execute_realtime_file(
        target,
        10,
        1.0,
        plugin,
        auto_tune=True,
        use_sandbox=False,
        deterministic_mode=True,
        no_cache=True,
        max_iterations=7,
        trace_enabled=False,
    )

    assert observed["file_path"] == target
    assert observed["max_paths"] == 10
    assert observed["timeout"] == 1.0
    assert observed["auto_tune"] is True
    assert observed["use_sandbox"] is False
    assert observed["deterministic_mode"] is True
    assert observed["no_cache"] is True
    assert observed["max_iterations"] == 7
    assert observed["execution_observer"] is plugin


def test_execute_realtime_file_returns_canonical_scanner_result(tmp_path: Path) -> None:
    target = tmp_path / "division.py"
    target.write_text("def target(value: int) -> int:\n    return 1 // value\n", encoding="utf-8")
    expected = scan_file(target, use_sandbox=False, deterministic_mode=True, trace_enabled=False)

    actual = execute_realtime_file(
        target,
        100,
        30.0,
        RealtimeVisualizationPlugin(sleep_ms=0),
        use_sandbox=False,
        deterministic_mode=True,
        trace_enabled=False,
    )

    assert actual.issues == expected.issues
    assert actual.error == expected.error
    assert actual.code_objects == expected.code_objects


def test_run_realtime_scan_marks_failed_analysis_and_resets_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "syntax_failure.py"
    target.write_text("def broken(:\n", encoding="utf-8")
    global_state.stats["files"] = 99
    global_state.stats["scan_errors"] = 99

    monkeypatch.setattr("pysymex.reporting.realtime.scan.start_realtime_server", object)
    monkeypatch.setattr(
        "pysymex.reporting.realtime.scan.shutdown_realtime_server",
        _ignore_server_shutdown,
    )

    results = run_realtime_scan(target, use_sandbox=False, trace_enabled=False)
    payload = json.loads(global_state.get_json())
    file_node = next(node for node in payload["nodes"] if node["type"] == "file")

    assert results[0].error is not None
    assert results[0].error.startswith("Syntax Error:")
    assert payload["stats"]["files"] == 1
    assert payload["stats"]["scan_errors"] == 1
    assert file_node["status"] == "done_error"


def test_run_realtime_scan_marks_degraded_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "degraded.py"
    target.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("pysymex.reporting.realtime.scan.start_realtime_server", object)
    monkeypatch.setattr(
        "pysymex.reporting.realtime.scan.shutdown_realtime_server",
        _ignore_server_shutdown,
    )
    monkeypatch.setattr(
        "pysymex.reporting.realtime.scan.execute_realtime_file",
        _degraded_realtime_result,
    )

    run_realtime_scan(target, use_sandbox=False, trace_enabled=False)
    payload = json.loads(global_state.get_json())
    file_node = next(node for node in payload["nodes"] if node["type"] == "file")

    assert payload["stats"]["degraded_scans"] == 1
    assert file_node["status"] == "done_degraded"


def test_global_state_resets_custom_lists_and_serializes() -> None:
    from pysymex.reporting.realtime.graph import initialize_graph

    global_state.issues_list.append({"test": "issue"})
    global_state.visited_functions.append("test_func")

    initialize_graph([], Path("/tmp"))

    assert len(global_state.issues_list) == 0
    assert len(global_state.visited_functions) == 0

    payload = json.loads(global_state.get_json())
    assert "issues_list" in payload
    assert "visited_functions" in payload


def test_plugin_begin_code_keeps_function_node_unique(tmp_path: Path) -> None:
    from pysymex.reporting.realtime.graph import initialize_graph

    target_file = tmp_path / "test.py"
    initialize_graph([target_file], tmp_path)
    global_state.active_file = target_file

    class FakeCode:
        co_name = "target_func"
        co_filename = str(target_file)

    plugin = RealtimeVisualizationPlugin(sleep_ms=0)
    plugin.begin_code(cast("Any", FakeCode()))
    plugin.begin_code(cast("Any", FakeCode()))

    function_nodes = [node for node in global_state.nodes if node["type"] == "function"]
    function_edges = [
        edge for edge in global_state.edges if edge["target"].endswith("::target_func")
    ]

    assert len(function_nodes) == 1
    assert len(function_edges) == 1


def test_plugin_hooks_populate_execution_tree_and_issues(tmp_path: Path) -> None:
    from pysymex.analysis.detectors.detector.types import Issue, IssueKind
    from pysymex.reporting.realtime.graph import initialize_graph

    # 1. Initialize
    target_file = tmp_path / "test.py"
    initialize_graph([target_file], tmp_path)
    global_state.active_file = target_file

    plugin = RealtimeVisualizationPlugin(sleep_ms=0)
    hooks = plugin.get_hooks()
    pre_step = hooks["pre_step"]
    on_fork = hooks["on_fork"]
    on_prune = hooks["on_prune"]
    on_issue = hooks["on_issue"]

    # 2. Begin code
    class FakeCode:
        co_name = "target_func"
        co_filename = str(target_file)

    plugin.begin_code(cast("Any", FakeCode()))

    # Check function node exists and visited functions
    assert "target_func" in global_state.visited_functions
    func_node = next(n for n in global_state.nodes if n["type"] == "function")
    assert func_node["label"] == "def target_func()"

    # 3. Pre step for path 0
    class FakeState:
        path_id = 0
        pc = 0

    class FakeExecutor:
        instructions: list[object] = []
        _paths_explored = 1

    pre_step(cast("Any", FakeExecutor()), cast("Any", FakeState()))

    path_node = next(n for n in global_state.nodes if n["type"] == "path_node")
    assert path_node["label"] == "Path 0"

    # 4. Fork path 0 to path 1
    class ChildState:
        path_id = 1
        pc = 0

    on_fork(
        cast("Any", FakeExecutor()),
        cast("Any", FakeState()),
        [cast("Any", ChildState())],
    )

    # 5. Pre step for path 1
    pre_step(cast("Any", FakeExecutor()), cast("Any", ChildState()))
    path1_node = next(n for n in global_state.nodes if n["id"].endswith("::path_1"))
    assert path1_node["label"] == "Path 1"

    # Check parent edge
    edge = next(e for e in global_state.edges if e["target"] == path1_node["id"])
    assert edge["source"] == path_node["id"]

    # 6. Issue on path 0
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="zero division",
        file=str(target_file),
        line=10,
    )
    on_issue(cast("Any", FakeExecutor()), cast("Any", FakeState()), issue)

    issue_node = next(n for n in global_state.nodes if n["type"] == "issue")
    assert issue_node["label"] == "Bug: DIVISION_BY_ZERO"
    assert len(global_state.issues_list) == 1
    assert global_state.issues_list[0]["message"] == "zero division"

    # 7. Prune path 1
    on_prune(cast("Any", FakeExecutor()), cast("Any", ChildState()), "infeasible")
    assert path1_node["type"] == "dead_path"
    assert path1_node["status"] == "pruned (infeasible)"
