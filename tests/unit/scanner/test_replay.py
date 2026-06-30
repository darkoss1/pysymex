from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import ClassVar

from pytest import MonkeyPatch

from pysymex._internal.analysis.records import IssueRecord
from pysymex._internal.sandbox.types import ExecutionStatus, SandboxBackendStrength, SandboxResult
from pysymex._internal.scanner.replay import confirm_issue_replays


class _FakeSandbox:
    observation: ClassVar[dict[str, object]] = {
        "phase": "call",
        "exception_type": "ZeroDivisionError",
        "trace_lines": [2],
    }
    executions: ClassVar[int] = 0

    def __init__(self, _config: object) -> None:
        self.backend_strength = SandboxBackendStrength.STRONG

    def __enter__(self) -> _FakeSandbox:
        return self

    def __exit__(self, *args: object) -> None:
        _ = args

    def reset_workspace(self) -> None:
        pass

    def execute_code(self, code: str, **_kwargs: object) -> SandboxResult:
        type(self).executions += 1
        marker_match = re.search(r"^_MARKER = (.+)$", code, flags=re.MULTILINE)
        assert marker_match is not None
        marker = ast.literal_eval(marker_match.group(1))
        stdout = f"{marker}{json.dumps(type(self).observation)}\n".encode()
        return SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0, stdout=stdout)


def _issue(*, line: int = 2, function_name: str = "f") -> IssueRecord:
    return {
        "kind": "DIVISION_BY_ZERO",
        "message": "possible division by zero",
        "line": line,
        "function_name": function_name,
        "class_name": None,
        "counterexample": {"x": 0},
    }


def _install_fake_sandbox(monkeypatch: MonkeyPatch) -> None:
    import pysymex._internal.sandbox.runner as sandbox_runner

    _FakeSandbox.executions = 0
    monkeypatch.setattr(sandbox_runner, "SecureSandbox", _FakeSandbox)


def test_concrete_replay_confirms_matching_exception_and_line(
    monkeypatch: MonkeyPatch,
) -> None:
    _install_fake_sandbox(monkeypatch)
    _FakeSandbox.observation = {
        "phase": "call",
        "exception_type": "ZeroDivisionError",
        "trace_lines": [2],
    }
    issue = _issue()

    confirm_issue_replays(
        content="def f(x: int) -> int:\n    return 1 // x\n",
        file_path=Path("target.py"),
        issues=[issue],
    )

    assert issue["replay_status"] == "confirmed"
    assert issue["replay_exception"] == "ZeroDivisionError"


def test_concrete_replay_mismatch_never_suppresses_candidate(
    monkeypatch: MonkeyPatch,
) -> None:
    _install_fake_sandbox(monkeypatch)
    _FakeSandbox.observation = {
        "phase": "call",
        "exception_type": "ZeroDivisionError",
        "trace_lines": [8],
    }
    issue = _issue()

    confirm_issue_replays(
        content="def f(x: int) -> int:\n    return 1 // x\n",
        file_path=Path("target.py"),
        issues=[issue],
    )

    assert issue["replay_status"] == "mismatch"


def test_concrete_replay_only_attempts_bounded_candidates(monkeypatch: MonkeyPatch) -> None:
    _install_fake_sandbox(monkeypatch)
    _FakeSandbox.observation = {
        "phase": "call",
        "exception_type": "ZeroDivisionError",
        "trace_lines": [2],
    }
    content = "\n\n".join(f"def f{index}(x: int) -> int:\n    return 1 // x" for index in range(4))
    issues = [_issue(line=3 * index + 2, function_name=f"f{index}") for index in range(4)]

    confirm_issue_replays(content=content, file_path=Path("target.py"), issues=issues)

    assert _FakeSandbox.executions == 3
    assert "replay_status" not in issues[3]


def test_concrete_replay_skips_non_json_witnesses(monkeypatch: MonkeyPatch) -> None:
    _install_fake_sandbox(monkeypatch)
    issue = _issue()
    issue["counterexample"] = {"x": object()}

    confirm_issue_replays(
        content="def f(x: int) -> int:\n    return 1 // x\n",
        file_path=Path("target.py"),
        issues=[issue],
    )

    assert _FakeSandbox.executions == 0
    assert "replay_status" not in issue
