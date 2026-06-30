# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Opt-in concrete replay confirmation for normalized scanner issues.

This module owns the post-scan boundary from solver-backed counterexamples to
OS-isolated CPython execution. It may upgrade an issue's evidence level, but it
does not suppress findings or reinterpret symbolic feasibility.
"""

from __future__ import annotations

import ast
import json
import secrets
import textwrap
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.analysis.records import IssueRecord, normalize_trigger_input
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.sandbox.runner import SandboxRunner

ReplayStatus = Literal["confirmed", "mismatch", "execution_failed", "unavailable"]

# Replay is deliberately bounded because sandbox setup and target import are expensive.
_MAX_REPLAY_CANDIDATES = 3
_REPLAY_TARGET_NAME = "_pysymex_replay_target.py"
_EXPECTED_EXCEPTIONS: dict[str, frozenset[str]] = {
    "ASSERTION_ERROR": frozenset(("AssertionError",)),
    "ATTRIBUTE_ERROR": frozenset(("AttributeError",)),
    "DIVISION_BY_ZERO": frozenset(("ZeroDivisionError",)),
    "INDEX_ERROR": frozenset(("IndexError",)),
    "KEY_ERROR": frozenset(("KeyError",)),
    "MODULO_BY_ZERO": frozenset(("ZeroDivisionError",)),
    "NAME_ERROR": frozenset(("NameError",)),
    "OVERFLOW": frozenset(("OverflowError",)),
    "RUNTIME_ERROR": frozenset(("RuntimeError",)),
    "TYPE_ERROR": frozenset(("TypeError",)),
    "UNBOUND_VARIABLE": frozenset(("UnboundLocalError",)),
    "VALUE_ERROR": frozenset(("ValueError",)),
}

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _ReplayCall:
    function_name: str
    args: tuple[object, ...]
    kwargs: dict[str, object]
    issue_line: int
    expected_exceptions: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ReplayObservation:
    exception_type: str | None
    trace_lines: tuple[int, ...]


def confirm_issue_replays(
    *,
    content: str,
    file_path: Path,
    issues: list[IssueRecord],
    timeout_seconds: float = 2.0,
) -> None:
    """Upgrade replayed issues when isolated CPython reproduces the reported exception.

    Only top-level functions with JSON-safe concrete argument assignments are eligible.
    Replay failures remain possible issues and receive a bounded ``replay_status`` field.

    Side Effects:
        Mutates eligible issue records in place. Creates and cleans up one native sandbox.

    Limitations:
        Methods, closures, generators, non-JSON witness values, and imports requiring
        unstaged sibling files are not replayed.
    """
    if timeout_seconds <= 0:
        msg = "replay timeout must be positive"
        raise ValueError(msg)

    calls = _eligible_replay_calls(content, issues)
    if not calls:
        return

    from pysymex._internal.config.sandbox.types import SandboxConfig, SandboxResourceLimits
    from pysymex._internal.sandbox.errors import SandboxError
    from pysymex._internal.sandbox.runner import SecureSandbox
    from pysymex._internal.sandbox.types import SandboxBackendStrength

    limits = SandboxResourceLimits(timeout_seconds=timeout_seconds)
    try:
        with SecureSandbox(SandboxConfig(limits=limits)) as sandbox:
            if sandbox.backend_strength is not SandboxBackendStrength.STRONG:
                _mark_unavailable(calls)
                return
            for issue, call in calls:
                sandbox.reset_workspace()
                observation = _execute_replay(
                    sandbox=sandbox,
                    content=content,
                    file_path=file_path,
                    call=call,
                )
                if observation is None:
                    issue["replay_status"] = "execution_failed"
                    continue
                if (
                    observation.exception_type in call.expected_exceptions
                    and call.issue_line in observation.trace_lines
                ):
                    issue["replay_status"] = "confirmed"
                    issue["replay_exception"] = observation.exception_type
                else:
                    issue["replay_status"] = "mismatch"
    except (SandboxError, OSError):
        logger.debug("Concrete replay sandbox unavailable for %s", file_path, exc_info=True)
        _mark_unavailable(calls)


def _eligible_replay_calls(
    content: str,
    issues: list[IssueRecord],
) -> list[tuple[IssueRecord, _ReplayCall]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    calls: list[tuple[IssueRecord, _ReplayCall]] = []
    for issue in issues:
        if len(calls) >= _MAX_REPLAY_CANDIDATES:
            break
        call = _replay_call_for_issue(issue, functions)
        if call is not None:
            calls.append((issue, call))
    return calls


def _replay_call_for_issue(
    issue: IssueRecord,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> _ReplayCall | None:
    if issue.get("class_name") is not None:
        return None
    function_name = issue.get("function_name")
    issue_line = issue.get("line")
    if not isinstance(function_name, str) or not isinstance(issue_line, int):
        return None
    function = functions.get(function_name)
    if function is None or isinstance(function, ast.AsyncFunctionDef):
        return None
    expected = _EXPECTED_EXCEPTIONS.get(str(issue.get("kind", "UNKNOWN")))
    trigger = normalize_trigger_input(issue.get("counterexample"))
    if expected is None or trigger is None:
        return None

    positional = [*function.args.posonlyargs, *function.args.args]
    required_positional = len(positional) - len(function.args.defaults)
    args: list[object] = []
    for index, parameter in enumerate(positional):
        if parameter.arg not in trigger:
            if index < required_positional:
                return None
            break
        args.append(trigger[parameter.arg])

    kwargs: dict[str, object] = {}
    for parameter, default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
        strict=True,
    ):
        if parameter.arg in trigger:
            kwargs[parameter.arg] = trigger[parameter.arg]
        elif default is None:
            return None

    try:
        json.dumps({"args": args, "kwargs": kwargs}, allow_nan=False)
    except (TypeError, ValueError):
        return None
    return _ReplayCall(function_name, tuple(args), kwargs, issue_line, expected)


def _execute_replay(
    *,
    sandbox: object,
    content: str,
    file_path: Path,
    call: _ReplayCall,
) -> _ReplayObservation | None:

    runner = cast("SandboxRunner", sandbox)
    marker = f"__PYSYMEX_REPLAY_{secrets.token_hex(16)}__"
    payload = json.dumps(
        {
            "function_name": call.function_name,
            "args": call.args,
            "kwargs": call.kwargs,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    result = runner.execute_code(
        _replay_worker(marker, payload),
        filename="_pysymex_replay_worker.py",
        extra_files={_REPLAY_TARGET_NAME: content.encode("utf-8")},
    )
    if not result.succeeded:
        logger.debug("Concrete replay execution failed for %s", file_path)
        return None
    return _parse_replay_observation(result.get_stdout_text(), marker)


def _replay_worker(marker: str, payload: str) -> str:
    return textwrap.dedent(
        f"""
        import json
        import os
        import runpy
        import sys

        _MARKER = {marker!r}
        _PAYLOAD = json.loads({payload!r})
        _dumps = json.dumps
        _write = sys.__stdout__.buffer.write
        _phase = "load"
        try:
            _target_path = os.path.join(os.path.dirname(__file__), {_REPLAY_TARGET_NAME!r})
            _namespace = runpy.run_path(_target_path)
            _target = _namespace[_PAYLOAD["function_name"]]
            _phase = "call"
            _target(*_PAYLOAD["args"], **_PAYLOAD["kwargs"])
        except BaseException as _exc:
            _trace_lines = []
            _tb = _exc.__traceback__
            while _tb is not None:
                if _tb.tb_frame.f_code.co_filename.endswith({_REPLAY_TARGET_NAME!r}):
                    _trace_lines.append(_tb.tb_lineno)
                _tb = _tb.tb_next
            _report = {{
                "phase": _phase,
                "exception_type": type(_exc).__name__,
                "trace_lines": _trace_lines,
            }}
        else:
            _report = {{"phase": _phase, "exception_type": None, "trace_lines": []}}
        _write((_MARKER + _dumps(_report, separators=(",", ":")) + "\\n").encode("utf-8"))
        """,
    ).strip()


def _parse_replay_observation(output: str, marker: str) -> _ReplayObservation | None:
    marker_index = output.rfind(marker)
    if marker_index < 0:
        return None
    raw_payload = output[marker_index + len(marker) :].splitlines()[0]
    try:
        payload: object = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not RuntimeObjectGuards.dict(payload) or payload.get("phase") != "call":
        return None
    exception_type = payload.get("exception_type")
    raw_lines = payload.get("trace_lines")
    if exception_type is not None and not isinstance(exception_type, str):
        return None
    if not RuntimeObjectGuards.list(raw_lines) or not all(
        isinstance(line, int) for line in raw_lines
    ):
        return None
    trace_lines = tuple(line for line in raw_lines if isinstance(line, int))
    return _ReplayObservation(exception_type, trace_lines)


def _mark_unavailable(calls: list[tuple[IssueRecord, _ReplayCall]]) -> None:
    for issue, _call in calls:
        issue["replay_status"] = "unavailable"
