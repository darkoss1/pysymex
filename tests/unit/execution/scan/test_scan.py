from __future__ import annotations

import types

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.analysis.records import IssueRecord
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.scan.callables import prioritize_scan_items
from pysymex._internal.execution.scan.hints import callable_type_hints
from pysymex._internal.execution.scan.issues import emit_execution_issues
from pysymex._internal.execution.scan.partition import split_module_item
from pysymex._internal.execution.scan.types import CodeContext


class CollectingIssueSink:
    def __init__(self) -> None:
        self.issues: list[Issue | IssueRecord] = []

    def handle_issue(self, issue: Issue | IssueRecord) -> None:
        self.issues.append(issue)


def test_emit_execution_issues_attaches_code_context() -> None:
    code = _single_function_code()
    sink = CollectingIssueSink()
    result = ExecutionResult(issues=[Issue(kind=IssueKind.UNKNOWN, message="unit", pc=7)])

    emit_execution_issues(result, code, "Owner", "pkg/mod.py", sink)

    assert len(sink.issues) == 1
    emitted = sink.issues[0]
    assert isinstance(emitted, Issue)
    assert emitted.function_name == "target"
    assert emitted.class_name == "Owner"
    assert emitted.full_path == "pkg/mod.py"
    assert emitted.pc == 7


def test_emit_execution_issues_preserves_existing_callee_context() -> None:
    code = _single_function_code()
    sink = CollectingIssueSink()
    result = ExecutionResult(
        issues=[
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message="unit",
                pc=11,
                function_name="helper",
            )
        ]
    )

    emit_execution_issues(result, code, None, "target", sink)

    assert len(sink.issues) == 1
    emitted = sink.issues[0]
    assert isinstance(emitted, Issue)
    assert emitted.function_name == "helper"
    assert emitted.full_path == "helper"
    assert emitted.pc == 11


def test_split_module_item_separates_module_code() -> None:
    module_code = compile("def target():\n    return 1\n", "<scan-test>", "exec")
    function_code = _single_function_code()

    module_item, other_items = split_module_item(
        [(function_code, None, "target"), (module_code, None, None)]
    )

    assert module_item is not None
    assert module_item[0] is module_code
    assert other_items == [(function_code, None, "target")]


def test_callable_type_hints_includes_init_attributes() -> None:
    hints = callable_type_hints(
        source_type_hints={
            ("method", "Widget"): {"x": "int"},
            ("__init__", "Widget"): {"self": "Widget", "size": "int"},
        },
        code_name="method",
        class_name="Widget",
    )

    assert hints == {"x": "int", "__init__.size": "int"}


def test_prioritized_scan_items_runs_no_arg_wrappers_before_symbolic_entrypoints() -> None:
    module_code = compile(
        "def target(mode: int) -> int:\n"
        "    return mode\n"
        "\n"
        "def trigger_bug() -> int:\n"
        "    return target(1)\n"
        "\n"
        "def other(value: int) -> int:\n"
        "    return value\n",
        "<scan-test>",
        "exec",
    )
    code_by_name = {
        constant.co_name: constant
        for constant in module_code.co_consts
        if isinstance(constant, types.CodeType)
    }
    items: list[CodeContext] = [
        (code_by_name["target"], None, "target"),
        (code_by_name["trigger_bug"], None, "trigger_bug"),
        (code_by_name["other"], None, "other"),
    ]

    ordered_names = [item[0].co_name for item in prioritize_scan_items(items)]

    assert ordered_names == ["trigger_bug", "target", "other"]


def _single_function_code() -> types.CodeType:
    module_code = compile("def target():\n    return 1\n", "<scan-test>", "exec")
    for constant in module_code.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("test fixture did not compile a function code object")
