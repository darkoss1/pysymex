"""Hundred-case symbolic-execution corpus for basic engine behavior."""

from __future__ import annotations

import textwrap
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

import pytest

from pysymex.analysis.detectors import IssueKind
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig


@dataclass(frozen=True, slots=True)
class CorpusCase:
    name: str
    source: str
    symbolic_args: Mapping[str, str]
    expected_issue_kinds: frozenset[IssueKind] = frozenset()

    @property
    def expects_clean_run(self) -> bool:
        return not self.expected_issue_kinds


_ANNOTATIONS: Mapping[str, str] = {
    "bool": "bool",
    "dict": "dict[str, int]",
    "float": "float",
    "int": "int",
    "list": "list[int]",
    "none": "object",
    "nullable": "object",
    "object": "object",
    "str": "str",
}


def _case(
    name: str,
    symbolic_args: Mapping[str, str],
    body: str,
    *,
    expected_issue_kinds: Iterable[IssueKind] = (),
) -> CorpusCase:
    params = ", ".join(
        f"{arg_name}: {_ANNOTATIONS.get(arg_type, 'object')}"
        for arg_name, arg_type in symbolic_args.items()
    )
    normalized_body = textwrap.dedent(body).strip()
    source = f"def {name}({params}) -> object:\n{textwrap.indent(normalized_body, '    ')}\n"
    return CorpusCase(
        name=name,
        source=source,
        symbolic_args=dict(symbolic_args),
        expected_issue_kinds=frozenset(expected_issue_kinds),
    )


def _clean_nonzero_division_cases() -> list[CorpusCase]:
    return [
        _case(
            f"clean_nonzero_division_{index}",
            {"x": "int"},
            f"""
            if x == {index}:
                return 100 // (x - {index} + 1)
            return 1
            """,
        )
        for index in range(10)
    ]


def _clean_guarded_list_cases() -> list[CorpusCase]:
    return [
        _case(
            f"clean_guarded_list_index_{index}",
            {"i": "int"},
            f"""
            values = [{index}, {index + 1}, {index + 2}]
            if i >= 0 and i < 3:
                return values[i]
            return values[0]
            """,
        )
        for index in range(10)
    ]


def _clean_dict_cases() -> list[CorpusCase]:
    return [
        _case(
            f"clean_dict_get_default_{index}",
            {"flag": "int"},
            f"""
            values = {{"present": {index}}}
            if flag > {index}:
                return values.get("missing", {index})
            return values["present"]
            """,
        )
        for index in range(10)
    ]


def _clean_arithmetic_branch_cases() -> list[CorpusCase]:
    return [
        _case(
            f"clean_arithmetic_branch_{index}",
            {"x": "int", "y": "int"},
            f"""
            if x > {index} and y < {index + 5}:
                return (x + y) - {index}
            return (x - y) + {index}
            """,
        )
        for index in range(10)
    ]


def _clean_fixed_loop_cases() -> list[CorpusCase]:
    return [
        _case(
            f"clean_fixed_loop_{index}",
            {"x": "int"},
            f"""
            total = 0
            for value in range({index % 4 + 1}):
                total += value
            if x > {index}:
                return total + x
            return total - x
            """,
        )
        for index in range(10)
    ]


def _division_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            f"bug_floor_division_zero_{index}",
            {"x": "int"},
            f"""
            if x == {index}:
                return 100 // (x - {index})
            return 1
            """,
            expected_issue_kinds=[IssueKind.DIVISION_BY_ZERO],
        )
        for index in range(12)
    ]


def _modulo_and_true_division_issue_cases() -> list[CorpusCase]:
    cases: list[CorpusCase] = []
    for index in range(4):
        cases.append(
            _case(
                f"bug_modulo_zero_{index}",
                {"x": "int"},
                f"""
                if x == {index}:
                    return 100 % (x - {index})
                return 1
                """,
                expected_issue_kinds=[IssueKind.DIVISION_BY_ZERO],
            )
        )
    for index in range(4):
        cases.append(
            _case(
                f"bug_true_division_zero_{index}",
                {"x": "int"},
                f"""
                if x == {index}:
                    return 100.0 / (x - {index})
                return 1.0
                """,
                expected_issue_kinds=[IssueKind.DIVISION_BY_ZERO],
            )
        )
    return cases


def _positive_index_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            f"bug_positive_index_{index}",
            {"i": "int"},
            f"""
            values = [1, 2, 3]
            if i >= {index + 3}:
                return values[i - {index}]
            return values[0]
            """,
            expected_issue_kinds=[IssueKind.INDEX_ERROR],
        )
        for index in range(10)
    ]


def _negative_index_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            f"bug_negative_index_{index}",
            {"i": "int"},
            f"""
            values = [1, 2, 3]
            if i < {-index - 3}:
                return values[i + {index}]
            return values[0]
            """,
            expected_issue_kinds=[IssueKind.INDEX_ERROR],
        )
        for index in range(5)
    ]


def _key_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            f"bug_missing_dict_key_{index}",
            {"flag": "int"},
            f"""
            values = {{"present": {index}}}
            if flag == {index}:
                return values["missing_{index}"]
            return values["present"]
            """,
            expected_issue_kinds=[IssueKind.KEY_ERROR],
        )
        for index in range(8)
    ]


def _none_issue_cases() -> list[CorpusCase]:
    cases: list[CorpusCase] = []
    for index in range(2):
        cases.append(
            _case(
                f"bug_none_attribute_{index}",
                {"flag": "int"},
                f"""
                value = None
                if flag == {index}:
                    return value.missing
                return 0
                """,
                expected_issue_kinds=[IssueKind.NULL_DEREFERENCE],
            )
        )
    for index in range(2):
        cases.append(
            _case(
                f"bug_none_subscript_{index}",
                {"flag": "int"},
                f"""
                value = None
                if flag == {index}:
                    return value[0]
                return 0
                """,
                expected_issue_kinds=[IssueKind.NULL_DEREFERENCE],
            )
        )
    return cases


def _type_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            "bug_int_plus_string",
            {"x": "int"},
            """
            if x > 0:
                return x + "suffix"
            return x
            """,
            expected_issue_kinds=[IssueKind.TYPE_ERROR],
        ),
        _case(
            "bug_string_minus_int",
            {"x": "int"},
            """
            if x > 0:
                return "prefix" - x
            return x
            """,
            expected_issue_kinds=[IssueKind.TYPE_ERROR],
        ),
    ]


def _assertion_issue_cases() -> list[CorpusCase]:
    return [
        _case(
            "bug_explicit_assertion",
            {"x": "int"},
            """
            if x == 13:
                raise AssertionError("hundred-case assertion")
            return x
            """,
            expected_issue_kinds=[IssueKind.ASSERTION_ERROR],
        )
    ]


CASES: list[CorpusCase] = [
    *_clean_nonzero_division_cases(),
    *_clean_guarded_list_cases(),
    *_clean_dict_cases(),
    *_clean_arithmetic_branch_cases(),
    *_clean_fixed_loop_cases(),
    *_division_issue_cases(),
    *_modulo_and_true_division_issue_cases(),
    *_positive_index_issue_cases(),
    *_negative_index_issue_cases(),
    *_key_issue_cases(),
    *_none_issue_cases(),
    *_type_issue_cases(),
    *_assertion_issue_cases(),
]


def _build_executor() -> SymbolicExecutor:
    return SymbolicExecutor(
        ExecutionConfig(
            max_paths=64,
            max_depth=96,
            max_iterations=4096,
            timeout_seconds=5.0,
            solver_timeout_ms=1000,
            enable_abstract_interpretation=False,
            enable_caching=False,
            enable_chtd=False,
            enable_cross_function=False,
            enable_fp_filtering=False,
            enable_h_acceleration=False,
            enable_solver_cache=True,
            enable_state_merging=False,
            enable_type_inference=False,
            use_loop_analysis=False,
            verbose=False,
        )
    )


def _compile_case(case: CorpusCase) -> Callable[..., object]:
    namespace: dict[str, object] = {}
    code = compile(case.source, f"<hundred-case:{case.name}>", "exec")
    exec(code, namespace)
    function = namespace[case.name]
    assert callable(function)
    return function


def test_hundred_case_corpus_has_exactly_100_cases() -> None:
    assert len(CASES) == 100
    assert sum(1 for case in CASES if case.expects_clean_run) == 50
    assert sum(1 for case in CASES if not case.expects_clean_run) == 50


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_symbolic_executor_hundred_case_basic_corpus(case: CorpusCase) -> None:
    function = _compile_case(case)
    result = _build_executor().execute_function(function, symbolic_args=dict(case.symbolic_args))
    actual_issue_kinds = {issue.kind for issue in result.issues}

    assert result.paths_explored >= 1
    assert IssueKind.RUNTIME_ERROR not in actual_issue_kinds
    assert IssueKind.UNKNOWN not in actual_issue_kinds

    if case.expects_clean_run:
        assert actual_issue_kinds == set()
    else:
        assert case.expected_issue_kinds <= actual_issue_kinds
