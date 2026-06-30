from __future__ import annotations

from collections.abc import Callable

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.executors.verified.api import verify
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex.contracts import ensures


def _execute_with_contracts(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None,
    initial_values: dict[str, object],
) -> ExecutionResult:
    executor = SymbolicExecutor(
        ExecutionConfig(
            max_paths=20,
            max_iterations=100,
            enable_contract_verification=True,
            check_contract_preconditions=True,
            check_contract_postconditions=True,
        )
    )
    return executor.execute_function(func, symbolic_args, initial_values)


def test_container_initial_values_seed_exact_contract_entry_snapshots() -> None:
    @ensures("result() == old(len(xs)) + 1")
    def append_initial_list(xs: list[int]) -> int:
        xs.append(1)
        return len(xs)

    list_result = _execute_with_contracts(append_initial_list, None, {"xs": []})

    assert list_result.issues == []

    @ensures("result() == old(len(d)) + 1")
    def set_initial_dict(d: dict[str, int]) -> int:
        d["x"] = 1
        return len(d)

    dict_result = _execute_with_contracts(set_initial_dict, None, {"d": {}})

    assert dict_result.issues == []


def test_exact_set_entry_snapshots_support_old_length_postconditions() -> None:
    @ensures("result() == old(len(s)) + 1")
    def add_initial_set(s: set[int]) -> int:
        s.add(1)
        return len(s)

    initial_result = _execute_with_contracts(add_initial_set, None, {"s": set()})

    assert initial_result.issues == []

    @ensures("result() == old(len(s)) + 1")
    def add_default_set(s: set[int] = set()) -> int:
        s.add(1)
        return len(s)

    add_default_set.__defaults__ = (set(),)
    default_result = verify(add_default_set, {})

    assert default_result.issues == []
    assert default_result.contract_issues == []
    assert default_result.contracts_checked == 1
    assert default_result.contracts_verified == 1


def test_scalar_initial_values_remain_precise_contract_constraints() -> None:
    @ensures("result() == old(x) + 2")
    def add_initial_scalar(x: int) -> int:
        return x + 2

    result = _execute_with_contracts(add_initial_scalar, {"x": "int"}, {"x": 4})

    assert not result.get_issues_by_kind(IssueKind.CONTRACT_VIOLATION)
