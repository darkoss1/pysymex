from __future__ import annotations

from unittest.mock import patch

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, assumes, ensures, requires


def test_postcondition_solver_exception_is_unknown() -> None:
    @ensures("result() == x")
    def identity(x: int) -> int:
        return x

    with patch(
        "pysymex._internal.core.solver.engine.incremental.IncrementalSolver.check_sat_result",
        side_effect=RuntimeError("solver transport failed"),
    ):
        result = verify(identity, {"x": "int"})

    issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.ENSURES]
    assert len(issues) == 1
    assert issues[0].result is VerificationResult.UNKNOWN
    assert "inconclusive" in issues[0].message


def test_nested_precondition_solver_exception_is_unknown() -> None:
    @requires("x == x")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    with patch(
        "pysymex._internal.core.solver.engine.incremental.IncrementalSolver.check_sat_result",
        side_effect=RuntimeError("solver transport failed"),
    ):
        result = verify(caller, {"x": "int"})

    issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.REQUIRES]
    assert len(issues) == 1
    assert issues[0].result is VerificationResult.UNKNOWN
    assert "inconclusive" in issues[0].message


def test_unsat_nested_precondition_blocks_vacuous_callee_postcondition_proof() -> None:
    @requires("False")
    @ensures("False")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})

    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert result.contracts_violated == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED),
        (ContractKind.ENSURES, VerificationResult.UNREACHABLE),
    ]
    assert result.contract_issues[1].evidence is not None
    assert result.contract_issues[1].evidence.solver_status is SolverStatus.UNSAT


def test_unsupported_nested_precondition_blocks_dependent_callee_postcondition() -> None:
    @requires("mystery(x) > 0")
    @ensures("False")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})

    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.UNSUPPORTED),
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED),
    ]
    assert result.contract_issues[1].evidence is not None
    assert result.contract_issues[1].evidence.solver_status is SolverStatus.UNSUPPORTED
    assert result.contract_issues[1].evidence.unsupported_reasons == (
        UnsupportedReason.PREDICATE_LOWERING,
    )


def test_inconclusive_nested_precondition_blocks_dependent_callee_postcondition() -> None:
    @requires("x == x")
    @ensures("False")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    with patch(
        "pysymex._internal.core.solver.engine.incremental.IncrementalSolver.check_sat_result",
        side_effect=RuntimeError("solver transport failed"),
    ):
        result = verify(caller, {"x": "int"})

    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.UNKNOWN),
        (ContractKind.ENSURES, VerificationResult.UNKNOWN),
    ]
    assert result.contract_issues[1].evidence is not None
    assert result.contract_issues[1].evidence.solver_status is SolverStatus.UNKNOWN
    assert result.contract_issues[1].evidence.unsupported_reasons == (
        UnsupportedReason.SOLVER_FAILURE,
    )


def test_precondition_violation_does_not_hide_valid_domain_postcondition_failure() -> None:
    @requires("x > 0")
    @ensures("result() < 0")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert result.contracts_violated == 2
    assert {issue.kind for issue in result.contract_issues} == {
        ContractKind.REQUIRES,
        ContractKind.ENSURES,
    }


def test_multipath_postcondition_counts_one_declared_obligation() -> None:
    @ensures("result() > 0")
    def target(x: int, y: int) -> int:
        if x * y == 6 and x == 2:
            return -1
        return 1

    result = verify(
        target,
        {"x": "int", "y": "int"},
        max_paths=40,
        max_iterations=400,
        timeout_seconds=8,
    )

    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_later_exception_handler_keeps_contract_run_false_positive_free() -> None:
    @ensures("result() == 0")
    def target(x: int) -> int:
        try:
            if x > 0:
                raise LookupError("bad")
        except ValueError:
            return 1
        except LookupError:
            return 0
        return 0

    result = verify(target, {"x": "int"}, max_paths=8, max_iterations=160)

    assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)
    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1


def test_string_boolop_short_circuits_before_unsupported_contract_call() -> None:
    @ensures("True or mystery(x)")
    def true_or_unknown(x: int) -> int:
        return x

    true_result = verify(true_or_unknown, {"x": "int"})

    assert true_result.contract_issues == []
    assert true_result.contracts_checked == 1
    assert true_result.contracts_verified == 1

    @ensures("False and mystery(x)")
    def false_and_unknown(x: int) -> int:
        return x

    false_result = verify(false_and_unknown, {"x": "int"})

    assert false_result.contracts_checked == 1
    assert false_result.contracts_verified == 0
    assert [(issue.kind, issue.result) for issue in false_result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_string_boolop_preserves_unsupported_earlier_operand() -> None:
    @ensures("mystery(x) or True")
    def unknown_before_true(x: int) -> int:
        return x

    true_result = verify(unknown_before_true, {"x": "int"})

    assert [(issue.kind, issue.result) for issue in true_result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]

    @ensures("mystery(x) and False")
    def unknown_before_false(x: int) -> int:
        return x

    false_result = verify(unknown_before_false, {"x": "int"})

    assert [(issue.kind, issue.result) for issue in false_result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_string_boolop_short_circuits_simplifiable_result_length_before_index() -> None:
    @ensures("len(result()) == 1 or result()[0] == x")
    def length_proves_postcondition(x: int) -> object:
        return [x]

    clean_result = verify(length_proves_postcondition, {"x": "int"})

    assert clean_result.contract_issues == []
    assert clean_result.contracts_checked == 1
    assert clean_result.contracts_verified == 1

    @ensures("len(result()) == 1 or result()[0] == x")
    def length_proves_postcondition_with_runtime_bug(x: int, y: int) -> object:
        _ = x // y
        return [x]

    bug_result = verify(length_proves_postcondition_with_runtime_bug, {"x": "int", "y": "int"})

    assert bug_result.contract_issues == []
    assert bug_result.contracts_checked == 1
    assert bug_result.contracts_verified == 1
    assert [issue.kind for issue in bug_result.arithmetic_issues] == ["division_by_zero"]

    @ensures("len(result()) == 0 or result()[0] == x")
    def unsupported_rhs_required(x: int) -> object:
        return [x]

    unsupported_result = verify(unsupported_rhs_required, {"x": "int"})

    assert [(issue.kind, issue.result) for issue in unsupported_result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_nested_assumption_constrains_callee_postcondition_analysis() -> None:
    @assumes("x > 0")
    @ensures("result() > 0")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})
    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1


def test_nested_scalar_old_snapshot_belongs_to_callee_entry() -> None:
    @ensures("result() == old(x) + 1")
    def child(x: int) -> int:
        x = x + 1
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})
    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1


def test_omitted_default_parameters_use_cpython_defaults_for_postconditions() -> None:
    @ensures("result() == old(x) - 5")
    def add_default(x: int, offset: int = -5) -> int:
        return x + offset

    result = verify(add_default, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1

    symbolic_default_result = verify(add_default, {"x": "int", "offset": "int"})

    assert [(issue.kind, issue.result) for issue in symbolic_default_result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]

    @ensures("result() == old(x) + 3")
    def add_keyword_only_default(x: int, *, offset: int = 3) -> int:
        return x + offset

    kwonly_result = verify(add_keyword_only_default, {"x": "int"})

    assert kwonly_result.contract_issues == []
    assert kwonly_result.contracts_checked == 1
    assert kwonly_result.contracts_verified == 1


def test_omitted_default_lists_use_modeled_containers_for_old_length_postconditions() -> None:
    @ensures("result() == old(len(xs)) + 1")
    def append_default(xs: list[int] = []) -> int:
        xs.append(1)
        return len(xs)

    append_default.__defaults__ = ([],)
    result = verify(append_default, {})

    assert result.issues == []
    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1

    @ensures("result() == old(len(xs)) + 1")
    def child(xs: list[int] = []) -> int:
        xs.append(1)
        return len(xs)

    def caller() -> int:
        return child()

    child.__defaults__ = ([],)
    nested_result = verify(caller, {})

    assert nested_result.issues == []
    assert nested_result.contract_issues == []
    assert nested_result.contracts_checked == 1
    assert nested_result.contracts_verified == 1
