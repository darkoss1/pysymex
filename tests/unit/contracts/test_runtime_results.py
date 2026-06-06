from __future__ import annotations

from unittest.mock import patch

import z3

from pysymex.config.defaults import DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
from pysymex.contracts import assumes, ensures, requires
from pysymex.contracts.ir.evidence import SolverStatus, TheoryFeature, UnsupportedReason
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.types import ContractKind, Severity, VerificationResult
from pysymex.execution.executors.verified.api import verify


def test_postcondition_solver_exception_is_unknown() -> None:
    @ensures("result() == x")
    def identity(x: int) -> int:
        return x

    with patch(
        "pysymex.core.solver.engine.incremental.IncrementalSolver.check_sat_result",
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
        "pysymex.core.solver.engine.incremental.IncrementalSolver.check_sat_result",
        side_effect=RuntimeError("solver transport failed"),
    ):
        result = verify(caller, {"x": "int"})

    issues = [issue for issue in result.contract_issues if issue.kind is ContractKind.REQUIRES]
    assert len(issues) == 1
    assert issues[0].result is VerificationResult.UNKNOWN
    assert "inconclusive" in issues[0].message


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


def test_nested_modeled_method_contracts_preserve_callable_metadata() -> None:
    class Wallet:
        def __init__(self) -> None:
            self.balance = 10

        @requires("amount >= 0")
        @ensures("result() >= old(self.balance)")
        def deposit(self, amount: int) -> int:
            self.balance = self.balance + amount
            return self.balance

    def caller(amount: int) -> int:
        wallet = Wallet()
        return wallet.deposit(amount - 20)

    result = verify(caller, {"amount": "int"})

    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_unsupported_nested_assumption_is_visible_without_claiming_proof() -> None:
    @assumes("mystery(x) > 0")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"})
    assert result.contracts_checked == 0
    assert len(result.contract_issues) == 1
    assert result.contract_issues[0].kind is ContractKind.ASSUMES
    assert result.contract_issues[0].result is VerificationResult.UNSUPPORTED


def test_unsupported_root_precondition_blocks_dependent_postcondition_claim() -> None:
    @requires("mystery(x) > 0")
    @ensures("False")
    def impossible_to_scope(x: int) -> int:
        return x

    result = verify(impossible_to_scope, {"x": "int"})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.UNSUPPORTED),
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED),
    ]


def test_none_predicate_is_unsupported_instead_of_false_verification() -> None:
    @ensures("None == False")
    def target() -> int:
        return 1

    result = verify(target, {})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_float_literal_predicate_is_unsupported_instead_of_real_arithmetic_proof() -> None:
    @ensures("0.1 + 0.2 == 0.3")
    def target() -> int:
        return 1

    result = verify(target, {})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_partial_arithmetic_predicate_is_unsupported_instead_of_vacuous_proof() -> None:
    @ensures("1 // 0 == 1 // 0")
    def target() -> int:
        return 1

    result = verify(target, {})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_tuple_result_postcondition_is_unsupported_without_aggregate_encoding() -> None:
    @ensures("result() == (b, a)")
    def swap(a: int, b: int) -> tuple[int, int]:
        return (a, b)

    result = verify(swap, {"a": "int", "b": "int"})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_callable_modulo_predicate_is_unsupported_instead_of_false_verification() -> None:
    def modulo_condition(result: z3.ArithRef) -> z3.BoolRef:
        return result % -2 == 1

    @ensures(modulo_condition)
    def target() -> int:
        return 3

    result = verify(target, {})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_string_postcondition_can_query_runtime_integer_modulo_result() -> None:
    @ensures("result() >= 0")
    def target(x: int) -> int:
        return (x % 2) - 2

    result = verify(
        target,
        {"x": "int"},
        max_paths=20,
        max_iterations=200,
        solver_timeout_ms=100,
        timeout_seconds=5,
    )

    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_runtime_type_helper_postcondition_is_unsupported_not_false_violation() -> None:
    def is_positive_int(value: object) -> bool:
        return isinstance(value, int) and value > 0

    @ensures(is_positive_int)
    def target() -> int:
        return 1

    result = verify(target, {})
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_root_assumption_still_scopes_postcondition_when_requires_are_disabled() -> None:
    @assumes("x > 0")
    @ensures("result() > 0")
    def identity(x: int) -> int:
        return x

    result = verify(identity, {"x": "int"}, check_preconditions=False)
    assert result.contract_issues == []
    assert result.contracts_verified == 1


def test_nested_assumption_still_scopes_postcondition_when_requires_are_disabled() -> None:
    @assumes("x > 0")
    @ensures("result() > 0")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    result = verify(caller, {"x": "int"}, check_preconditions=False)
    assert result.contract_issues == []
    assert result.contracts_verified == 1


def test_unique_existential_postcondition_is_verified_without_free_witness() -> None:
    @ensures("exists!(i, 0 <= i < 10, i == 5)")
    def target() -> int:
        return 1

    result = verify(target, {})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1


def test_unbounded_quantifier_postcondition_has_specific_unsupported_reason() -> None:
    @ensures("forall(i, 0 <= i < n, i >= 0)")
    def target(n: int) -> int:
        return n

    result = verify(target, {"n": "int"})
    issue = result.contract_issues[0]

    assert issue.kind is ContractKind.ENSURES
    assert issue.result is VerificationResult.UNSUPPORTED
    assert issue.evidence is not None
    assert issue.evidence.unsupported_reasons == (UnsupportedReason.UNBOUNDED_QUANTIFIER,)


def test_warning_contract_severity_survives_verified_execution_reporting() -> None:
    @ensures("result() > 0", severity=Severity.WARNING)
    def target() -> int:
        return 0

    result = verify(target, {})
    issue = result.contract_issues[0]

    assert issue.severity is Severity.WARNING
    assert "[WARNING]" in issue.format()


def test_contract_issue_carries_runtime_evidence() -> None:
    @ensures("result() > 0")
    def target() -> int:
        return 0

    result = verify(target, {})
    issue = result.contract_issues[0]

    assert issue.result is VerificationResult.VIOLATED
    assert issue.evidence is not None
    assert issue.evidence.solver_status is SolverStatus.SAT
    assert issue.evidence.need_model is True
    assert issue.evidence.timeout_ms == DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
    assert TheoryFeature.INTEGER in issue.evidence.theory_profile
    assert issue.evidence.obligation.hook is ObligationHook.FRAME_EXIT
    assert issue.evidence.obligation.query_kind is QueryKind.POSTCONDITION
