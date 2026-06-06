from __future__ import annotations

from collections.abc import Callable
from typing import cast

from pysymex.contracts import ContractKind, VerificationResult
from pysymex.contracts.decorators import invariant
from pysymex.execution.executors.verified.executor import VerifiedExecutor
from pysymex.execution.executors.verified.types import VerifiedExecutionConfig


@invariant("self.balance >= 0")
class _ValidBoundAccount:
    def __init__(self) -> None:
        self.balance = 1

    def withdraw(self, amount: int) -> int:
        return amount


@invariant("self.balance >= 0")
class _InvalidConstructorAccount:
    def __init__(self) -> None:
        self.balance = -1


@invariant("self.balance >= 0")
class _BreakingPublicAccount:
    def break_invariant(self, amount: int) -> int:
        self.balance = -1
        return amount


@invariant("self.balance >= 0")
class _BoundMutableAccount:
    def __init__(self) -> None:
        self.balance = 1

    def withdraw(self, amount: int) -> int:
        self.balance = self.balance - amount
        return self.balance


@invariant("self.balance >= 0")
class _NestedWrapperAccount:
    def __init__(self) -> None:
        self.balance = 1

    def withdraw(self, amount: int) -> int:
        self.balance = self.balance - amount
        return self.balance


@invariant("self.balance >= 0")
class _UnmodeledEntryAccount:
    def withdraw(self, amount: int) -> int:
        return amount


@invariant("self.balance >= 0")
class _PrivateMutationAccount:
    def _reset(self) -> int:
        self.balance = -1
        return 0


def test_bound_public_method_invariant_is_checked_at_entry_and_exit() -> None:
    result = VerifiedExecutor().execute_function(_ValidBoundAccount().withdraw, {"amount": "int"})

    assert result.contracts_checked == 2
    assert result.contracts_verified == 2
    assert result.contract_issues == []


def test_invalid_constructor_exit_invariant_is_detected() -> None:
    result = VerifiedExecutor().execute_function(
        _InvalidConstructorAccount.__init__, {"self": "object"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 1
    assert len(invariant_issues) == 1
    assert invariant_issues[0].result is VerificationResult.VIOLATED
    assert "exit" in invariant_issues[0].message


def test_public_method_exit_invariant_break_is_detected() -> None:
    result = VerifiedExecutor().execute_function(
        _BreakingPublicAccount.break_invariant, {"self": "object", "amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 2
    assert any(issue.result is VerificationResult.VIOLATED for issue in invariant_issues)
    assert any(issue.result is VerificationResult.UNSUPPORTED for issue in invariant_issues)


def test_bound_method_exit_invariant_does_not_use_stale_receiver_snapshot() -> None:
    result = VerifiedExecutor().execute_function(_BoundMutableAccount().withdraw, {"amount": "int"})

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert len(invariant_issues) == 1
    assert invariant_issues[0].result is VerificationResult.UNSUPPORTED
    assert any("exit" in issue.message for issue in invariant_issues)


def test_nested_modeled_method_invariant_is_checked_through_wrapper() -> None:
    def wrapper(amount: int) -> int:
        account = _NestedWrapperAccount()
        return account.withdraw(amount)

    result = VerifiedExecutor().execute_function(wrapper, {"amount": "int"})

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 3
    assert result.contracts_verified == 2
    assert any(issue.result is VerificationResult.VIOLATED for issue in invariant_issues)
    assert any("exit" in issue.message for issue in invariant_issues)


def test_unmodeled_public_receiver_state_is_unsupported_not_verified() -> None:
    result = VerifiedExecutor().execute_function(
        _UnmodeledEntryAccount.withdraw, {"self": "object", "amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert {issue.result for issue in invariant_issues} == {VerificationResult.UNSUPPORTED}


def test_disabled_class_invariant_check_does_not_report_obligation() -> None:
    config = VerifiedExecutionConfig(check_class_invariants=False)
    result = VerifiedExecutor(config).execute_function(
        _ValidBoundAccount().withdraw, {"amount": "int"}
    )

    assert result.contracts_checked == 0
    assert result.contract_issues == []


def test_private_method_invariant_obligations_are_off_by_default() -> None:
    private_reset = cast(Callable[[object], int], getattr(_PrivateMutationAccount, "_reset"))
    result = VerifiedExecutor().execute_function(private_reset, {"self": "object"})

    assert result.contracts_checked == 0
    assert [issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT] == []
