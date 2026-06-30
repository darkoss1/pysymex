from __future__ import annotations

from typing import ClassVar, Protocol

from pysymex._internal.contracts.decorators import invariant
from pysymex._internal.execution.executors.verified.executor.runner import VerifiedExecutor
from pysymex.contracts import ContractKind, VerificationResult


class _BalanceCarrier(Protocol):
    balance: int


def _balance_nonnegative(self: _BalanceCarrier) -> bool:
    return self.balance >= 0


def _account_nonnegative(account: _BalanceCarrier) -> bool:
    return account.balance >= 0


@invariant(_balance_nonnegative)
class _CallableInvariantValidAccount:
    def __init__(self) -> None:
        self.balance = 1

    def noop(self, amount: int) -> int:
        return amount


@invariant(_account_nonnegative)
class _CallableInvariantNamedReceiverAccount:
    def __init__(self) -> None:
        self.balance = 1

    def noop(self, amount: int) -> int:
        return amount


@invariant(_balance_nonnegative)
class _CallableInvariantBreakingAccount:
    def __init__(self) -> None:
        self.balance = 1

    def break_invariant(self, amount: int) -> int:
        self.balance = -1
        return amount


@invariant(_balance_nonnegative)
class _CallableInvariantPropertyAccount:
    def __init__(self) -> None:
        self._balance = 1

    @property
    def balance(self) -> int:
        return self._balance

    def noop(self, amount: int) -> int:
        return amount


@invariant("self.balance >= 0")
class _RaisingPropertyStringInvariantAccount:
    read_count: ClassVar[int] = 0

    @property
    def balance(self) -> int:
        type(self).read_count += 1
        raise RuntimeError("property descriptor was invoked")

    def noop(self, amount: int) -> int:
        return amount


@invariant(_balance_nonnegative)
class _RaisingPropertyCallableInvariantAccount:
    read_count: ClassVar[int] = 0

    @property
    def balance(self) -> int:
        type(self).read_count += 1
        raise RuntimeError("property descriptor was invoked")

    def noop(self, amount: int) -> int:
        return amount


def test_callable_invariant_can_read_modeled_shallow_receiver_attributes() -> None:
    result = VerifiedExecutor().execute_function(
        _CallableInvariantValidAccount().noop, {"amount": "int"}
    )

    assert result.contract_issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 2


def test_callable_invariant_supports_named_receiver_parameter() -> None:
    result = VerifiedExecutor().execute_function(
        _CallableInvariantNamedReceiverAccount().noop, {"amount": "int"}
    )

    assert result.contract_issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 2


def test_callable_invariant_exit_break_is_detected() -> None:
    result = VerifiedExecutor().execute_function(
        _CallableInvariantBreakingAccount().break_invariant, {"amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert len(invariant_issues) == 1
    assert invariant_issues[0].result is VerificationResult.VIOLATED
    assert "exit" in invariant_issues[0].message


def test_callable_invariant_does_not_invoke_property_descriptors() -> None:
    result = VerifiedExecutor().execute_function(
        _CallableInvariantPropertyAccount().noop, {"amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert [issue.result for issue in invariant_issues] == [
        VerificationResult.UNSUPPORTED,
        VerificationResult.UNSUPPORTED,
    ]


def test_property_backed_string_invariant_does_not_invoke_descriptor() -> None:
    _RaisingPropertyStringInvariantAccount.read_count = 0

    result = VerifiedExecutor().execute_function(
        _RaisingPropertyStringInvariantAccount().noop, {"amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert _RaisingPropertyStringInvariantAccount.read_count == 0
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert [issue.result for issue in invariant_issues] == [
        VerificationResult.UNSUPPORTED,
        VerificationResult.UNSUPPORTED,
    ]
    assert all(
        "Unsupported attribute reference: self.balance" in issue.message
        for issue in invariant_issues
    )


def test_property_backed_callable_invariant_does_not_invoke_descriptor() -> None:
    _RaisingPropertyCallableInvariantAccount.read_count = 0

    result = VerifiedExecutor().execute_function(
        _RaisingPropertyCallableInvariantAccount().noop, {"amount": "int"}
    )

    invariant_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.INVARIANT
    ]
    assert _RaisingPropertyCallableInvariantAccount.read_count == 0
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert [issue.result for issue in invariant_issues] == [
        VerificationResult.UNSUPPORTED,
        VerificationResult.UNSUPPORTED,
    ]
    assert all(
        "Unsupported receiver attribute reference: self.balance" in issue.message
        for issue in invariant_issues
    )
