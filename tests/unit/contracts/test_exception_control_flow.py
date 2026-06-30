from __future__ import annotations

from collections.abc import Callable

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, ensures, invariant


@ensures("result() == 7")
def finally_return_suppresses_user_exception(x: int) -> int:
    try:
        if x > 0:
            raise ValueError("bad")
        return 7
    finally:
        return 7


@ensures("result() == 0")
def subclass_handler_catches_key_error(x: int) -> int:
    try:
        if x > 0:
            raise KeyError("bad")
    except LookupError:
        return 0
    return 0


@ensures("result() == 0")
def raise_from_caught_by_outer_value_error(x: int) -> int:
    try:
        try:
            if x > 0:
                raise TypeError("cause")
        except TypeError as exc:
            raise ValueError("wrapped") from exc
    except ValueError:
        return 0
    return 0


@ensures("result() == 0")
def except_else_normal_path_safe(x: int) -> int:
    try:
        if x > 0:
            value = 0
        else:
            raise ValueError("bad")
    except ValueError:
        value = 0
    else:
        value = 0
    return value


@ensures("result() == 5")
def property_getattr_attribute_error_caught(y: int) -> int:
    class Box:
        @property
        def value(self) -> int:
            raise AttributeError("value")

        def __getattr__(self, name: str) -> int:
            if name == "value":
                raise AttributeError(name)
            return 10 // y

    try:
        return Box().value
    except AttributeError:
        return 5


@ensures("result() == 0")
def finally_conditional_return_violation(x: int) -> int:
    try:
        return 0
    finally:
        if x > 0:
            return 1


@ensures("result() == 0")
def except_branch_postcondition_violation(x: int) -> int:
    try:
        if x > 0:
            raise ValueError("bad")
    except ValueError:
        return 1
    return 0


@invariant("self.balance >= 0")
class _CaughtCalleeContractAccount:
    def __init__(self) -> None:
        self.balance = 1

    @ensures("result() == 99")
    def explode(self, x: int) -> int:
        self.balance = self.balance - x
        raise ValueError("boom")


@ensures("result() == 0")
def catches_raising_contract_method_after_receiver_mutation(x: int) -> int:
    account = _CaughtCalleeContractAccount()
    try:
        account.explode(x)
    except ValueError:
        return 0
    return 1


def test_exception_control_flow_false_positive_controls() -> None:
    cases: tuple[tuple[Callable[[int], int], int, int], ...] = (
        (finally_return_suppresses_user_exception, 7, 7),
        (subclass_handler_catches_key_error, 0, 0),
        (raise_from_caught_by_outer_value_error, 0, 0),
        (except_else_normal_path_safe, 0, 0),
    )
    for target, negative_result, positive_result in cases:
        assert target(-1) == negative_result
        assert target(1) == positive_result

        result = verify(target, {"x": "int"}, max_paths=20, max_iterations=500)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)
        assert result.contract_issues == []
        assert result.contracts_checked == 1
        assert result.contracts_verified == 1


def test_property_getattr_attribute_error_handler_has_no_unhandled_false_positive() -> None:
    assert property_getattr_attribute_error_caught(0) == 5

    result = verify(
        property_getattr_attribute_error_caught,
        {"y": "int"},
        max_paths=20,
        max_iterations=500,
    )

    assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)
    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1


def test_exception_control_flow_postcondition_bug_detection() -> None:
    cases: tuple[Callable[[int], int], ...] = (
        finally_conditional_return_violation,
        except_branch_postcondition_violation,
    )
    for target in cases:
        assert target(-1) == 0
        assert target(1) == 1

        result = verify(target, {"x": "int"}, max_paths=20, max_iterations=500)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)
        assert result.contracts_checked == 1
        assert result.contracts_verified == 0
        assert result.contracts_violated == 1
        assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
            (ContractKind.ENSURES, VerificationResult.VIOLATED)
        ]


def test_caught_raising_callee_drops_nested_contract_frame_after_mutation() -> None:
    assert catches_raising_contract_method_after_receiver_mutation(5) == 0

    result = verify(
        catches_raising_contract_method_after_receiver_mutation,
        {"x": "int"},
        max_paths=20,
        max_iterations=500,
    )

    assert result.issues == []
    assert result.contract_issues == []
    assert result.contracts_checked == 3
    assert result.contracts_verified == 3
