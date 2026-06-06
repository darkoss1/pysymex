from __future__ import annotations

from pysymex.contracts import ensures
from pysymex.contracts.types import ContractKind, VerificationResult
from pysymex.execution.executors.verified.api import check_arithmetic, verify


def test_verify_does_not_report_fixed_width_overflow_for_python_int_addition() -> None:
    def add(left: int, right: int) -> int:
        return left + right

    result = verify(add, {"left": "int", "right": "int"})

    assert result.arithmetic_issues == []


def test_real_average_contract_does_not_add_python_int_overflow_false_positive() -> None:
    @ensures("result() == (left + right) / 2")
    def average(left: int, right: int) -> int:
        return (left + right) // 2

    result = verify(average, {"left": "int", "right": "int"})

    assert result.arithmetic_issues == []
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNSUPPORTED)
    ]


def test_check_arithmetic_explicitly_enables_bounded_integer_overflow_policy() -> None:
    def add(left: int, right: int) -> int:
        return left + right

    issues = check_arithmetic(add, {"left": "int", "right": "int"})

    assert any(issue.kind == "overflow" for issue in issues)
    assert any("bounded integer overflow" in issue.message for issue in issues)


def test_detect_overflow_enables_bounded_integer_checks() -> None:
    def add(left: int, right: int) -> int:
        return left + right

    issues = verify(add, {"left": "int", "right": "int"}, detect_overflow=True).arithmetic_issues

    assert any(issue.kind == "overflow" for issue in issues)
