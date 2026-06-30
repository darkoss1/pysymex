from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, assigns


def test_assigns_rejects_default_alias_after_feasible_external_rebind() -> None:
    shared: list[int] = []
    other: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = shared, ys: list[int] = shared) -> int:
        if x > 0:
            ys = other
        ys.append(x)
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})
    assigns_issues = [
        issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS
    ]

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "other[*]" in assigns_issues[0].message
    assert shared == []
    assert other == []


def test_assigns_allows_default_alias_when_external_rebind_is_infeasible() -> None:
    shared: list[int] = []
    other: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = shared, ys: list[int] = shared) -> int:
        if x > 0 and x <= 0:
            ys = other
        ys.append(x)
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared == []
    assert other == []


def test_assigns_allows_default_alias_after_feasible_fresh_rebind() -> None:
    shared: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = shared, ys: list[int] = shared) -> int:
        if x > 0:
            ys = []
        ys.append(x)
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared == []


def test_assigns_allows_guarded_write_through_unrebound_default_alias() -> None:
    shared: list[int] = []

    @assigns("xs[*]")
    def target(x: int, xs: list[int] = shared, ys: list[int] = shared) -> int:
        if x > 0:
            ys.append(x)
        return len(xs) + len(ys)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared == []
