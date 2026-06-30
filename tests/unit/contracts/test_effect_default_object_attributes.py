from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex._internal.execution.executors.verified.api import verify
from pysymex._internal.execution.executors.verified.types import VerifiedExecutionResult
from pysymex.contracts import ContractKind, assigns, pure


class Box:
    def __init__(self) -> None:
        self.items: list[int] = []


_GLOBAL_SHARED_BOX = Box()
_GLOBAL_OTHER_BOX = Box()


def _assigns_issues(result: VerifiedExecutionResult) -> list[ContractIssue]:
    return [issue for issue in result.contract_issues if issue.kind is ContractKind.ASSIGNS]


def _pure_issues(result: VerifiedExecutionResult) -> list[ContractIssue]:
    return [issue for issue in result.contract_issues if issue.kind is ContractKind.PURE]


def test_pure_reports_default_object_attribute_container_write() -> None:
    shared = Box()

    @pure
    def target(x: int, box: Box = shared) -> int:
        box.items.append(x)
        return len(box.items)

    result = verify(target, {"x": "int"})
    pure_issues = _pure_issues(result)

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "box.items[*]" in pure_issues[0].message
    assert shared.items == []


def test_assigns_allows_default_object_attribute_container_write() -> None:
    shared = Box()

    @assigns("box.items[*]")
    def target(x: int, box: Box = shared) -> int:
        box.items.append(x)
        return len(box.items)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared.items == []


def test_assigns_rejects_distinct_default_object_attribute_container_write() -> None:
    shared = Box()
    other = Box()

    @assigns("box.items[*]")
    def target(x: int, box: Box = shared, alias: Box = other) -> int:
        alias.items.append(x)
        return len(box.items) + len(alias.items)

    result = verify(target, {"x": "int"})
    assigns_issues = _assigns_issues(result)

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "alias.items[*]" in assigns_issues[0].message
    assert shared.items == []
    assert other.items == []


def test_nested_child_reports_default_object_attribute_container_write() -> None:
    shared = Box()

    @pure
    def target(x: int, box: Box = shared) -> int:
        def child() -> None:
            box.items.append(x)

        child()
        return len(box.items)

    result = verify(target, {"x": "int"})
    pure_issues = _pure_issues(result)

    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "box.items[*]" in pure_issues[0].message
    assert shared.items == []


def test_assigns_rejects_default_object_alias_after_feasible_external_rebind() -> None:
    shared = Box()
    other = Box()

    @assigns("box.items[*]")
    def target(flag: bool, x: int, box: Box = shared, alias: Box = shared) -> int:
        if flag:
            alias = other
        alias.items.append(x)
        return len(box.items) + len(alias.items)

    result = verify(target, {"flag": "bool", "x": "int"})
    assigns_issues = _assigns_issues(result)

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "other.items[*]" in assigns_issues[0].message
    assert shared.items == []
    assert other.items == []


def test_assigns_allows_default_object_alias_when_external_rebind_is_infeasible() -> None:
    shared = Box()
    other = Box()

    @assigns("box.items[*]")
    def target(x: int, box: Box = shared, alias: Box = shared) -> int:
        if x > 0 and x < 0:
            alias = other
        alias.items.append(x)
        return len(box.items) + len(alias.items)

    result = verify(target, {"x": "int"})

    assert result.contract_issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 1
    assert shared.items == []
    assert other.items == []


def test_assigns_rejects_default_object_alias_after_feasible_global_rebind() -> None:
    _GLOBAL_SHARED_BOX.items.clear()
    _GLOBAL_OTHER_BOX.items.clear()

    @assigns("box.items[*]")
    def target(
        flag: bool,
        x: int,
        box: Box = _GLOBAL_SHARED_BOX,
        alias: Box = _GLOBAL_SHARED_BOX,
    ) -> int:
        if flag:
            alias = _GLOBAL_OTHER_BOX
        alias.items.append(x)
        return len(box.items) + len(alias.items)

    result = verify(target, {"flag": "bool", "x": "int"})
    assigns_issues = _assigns_issues(result)

    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "global._GLOBAL_OTHER_BOX.items[*]" in assigns_issues[0].message
    assert _GLOBAL_SHARED_BOX.items == []
    assert _GLOBAL_OTHER_BOX.items == []
