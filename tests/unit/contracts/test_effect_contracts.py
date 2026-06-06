from __future__ import annotations

from pysymex.contracts import assigns, pure
from pysymex.contracts.types import ContractKind, VerificationResult

contract_effect_global = 0


def test_pure_decorator() -> None:
    from pysymex.execution.executors.verified.api import verify

    def pure_func(x: int) -> int:
        return x * 2

    pure_f = pure(pure_func)

    res = verify(pure_f, {"x": "int"})
    assert len([iss for iss in res.issues if "unbound" in iss.message]) == 0
    assert res.contract_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_pure_decorator_catches_modeled_global_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @pure
    def writes_global(x: int) -> int:
        global contract_effect_global
        contract_effect_global = x
        return x

    res = verify(writes_global, {"x": "int"})
    pure_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.PURE]
    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "global.contract_effect_global" in pure_issues[0].message


def test_empty_assigns_catches_modeled_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @assigns()
    def writes_global(x: int) -> int:
        global contract_effect_global
        contract_effect_global = x
        return x

    res = verify(writes_global, {"x": "int"})
    assigns_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.ASSIGNS]
    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED


def test_pure_catches_modeled_list_append_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @pure
    def appends_to_argument(xs: list[int], x: int) -> int:
        xs.append(x)
        return len(xs)

    res = verify(appends_to_argument, {"xs": "list", "x": "int"})
    pure_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.PURE]
    assert len(pure_issues) == 1
    assert pure_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in pure_issues[0].message
    assert "model.append" in pure_issues[0].message


def test_empty_assigns_catches_modeled_list_append_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @assigns()
    def appends_to_argument(xs: list[int], x: int) -> int:
        xs.append(x)
        return len(xs)

    res = verify(appends_to_argument, {"xs": "list", "x": "int"})
    assigns_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.ASSIGNS]
    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "xs[*]" in assigns_issues[0].message


def test_assigns_allows_declared_modeled_list_append_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @assigns("xs[*]")
    def appends_to_argument(xs: list[int], x: int) -> int:
        xs.append(x)
        return len(xs)

    res = verify(appends_to_argument, {"xs": "list", "x": "int"})
    assigns_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.ASSIGNS]
    assert assigns_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_assigns_allows_tracked_shallow_attribute_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @assigns("self.balance")
    def deposit(self: object, amount: int) -> int:
        self.balance = amount  # type: ignore[attr-defined]
        return amount

    res = verify(deposit, {"self": "object", "amount": "int"})
    assigns_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.ASSIGNS]
    assert assigns_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_assigns_rejects_other_tracked_shallow_attribute_write() -> None:
    from pysymex.execution.executors.verified.api import verify

    @assigns("self.balance")
    def deposit(self: object, amount: int) -> int:
        self.audit = amount  # type: ignore[attr-defined]
        return amount

    res = verify(deposit, {"self": "object", "amount": "int"})
    assigns_issues = [issue for issue in res.contract_issues if issue.kind is ContractKind.ASSIGNS]
    assert len(assigns_issues) == 1
    assert assigns_issues[0].result is VerificationResult.VIOLATED
    assert "self.audit" in assigns_issues[0].message
