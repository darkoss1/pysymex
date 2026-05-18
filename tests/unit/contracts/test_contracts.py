from pysymex.contracts import requires, ensures, invariant, pure
from pysymex.contracts.types import ContractKind, VerificationResult


def test_precondition_verified():
    from pysymex.execution.executors.verified import verify

    @requires("x > 0")
    def safe_div(x: int) -> int:
        return 100 // x

    res = verify(safe_div, {"x": "int"})
    assert len([i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]) == 0


def test_postcondition_verified():
    from pysymex.execution.executors.verified import verify

    def increment(x: int) -> int:
        return x + 1

    def postcondition(__result__: int, x: int) -> bool:
        return __result__ == x + 1

    inc_ensured = ensures(postcondition)(increment)

    res = verify(inc_ensured, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 0


def test_postcondition_uses_precondition_path_facts():
    from pysymex.execution.executors.verified import verify

    @requires("x > 0")
    @ensures("__result__ > 0")
    def identity_positive(x: int) -> int:
        return x

    res = verify(identity_positive, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []


def test_postcondition_violation_reports_feasible_counterexample():
    from pysymex.execution.executors.verified import verify

    @ensures("__result__ > 0")
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.VIOLATED


def test_unsupported_postcondition_is_unknown_not_verified():
    from pysymex.execution.executors.verified import verify

    def unsupported(__result__: int) -> object:
        _ = __result__
        return object()

    @ensures(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
    def returns_one() -> int:
        return 1

    res = verify(returns_one, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.UNKNOWN


def test_unsupported_precondition_is_unknown_not_verified():
    from pysymex.execution.executors.verified import verify

    def unsupported(x: int) -> object:
        _ = x
        return object()

    @requires(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})
    pre_issues = [i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]
    assert len(pre_issues) == 1
    assert pre_issues[0].result == VerificationResult.UNKNOWN


def test_class_invariant_verified():
    @invariant("self.balance >= 0")
    class TestAccount:
        def __init__(self, balance: int):
            self.balance = balance

        def withdraw(self, amount: int):
            self.balance = -1
            return self.balance

    from pysymex.analysis.specialized.invariants import (
        ClassInvariant,
        InvariantState,
        check_object_invariants,
    )

    state = InvariantState()
    invariants = getattr(TestAccount, "__invariants__", [])
    class_invariants: list[ClassInvariant] = []
    for inv in invariants:
        class_invariants.append(
            ClassInvariant(condition=inv.condition, message=inv.message, class_name="TestAccount")
        )
    state.register_class("TestAccount", class_invariants)

    acc = TestAccount(-1)
    check_object_invariants(acc, state, "init", "init", [])
    assert len(state.violations) > 0


def test_pure_decorator():
    from pysymex.execution.executors.verified import verify

    def pure_func(x: int) -> int:
        return x * 2

    pure_f = pure(pure_func)

    res = verify(pure_f, {"x": "int"})
    assert len([iss for iss in res.issues if "unbound" in iss.message]) == 0


if __name__ == "__main__":
    pass
