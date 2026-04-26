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
    inc_ensured = ensures(lambda __result__, x: __result__ == x + 1)(increment)

    res = verify(inc_ensured, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 0

def test_class_invariant_verified():
    from pysymex.execution.executors.verified import verify
    @invariant("self.balance >= 0")
    class TestAccount:
        def __init__(self, balance: int):
            self.balance = balance

        def withdraw(self, amount: int):
            self.balance = -1
            return self.balance

    def execute_account(balance: int) -> TestAccount:
        acc = TestAccount(balance)
        acc.balance = -10
        return acc

    from pysymex.analysis.specialized.invariants import check_object_invariants, InvariantState, InvariantViolation, ClassInvariant
    state = InvariantState()
    invariants = getattr(TestAccount, "__invariants__", [])
    class_invariants = []
    for inv in invariants:
        class_invariants.append(ClassInvariant(condition=inv.condition, message=inv.message, class_name="TestAccount"))
    state.register_class("TestAccount", class_invariants)

    acc = TestAccount(-1)
    res = check_object_invariants(acc, state, "init", "init", [])
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
