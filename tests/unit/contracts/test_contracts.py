from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, ensures, requires


def test_precondition_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("x > 0")
    def safe_div(x: int) -> int:
        return 100 // x

    res = verify(safe_div, {"x": "int"})
    assert len([i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]) == 0


def test_postcondition_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    def increment(x: int) -> int:
        return x + 1

    def postcondition(__result__: int, x: int) -> bool:
        return __result__ == x + 1

    inc_ensured = ensures(postcondition)(increment)

    res = verify(inc_ensured, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 0


def test_postcondition_uses_precondition_path_facts():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("x > 0")
    @ensures("__result__ > 0")
    def identity_positive(x: int) -> int:
        return x

    res = verify(identity_positive, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []


def test_string_length_precondition_keeps_postconditions_checkable():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("len(text) <= 8")
    @ensures("result() != 0")
    def reject_bad(text: str) -> int:
        if text == "bad":
            return 0
        return 1

    res = verify(reject_bad, {"text": "str"})
    pre_issues = [i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert pre_issues == []
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.VIOLATED


def test_infeasible_entry_precondition_cannot_create_postcondition_counterexample():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("False")
    @ensures("False")
    def impossible_domain(x: int) -> int:
        return x

    res = verify(impossible_domain, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.UNREACHABLE
    assert [(i.kind, i.result) for i in res.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.UNREACHABLE),
        (ContractKind.ENSURES, VerificationResult.UNREACHABLE),
    ]
    assert res.contracts_verified == 0
    assert res.is_verified is False


def test_result_call_postcondition_is_bound_to_return_value():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("result() == x + 1")
    def increment(x: int) -> int:
        return x + 1

    res = verify(increment, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []


def test_nested_postcondition_does_not_execute_decorator_wrapper_frames():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("result() == x")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    res = verify(caller, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_nested_postcondition_violation_is_reported_once_with_callee_name():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("result() > 0")
    def child(x: int) -> int:
        return 0

    def caller(x: int) -> int:
        return child(x)

    res = verify(caller, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].function_name == "child"
    assert res.contracts_checked == 1
    assert res.contracts_violated == 1


def test_nested_verified_precondition_is_counted():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("x == x")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    res = verify(caller, {"x": "int"})
    assert res.contract_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_nested_contract_with_target_name_is_still_counted():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("x == x")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    child.__name__ = caller.__name__
    res = verify(caller, {"x": "int"})
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_nested_precondition_violations_are_reported_per_clause():
    from pysymex._internal.execution.executors.verified.api import verify

    @requires("x > 0")
    @requires("x < 0")
    def child(x: int) -> int:
        return x

    def caller(x: int) -> int:
        return child(x)

    res = verify(caller, {"x": "int"})
    pre_issues = [i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]
    assert len(pre_issues) == 2
    assert res.contracts_checked == 2
    assert res.contracts_violated == 2


def test_caught_nested_exception_preserves_outer_postcondition_frame():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("__result__ == 7")
    def raises_before_return() -> int:
        raise ValueError("boom")

    @ensures("__result__ == 1")
    def catches_nested_error() -> int:
        try:
            return raises_before_return()
        except ValueError:
            return 1

    res = verify(catches_nested_error, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []


def test_postcondition_violation_reports_feasible_counterexample():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("__result__ > 0")
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.VIOLATED


def test_unsupported_postcondition_is_classified_not_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    def unsupported(__result__: int) -> object:
        _ = __result__
        return object()

    @ensures(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
    def returns_one() -> int:
        return 1

    res = verify(returns_one, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.UNSUPPORTED


def test_unsupported_precondition_is_classified_not_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    def unsupported(x: int) -> object:
        _ = x
        return object()

    @requires(unsupported)  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})
    pre_issues = [i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]
    assert len(pre_issues) == 1
    assert pre_issues[0].result == VerificationResult.UNSUPPORTED


def test_callable_precondition_with_unbound_parameter_is_unsupported():
    from pysymex._internal.execution.executors.verified.api import verify

    def unbound_predicate(missing: int) -> bool:
        return missing > 0

    @requires(unbound_predicate)
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})
    pre_issues = [i for i in res.contract_issues if i.kind == ContractKind.REQUIRES]
    assert len(pre_issues) == 1
    assert pre_issues[0].result == VerificationResult.UNSUPPORTED


def test_scalar_old_value_postcondition_is_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("result() == old(x) + 1")
    def increment_after_rebind(x: int) -> int:
        x = x + 1
        return x

    res = verify(increment_after_rebind, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_scalar_old_value_postcondition_can_be_violated():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("result() >= old(x)")
    def decrement(x: int) -> int:
        return x - 1

    res = verify(decrement, {"x": "int"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.VIOLATED


def test_old_value_for_mutable_reference_is_unsupported():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("old(xs) == xs")
    def identity(xs: list[int]) -> list[int]:
        return xs

    res = verify(identity, {"xs": "list"})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.UNSUPPORTED


def test_supported_quantified_postcondition_is_verified():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("forall (i, 0 <= i < 1, i >= 0)")
    def returns_one() -> int:
        return 1

    res = verify(returns_one, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert post_issues == []
    assert res.contracts_checked == 1
    assert res.contracts_verified == 1


def test_false_quantified_postcondition_reports_violation():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("forall(i, 0 <= i < 1, i > 0)")
    def returns_one() -> int:
        return 1

    res = verify(returns_one, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.VIOLATED


def test_malformed_quantified_postcondition_is_unsupported():
    from pysymex._internal.execution.executors.verified.api import verify

    @ensures("forall(i, malformed, i > 0)")
    def returns_one() -> int:
        return 1

    res = verify(returns_one, {})
    post_issues = [i for i in res.contract_issues if i.kind == ContractKind.ENSURES]
    assert len(post_issues) == 1
    assert post_issues[0].result == VerificationResult.UNSUPPORTED
