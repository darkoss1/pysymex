from __future__ import annotations

from pysymex.contracts import ensures, requires
from pysymex.contracts.types import ContractKind, VerificationResult
from pysymex.execution.executors.verified.api import verify


class ModuleCounter:
    @requires("x >= 0")
    @ensures("result() >= 0")
    def bump(self, x: int) -> int:
        return x


module_counter = ModuleCounter()


def _module_global_instance_caller(x: int) -> int:
    return module_counter.bump(x - 3)


def test_module_global_instance_method_contracts_bind_receiver() -> None:
    result = verify(_module_global_instance_caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_staticmethod_contracts_do_not_bind_receiver() -> None:
    class Factory:
        @staticmethod
        @requires("x >= 0")
        @ensures("result() >= 0")
        def build(x: int) -> int:
            return x

    def caller(x: int) -> int:
        return Factory.build(x - 5)

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_nested_precondition_checks_can_be_disabled_without_disabling_postconditions() -> None:
    result = verify(
        _module_global_instance_caller,
        {"x": "int"},
        check_preconditions=False,
    )

    assert result.issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_nested_classmethod_contracts_bind_class_receiver() -> None:
    class Factory:
        @classmethod
        @requires("x >= 0")
        @ensures("result() >= 0")
        def build(cls, x: int) -> int:
            return x

    def caller(x: int) -> int:
        return Factory.build(x - 5)

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_classmethod_explicit_class_argument_is_not_the_bound_receiver() -> None:
    class Factory:
        @classmethod
        @requires("x >= 0")
        @ensures("result() >= 0")
        def build(cls, marker: object, x: int) -> int:
            return x

    def caller(x: int) -> int:
        return Factory.build(Factory, x - 5)

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]
