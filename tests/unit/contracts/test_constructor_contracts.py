from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, ensures, requires


def test_constructor_precondition_is_checked_through_class_call() -> None:
    class Box:
        value: int

        @requires("value >= 0")
        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value

    def caller(x: int) -> int:
        return Box(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_constructor_postcondition_is_checked_when_replay_would_have_summarized_init() -> None:
    class Box:
        value: int

        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value - 5

    def caller(x: int) -> int:
        return Box(x).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_constructor_postcondition_checks_can_be_disabled() -> None:
    class Box:
        value: int

        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value - 5

    def caller(x: int) -> int:
        return Box(x).value

    result = verify(caller, {"x": "int"}, check_postconditions=False)

    assert result.issues == []
    assert result.contracts_checked == 0
    assert result.contract_issues == []


def test_new_precondition_is_checked_without_construction_degradation() -> None:
    class Box:
        value: int

        @requires("value >= 0")
        def __new__(cls, value: int) -> Box:
            return object.__new__(cls)

        def __init__(self, value: int) -> None:
            self.value = value

    def caller(x: int) -> int:
        return Box(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_new_postcondition_issue_does_not_skip_init_continuation() -> None:
    class Box:
        value: int

        @ensures("value >= 0")
        def __new__(cls, value: int) -> Box:
            return object.__new__(cls)

        def __init__(self, value: int) -> None:
            self.value = value

    def caller(x: int) -> int:
        return Box(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_new_return_continues_to_init_postcondition_obligations() -> None:
    class Box:
        value: int

        @requires("value >= 0")
        def __new__(cls, value: int) -> Box:
            return object.__new__(cls)

        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value - 5

    def caller(x: int) -> int:
        return Box(x).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 2
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED),
        (ContractKind.ENSURES, VerificationResult.VIOLATED),
    ]


def test_new_subclass_return_runs_effective_init_with_original_arguments() -> None:
    class Base:
        value: int

        def __new__(cls, value: int) -> Child:
            return Child(7)

        def __init__(self, value: int) -> None:
            self.value = 99

    class Child(Base):
        def __new__(cls, value: int) -> Child:
            return object.__new__(cls)

        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value

    def caller(x: int) -> int:
        return Base(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 2
    assert result.contracts_verified == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]


def test_new_foreign_return_skips_original_init_contract_obligations() -> None:
    class Other:
        value: int

        def __init__(self) -> None:
            self.value = 11

    class ForeignBase:
        value: int

        def __new__(cls, value: int) -> Other:
            return Other()

        @ensures("self.value >= 0")
        def __init__(self, value: int) -> None:
            self.value = value - 20

    def caller(x: int) -> int:
        return ForeignBase(x).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 0
    assert result.contract_issues == []


def test_constructor_property_setter_contract_is_checked() -> None:
    class Box:
        _value: int

        def __init__(self, value: int) -> None:
            self.value = value

        @property
        def value(self) -> int:  # pyright: ignore[reportRedeclaration]
            return self._value

        @value.setter
        @requires("value >= 0")
        def value(self, value: int) -> None:  # pyright: ignore[reportRedeclaration]
            self._value = value

    def caller(x: int) -> int:
        return Box(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]


def test_constructor_custom_setattr_contract_preserves_object_setattr_write() -> None:
    class GuardedSetattr:
        @requires("value >= 0")
        def __setattr__(self, name: str, value: int) -> None:
            object.__setattr__(self, name, value)

    class Box(GuardedSetattr):
        value: int

        def __init__(self, value: int) -> None:
            self.value = value

    def caller(x: int) -> int:
        return Box(x - 5).value

    result = verify(caller, {"x": "int"})

    assert result.issues == []
    assert result.degraded_passes == []
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]
