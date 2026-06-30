from __future__ import annotations

from typing import Protocol

import z3

from pysymex.contracts import ensures, requires


class _ContractReceiver(Protocol):
    balance: z3.ArithRef


def test_callable_postcondition_first_parameter_is_bound_to_return_value() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def postcondition(output: int, x: int) -> bool:
        return output == x + 1

    @ensures(postcondition)
    def increment(x: int) -> int:
        return x + 1

    res = verify(increment, {"x": "int"})
    assert res.contract_issues == []


def test_callable_contract_predicate_defaults_are_supported() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def precondition(x: z3.ArithRef, minimum: int = 0) -> z3.BoolRef:
        return x >= minimum

    def postcondition(output: z3.ArithRef, x: z3.ArithRef, offset: int = 0) -> z3.BoolRef:
        return output == x + offset

    @requires(precondition)
    @ensures(postcondition)
    def identity(x: int) -> int:
        return x

    res = verify(identity, {"x": "int"})

    assert res.contract_issues == []
    assert res.contracts_checked == 2
    assert res.contracts_verified == 2


def test_callable_method_contracts_can_read_modeled_receiver_attributes() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    def precondition(self: _ContractReceiver, amount: z3.ArithRef) -> z3.BoolRef:
        return self.balance >= amount

    def postcondition(
        output: z3.ArithRef,
        self: _ContractReceiver,
        amount: z3.ArithRef,
    ) -> z3.BoolRef:
        return output == self.balance - amount

    class Wallet:
        def __init__(self) -> None:
            self.balance = 10

        @requires(precondition)
        @ensures(postcondition)
        def spend(self, amount: int) -> int:
            return self.balance - amount

    res = verify(Wallet().spend, {"amount": "int"})

    assert res.contract_issues == []
    assert res.contracts_checked == 2
    assert res.contracts_verified == 2
