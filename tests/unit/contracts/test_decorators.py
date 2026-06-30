from __future__ import annotations

from collections.abc import Callable, MutableMapping
from typing import cast

import pytest

from pysymex._internal.contracts.decorator.registry import ContractRegistry, function_contracts
from pysymex._internal.contracts.decorators import (
    assigns,
    assumes,
    ensures,
    invariant,
    loop_invariant,
    pure,
    requires,
)
from pysymex._internal.contracts.enums import EffectKind
from pysymex._internal.contracts.types import FunctionContract
from pysymex.contracts import ContractKind


class TestDecorators:
    """Test suite for contracts/decorators.py."""

    def test_requires_decorator(self) -> None:
        """Verify that requires decorator creates a contract and adds a precondition."""

        @requires("x > 0")
        def my_func(x: int) -> int:
            return x

        contract = ContractRegistry.get(my_func)
        assert contract is not None
        assert len(contract.preconditions) == 1
        assert contract.preconditions[0].kind == ContractKind.REQUIRES

    def test_ensures_decorator(self) -> None:
        """Verify that ensures decorator adds a postcondition."""

        @ensures("result() > 0")
        def my_func2(x: int) -> int:
            return x + 1

        contract = ContractRegistry.get(my_func2)
        assert contract is not None
        assert len(contract.postconditions) == 1
        assert contract.postconditions[0].kind == ContractKind.ENSURES

    def test_invariant_decorator(self) -> None:
        """Verify that invariant decorator adds to class __invariants__."""

        @invariant("self.x > 0")
        class MyClass:
            pass

        invariants = getattr(MyClass, "__invariants__", None)
        assert invariants is not None
        assert len(invariants) == 1
        assert invariants[0].kind == ContractKind.INVARIANT

    def test_assumes_decorator(self) -> None:
        """Verify that assumes decorator adds an assumption."""

        @assumes("True")
        def my_func3() -> None:
            pass

        contract = ContractRegistry.get(my_func3)
        assert contract is not None
        assert len(contract.assumptions) == 1
        assert contract.assumptions[0].kind == ContractKind.ASSUMES

    def test_assigns_decorator(self) -> None:
        """Verify that assigns decorator sets the assigns frozenset."""

        @assigns("self.x", "self.y")
        def my_func4() -> None:
            pass

        contract = ContractRegistry.get(my_func4)
        assert contract is not None
        assert contract.assigns_set == frozenset({"self.x", "self.y"})

    def test_pure_decorator(self) -> None:
        """Verify that pure remains distinct from the assigns frame condition."""

        @pure
        def my_func5() -> int:
            return 1

        contract = ContractRegistry.get(my_func5)
        assert contract is not None
        assert contract.effect_type == EffectKind.PURE
        assert contract.assigns_declared is False
        assert contract.assigns_set == frozenset()

    def test_loop_invariant_helper(self) -> None:
        """Verify that loop_invariant returns a Contract object."""
        contract = loop_invariant("i < 10")
        assert contract.kind == ContractKind.LOOP_INVARIANT

    def test_get_function_contract(self) -> None:
        """Verify that ContractRegistry.get retrieves the contract."""

        def undecorated() -> None:
            pass

        @requires("True")
        def decorated() -> None:
            pass

        assert ContractRegistry.get(undecorated) is None
        assert ContractRegistry.get(decorated) is not None

    def test_get_or_create_contract_preserves_registry_entry(self) -> None:
        """Losing the function attribute must not drop the keyed registry contract."""

        @requires("x > 0")
        def decorated(x: int) -> int:
            return x

        original = ContractRegistry.get(decorated)
        assert original is not None
        assert len(original.preconditions) == 1

        delattr(decorated, "__contract__")
        recovered = ContractRegistry.get_or_create(decorated)

        assert recovered is original
        assert len(recovered.preconditions) == 1

    def test_redefined_callable_does_not_inherit_stale_contracts(self) -> None:
        """New functions at the same qualified name own distinct obligations."""

        def make_function(predicate: str) -> object:
            @requires(predicate)
            def dynamic(x: int) -> int:
                return x

            return dynamic

        first = make_function("x > 0")
        second = make_function("x < 0")
        first_contract = ContractRegistry.get(cast(Callable[..., object], first))
        second_contract = ContractRegistry.get(cast(Callable[..., object], second))

        assert first_contract is not None
        assert second_contract is not None
        assert first_contract is not second_contract
        assert [item.condition for item in first_contract.preconditions] == ["x > 0"]
        assert [item.condition for item in second_contract.preconditions] == ["x < 0"]

    def test_function_contracts_public_view_is_read_only(self) -> None:
        """The public registry view must not expose direct mutation of global state."""
        with pytest.raises(TypeError):
            cast(MutableMapping[str, FunctionContract], function_contracts)["tests.mutated"] = (
                FunctionContract("mutated")
            )

    def test_contract_verifier_package_export_is_lazy(self) -> None:
        """Verify the verifier module works without eager solver import cycles."""
        from pysymex._internal.contracts.verifier import ContractVerifier

        assert ContractVerifier.__name__ == "ContractVerifier"
