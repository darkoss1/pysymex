from __future__ import annotations

import z3

from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractViolation,
    FunctionContract,
    EffectKind,
)


class TestContractType:
    """Test suite for Contract in contracts/types.py."""

    def test_contract_initialization_string_predicate(self) -> None:
        """Verify Contract caching for string predicate."""
        contract = Contract(kind=ContractKind.REQUIRES, predicate="x > 0")
        assert contract.condition == "x > 0"

    def test_contract_initialization_callable_predicate(self) -> None:
        """Verify Contract caching for callable predicate."""

        def my_pred(x: z3.ArithRef) -> z3.BoolRef:
            return x > 0

        contract = Contract(kind=ContractKind.REQUIRES, predicate=my_pred)
        assert "my_pred" in contract.condition

    def test_contract_compile(self) -> None:
        """Verify that Contract.compile delegates to ContractCompiler."""
        contract = Contract(kind=ContractKind.REQUIRES, predicate="x == 0")
        symbols = {"x": z3.Int("x")}
        result = contract.compile(symbols)
        assert isinstance(result, z3.BoolRef)


class TestContractViolation:
    """Test suite for ContractViolation in contracts/types.py."""

    def test_violation_format_all_fields(self) -> None:
        """Verify formatting with all fields present."""
        violation = ContractViolation(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="Must be positive",
            line_number=42,
            function_name="foo.bar",
            counterexample={"x": 0},
            bytecode_offset=10,
        )
        fmt = violation.format()
        assert "at line 42" in fmt
        assert "in foo.bar" in fmt
        assert "offset 0x0A" in fmt
        assert "Must be positive" in fmt
        assert "x = 0" in fmt

    def test_violation_format_missing_optional_fields(self) -> None:
        """Verify formatting with missing optional fields."""
        violation = ContractViolation(
            kind=ContractKind.ENSURES,
            condition="y == 1",
            message="y is not 1",
        )
        fmt = violation.format()
        assert "[ENSURES]: y is not 1" in fmt


class TestFunctionContract:
    """Test suite for FunctionContract in contracts/types.py."""

    def test_add_precondition(self) -> None:
        """Verify appending precondition."""
        fc = FunctionContract(function_name="foo")
        fc.add_precondition("x > 0")
        assert len(fc.preconditions) == 1
        assert fc.preconditions[0].kind == ContractKind.REQUIRES

    def test_add_postcondition(self) -> None:
        """Verify appending postcondition."""
        fc = FunctionContract(function_name="foo")
        fc.add_postcondition("y == 1")
        assert len(fc.postconditions) == 1
        assert fc.postconditions[0].kind == ContractKind.ENSURES

    def test_add_assumption(self) -> None:
        """Verify appending assumption."""
        fc = FunctionContract(function_name="foo")
        fc.add_assumption("True")
        assert len(fc.assumptions) == 1
        assert fc.assumptions[0].kind == ContractKind.ASSUMES

    def test_add_loop_invariant(self) -> None:
        """Verify appending loop invariant."""
        fc = FunctionContract(function_name="foo")
        fc.add_loop_invariant(10, "i < 10")
        assert 10 in fc.loop_invariants
        assert len(fc.loop_invariants[10]) == 1
        assert fc.loop_invariants[10][0].kind == ContractKind.LOOP_INVARIANT

    def test_set_assigns(self) -> None:
        """Verify setting assigns frozenset."""
        fc = FunctionContract(function_name="foo")
        fc.set_assigns(frozenset({"x"}))
        assert fc.assigns_set == frozenset({"x"})

    def test_set_pure(self) -> None:
        """Verify setting pure effect type."""
        fc = FunctionContract(function_name="foo")
        fc.set_pure()
        assert fc.effect_type == EffectKind.PURE
