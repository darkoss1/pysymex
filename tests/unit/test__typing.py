"""Tests for pysymex._typing — shared type aliases, TypeGuards, and Protocols."""

from __future__ import annotations

import z3

import pysymex._typing as mod
from pysymex.core.types.scalars import SymbolicValue, SymbolicString


class TestSymbolicTypeProtocol:
    """Tests for SymbolicTypeProtocol — runtime_checkable Protocol."""

    def test_symbolic_value_satisfies_protocol(self) -> None:
        """SymbolicValue instances satisfy SymbolicTypeProtocol."""
        val = SymbolicValue.from_const(42)
        assert isinstance(val, mod.SymbolicTypeProtocol)

    def test_name_property(self) -> None:
        """SymbolicValue exposes a name property."""
        val = SymbolicValue.from_const(42)
        assert isinstance(val.name, str)

    def test_to_z3_returns_expr(self) -> None:
        """to_z3() returns a Z3 expression."""
        val = SymbolicValue.from_const(42)
        result = val.to_z3()
        assert isinstance(result, z3.ExprRef)

    def test_could_be_truthy_returns_boolref(self) -> None:
        """could_be_truthy() returns a Z3 BoolRef."""
        val = SymbolicValue.from_const(42)
        result = val.could_be_truthy()
        assert isinstance(result, z3.ExprRef)

    def test_could_be_falsy_returns_boolref(self) -> None:
        """could_be_falsy() returns a Z3 BoolRef."""
        val = SymbolicValue.from_const(0)
        result = val.could_be_falsy()
        assert isinstance(result, z3.ExprRef)


class TestSolverProtocol:
    """Tests for SolverProtocol — runtime_checkable Protocol."""

    def test_incremental_solver_satisfies(self) -> None:
        """IncrementalSolver satisfies SolverProtocol."""
        from pysymex.core.solver.engine import IncrementalSolver

        solver = IncrementalSolver()
        assert isinstance(solver, mod.SolverProtocol)


class TestDetectorProtocol:
    """Tests for DetectorProtocol — runtime_checkable Protocol."""

    def test_protocol_exists(self) -> None:
        """DetectorProtocol is a runtime-checkable Protocol."""
        assert hasattr(mod, "DetectorProtocol")


class TestStateViewProtocol:
    """Tests for StateViewProtocol — runtime_checkable Protocol."""

    def test_vmstate_satisfies_protocol(self) -> None:
        """VMState satisfies StateViewProtocol at structural level."""
        from pysymex.core.state import VMState

        state = VMState()
        # Check that required attributes exist
        assert hasattr(state, "pc")
        assert hasattr(state, "stack")
        assert hasattr(state, "path_constraints")

    def test_pc_property(self) -> None:
        """VMState exposes pc as int."""
        from pysymex.core.state import VMState

        state = VMState()
        assert isinstance(state.pc, int)

    def test_stack_property(self) -> None:
        """VMState exposes stack."""
        from pysymex.core.state import VMState

        state = VMState()
        assert hasattr(state.stack, "__len__")


class TestSymbolicStringProtocol:
    """Tests for SymbolicStringProtocol — runtime_checkable Protocol."""

    def test_symbolic_string_has_name(self) -> None:
        """SymbolicString has a name property."""
        ss = SymbolicString(_name="mystr")
        assert isinstance(ss.name, str)
        assert ss.name == "mystr"

    def test_symbolic_string_to_z3_returns_expr(self) -> None:
        """SymbolicString.to_z3() returns Z3 SeqRef."""
        ss = SymbolicString(_name="s", _z3_str=z3.StringVal("hello"))
        result = ss.to_z3()
        assert isinstance(result, z3.ExprRef)

    def test_could_be_truthy(self) -> None:
        """SymbolicString.could_be_truthy() returns Z3 BoolRef."""
        ss = SymbolicString(
            _name="s",
            _z3_str=z3.String("sym_s"),
            _z3_len=z3.Length(z3.String("sym_s")),
        )
        result = ss.could_be_truthy()
        assert isinstance(result, z3.ExprRef)

    def test_could_be_falsy(self) -> None:
        """SymbolicString.could_be_falsy() returns Z3 BoolRef."""
        ss = SymbolicString(
            _name="s",
            _z3_str=z3.String("sym_s"),
            _z3_len=z3.Length(z3.String("sym_s")),
        )
        result = ss.could_be_falsy()
        assert isinstance(result, z3.ExprRef)


class TestVerificationResultProtocol:
    """Tests for VerificationResultProtocol."""

    def test_protocol_exists(self) -> None:
        """VerificationResultProtocol exists as a runtime-checkable Protocol."""
        assert hasattr(mod, "VerificationResultProtocol")


class TestSymbolicContainerProtocol:
    """Tests for SymbolicContainerProtocol — runtime_checkable Protocol."""

    def test_symbolic_list_has_required_methods(self) -> None:
        """SymbolicList has name, to_z3, is_truthy, is_falsy structural methods."""
        from pysymex.core.types.containers import SymbolicList

        sl, _ = SymbolicList.symbolic("lst")
        assert hasattr(sl, "name")
        assert hasattr(sl, "to_z3")
        assert hasattr(sl, "could_be_truthy")
        assert hasattr(sl, "could_be_falsy")


class TestSummaryProtocol:
    """Tests for SummaryProtocol — runtime_checkable Protocol."""

    def test_protocol_exists(self) -> None:
        """SummaryProtocol exists."""
        assert hasattr(mod, "SummaryProtocol")


class TestSummaryBuilderProtocol:
    """Tests for SummaryBuilderProtocol."""

    def test_protocol_exists(self) -> None:
        """SummaryBuilderProtocol exists."""
        assert hasattr(mod, "SummaryBuilderProtocol")


class TestIsSymbolicValue:
    """Tests for is_symbolic_value TypeGuard."""

    def test_symbolic_value_returns_true(self) -> None:
        """SymbolicValue passes the guard."""
        val = SymbolicValue.from_const(1)
        assert mod.is_symbolic_value(val) is True

    def test_int_returns_false(self) -> None:
        """Plain int does not pass the guard."""
        assert mod.is_symbolic_value(42) is False

    def test_none_returns_false(self) -> None:
        """None does not pass the guard."""
        assert mod.is_symbolic_value(None) is False

    def test_string_returns_false(self) -> None:
        """Plain string does not pass the guard."""
        assert mod.is_symbolic_value("hello") is False


class TestIsSymbolicString:
    """Tests for is_symbolic_string TypeGuard."""

    def test_symbolic_string_returns_true(self) -> None:
        """SymbolicString passes the guard."""
        assert mod.is_symbolic_string(SymbolicString(_name="s")) is True

    def test_plain_string_returns_false(self) -> None:
        """Plain str does not pass the guard."""
        assert mod.is_symbolic_string("hello") is False

    def test_symbolic_value_returns_false(self) -> None:
        """SymbolicValue (int) does not pass the string guard."""
        assert mod.is_symbolic_string(SymbolicValue.from_const(1)) is False


class TestIsSymbolicContainer:
    """Tests for is_symbolic_container TypeGuard."""

    def test_symbolic_list_returns_true(self) -> None:
        """SymbolicList passes the container guard."""
        from pysymex.core.types.containers import SymbolicList

        sl, _ = SymbolicList.symbolic("lst")
        assert mod.is_symbolic_container(sl) is True

    def test_plain_list_returns_false(self) -> None:
        """Plain list does not pass the container guard."""
        assert mod.is_symbolic_container([1, 2, 3]) is False

    def test_int_returns_false(self) -> None:
        """Int does not pass the container guard."""
        assert mod.is_symbolic_container(42) is False


class TestIsListOfObjects:
    """Tests for is_list_of_objects TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list passes."""
        assert mod.is_list_of_objects([1, "a"]) is True

    def test_tuple_returns_false(self) -> None:
        """A tuple does not pass."""
        assert mod.is_list_of_objects((1, 2)) is False

    def test_dict_returns_false(self) -> None:
        """A dict does not pass."""
        assert mod.is_list_of_objects({"a": 1}) is False


class TestIsTupleOfObjects:
    """Tests for is_tuple_of_objects TypeGuard."""

    def test_tuple_returns_true(self) -> None:
        """A tuple passes."""
        assert mod.is_tuple_of_objects((1, 2)) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert mod.is_tuple_of_objects([1, 2]) is False


class TestIsDictOfObjects:
    """Tests for is_dict_of_objects TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict passes."""
        assert mod.is_dict_of_objects({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert mod.is_dict_of_objects([1]) is False


class TestIsSetOfObjects:
    """Tests for is_set_of_objects TypeGuard."""

    def test_set_returns_true(self) -> None:
        """A set passes."""
        assert mod.is_set_of_objects({1, 2}) is True

    def test_frozenset_returns_false(self) -> None:
        """A frozenset does not pass (it's not a set)."""
        assert mod.is_set_of_objects(frozenset([1])) is False

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert mod.is_set_of_objects([1, 2]) is False
