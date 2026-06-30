"""Tests for pysymex._internal.typing — shared type aliases, TypeGuards, and Protocols."""

from __future__ import annotations

import z3

import pysymex._internal.guards as guards
import pysymex._internal.typing.protocols as typing_protocols
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.typing.protocols import SolverProtocol, SymbolicTypeProtocol


class TestSymbolicTypeProtocol:
    """Tests for SymbolicTypeProtocol — runtime_checkable Protocol."""

    def test_symbolic_value_satisfies_protocol(self) -> None:
        """SymbolicValue instances satisfy SymbolicTypeProtocol."""
        val = SymbolicValue.from_const(42)
        assert isinstance(val, SymbolicTypeProtocol)

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
        from pysymex._internal.core.solver.engine.incremental import IncrementalSolver

        solver = IncrementalSolver()
        assert isinstance(solver, SolverProtocol)


class TestDetectorProtocol:
    """Tests for DetectorProtocol — runtime_checkable Protocol."""

    def test_protocol_exists(self) -> None:
        """DetectorProtocol is a runtime-checkable Protocol."""
        assert hasattr(typing_protocols, "DetectorProtocol")


class TestStateViewProtocol:
    """Tests for StateViewProtocol — runtime_checkable Protocol."""

    def test_vmstate_satisfies_protocol(self) -> None:
        """VMState satisfies StateViewProtocol at structural level."""
        from pysymex._internal.core.state.record import VMState

        state = VMState()
        # Check that required attributes exist
        assert hasattr(state, "pc")
        assert hasattr(state, "stack")
        assert hasattr(state, "path_constraints")

    def test_pc_property(self) -> None:
        """VMState exposes pc as int."""
        from pysymex._internal.core.state.record import VMState

        state = VMState()
        assert isinstance(state.pc, int)

    def test_stack_property(self) -> None:
        """VMState exposes stack."""
        from pysymex._internal.core.state.record import VMState

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


class TestSymbolicContainerProtocol:
    """Tests for SymbolicContainerProtocol — runtime_checkable Protocol."""

    def test_symbolic_list_has_required_methods(self) -> None:
        """SymbolicList has name, to_z3, is_truthy, is_falsy structural methods."""
        from pysymex._internal.core.types.containers.lists import SymbolicList

        sl, _ = SymbolicList.symbolic("lst")
        assert hasattr(sl, "name")
        assert hasattr(sl, "to_z3")
        assert hasattr(sl, "could_be_truthy")
        assert hasattr(sl, "could_be_falsy")


class TestIsListOfObjects:
    """Tests for RuntimeObjectGuards.list TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list passes."""
        assert guards.RuntimeObjectGuards.list([1, "a"]) is True

    def test_tuple_returns_false(self) -> None:
        """A tuple does not pass."""
        assert guards.RuntimeObjectGuards.list((1, 2)) is False

    def test_dict_returns_false(self) -> None:
        """A dict does not pass."""
        assert guards.RuntimeObjectGuards.list({"a": 1}) is False


class TestIsTupleOfObjects:
    """Tests for RuntimeObjectGuards.tuple TypeGuard."""

    def test_tuple_returns_true(self) -> None:
        """A tuple passes."""
        assert guards.RuntimeObjectGuards.tuple((1, 2)) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert guards.RuntimeObjectGuards.tuple([1, 2]) is False


class TestIsDictOfObjects:
    """Tests for RuntimeObjectGuards.dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict passes."""
        assert guards.RuntimeObjectGuards.dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert guards.RuntimeObjectGuards.dict([1]) is False


class TestIsSetOfObjects:
    """Tests for RuntimeObjectGuards.set TypeGuard."""

    def test_set_returns_true(self) -> None:
        """A set passes."""
        assert guards.RuntimeObjectGuards.set({1, 2}) is True

    def test_frozenset_returns_false(self) -> None:
        """A frozenset does not pass (it's not a set)."""
        assert guards.RuntimeObjectGuards.set(frozenset([1])) is False

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert guards.RuntimeObjectGuards.set([1, 2]) is False


class TestIsFrozensetOfObjects:
    """Tests for RuntimeObjectGuards.frozenset TypeGuard."""

    def test_frozenset_returns_true(self) -> None:
        """A frozenset passes."""
        assert guards.RuntimeObjectGuards.frozenset(frozenset([1, 2])) is True

    def test_set_returns_false(self) -> None:
        """A mutable set does not pass."""
        assert guards.RuntimeObjectGuards.frozenset({1, 2}) is False

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert guards.RuntimeObjectGuards.frozenset([1, 2]) is False
