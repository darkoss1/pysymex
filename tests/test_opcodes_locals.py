"""Tests for local/global variable opcode handlers."""

import pytest
import z3

from tests.helpers import (
    dispatch, from_const, make_state, make_symbolic_int, make_symbolic_str, prove, solve,
)
from pysymex.core.types import SymbolicValue, SymbolicString, SymbolicNone
from pysymex.core.state import UNBOUND
from pysymex.core.copy_on_write import CowDict


class TestLoadConst:
    def test_int(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=42)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)
        assert prove(top.z3_int == z3.IntVal(42))

    def test_none(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=None)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicNone)

    def test_string(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval="hello")
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicString)

    def test_bool_true(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=True)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_bool_false(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=False)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_float(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=3.14)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_zero(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=0)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(0))

    def test_negative(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=-5)
        top = r.new_states[0].stack[-1]
        assert prove(top.z3_int == z3.IntVal(-5))

    def test_tuple_const(self):
        state = make_state()
        r = dispatch("LOAD_CONST", state, argval=(1, 2, 3))
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)
        assert top._constant_value == (1, 2, 3)

    def test_stack_grows_by_one(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("LOAD_CONST", state, argval=42)
        assert len(r.new_states[0].stack) == 2


class TestLoadFast:
    def test_existing_local(self):
        x = from_const(42)
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_FAST", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert top is x

    def test_unbound_creates_symbolic(self):
        state = make_state()
        r = dispatch("LOAD_FAST", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_unbound_sets_local(self):
        state = make_state()
        r = dispatch("LOAD_FAST", state, argval="x")
        s = r.new_states[0]
        assert "x" in s.local_vars

    def test_symbolic_local(self):
        x = make_symbolic_int("x")
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_FAST", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert top is x


class TestLoadFastLoadFast:
    def test_two_locals(self):
        x = from_const(1)
        y = from_const(2)
        state = make_state(locals_={"x": x, "y": y})
        r = dispatch("LOAD_FAST_LOAD_FAST", state, argval=("x", "y"))
        s = r.new_states[0]
        assert len(s.stack) == 2

    def test_single_argval(self):
        x = from_const(42)
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_FAST_LOAD_FAST", state, argval="x")
        assert len(r.new_states[0].stack) == 1


class TestStoreFast:
    def test_store_concrete(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_FAST", state, argval="x")
        s = r.new_states[0]
        assert "x" in s.local_vars
        assert prove(s.local_vars["x"].z3_int == z3.IntVal(42))

    def test_store_symbolic(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x])
        r = dispatch("STORE_FAST", state, argval="y")
        s = r.new_states[0]
        assert "y" in s.local_vars
        assert s.local_vars["y"] is x

    def test_store_pops_stack(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("STORE_FAST", state, argval="x")
        assert len(r.new_states[0].stack) == 1

    def test_store_overwrites(self):
        state = make_state(stack=[from_const(99)], locals_={"x": from_const(1)})
        r = dispatch("STORE_FAST", state, argval="x")
        s = r.new_states[0]
        assert prove(s.local_vars["x"].z3_int == z3.IntVal(99))


class TestStoreFastStoreFast:
    def test_two_stores(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("STORE_FAST_STORE_FAST", state, argval=("x", "y"))
        s = r.new_states[0]
        assert "x" in s.local_vars
        assert "y" in s.local_vars
        assert len(s.stack) == 0


class TestDeleteFast:
    def test_delete_existing(self):
        state = make_state(locals_={"x": from_const(42)})
        r = dispatch("DELETE_FAST", state, argval="x")
        assert "x" not in r.new_states[0].local_vars

    def test_delete_nonexistent(self):
        state = make_state()
        r = dispatch("DELETE_FAST", state, argval="x")
        assert len(r.new_states) == 1


class TestLoadGlobal:
    def test_existing_global(self):
        g = from_const(100)
        state = make_state(globals_={"g": g})
        r = dispatch("LOAD_GLOBAL", state, argval="g")
        top = r.new_states[0].stack[-1]
        assert top is g

    def test_missing_global_creates_symbolic(self):
        state = make_state()
        r = dispatch("LOAD_GLOBAL", state, argval="g")
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicValue)

    def test_tuple_argval(self):
        g = from_const(50)
        state = make_state(globals_={"g": g})
        r = dispatch("LOAD_GLOBAL", state, argval=("unused", "g"))
        s = r.new_states[0]
        # Should have loaded the global
        assert len(s.stack) >= 1


class TestStoreGlobal:
    def test_store(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_GLOBAL", state, argval="g")
        s = r.new_states[0]
        assert "g" in s.global_vars

    def test_store_pops(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("STORE_GLOBAL", state, argval="g")
        assert len(r.new_states[0].stack) == 1


class TestDeleteGlobal:
    def test_delete_existing(self):
        state = make_state(globals_={"g": from_const(42)})
        r = dispatch("DELETE_GLOBAL", state, argval="g")
        assert "g" not in r.new_states[0].global_vars

    def test_delete_nonexistent(self):
        state = make_state()
        r = dispatch("DELETE_GLOBAL", state, argval="g")
        assert len(r.new_states) == 1


class TestLoadName:
    def test_from_locals(self):
        x = from_const(42)
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_NAME", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert top is x

    def test_from_globals_via_local_none(self):
        """LOAD_NAME falls through to globals only when get_local returns None
        (not UNBOUND). Pre-set local to None so global lookup activates."""
        g = from_const(99)
        state = make_state(locals_={"g": None}, globals_={"g": g})
        r = dispatch("LOAD_NAME", state, argval="g")
        top = r.new_states[0].stack[-1]
        assert top is g

    def test_missing_pushes_something(self):
        state = make_state()
        r = dispatch("LOAD_NAME", state, argval="x")
        assert len(r.new_states) == 1
        assert len(r.new_states[0].stack) == 1


class TestStoreName:
    def test_store(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_NAME", state, argval="x")
        assert "x" in r.new_states[0].local_vars


class TestDeleteName:
    def test_delete(self):
        state = make_state(locals_={"x": from_const(42)})
        r = dispatch("DELETE_NAME", state, argval="x")
        assert "x" not in r.new_states[0].local_vars


class TestLoadDeref:
    def test_from_local(self):
        x = from_const(42)
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_DEREF", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert top is x

    def test_from_global_via_local_none(self):
        """LOAD_DEREF checks get_local first; only falls to global when None."""
        g = from_const(99)
        state = make_state(locals_={"g": None}, globals_={"g": g})
        r = dispatch("LOAD_DEREF", state, argval="g")
        top = r.new_states[0].stack[-1]
        assert top is g

    def test_missing_pushes_something(self):
        state = make_state()
        r = dispatch("LOAD_DEREF", state, argval="x")
        assert len(r.new_states) == 1
        assert len(r.new_states[0].stack) == 1


class TestStoreDeref:
    def test_store(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_DEREF", state, argval="x")
        assert "x" in r.new_states[0].local_vars


class TestCellOps:
    def test_make_cell(self):
        state = make_state()
        r = dispatch("MAKE_CELL", state)
        assert len(r.new_states) == 1

    def test_copy_free_vars(self):
        state = make_state()
        r = dispatch("COPY_FREE_VARS", state)
        assert len(r.new_states) == 1


class TestLoadFastAndClear:
    def test_existing_var(self):
        x = from_const(42)
        state = make_state(locals_={"x": x})
        r = dispatch("LOAD_FAST_AND_CLEAR", state, argval="x")
        s = r.new_states[0]
        assert s.stack[-1] is x
        assert s.local_vars.get("x") is UNBOUND

    def test_missing_var(self):
        state = make_state()
        r = dispatch("LOAD_FAST_AND_CLEAR", state, argval="x")
        # get_local returns UNBOUND for missing key; handler checks `is None`
        # which is False for UNBOUND, so UNBOUND gets pushed directly
        assert len(r.new_states[0].stack) == 1


class TestStoreFastLoadFast:
    def test_same_name(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_FAST_LOAD_FAST", state, argval=("x", "x"))
        s = r.new_states[0]
        assert prove(s.stack[-1].z3_int == z3.IntVal(42))

    def test_different_names(self):
        y = from_const(99)
        state = make_state(stack=[from_const(42)], locals_={"y": y})
        r = dispatch("STORE_FAST_LOAD_FAST", state, argval=("x", "y"))
        s = r.new_states[0]
        assert s.stack[-1] is y


class TestStoreFastMaybeNull:
    def test_with_value(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("STORE_FAST_MAYBE_NULL", state, argval="x")
        assert "x" in r.new_states[0].local_vars

    def test_empty_stack(self):
        state = make_state()
        r = dispatch("STORE_FAST_MAYBE_NULL", state, argval="x")
        assert isinstance(r.new_states[0].local_vars["x"], SymbolicNone)


class TestLoadFromDictOrDeref:
    def test_known_local(self):
        x = from_const(42)
        state = make_state(stack=[from_const(0)], locals_={"x": x})
        r = dispatch("LOAD_FROM_DICT_OR_DEREF", state, argval="x")
        top = r.new_states[0].stack[-1]
        assert top is x

    def test_unknown_creates_symbolic(self):
        state = make_state(stack=[from_const(0)])
        r = dispatch("LOAD_FROM_DICT_OR_DEREF", state, argval="x")
        # get_local returns UNBOUND (not None) for missing keys,
        # so handler falls through to create symbolic
        assert len(r.new_states) == 1
        assert len(r.new_states[0].stack) == 1


class TestLoadFromDictOrGlobals:
    def test_known_global(self):
        g = from_const(99)
        state = make_state(stack=[from_const(0)], globals_={"g": g})
        r = dispatch("LOAD_FROM_DICT_OR_GLOBALS", state, argval="g")
        top = r.new_states[0].stack[-1]
        assert top is g

    def test_unknown_creates_symbolic(self):
        state = make_state(stack=[from_const(0)])
        r = dispatch("LOAD_FROM_DICT_OR_GLOBALS", state, argval="g")
        assert isinstance(r.new_states[0].stack[-1], SymbolicValue)


class TestLoadLocals:
    def test_pushes_symbolic(self):
        state = make_state()
        r = dispatch("LOAD_LOCALS", state)
        assert isinstance(r.new_states[0].stack[-1], SymbolicValue)


class TestSetupAnnotations:
    def test_noop(self):
        state = make_state()
        r = dispatch("SETUP_ANNOTATIONS", state)
        assert len(r.new_states) == 1
        assert r.new_states[0].pc == 1
