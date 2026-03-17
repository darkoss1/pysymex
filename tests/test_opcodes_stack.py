"""Tests for stack manipulation opcode handlers."""

import pytest
import z3

from tests.helpers import dispatch, from_const, make_state, make_symbolic_int, prove
from pysymex.core.types import SymbolicValue, SymbolicNone


class TestPopTop:
    def test_pop(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("POP_TOP", state)
        assert len(r.new_states[0].stack) == 1

    def test_pop_empty(self):
        state = make_state()
        r = dispatch("POP_TOP", state)
        assert len(r.new_states[0].stack) == 0

    def test_pc_advances(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("POP_TOP", state)
        assert r.new_states[0].pc == 1


class TestDupTop:
    def test_dup(self):
        v = from_const(42)
        state = make_state(stack=[v])
        r = dispatch("DUP_TOP", state)
        s = r.new_states[0]
        assert len(s.stack) == 2
        assert s.stack[-1] is v
        assert s.stack[-2] is v

    def test_dup_empty_stack(self):
        state = make_state()
        r = dispatch("DUP_TOP", state)
        assert len(r.new_states[0].stack) == 0

    def test_dup_symbolic(self):
        x = make_symbolic_int("x")
        state = make_state(stack=[x])
        r = dispatch("DUP_TOP", state)
        s = r.new_states[0]
        assert len(s.stack) == 2
        assert s.stack[-1] is x


class TestDupTopTwo:
    def test_dup_two(self):
        a = from_const(1)
        b = from_const(2)
        state = make_state(stack=[a, b])
        r = dispatch("DUP_TOP_TWO", state)
        s = r.new_states[0]
        assert len(s.stack) == 4

    def test_dup_two_insufficient_stack(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("DUP_TOP_TWO", state)
        assert len(r.new_states[0].stack) == 1  # unchanged


class TestRotTwo:
    def test_swap(self):
        a = from_const(1)
        b = from_const(2)
        state = make_state(stack=[a, b])
        r = dispatch("ROT_TWO", state)
        s = r.new_states[0]
        assert s.stack[-1] is a
        assert s.stack[-2] is b

    def test_insufficient_stack(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("ROT_TWO", state)
        assert len(r.new_states[0].stack) == 1


class TestRotThree:
    def test_rotate(self):
        a = from_const(1)
        b = from_const(2)
        c = from_const(3)
        state = make_state(stack=[a, b, c])
        r = dispatch("ROT_THREE", state)
        assert len(r.new_states[0].stack) == 3

    def test_insufficient_stack(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("ROT_THREE", state)
        assert len(r.new_states[0].stack) == 2


class TestRotFour:
    def test_rotate(self):
        state = make_state(stack=[from_const(i) for i in range(4)])
        r = dispatch("ROT_FOUR", state)
        assert len(r.new_states[0].stack) == 4

    def test_insufficient_stack(self):
        state = make_state(stack=[from_const(1), from_const(2)])
        r = dispatch("ROT_FOUR", state)
        assert len(r.new_states[0].stack) == 2


class TestCopy:
    def test_copy_1(self):
        v = from_const(42)
        state = make_state(stack=[v])
        r = dispatch("COPY", state, argval=1)
        s = r.new_states[0]
        assert len(s.stack) == 2
        assert s.stack[-1] is v

    def test_copy_2(self):
        a = from_const(1)
        b = from_const(2)
        state = make_state(stack=[a, b])
        r = dispatch("COPY", state, argval=2)
        s = r.new_states[0]
        assert len(s.stack) == 3
        assert s.stack[-1] is a


class TestSwap:
    def test_swap_2(self):
        a = from_const(1)
        b = from_const(2)
        state = make_state(stack=[a, b])
        r = dispatch("SWAP", state, argval=2)
        s = r.new_states[0]
        assert s.stack[-1] is a
        assert s.stack[-2] is b

    def test_swap_3(self):
        a = from_const(1)
        b = from_const(2)
        c = from_const(3)
        state = make_state(stack=[a, b, c])
        r = dispatch("SWAP", state, argval=3)
        s = r.new_states[0]
        assert s.stack[-1] is a
        assert s.stack[-3] is c


class TestNop:
    def test_nop(self):
        state = make_state()
        r = dispatch("NOP", state)
        assert len(r.new_states) == 1
        assert r.new_states[0].pc == 1

    def test_resume(self):
        state = make_state()
        r = dispatch("RESUME", state)
        assert r.new_states[0].pc == 1

    def test_extended_arg(self):
        state = make_state()
        r = dispatch("EXTENDED_ARG", state)
        assert r.new_states[0].pc == 1


class TestPushNull:
    def test_pushes_none(self):
        state = make_state()
        r = dispatch("PUSH_NULL", state)
        top = r.new_states[0].stack[-1]
        assert isinstance(top, SymbolicNone)

    def test_stack_grows(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("PUSH_NULL", state)
        assert len(r.new_states[0].stack) == 2


class TestCache:
    def test_noop(self):
        state = make_state()
        r = dispatch("CACHE", state)
        assert r.new_states[0].pc == 1
        assert len(r.new_states[0].stack) == 0
