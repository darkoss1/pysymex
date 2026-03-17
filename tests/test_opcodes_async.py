"""Tests for async opcode handlers."""

import pytest

from tests.helpers import dispatch, from_const, make_state
from pysymex.core.types import SymbolicValue


class TestAsyncGenWrap:
    def test_wraps_value(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("ASYNC_GEN_WRAP", state)
        s = r.new_states[0]
        assert isinstance(s.stack[-1], SymbolicValue)

    def test_empty_stack(self):
        state = make_state()
        r = dispatch("ASYNC_GEN_WRAP", state)
        assert len(r.new_states) == 1
        assert isinstance(r.new_states[0].stack[-1], SymbolicValue)

    def test_pc_advances(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("ASYNC_GEN_WRAP", state)
        assert r.new_states[0].pc == 1


class TestGenStart:
    def test_pops_initial(self):
        state = make_state(stack=[from_const(42)])
        r = dispatch("GEN_START", state)
        assert len(r.new_states[0].stack) == 0

    def test_empty_stack(self):
        state = make_state()
        r = dispatch("GEN_START", state)
        assert len(r.new_states[0].stack) == 0

    def test_pc_advances(self):
        state = make_state(stack=[from_const(1)])
        r = dispatch("GEN_START", state)
        assert r.new_states[0].pc == 1


class TestExtendedArgQuick:
    def test_noop(self):
        state = make_state()
        r = dispatch("EXTENDED_ARG_QUICK", state)
        assert r.new_states[0].pc == 1
        assert len(r.new_states[0].stack) == 0
