"""Unit tests for VMState."""

import pytest

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicValue


class TestVMState:
    """Tests for VMState class."""

    def test_create_empty(self):
        """Test creating empty state."""

        state = VMState()

        assert state.pc == 0

        assert len(state.stack) == 0

    def test_push_pop(self):
        """Test push and pop operations."""

        state = VMState()

        x, _ = SymbolicValue.symbolic("x")

        state.push(x)

        assert len(state.stack) == 1

        popped = state.pop()

        assert popped == x

        assert len(state.stack) == 0

    def test_peek(self):
        """Test peek operation."""

        state = VMState()

        x, _ = SymbolicValue.symbolic("x")

        state.push(x)

        peeked = state.peek()

        assert peeked == x

        assert len(state.stack) == 1

    def test_local_vars(self):
        """Test local variable storage."""

        state = VMState()

        x, _ = SymbolicValue.symbolic("x")

        state.local_vars["var"] = x

        loaded = state.local_vars.get("var")

        assert loaded == x

    def test_fork_creates_copy(self):
        """Test that fork creates independent copy."""

        state = VMState()

        x, _ = SymbolicValue.symbolic("x")

        state.push(x)

        state.pc = 10

        forked = state.fork()

        state.pc = 20

        assert forked.pc == 10

    def test_add_constraint(self):
        """Test adding path constraints."""

        import z3

        state = VMState()

        x = z3.Bool("cond")

        state.add_constraint(x)

        assert len(state.path_constraints) == 1

    def test_visited_pcs(self):
        """Test visited program counters tracking."""

        state = VMState()

        state.visited_pcs.add(0)

        state.visited_pcs.add(10)

        state.visited_pcs.add(20)

        assert 0 in state.visited_pcs

        assert 10 in state.visited_pcs

        assert 15 not in state.visited_pcs


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
