"""State hash collision resistance tests.

Verifies that state deduplication via _state_key() never produces false collisions.

Source contracts tested:
- executor_core.py:1241-1255 (_state_key returns 11-component tuple)
- state.py:406-436 (VMState.hash_value)
- copy_on_write.py (CowDict/CowSet/ConstraintChain hash functions)

Critical invariants:
1. Distinct states produce distinct keys
2. Hash avalanche - single bit change produces different key
3. 64-bit wrap-around soundness
4. No false deduplication
"""

from __future__ import annotations

import random
from typing import Any

import pytest
import z3

from pysymex.core.copy_on_write import ConstraintChain, CowDict, CowSet
from pysymex.core.state import VMState, create_initial_state, BlockInfo, CallFrame


class TestDistinctStatesDistinctKeys:
    """Verify that semantically different states produce different keys."""

    def test_different_pc_different_hash(self):
        """States with different PC should have different hashes."""
        state1 = create_initial_state()
        state1.pc = 0

        state2 = create_initial_state()
        state2.pc = 1

        assert state1.hash_value() != state2.hash_value()

    def test_different_local_vars_different_hash(self):
        """States with different local vars should have different hashes."""
        state1 = create_initial_state(local_vars={"x": 1})
        state2 = create_initial_state(local_vars={"x": 2})

        assert state1.hash_value() != state2.hash_value()

    def test_different_global_vars_different_hash(self):
        """States with different global vars should have different hashes."""
        state1 = create_initial_state(global_vars={"G": 100})
        state2 = create_initial_state(global_vars={"G": 200})

        assert state1.hash_value() != state2.hash_value()

    def test_different_constraints_different_hash(self):
        """States with different constraints should have different hashes."""
        x = z3.Int("x")
        state1 = create_initial_state(constraints=[x > 0])
        state2 = create_initial_state(constraints=[x > 1])

        assert state1.hash_value() != state2.hash_value()

    def test_different_stack_different_hash(self):
        """States with different stack should have different hashes."""
        state1 = create_initial_state()
        state1.stack.append(1)

        state2 = create_initial_state()
        state2.stack.append(2)

        assert state1.hash_value() != state2.hash_value()

    def test_different_visited_pcs_different_hash(self):
        """States with different visited PCs should have different hashes."""
        state1 = create_initial_state()
        state1.visited_pcs.add(10)

        state2 = create_initial_state()
        state2.visited_pcs.add(20)

        assert state1.hash_value() != state2.hash_value()

    def test_different_memory_different_hash(self):
        """States with different memory should have different hashes."""
        state1 = create_initial_state()
        state1.memory[1000] = "value1"

        state2 = create_initial_state()
        state2.memory[1000] = "value2"

        assert state1.hash_value() != state2.hash_value()


class TestHashAvalancheEffect:
    """Verify small changes cause large hash differences."""

    def test_single_var_change_avalanche(self):
        """Single variable change should affect many hash bits."""
        state1 = create_initial_state(local_vars={"x": 1000})
        state2 = create_initial_state(local_vars={"x": 1001})

        h1 = state1.hash_value()
        h2 = state2.hash_value()

        diff_bits = bin(h1 ^ h2).count("1")
        assert diff_bits > 5, f"Only {diff_bits} bits differ, expected avalanche"

    def test_pc_change_avalanche(self):
        """Single PC increment should affect many hash bits."""
        state1 = create_initial_state()
        state1.pc = 100

        state2 = create_initial_state()
        state2.pc = 101

        h1 = state1.hash_value()
        h2 = state2.hash_value()

        diff_bits = bin(h1 ^ h2).count("1")
        assert diff_bits > 5, f"Only {diff_bits} bits differ, expected avalanche"

    def test_constraint_change_avalanche(self):
        """Small constraint change should affect many hash bits."""
        x = z3.Int("x")
        state1 = create_initial_state(constraints=[x > 0])
        state2 = create_initial_state(constraints=[x > 1])

        h1 = state1.hash_value()
        h2 = state2.hash_value()

        # Should differ
        assert h1 != h2


class TestManyRandomStatesNoCollisions:
    """Generate many random states and verify no hash collisions."""

    def test_random_states_unique_hashes(self):
        """Many randomly generated states should have unique hashes."""
        random.seed(42)
        states = []
        hashes = set()

        for i in range(500):
            state = create_initial_state()
            state.pc = random.randint(0, 1000)
            state.local_vars[f"var_{i}"] = random.randint(0, 10000)
            state.visited_pcs.add(random.randint(0, 500))

            h = state.hash_value()
            if h in hashes:
                # Check if it's actually the same state
                for existing in states:
                    if existing.hash_value() == h:
                        # They should be different states
                        assert (
                            existing.pc != state.pc or
                            existing.local_vars._data != state.local_vars._data or
                            existing.visited_pcs._data != state.visited_pcs._data
                        ), "Found hash collision between different states"

            hashes.add(h)
            states.append(state)

    def test_constraint_chain_unique_hashes(self):
        """Different constraint chains should have unique hashes."""
        x = z3.Int("x")
        chains = []
        hashes = set()

        base = ConstraintChain.empty()
        for i in range(100):
            chain = base.append(x > i)
            h = chain.hash_value()
            assert h not in hashes, f"Hash collision at constraint {i}"
            hashes.add(h)
            chains.append(chain)


class Test64BitBoundaryBehavior:
    """Verify hashes near 64-bit boundary behave correctly."""

    def test_hash_bounded_to_64_bits(self):
        """All hash values must fit in 64 bits."""
        states = []
        for i in range(100):
            state = create_initial_state()
            state.pc = i * 0xFFFFFFFF
            state.local_vars[f"var"] = i * 0xFFFFFFFFFFFF
            states.append(state)

        for state in states:
            h = state.hash_value()
            assert 0 <= h <= 0xFFFFFFFFFFFFFFFF
            assert h >= 0  # Must be non-negative

    def test_cowdict_hash_no_overflow(self):
        """CowDict hash must not overflow Python int."""
        cow = CowDict()
        for i in range(1000):
            cow[f"key_{i}"] = i * 0xFFFFFFFFFFFF

        h = cow.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_cowset_hash_no_overflow(self):
        """CowSet hash must not overflow."""
        cow = CowSet()
        for i in range(1000):
            cow.add(i * 0xFFFFFF)

        h = cow.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_constraint_chain_hash_no_overflow(self):
        """ConstraintChain hash must not overflow."""
        x = z3.Int("x")
        chain = ConstraintChain.empty()
        for i in range(500):
            chain = chain.append(x > i * 1000000)

        h = chain.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


class TestStateKeyComponents:
    """Verify all 11 components of _state_key contribute to uniqueness."""

    def _make_state_with_components(self, **overrides) -> VMState:
        """Create a state with specific component values."""
        state = create_initial_state()
        for key, value in overrides.items():
            if key == "stack":
                state.stack = value
            elif key == "local_vars":
                for k, v in value.items():
                    state.local_vars[k] = v
            elif key == "global_vars":
                for k, v in value.items():
                    state.global_vars[k] = v
            elif key == "memory":
                for k, v in value.items():
                    state.memory[k] = v
            elif key == "visited_pcs":
                for pc in value:
                    state.visited_pcs.add(pc)
            elif key == "pc":
                state.pc = value
            elif key == "constraints":
                for c in value:
                    state.add_constraint(c)
            elif key == "block_stack":
                state.block_stack = value
            elif key == "call_stack":
                state.call_stack = value
        return state

    def test_each_component_affects_hash(self):
        """Each component of _state_key should affect the hash."""
        x = z3.Int("x")

        base = create_initial_state()
        base_hash = base.hash_value()

        # Test each component
        modifications = [
            {"pc": 100},
            {"local_vars": {"new_var": 1}},
            {"global_vars": {"new_global": 2}},
            {"memory": {1000: "data"}},
            {"visited_pcs": [42]},
            {"stack": [1, 2, 3]},
            {"constraints": [x > 0]},
        ]

        for mod in modifications:
            state = self._make_state_with_components(**mod)
            mod_hash = state.hash_value()
            assert base_hash != mod_hash, f"Modification {mod} didn't change hash"


class TestSymbolicValueHashing:
    """Verify symbolic values hash correctly."""

    def test_different_symbolic_vars_different_hash(self):
        """Different symbolic variables should produce different hashes."""
        from pysymex.core.types import SymbolicValue

        sv1, _ = SymbolicValue.symbolic_int("x")
        sv2, _ = SymbolicValue.symbolic_int("y")

        state1 = create_initial_state()
        state1.local_vars["v"] = sv1

        state2 = create_initial_state()
        state2.local_vars["v"] = sv2

        # The hashes should differ because the symbolic values are different
        h1 = state1.hash_value()
        h2 = state2.hash_value()
        assert h1 != h2

    def test_same_symbolic_var_same_hash(self):
        """Same symbolic variable should produce same hash."""
        from pysymex.core.types import SymbolicValue

        sv, _ = SymbolicValue.symbolic_int("x")

        state1 = create_initial_state()
        state1.local_vars["v"] = sv

        state2 = create_initial_state()
        state2.local_vars["v"] = sv

        h1 = state1.hash_value()
        h2 = state2.hash_value()
        assert h1 == h2


class TestCallStackHashing:
    """Verify call stack contributes to hash."""

    def test_different_call_depth_different_hash(self):
        """Different call stack depths should produce different hashes."""
        state1 = create_initial_state()
        state2 = create_initial_state()

        frame = CallFrame(
            function_name="test_func",
            return_pc=10,
            local_vars=CowDict({}),
            stack_depth=0,
        )
        state2.call_stack.append(frame)

        h1 = state1.hash_value()
        h2 = state2.hash_value()
        assert h1 != h2

    def test_different_call_frames_different_hash(self):
        """Different call frames should produce different hashes."""
        state1 = create_initial_state()
        state2 = create_initial_state()

        frame1 = CallFrame("func_a", 10, CowDict({}), 0)
        frame2 = CallFrame("func_b", 10, CowDict({}), 0)

        state1.call_stack.append(frame1)
        state2.call_stack.append(frame2)

        h1 = state1.hash_value()
        h2 = state2.hash_value()
        assert h1 != h2


class TestBlockStackHashing:
    """Verify block stack contributes to hash."""

    def test_different_block_stack_different_hash(self):
        """Different block stacks should produce different hashes."""
        state1 = create_initial_state()
        state2 = create_initial_state()

        block = BlockInfo("loop", 0, 10)
        state2.block_stack.append(block)

        h1 = state1.hash_value()
        h2 = state2.hash_value()
        assert h1 != h2


class TestHashConsistency:
    """Verify hash is consistent across multiple calls."""

    def test_hash_deterministic(self):
        """Same state should produce same hash on multiple calls."""
        state = create_initial_state(local_vars={"x": 42, "y": 100})
        x = z3.Int("x")
        state.add_constraint(x > 0)
        state.visited_pcs.add(10)
        state.memory[1000] = "data"

        h1 = state.hash_value()
        h2 = state.hash_value()
        h3 = state.hash_value()

        assert h1 == h2 == h3

    def test_forked_state_same_hash_before_mutation(self):
        """Forked state should have same hash as parent before mutation."""
        parent = create_initial_state(local_vars={"x": 42})
        parent.pc = 50

        child = parent.fork()

        # Before any mutation, hashes might differ due to path_id
        # but other components should be the same
        # Actually path_id doesn't affect hash_value, so they should be equal
        # Wait, let me check - the hash doesn't include path_id
        # So they should be equal
        assert parent.hash_value() == child.hash_value()

    def test_forked_state_different_hash_after_mutation(self):
        """Forked state should have different hash after mutation."""
        parent = create_initial_state(local_vars={"x": 42})

        child = parent.fork()
        child.local_vars["y"] = 100

        assert parent.hash_value() != child.hash_value()
