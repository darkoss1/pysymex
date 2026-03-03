"""Tests for Copy-on-Write VMState (v0.4.0 CoW rewrite)."""

import pytest

import z3


from pysymex.core.copy_on_write import CowDict, CowSet, ConstraintChain

from pysymex.core.state import VMState


class TestCowDict:
    """Copy-on-write dictionary."""

    def test_create_empty(self):
        d = CowDict()

        assert len(d) == 0

    def test_create_from_dict(self):
        d = CowDict({"a": 1, "b": 2})

        assert d["a"] == 1

        assert len(d) == 2

    def test_set_and_get(self):
        d = CowDict()

        d["x"] = 42

        assert d["x"] == 42

    def test_contains(self):
        d = CowDict({"a": 1})

        assert "a" in d

        assert "b" not in d

    def test_delete(self):
        d = CowDict({"a": 1, "b": 2})

        del d["a"]

        assert "a" not in d

        assert len(d) == 1

    def test_iter(self):
        d = CowDict({"a": 1, "b": 2})

        keys = list(d)

        assert sorted(keys) == ["a", "b"]

    def test_items(self):
        d = CowDict({"a": 1})

        items = list(d.items())

        assert items == [("a", 1)]

    def test_values(self):
        d = CowDict({"a": 1, "b": 2})

        vals = sorted(d.values())

        assert vals == [1, 2]

    def test_keys(self):
        d = CowDict({"a": 1})

        assert list(d.keys()) == ["a"]

    def test_get_default(self):
        d = CowDict()

        assert d.get("missing", 99) == 99

    def test_copy(self):
        d = CowDict({"a": 1})

        d2 = d.copy()

        d2["b"] = 2

        assert "b" not in d

    def test_update(self):
        d = CowDict({"a": 1})

        d.update({"b": 2, "c": 3})

        assert len(d) == 3


class TestCowDictFork:
    """Copy-on-write fork behavior."""

    def test_fork_is_o1(self):
        d = CowDict({"a": 1, "b": 2, "c": 3})

        forked = d.cow_fork()

        assert len(forked) == 3

        assert forked["a"] == 1

    def test_fork_shares_data(self):
        d = CowDict({"a": 1})

        forked = d.cow_fork()

        assert d._shared is True

        assert forked._shared is True

    def test_fork_write_isolation(self):
        d = CowDict({"a": 1, "b": 2})

        forked = d.cow_fork()

        forked["c"] = 3

        assert "c" not in d

        assert "c" in forked

    def test_fork_original_write_isolation(self):
        d = CowDict({"a": 1})

        forked = d.cow_fork()

        d["z"] = 99

        assert "z" not in forked

    def test_deep_fork_chain(self):
        d = CowDict({"a": 1})

        states = [d]

        for i in range(100):
            states.append(states[-1].cow_fork())

        states[-1]["new"] = True

        assert "new" not in states[0]


class TestCowSet:
    """Copy-on-write set."""

    def test_create_empty(self):
        s = CowSet()

        assert len(s) == 0

    def test_add(self):
        s = CowSet()

        s.add(1)

        assert 1 in s

    def test_discard(self):
        s = CowSet({1, 2, 3})

        s.discard(2)

        assert 2 not in s

        assert len(s) == 2

    def test_fork_isolation(self):
        s = CowSet({1, 2, 3})

        forked = s.cow_fork()

        forked.add(4)

        assert 4 not in s

        assert 4 in forked


class TestConstraintChain:
    """Persistent constraint chain."""

    def test_empty_chain(self):
        chain = ConstraintChain.empty()

        assert len(chain) == 0

        assert chain.to_list() == []

    def test_append(self):
        chain = ConstraintChain.empty()

        x = z3.Int("x")

        chain2 = chain.append(x > 0)

        assert len(chain2) == 1

        assert len(chain) == 0

    def test_multiple_append(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        chain = chain.append(x > 0)

        chain = chain.append(x < 100)

        chain = chain.append(x != 50)

        assert len(chain) == 3

    def test_to_list(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        chain = chain.append(x > 0)

        chain = chain.append(x < 100)

        lst = chain.to_list()

        assert len(lst) == 2

    def test_fork_is_o1(self):
        """Forking a constraint chain should share the chain."""

        x = z3.Int("x")

        chain = ConstraintChain.empty()

        for i in range(100):
            chain = chain.append(x > i)

        fork1 = chain

        fork2 = chain.append(x < 999)

        assert len(fork1) == 100

        assert len(fork2) == 101

    def test_iter(self):
        x = z3.Int("x")

        chain = ConstraintChain.empty()

        chain = chain.append(x > 0)

        chain = chain.append(x < 10)

        items = list(chain)

        assert len(items) == 2


class TestVMStateFork:
    """VMState fork with CoW."""

    def test_fork_creates_new_state(self):
        state = VMState()

        state.local_vars["x"] = z3.Int("x")

        forked = state.fork()

        assert forked is not state

        assert "x" in forked.local_vars

    def test_fork_local_vars_isolation(self):
        state = VMState()

        state.local_vars["x"] = z3.Int("x")

        forked = state.fork()

        forked.local_vars["y"] = z3.Int("y")

        assert "y" not in state.local_vars

    def test_fork_constraints_isolation(self):
        state = VMState()

        x = z3.Int("x")

        state.add_constraint(x > 0)

        forked = state.fork()

        forked.add_constraint(x < 100)

        orig_constraints = list(state.path_constraints)

        forked_constraints = list(forked.path_constraints)

        assert len(forked_constraints) >= len(orig_constraints)

    def test_fork_stack_isolation(self):
        state = VMState()

        state.stack.append(z3.IntVal(1))

        forked = state.fork()

        forked.stack.append(z3.IntVal(2))

        assert len(state.stack) == 1

        assert len(forked.stack) == 2

    def test_fork_pc_independent(self):
        state = VMState()

        state.pc = 10

        forked = state.fork()

        forked.pc = 20

        assert state.pc == 10

    def test_mass_forking(self):
        """Fork 1000 times from the same state."""

        state = VMState()

        for i in range(50):
            state.local_vars[f"v{i}"] = z3.Int(f"v{i}")

        forks = [state.fork() for _ in range(1000)]

        assert len(forks) == 1000

        forks[0].local_vars["unique"] = 42

        assert "unique" not in state.local_vars
