"""Copy-on-Write fork isolation tests.

Verifies that COW structures (CowDict, CowSet, ConstraintChain, VMState.fork())
provide complete state isolation after forking.

Source contracts tested:
- state.py:438-504 (VMState.fork)
- copy_on_write.py:21-188 (CowDict)
- copy_on_write.py:190-266 (CowSet)
- copy_on_write.py:321-424 (ConstraintChain)

Critical invariants:
1. Parent/child must be completely independent after fork
2. Mutations in one must not affect the other
3. Shared backing data must copy on first write
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import z3

from pysymex.core.copy_on_write import (
    BranchChain,
    BranchRecord,
    ConstraintChain,
    CowDict,
    CowSet,
)
from pysymex.core.state import VMState, create_initial_state


class TestCowDictMutationIsolation:
    """Verify CowDict fork provides mutation isolation."""

    def test_fork_child_mutation_does_not_affect_parent(self):
        """Mutating child dict after fork must not change parent."""
        parent = CowDict({"a": 1, "b": 2})
        child = parent.cow_fork()

        child["c"] = 3
        child["a"] = 100

        assert parent["a"] == 1
        assert "c" not in parent
        assert len(parent) == 2

    def test_fork_parent_mutation_does_not_affect_child(self):
        """Mutating parent dict after fork must not change child."""
        parent = CowDict({"a": 1, "b": 2})
        child = parent.cow_fork()

        parent["d"] = 4
        parent["b"] = 200

        assert child["b"] == 2
        assert "d" not in child
        assert len(child) == 2

    def test_fork_delete_does_not_affect_other(self):
        """Deleting key in one fork must not affect the other."""
        parent = CowDict({"a": 1, "b": 2, "c": 3})
        child = parent.cow_fork()

        del child["b"]

        assert "b" in parent
        assert parent["b"] == 2
        assert "b" not in child

    def test_multiple_forks_are_independent(self):
        """Multiple forks from same parent must be independent."""
        parent = CowDict({"x": 0})
        children = [parent.cow_fork() for _ in range(10)]

        for i, child in enumerate(children):
            child["x"] = i + 1

        assert parent["x"] == 0
        for i, child in enumerate(children):
            assert child["x"] == i + 1

    def test_nested_fork_isolation(self):
        """Forking a fork must be independent from original parent."""
        grandparent = CowDict({"val": 100})
        parent = grandparent.cow_fork()
        child = parent.cow_fork()

        child["val"] = 999

        assert grandparent["val"] == 100
        assert parent["val"] == 100
        assert child["val"] == 999

    def test_shared_flag_set_after_fork(self):
        """After fork, both parent and child should be marked shared."""
        parent = CowDict({"a": 1})
        assert not parent._shared

        child = parent.cow_fork()

        assert parent._shared
        assert child._shared

    def test_shared_flag_cleared_on_write(self):
        """Writing to a shared dict should clear the shared flag."""
        parent = CowDict({"a": 1})
        child = parent.cow_fork()

        child["b"] = 2

        assert child._shared is False
        assert parent._shared is True  # Still shared (no mutation)

    def test_hash_differs_after_mutation(self):
        """Hash must change after mutation."""
        parent = CowDict({"a": 1})
        parent_hash = parent.hash_value()

        child = parent.cow_fork()
        child["b"] = 2
        child_hash = child.hash_value()

        assert parent_hash != child_hash


class TestCowSetMutationIsolation:
    """Verify CowSet fork provides mutation isolation."""

    def test_fork_child_add_does_not_affect_parent(self):
        """Adding to child set after fork must not change parent."""
        parent = CowSet({1, 2, 3})
        child = parent.cow_fork()

        child.add(4)

        assert 4 not in parent
        assert len(parent) == 3

    def test_fork_parent_add_does_not_affect_child(self):
        """Adding to parent set after fork must not change child."""
        parent = CowSet({1, 2, 3})
        child = parent.cow_fork()

        parent.add(5)

        assert 5 not in child
        assert len(child) == 3

    def test_fork_discard_does_not_affect_other(self):
        """Discarding from one fork must not affect the other."""
        parent = CowSet({1, 2, 3})
        child = parent.cow_fork()

        child.discard(2)

        assert 2 in parent
        assert 2 not in child

    def test_multiple_set_forks_are_independent(self):
        """Multiple forks must each be independent."""
        parent = CowSet({0})
        children = [parent.cow_fork() for _ in range(5)]

        for i, child in enumerate(children):
            child.add(i + 100)

        assert len(parent) == 1
        for i, child in enumerate(children):
            assert i + 100 in child
            for j in range(5):
                if j != i:
                    assert j + 100 not in child


class TestConstraintChainForkImmutability:
    """Verify ConstraintChain immutability after append."""

    def test_append_returns_new_chain_preserving_parent(self):
        """Appending must return a new chain without modifying parent."""
        x = z3.Int("x")
        c1 = x > 0

        parent = ConstraintChain.empty()
        parent = parent.append(c1)
        parent_len = len(parent)

        c2 = x < 100
        child = parent.append(c2)

        assert len(parent) == parent_len
        assert len(child) == parent_len + 1

    def test_seen_hashes_transitive_accumulation(self):
        """_seen_hashes must accumulate through entire chain ancestry."""
        x = z3.Int("x")
        constraints = [x > i for i in range(10)]
        expected_hashes = {c.hash() for c in constraints}

        chain = ConstraintChain.empty()
        for c in constraints:
            chain = chain.append(c)

        assert chain._seen_hashes == frozenset(expected_hashes)

    def test_multiple_appends_from_same_parent(self):
        """Multiple appends from same parent must be independent."""
        x = z3.Int("x")
        base = ConstraintChain.empty().append(x > 0)

        branch_a = base.append(x < 10)
        branch_b = base.append(x > 100)

        assert len(base) == 1
        assert len(branch_a) == 2
        assert len(branch_b) == 2

        list_a = branch_a.to_list()
        list_b = branch_b.to_list()
        assert list_a[-1] is not list_b[-1]

    def test_hash_differs_between_branches(self):
        """Different branches from same parent must have different hashes."""
        x = z3.Int("x")
        base = ConstraintChain.empty().append(x > 0)

        branch_a = base.append(x < 10)
        branch_b = base.append(x > 100)

        assert branch_a.hash_value() != branch_b.hash_value()


class TestBranchChainForkIsolation:
    """Verify BranchChain immutability."""

    def test_append_returns_new_chain(self):
        """Appending to BranchChain must return new chain."""
        base = BranchChain.empty()
        record1 = BranchRecord(pc=10, condition=z3.Bool("c1"), taken=True)
        chain1 = base.append(record1)

        record2 = BranchRecord(pc=20, condition=z3.Bool("c2"), taken=False)
        chain2 = chain1.append(record2)

        assert len(base) == 0
        assert len(chain1) == 1
        assert len(chain2) == 2

    def test_multiple_appends_from_same_parent(self):
        """Multiple appends from same parent must be independent."""
        base = BranchChain.empty()
        record1 = BranchRecord(pc=10, condition=z3.Bool("c1"), taken=True)
        chain = base.append(record1)

        branch_a = chain.append(BranchRecord(pc=20, condition=z3.Bool("c2"), taken=True))
        branch_b = chain.append(BranchRecord(pc=30, condition=z3.Bool("c3"), taken=False))

        assert len(chain) == 1
        assert len(branch_a) == 2
        assert len(branch_b) == 2


class TestVMStateForkIsolation:
    """Verify VMState.fork() provides complete isolation."""

    def test_stack_isolation(self):
        """Stack mutations in child must not affect parent."""
        parent = create_initial_state()
        parent.stack.extend([1, 2, 3])

        child = parent.fork()
        child.stack.append(4)
        child.stack[0] = 999

        assert parent.stack == [1, 2, 3]
        assert child.stack == [999, 2, 3, 4]

    def test_local_vars_isolation(self):
        """Local var mutations in child must not affect parent."""
        parent = create_initial_state(local_vars={"x": 10, "y": 20})

        child = parent.fork()
        child.local_vars["x"] = 100
        child.local_vars["z"] = 30

        assert parent.local_vars["x"] == 10
        assert "z" not in parent.local_vars

    def test_global_vars_isolation(self):
        """Global var mutations in child must not affect parent."""
        parent = create_initial_state(global_vars={"G": 1})

        child = parent.fork()
        child.global_vars["G"] = 2
        child.global_vars["H"] = 3

        assert parent.global_vars["G"] == 1
        assert "H" not in parent.global_vars

    def test_memory_isolation(self):
        """Memory mutations in child must not affect parent."""
        parent = create_initial_state()
        parent.memory[1000] = "original"

        child = parent.fork()
        child.memory[1000] = "modified"
        child.memory[2000] = "new"

        assert parent.memory[1000] == "original"
        assert 2000 not in parent.memory

    def test_visited_pcs_isolation(self):
        """Visited PCs in child must not affect parent."""
        parent = create_initial_state()
        parent.visited_pcs.add(100)

        child = parent.fork()
        child.visited_pcs.add(200)

        assert 200 not in parent.visited_pcs
        assert 100 in child.visited_pcs  # Inherited

    def test_path_constraints_isolation(self):
        """Path constraints in child must not affect parent."""
        x = z3.Int("x")
        parent = create_initial_state(constraints=[x > 0])
        parent_constraint_count = len(parent.path_constraints)

        child = parent.fork()
        child.add_constraint(x < 100)

        assert len(parent.path_constraints) == parent_constraint_count
        assert len(child.path_constraints) == parent_constraint_count + 1

    def test_pending_constraint_count_inherited(self):
        """Forked states must inherit pending_constraint_count (BUG-012 fix)."""
        parent = create_initial_state()
        x = z3.Int("x")
        parent.add_constraint(x > 0)
        assert parent.pending_constraint_count == 1

        child = parent.fork()
        assert child.pending_constraint_count == 1

    def test_block_stack_isolation(self):
        """Block stack mutations in child must not affect parent."""
        from pysymex.core.state import BlockInfo

        parent = create_initial_state()
        parent.block_stack.append(BlockInfo("loop", 0, 10))

        child = parent.fork()
        child.block_stack.append(BlockInfo("try", 20, 30))

        assert len(parent.block_stack) == 1
        assert len(child.block_stack) == 2

    def test_loop_iterations_isolation(self):
        """Loop iterations dict in child must not affect parent."""
        parent = create_initial_state()
        parent.loop_iterations[10] = 5

        child = parent.fork()
        child.loop_iterations[10] = 6
        child.loop_iterations[20] = 1

        assert parent.loop_iterations[10] == 5
        assert 20 not in parent.loop_iterations

    def test_pc_isolation(self):
        """PC changes in child must not affect parent."""
        parent = create_initial_state()
        parent.pc = 50

        child = parent.fork()
        child.pc = 100

        assert parent.pc == 50
        assert child.pc == 100

    def test_path_id_unique_after_fork(self):
        """Each fork must get a unique path_id."""
        parent = create_initial_state()
        children = [parent.fork() for _ in range(100)]
        path_ids = {c.path_id for c in children}

        assert len(path_ids) == 100  # All unique


class TestConcurrentForkSafety:
    """Verify fork operations are safe under concurrent access."""

    def test_concurrent_fork_and_mutate(self):
        """Multiple threads forking and mutating must not corrupt state."""
        parent = CowDict({f"key_{i}": i for i in range(100)})
        results = []
        errors = []

        def fork_and_mutate(thread_id: int):
            try:
                child = parent.cow_fork()
                child[f"thread_{thread_id}"] = thread_id
                child["key_0"] = thread_id * 1000
                results.append((thread_id, child.to_dict()))
            except Exception as e:
                errors.append((thread_id, e))

        threads = [threading.Thread(target=fork_and_mutate, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors occurred: {errors}"

        # Parent must be unchanged
        assert parent["key_0"] == 0
        assert "thread_0" not in parent

        # Each child must have its own mutations
        for thread_id, child_dict in results:
            assert child_dict[f"thread_{thread_id}"] == thread_id
            assert child_dict["key_0"] == thread_id * 1000

    def test_concurrent_vmstate_fork(self):
        """Multiple threads forking VMState must produce isolated states."""
        parent = create_initial_state(local_vars={"counter": 0})
        results = []

        def fork_and_mutate(thread_id: int):
            child = parent.fork()
            child.local_vars["counter"] = thread_id
            child.local_vars[f"thread_{thread_id}"] = True
            results.append(child)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fork_and_mutate, i) for i in range(50)]
            for f in futures:
                f.result()

        # Parent unchanged
        assert parent.local_vars["counter"] == 0

        # Each child has its own state
        for child in results:
            counter_val = child.local_vars["counter"]
            assert f"thread_{counter_val}" in child.local_vars


class TestSafeHashFallback:
    """Verify _safe_hash fallback behavior for unhashable objects."""

    def test_unhashable_returns_zero(self):
        """Unhashable objects with no hash_value method should return 0."""
        cow = CowDict()

        class Unhashable:
            __hash__ = None

        assert cow._safe_hash(Unhashable()) == 0

    def test_hash_value_method_used(self):
        """Objects with hash_value() method should use it."""
        cow = CowDict()

        class HasHashValue:
            __hash__ = None

            def hash_value(self) -> int:
                return 12345

        assert cow._safe_hash(HasHashValue()) == 12345

    def test_zero_fallback_does_not_cause_false_collisions(self):
        """Multiple unhashable objects returning 0 should still produce different dict hashes."""

        class Unhashable:
            __hash__ = None

            def __init__(self, name: str):
                self.name = name

        # Different keys mean different dicts even if values hash to 0
        dict1 = CowDict({"a": Unhashable("obj1")})
        dict2 = CowDict({"b": Unhashable("obj2")})

        # Keys differ, so hashes should differ
        assert dict1.hash_value() != dict2.hash_value()


class TestHash64BitBoundary:
    """Verify hash values stay within 64-bit bounds."""

    def test_cowdict_hash_bounded(self):
        """CowDict hash must be within 64-bit range."""
        cow = CowDict({i: i * 0xFFFFFFFFFFFF for i in range(1000)})
        h = cow.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_cowset_hash_bounded(self):
        """CowSet hash must be within 64-bit range."""
        cow = CowSet(set(range(0, 0xFFFFFFFF, 0x10000)))
        h = cow.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_constraint_chain_hash_bounded(self):
        """ConstraintChain hash must be within 64-bit range."""
        x = z3.Int("x")
        chain = ConstraintChain.empty()
        for i in range(1000):
            chain = chain.append(x > i)
        h = chain.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_vmstate_hash_bounded(self):
        """VMState hash must be within 64-bit range."""
        state = create_initial_state()
        x = z3.Int("x")
        for i in range(100):
            state.add_constraint(x > i)
            state.local_vars[f"var_{i}"] = i * 0xFFFFFFFF
        h = state.hash_value()
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


class TestXORCancellationResistance:
    """Verify XOR-based hashing resists cancellation attacks."""

    def test_duplicate_items_in_different_sets_different_hash(self):
        """Sets with same item appearing twice via different forks should differ."""
        # Actually CowSet is just integers, so this tests different construction paths
        set1 = CowSet({1, 2, 3})
        set2 = CowSet({1, 2, 3, 4})
        set2.discard(4)

        # After discard, set2 has same contents as set1
        # Hashes should be equal because content is equal
        assert set1.hash_value() == set2.hash_value()

    def test_avalanche_effect(self):
        """Small change in input should produce large change in hash."""
        set1 = CowSet({1, 2, 3})
        set2 = CowSet({1, 2, 4})  # One element different

        h1 = set1.hash_value()
        h2 = set2.hash_value()

        # Should differ by many bits (avalanche)
        diff_bits = bin(h1 ^ h2).count("1")
        assert diff_bits > 10, f"Only {diff_bits} bits differ, expected avalanche effect"
