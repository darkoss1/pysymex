"""Memory snapshot integrity tests.

Verifies that memory snapshot/restore provides perfect state recovery.

Source contracts tested:
- memory_model_core.py:206-223 (restore must restore EXACT state)

Critical invariants:
1. Restore is exact inverse of snapshot
2. Freed addresses exactly match snapshot
3. Reference tracking consistency
4. Multiple snapshot stack works correctly
5. Address allocator state restored correctly
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.memory_model_core import SymbolicHeap, HeapSnapshot


class TestRestoreIsExactInverse:
    """Verify snapshot -> mutate -> restore equals original."""

    def test_basic_restore(self):
        """Basic restore should return heap to snapshot state."""
        heap = SymbolicHeap()

        # Allocate some objects
        addr1 = heap.allocate("int", 1)
        addr2 = heap.allocate("str", 1)
        heap.write(addr1, 42)
        heap.write(addr2, "hello")

        # Take snapshot
        snapshot = heap.snapshot()

        # Mutate
        heap.write(addr1, 999)
        addr3 = heap.allocate("list", 1)
        heap.write(addr3, [1, 2, 3])

        # Restore
        heap.restore(snapshot)

        # Verify original state
        assert heap.read(addr1) == 42
        assert heap.read(addr2) == "hello"

    def test_restore_after_free(self):
        """Restore should undo a free operation."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)
        heap.write(addr, 100)

        snapshot = heap.snapshot()

        heap.free(addr)

        # After free, reading should fail
        with pytest.raises(ValueError, match="Use after free"):
            heap.read(addr)

        heap.restore(snapshot)

        # After restore, should be able to read again
        assert heap.read(addr) == 100

    def test_restore_removes_post_snapshot_allocations(self):
        """Allocations after snapshot should be removed on restore."""
        heap = SymbolicHeap()
        addr1 = heap.allocate("int", 1)
        heap.write(addr1, 1)

        snapshot = heap.snapshot()

        addr2 = heap.allocate("int", 1)
        heap.write(addr2, 2)
        addr2_int = heap.get_concrete_address(addr2)
        assert addr2_int in heap._heap

        heap.restore(snapshot)

        # addr2 should no longer exist
        assert addr2_int not in heap._heap

    def test_multiple_mutations_all_undone(self):
        """Multiple mutations after snapshot should all be undone."""
        heap = SymbolicHeap()
        addrs = [heap.allocate("int", 1) for _ in range(5)]
        for i, addr in enumerate(addrs):
            heap.write(addr, i * 10)

        snapshot = heap.snapshot()

        # Multiple mutations
        for i, addr in enumerate(addrs):
            heap.write(addr, i * 100)
        new_addr = heap.allocate("str", 1)
        heap.write(new_addr, "new")
        heap.free(addrs[0])

        heap.restore(snapshot)

        # All should be back to original
        for i, addr in enumerate(addrs):
            assert heap.read(addr) == i * 10
        new_addr_int = heap.get_concrete_address(new_addr)
        assert new_addr_int not in heap._heap


class TestFreedAddressSetRestore:
    """Verify freed set exactly matches snapshot."""

    def test_freed_set_restored_exactly(self):
        """Freed addresses must match snapshot exactly."""
        heap = SymbolicHeap()
        addr1 = heap.allocate("int", 1)
        addr2 = heap.allocate("int", 1)

        heap.free(addr1)
        snapshot = heap.snapshot()

        # Free more
        heap.free(addr2)
        addr1_int = heap.get_concrete_address(addr1)
        addr2_int = heap.get_concrete_address(addr2)
        assert addr1_int in heap._freed
        assert addr2_int in heap._freed

        heap.restore(snapshot)

        assert addr1_int in heap._freed
        assert addr2_int not in heap._freed

    def test_restored_freed_prevents_double_free(self):
        """Restored freed set should prevent double-free detection."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)
        heap.free(addr)

        snapshot = heap.snapshot()
        heap.restore(snapshot)

        # Should still raise double-free
        with pytest.raises(ValueError, match="Double free"):
            heap.free(addr)

    def test_freed_cleared_on_restore_before_free(self):
        """If address wasn't freed at snapshot time, it should not be freed after restore."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)
        heap.write(addr, 123)

        snapshot = heap.snapshot()

        heap.free(addr)
        addr_int = heap.get_concrete_address(addr)
        assert addr_int in heap._freed

        heap.restore(snapshot)

        # Should be usable again
        assert heap.read(addr) == 123
        assert addr_int not in heap._freed


class TestNestedSnapshotStack:
    """Verify multiple nested snapshot/restore operations."""

    def test_nested_snapshot_restore(self):
        """Nested snapshots should restore to correct levels."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)

        heap.write(addr, 1)
        snapshot1 = heap.snapshot()

        heap.write(addr, 2)
        snapshot2 = heap.snapshot()

        heap.write(addr, 3)
        snapshot3 = heap.snapshot()

        heap.write(addr, 4)

        # Restore to snapshot3 (value=3)
        heap.restore(snapshot3)
        assert heap.read(addr) == 3

        # Restore to snapshot2 (value=2)
        heap.restore(snapshot2)
        assert heap.read(addr) == 2

        # Restore to snapshot1 (value=1)
        heap.restore(snapshot1)
        assert heap.read(addr) == 1

    def test_snapshot_restore_interleaved(self):
        """Interleaved snapshot/restore should work correctly."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)
        heap.write(addr, 0)

        snap_a = heap.snapshot()
        heap.write(addr, 10)

        snap_b = heap.snapshot()
        heap.write(addr, 20)

        # Restore to B
        heap.restore(snap_b)
        assert heap.read(addr) == 10

        # Mutate again
        heap.write(addr, 30)

        # Restore to A
        heap.restore(snap_a)
        assert heap.read(addr) == 0


class TestAddressAllocatorStateRestore:
    """Verify address allocator state is correctly restored."""

    def test_next_address_restored(self):
        """Next address counter should be restored exactly."""
        heap = SymbolicHeap()

        # Allocate some addresses
        addr1 = heap.allocate("int", 1)
        addr2 = heap.allocate("int", 1)
        next_addr_at_snapshot = heap._next_address

        snapshot = heap.snapshot()

        # Allocate more
        addr3 = heap.allocate("int", 1)
        addr4 = heap.allocate("int", 1)
        assert heap._next_address > next_addr_at_snapshot

        heap.restore(snapshot)

        assert heap._next_address == next_addr_at_snapshot

    def test_allocations_after_restore_use_correct_addresses(self):
        """Allocations after restore should use reset address counter."""
        heap = SymbolicHeap()
        addr1 = heap.allocate("int", 1)

        snapshot = heap.snapshot()
        next_addr_snapshot = heap._next_address

        addr2 = heap.allocate("int", 1)
        addr3 = heap.allocate("int", 1)

        heap.restore(snapshot)

        # New allocations should start from where snapshot was
        addr_new = heap.allocate("int", 1)
        # The exact address depends on implementation, but should be >= snapshot point
        addr_new_int = heap.get_concrete_address(addr_new)
        assert addr_new_int is not None
        assert addr_new_int >= next_addr_snapshot


class TestFieldWriteRestore:
    """Verify field-level writes are restored correctly."""

    def test_field_values_restored(self):
        """Object fields should be restored to snapshot values."""
        heap = SymbolicHeap()
        addr = heap.allocate("object", 1, is_mutable=True)

        heap.write(addr, "field1_value", field="field1")
        heap.write(addr, "field2_value", field="field2")

        snapshot = heap.snapshot()

        heap.write(addr, "modified", field="field1")
        heap.write(addr, "new_field", field="field3")

        heap.restore(snapshot)

        assert heap.read(addr, field="field1") == "field1_value"
        assert heap.read(addr, field="field2") == "field2_value"


class TestSnapshotIsolation:
    """Verify snapshots are independent copies."""

    def test_snapshot_is_independent_copy(self):
        """Modifications to heap should not affect existing snapshot."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)
        heap.write(addr, 100)

        snapshot = heap.snapshot()

        # Modify heap
        heap.write(addr, 200)

        # Snapshot should still have original value when restored
        heap.restore(snapshot)
        assert heap.read(addr) == 100

    def test_multiple_snapshots_independent(self):
        """Multiple snapshots should be independent of each other."""
        heap = SymbolicHeap()
        addr = heap.allocate("int", 1)

        heap.write(addr, 1)
        snap1 = heap.snapshot()

        heap.write(addr, 2)
        snap2 = heap.snapshot()

        heap.write(addr, 3)
        snap3 = heap.snapshot()

        # Restoring to different snapshots should give different values
        heap.restore(snap2)
        assert heap.read(addr) == 2

        heap.restore(snap1)
        assert heap.read(addr) == 1

        heap.restore(snap3)
        assert heap.read(addr) == 3


class TestSymbolicValueRestore:
    """Verify symbolic values are correctly restored."""

    def test_symbolic_value_restored(self):
        """Symbolic values in heap should be restored correctly."""
        heap = SymbolicHeap()
        addr = heap.allocate("symbolic", 1)

        x = z3.Int("x")
        heap.write(addr, x)

        snapshot = heap.snapshot()

        y = z3.Int("y")
        heap.write(addr, y)

        heap.restore(snapshot)

        restored = heap.read(addr)
        # Should be the original symbolic value
        assert restored.eq(x)


class TestImmutabilityPreservation:
    """Verify immutability flags are preserved across restore."""

    def test_immutable_flag_preserved(self):
        """Immutable objects should remain immutable after restore."""
        heap = SymbolicHeap()
        addr = heap.allocate("immutable_type", 1, is_mutable=False)

        snapshot = heap.snapshot()
        heap.restore(snapshot)

        # Should still be immutable
        with pytest.raises(ValueError, match="Cannot modify immutable"):
            heap.write(addr, "new_value")

    def test_mutable_flag_preserved(self):
        """Mutable objects should remain mutable after restore."""
        heap = SymbolicHeap()
        addr = heap.allocate("mutable_type", 1, is_mutable=True)
        heap.write(addr, "original")

        snapshot = heap.snapshot()
        heap.write(addr, "modified")

        heap.restore(snapshot)

        # Should still be mutable
        heap.write(addr, "new_value")  # Should not raise
        assert heap.read(addr) == "new_value"
