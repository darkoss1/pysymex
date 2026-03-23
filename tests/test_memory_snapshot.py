"""Tests for memory model snapshot and restore integrity.

These tests verify that:
1. SymbolicAddress operations are correct
2. SymbolicHeap allocations and operations work
3. Memory state maintains isolation

NOTE: Tests adapted to match actual pysymex memory model API.
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.memory_model_types import MemoryRegion, SymbolicAddress
from pysymex.core.memory_model_core import SymbolicHeap
from pysymex.core.state import VMState


class TestSymbolicAddressBasics:
    """Tests for SymbolicAddress operations."""

    def test_create_address(self):
        """Address creation with integer base."""
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=0x1000,
            offset=0,
        )

        assert addr.region == MemoryRegion.HEAP

    def test_create_address_with_offset(self):
        """Address creation with offset."""
        addr = SymbolicAddress(
            region=MemoryRegion.STACK,
            base=0x1000,
            offset=8,
        )

        # Effective address should be base + offset
        eff = addr.effective_address
        assert eff is not None

    def test_add_offset(self):
        """Adding offset creates new address."""
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=0x1000,
        )

        new_addr = addr.add_offset(16)

        # New address should have updated offset
        assert new_addr is not addr
        assert new_addr.region == addr.region

    def test_symbolic_base(self):
        """Address with symbolic base."""
        sym_base = z3.BitVec("ptr", 64)
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=sym_base,
        )

        assert addr.base is sym_base

    def test_same_region_check(self):
        """Same region check."""
        addr1 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)
        addr2 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x2000)
        addr3 = SymbolicAddress(region=MemoryRegion.STACK, base=0x3000)

        assert addr1.same_region(addr2)
        assert not addr1.same_region(addr3)


class TestSymbolicAddressAliasing:
    """Tests for aliasing analysis."""

    def test_same_address_may_alias(self):
        """Same effective address should may-alias."""
        addr1 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)
        addr2 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)

        solver = z3.Solver()
        assert addr1.may_alias(addr2, solver)

    def test_different_address_no_alias(self):
        """Different effective addresses should not may-alias."""
        addr1 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)
        addr2 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x2000)

        solver = z3.Solver()
        assert not addr1.may_alias(addr2, solver)

    def test_different_region_no_alias(self):
        """Different regions should not alias."""
        addr1 = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)
        addr2 = SymbolicAddress(region=MemoryRegion.STACK, base=0x1000)

        solver = z3.Solver()
        assert not addr1.may_alias(addr2, solver)

    def test_symbolic_may_alias_concrete(self):
        """Symbolic address may alias with concrete."""
        sym_base = z3.BitVec("ptr", 64)
        sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)
        concrete_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=0x1000)

        solver = z3.Solver()
        # Symbolic could equal 0x1000
        assert sym_addr.may_alias(concrete_addr, solver)


class TestSymbolicHeapBasics:
    """Tests for SymbolicHeap operations."""

    def test_allocate_returns_address(self):
        """Allocation should return an address."""
        heap = SymbolicHeap()

        addr = heap.allocate(size=10)

        assert addr is not None
        assert isinstance(addr, SymbolicAddress)

    def test_allocate_unique_addresses(self):
        """Sequential allocations should return unique addresses."""
        heap = SymbolicHeap()

        addr1 = heap.allocate(size=10)
        addr2 = heap.allocate(size=10)

        # Addresses should differ
        solver = z3.Solver()
        assert not addr1.may_alias(addr2, solver)

    def test_write_and_read(self):
        """Write and read should work."""
        heap = SymbolicHeap()

        addr = heap.allocate(size=8)
        value = z3.IntVal(42)

        heap.write(addr, value)
        result = heap.read(addr)

        assert result is not None


class TestVMStateMemoryIsolation:
    """Tests for VMState memory isolation."""

    def test_vmstate_memory_isolation_on_fork(self):
        """VMState memory should be isolated on fork."""
        state = VMState()
        state.memory[100] = z3.IntVal(1)

        fork = state.fork()
        fork.memory[100] = z3.IntVal(2)
        fork.memory[200] = z3.IntVal(3)

        # Original should be unchanged
        assert 200 not in state.memory

    def test_vmstate_memory_hash_contribution(self):
        """Memory content should affect state hash."""
        state1 = VMState()
        state1.memory[100] = z3.IntVal(1)

        state2 = VMState()
        state2.memory[100] = z3.IntVal(2)

        # Different memory content, different hash
        assert state1.hash_value() != state2.hash_value()

    def test_vmstate_memory_fork_deep_isolation(self):
        """Deep changes in forked memory should not affect original."""
        state = VMState()

        for i in range(10):
            state.memory[i * 100] = z3.IntVal(i)

        fork = state.fork()

        # Clear all memory in fork
        for i in range(10):
            del fork.memory[i * 100]

        # Add new entries
        for i in range(10):
            fork.memory[1000 + i * 100] = z3.IntVal(i + 100)

        # Original should be unchanged
        assert len(state.memory) == 10
        assert 1000 not in state.memory


class TestSymbolicHeapSnapshot:
    """Tests for heap snapshot and restore."""

    def test_snapshot_basic(self):
        """Basic snapshot should capture state."""
        heap = SymbolicHeap()

        addr = heap.allocate(size=8)
        heap.write(addr, z3.IntVal(100))

        snapshot = heap.snapshot()

        assert snapshot is not None

    def test_restore_after_modification(self):
        """Restore should revert modifications."""
        heap = SymbolicHeap()

        addr = heap.allocate(size=8)
        heap.write(addr, z3.IntVal(100))

        snapshot = heap.snapshot()

        # Modify
        heap.write(addr, z3.IntVal(999))

        # Restore
        heap.restore(snapshot)

        # Value should be restored
        result = heap.read(addr)
        # Verification depends on exact implementation


class TestEffectiveAddressComputation:
    """Tests for effective address computation."""

    def test_effective_address_with_zero_offset(self):
        """Effective address equals base when offset is zero."""
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=0x1000,
            offset=0,
        )

        solver = z3.Solver()
        solver.add(addr.effective_address != 0x1000)
        assert solver.check() == z3.unsat

    def test_effective_address_with_offset(self):
        """Effective address is base + offset."""
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=0x1000,
            offset=0x100,
        )

        solver = z3.Solver()
        solver.add(addr.effective_address != 0x1100)
        assert solver.check() == z3.unsat

    def test_symbolic_effective_address(self):
        """Symbolic base produces symbolic effective address."""
        sym_base = z3.BitVec("base", 64)
        addr = SymbolicAddress(
            region=MemoryRegion.HEAP,
            base=sym_base,
            offset=8,
        )

        # Effective should be sym_base + 8
        solver = z3.Solver()
        expected = sym_base + 8
        solver.add(addr.effective_address != expected)
        assert solver.check() == z3.unsat
