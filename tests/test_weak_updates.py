import pytest
import z3

from pysymex.core.memory_model_core import SymbolicHeap
from pysymex.core.memory_model_types import MemoryRegion, SymbolicAddress
from pysymex.core.types import SymbolicValue
from pysymex.core.solver import create_solver


def test_weak_read_symbolic_address():
    """1. What happens when you read through a symbolic address — did you fix that too or just the write?"""
    heap = SymbolicHeap()
    addr1 = heap.allocate(region=MemoryRegion.HEAP)
    addr2 = heap.allocate(region=MemoryRegion.HEAP)

    # Initialize values
    heap.write(addr1, 10, "__value__")
    heap.write(addr2, 20, "__value__")

    # Create a purely symbolic address
    sym_base = z3.BitVec("sym_base_read", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    # Read through the symbolic address
    result = heap.read(sym_addr, "__value__")
    assert isinstance(result, SymbolicValue)

    # If sym_addr aliases addr1, result should be 10
    solver = create_solver()
    solver.add(sym_addr.effective_address == addr1.effective_address)
    solver.add(result.z3_int != z3.IntVal(10))
    assert solver.check() == z3.unsat

    # If sym_addr aliases addr2, result should be 20
    solver = create_solver()
    solver.add(sym_addr.effective_address == addr2.effective_address)
    solver.add(result.z3_int != z3.IntVal(20))
    assert solver.check() == z3.unsat


def test_weak_write_loop_accumulation():
    """2. What happens inside a loop that writes through a symbolic pointer hundreds of times?"""
    heap = SymbolicHeap()
    addr1 = heap.allocate()
    heap.write(addr1, 0, "__value__")

    sym_base = z3.BitVec("sym_base_loop", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    # Write 100 times through the symbolic pointer
    for i in range(1, 101):
        heap.write(sym_addr, i, "__value__")

    # Read back from the concrete address
    result = heap.read(addr1, "__value__")
    assert isinstance(result, SymbolicValue)

    # Check if the final value is 100 if the symbolic address always aliased it
    solver = create_solver()
    solver.add(sym_addr.effective_address == addr1.effective_address)
    solver.add(result.z3_int != z3.IntVal(100))
    assert solver.check() == z3.unsat

    # Check if the final value is 0 if it never aliased it
    solver = create_solver()
    solver.add(sym_addr.effective_address != addr1.effective_address)
    solver.add(result.z3_int != z3.IntVal(0))
    assert solver.check() == z3.unsat


def test_weak_update_different_regions():
    """3. What happens when two pointers are in completely different memory regions?"""
    heap = SymbolicHeap()
    addr_heap = heap.allocate(region=MemoryRegion.HEAP)
    heap.write(addr_heap, 42, "__value__")

    sym_base = z3.BitVec("sym_base_stack", SymbolicAddress.ADDR_WIDTH)
    # Symbolic address in STACK region
    sym_addr_stack = SymbolicAddress(region=MemoryRegion.STACK, base=sym_base)

    heap.write(sym_addr_stack, 99, "__value__")

    # Read back from heap
    result = heap.read(addr_heap, "__value__")
    assert isinstance(result, SymbolicValue)
    
    # Since regions differ, the write should not have affected the heap object at all.
    # We can check this structurally by ensuring the result is simply the concrete 42
    solver = create_solver()
    solver.add(result.z3_int != z3.IntVal(42))
    assert solver.check() == z3.unsat

    # Check that there is no conditional logic tying them
    assert str(99) not in str(result.z3_int)


def test_weak_update_fork_isolation():
    """4. What happens when you fork the execution state after a symbolic write and then mutate one branch?"""
    heap = SymbolicHeap()
    addr1 = heap.allocate()
    heap.write(addr1, 10, "__value__")

    sym_base = z3.BitVec("sym_base_fork", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    heap.write(sym_addr, 20, "__value__")

    child_heap = heap.fork()
    child_heap.write(sym_addr, 30, "__value__")

    result_parent = heap.read(addr1, "__value__")
    result_child = child_heap.read(addr1, "__value__")

    # Parent should only have up to 20
    solver_parent = create_solver()
    solver_parent.add(sym_addr.effective_address == addr1.effective_address)
    solver_parent.add(result_parent.z3_int != z3.IntVal(20))
    assert solver_parent.check() == z3.unsat

    # Child should have 30
    solver_child = create_solver()
    solver_child.add(sym_addr.effective_address == addr1.effective_address)
    solver_child.add(result_child.z3_int != z3.IntVal(30))
    assert solver_child.check() == z3.unsat


def test_weak_free_symbolic_address():
    """5. What happens when you free a symbolic address — is that also handled?"""
    heap = SymbolicHeap()
    addr1 = heap.allocate()

    sym_base = z3.BitVec("sym_base_free", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    heap.free(sym_addr)

    obj = heap.get_object(addr1)
    is_alive_expr = obj.is_alive

    solver = create_solver()
    solver.add(sym_addr.effective_address == addr1.effective_address)
    solver.add(is_alive_expr == True)
    assert solver.check() == z3.unsat

    solver = create_solver()
    solver.add(sym_addr.effective_address != addr1.effective_address)
    solver.add(is_alive_expr == False)
    assert solver.check() == z3.unsat


def test_weak_read_no_alias_candidates():
    """6. What happens when there are no alias candidates at all?"""
    heap = SymbolicHeap()
    # Heap is completely empty for the HEAP region (or we allocate only STACK)
    heap.allocate(region=MemoryRegion.STACK)

    sym_base = z3.BitVec("sym_base_empty", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    # Read from an empty region
    result = heap.read(sym_addr, "__value__")
    
    # Should not crash, should return a fresh symbolic value
    assert isinstance(result, SymbolicValue)
    # The value is completely unconstrained
    solver = create_solver()
    solver.add(result.z3_int == z3.IntVal(42))
    assert solver.check() == z3.sat


def test_weak_update_partial_alias_transitivity():
    """7. What happens if three pointers have a partial alias relationship where A may-alias B and B may-alias C but A definitely cannot alias C?"""
    heap = SymbolicHeap()
    
    # Concrete locations A and C
    addr_A = heap.allocate()
    addr_C = heap.allocate()
    
    heap.write(addr_A, 100, "__value__")
    heap.write(addr_C, 300, "__value__")

    # B is a symbolic address that might alias A or C
    B_base = z3.BitVec("B_base", SymbolicAddress.ADDR_WIDTH)
    addr_B = SymbolicAddress(region=MemoryRegion.HEAP, base=B_base)
    
    # Write to B
    heap.write(addr_B, 200, "__value__")

    val_A = heap.read(addr_A, "__value__")
    val_C = heap.read(addr_C, "__value__")

    # If B aliases A, C must NOT be affected
    solver = create_solver()
    solver.add(addr_B.effective_address == addr_A.effective_address)
    # C's effective address is concretely known and definitely != A's effective address
    # so C should still be 300
    solver.add(val_C.z3_int != z3.IntVal(300))
    assert solver.check() == z3.unsat

    # If B aliases C, A must NOT be affected
    solver = create_solver()
    solver.add(addr_B.effective_address == addr_C.effective_address)
    solver.add(val_A.z3_int != z3.IntVal(100))
    assert solver.check() == z3.unsat

