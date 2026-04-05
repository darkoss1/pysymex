import time
import pytest
import z3

from pysymex.core.memory_model_core import SymbolicHeap
from pysymex.core.memory_model_types import MemoryRegion, SymbolicAddress
from pysymex.core.types import SymbolicValue
from pysymex.core.solver import create_solver, IncrementalSolver

def test_weak_update_pruning_performance():
    """
    Test that O(N) pruning avoids building massive conditional merge trees
    when reading/writing a symbolic address with many objects in the heap.
    """
    heap = SymbolicHeap()
    
    # Pre-allocate 1000 unrelated objects
    for i in range(1000):
        addr = heap.allocate()
        heap.write(addr, i, "__value__")

    # Create a symbolic address that is strictly constrained to be a specific object
    sym_base = z3.BitVec("sym_base_perf", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    target_addr = heap.allocate()
    heap.write(target_addr, 42, "__value__")

    # Setup solver with a strict constraint
    # We must use IncrementalSolver and set it as active solver context
    from pysymex.core.solver import active_incremental_solver
    solver = IncrementalSolver()
    solver.add(sym_addr.effective_address == target_addr.effective_address)

    active_incremental_solver.set(solver)
    
    try:
        start_time = time.perf_counter()
        
        # Write 100 times to the symbolic pointer
        for i in range(100):
            heap.write(sym_addr, i, "__value__")
            
        # Read from the target
        result = heap.read(target_addr, "__value__")
        
        elapsed = time.perf_counter() - start_time
        
        # O(N) naive iteration with 1000 objects * 100 iterations would take several seconds.
        # With trivial UNSAT pruning + solver bounds check, it should be very fast.
        assert elapsed < 2.0, f"Weak update performance is too slow! Took {elapsed:.2f} seconds."
        
        assert isinstance(result, SymbolicValue)
        # Verify the write actually landed
        solver.push()
        solver.add(result.z3_int != z3.IntVal(99))
        assert solver.check().is_unsat
        solver.pop()

    finally:
        active_incremental_solver.set(None)

def test_ast_simplification_loop():
    """
    Test that writing to a symbolic pointer in a loop does not explode the AST depth.
    """
    heap = SymbolicHeap()
    
    sym_base = z3.BitVec("sym_base_loop", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    addr1 = heap.allocate()
    heap.write(addr1, 0, "__value__")
    addr2 = heap.allocate()
    heap.write(addr2, 0, "__value__")

    start_time = time.perf_counter()
    
    # Write 200 times. Without AST simplification, this creates an If(...) depth of 200 * 2 = 400.
    # z3.simplify() inside the loop keeps it manageable.
    for i in range(200):
        heap.write(sym_addr, i, "__value__")
        
    elapsed = time.perf_counter() - start_time
    assert elapsed < 2.0, f"AST simplification might not be working! Took {elapsed:.2f} seconds."

