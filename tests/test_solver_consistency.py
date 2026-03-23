import z3
from pysymex.core.solver import IncrementalSolver

def test_solver_consistency():
    solver = IncrementalSolver()
    x = z3.Int("x")
    constraints = [x > 0, x < 10, x != 5]
    
    # First call
    res1 = solver.is_sat(constraints)
    hits_before = solver._cache_hits
    
    # Second call
    res2 = solver.is_sat(constraints)
    hits_after = solver._cache_hits
    
    assert res1 == res2, "Solver returned different results for the same constraints"
    assert hits_after > hits_before, "Solver did not use cache on the second identical query"
