from pysymex.core.solver import PortfolioSolver, SolverResult
import z3

def test_portfolio():
    ps = PortfolioSolver(timeout_ms=5000, fast_timeout_ms=100)
    
    # We will simulate that the default solver fails on materialization by mocking it.
    
    original_solver_check = z3.Solver.check
    
    def mocked_check(self, *args):
        # Fail the materialization check to simulate the default solver hanging
        # Wait, if we mock it, the worker process won't be affected if fork is not used (Windows uses spawn).
        # Actually we just mock it in the current process.
        return z3.unknown
        
    z3.Solver.check = mocked_check
    
    try:
        constraints = [z3.Int('x') == 5]
        # In worker, it uses a fresh process, where `z3.Solver.check` is original. 
        # So worker will return `z3.sat`.
        # Then `_materialize_sat_result` runs in MAIN process, where `check` is mocked to `unknown`.
        res = ps.check_hard(constraints)
        print(f"Result: is_sat={res.is_sat}, is_unknown={res.is_unknown}")
    finally:
        z3.Solver.check = original_solver_check

if __name__ == "__main__":
    test_portfolio()