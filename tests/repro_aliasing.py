
import z3
from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig
from pysymex.core.types_containers import SymbolicObject
from pysymex.core.state import VMState, CowDict

def test_pointer_aliasing_repro():
    def alias_target(p1, p2):
        p1.x = 10
        p2.x = 20
        # If p1 and p2 alias, p1.x should be 20 here.
        if p1 is p2:
            # If the engine is unsound, it might think p1.x is still 10
            # and thus this assertion could be falsified.
            assert p1.x == 20
        return p1.x

    # Manually setting up symbolic objects to ensure they have different concrete addresses
    # but could have the same symbolic address.
    p1_addr_sym = z3.Int("p1_addr")
    p2_addr_sym = z3.Int("p2_addr")
    
    # In PySyMex, SymbolicObject usually expects a concrete address for its "primary" identity
    # but also carries a z3_addr for symbolic reasoning.
    p1 = SymbolicObject("p1", 100, p1_addr_sym, {100, 200})
    p2 = SymbolicObject("p2", 200, p2_addr_sym, {100, 200})

    config = ExecutionConfig(detect_assertion_errors=True, verbose=True)
    executor = SymbolicExecutor(config)
    
    # Create initial state
    state = VMState()
    state.local_vars["p1"] = p1
    state.local_vars["p2"] = p2
    
    # We need to add a constraint that p1 is p2 is possible
    # and also that they could be different.
    # p1 is p2 means p1_addr_sym == p2_addr_sym
    
    results = executor.execute_function(alias_target, initial_state=state)
    
    print(f"Explored {results.paths_explored} paths")
    found_assertion_error = False
    for issue in results.issues:
        print(f"Issue found: {issue.kind} - {issue.message}")
        if "AssertionError" in issue.message or "assert" in issue.message:
            found_assertion_error = True
            
    if found_assertion_error:
        print("\nRESULT: Assertion error found! This confirms that when p1 is p2, p1.x was NOT 20.")
        print("This means PySyMex's memory model is UNSOUND for aliasing.")
    else:
        # Check if we even reached the branch p1 is p2
        reached_aliased_path = False
        for branch in results.branches:
             # This is a bit hard to check from results.branches without more info
             pass
        print("\nRESULT: No assertion error found. PySyMex might be sound for this case (unlikely) or didn't explore the path.")

if __name__ == "__main__":
    test_pointer_aliasing_repro()
