import time
import sys

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig

def extreme_path_explosion(x: int, y: int):
    # We want a branch that is explored but later becomes unsat.
    # Actually, let's just make a very large number of branches.
    # 20 branches = ~1 million paths.
    
    # We create a contradiction at the very end
    # that is independent of many variables?
    # To demonstrate O(1) pruning, we need the execution to fork,
    # and then immediately prune the branches because the bitmask says UNSAT.
    
    if x > 10 and y > 10:
        # Now we fork many times
        a = 0
        if x != 1: a += 1
        if x != 2: a += 1
        if x != 3: a += 1
        if x != 4: a += 1
        if x != 5: a += 1
        if x != 6: a += 1
        if x != 7: a += 1
        if x != 8: a += 1
        if x != 9: a += 1
        if x != 10: a += 1
        if x != 11: a += 1
        if x != 12: a += 1
        if x != 13: a += 1
        if x != 14: a += 1
        if x != 15: a += 1
        
        # Here's the contradiction
        if x + y < 0:
            # We are here on 2^15 = 32768 paths if the solver is lazy!
            pass

if __name__ == "__main__":
    # We use a large lazy_eval_threshold to simulate the need for MUS pruning.
    # By making the engine lazy, it will fork thousands of paths.
    # BUT with CHTD and TTS, the background thread will find the MUS (x>10, y>10, x+y<0)
    # and bitmask-prune all the remaining paths instantly!
    config = ExecutionConfig(
        max_paths=1000000, 
        timeout_seconds=20, 
        enable_chtd=True,
        strategy="adaptive",
        enable_caching=False,
        lazy_eval_threshold=100,
        detect_division_by_zero=False,
        detect_assertion_errors=False,
        detect_index_errors=False,
        detect_type_errors=False,
        detect_overflow=False,
        detect_value_errors=False,
        chtd_check_interval=16, # Dispatch MUS quicker for benchmark
    )
    from pysymex.analysis.detectors import DetectorRegistry
    empty_registry = DetectorRegistry()
    executor = SymbolicExecutor(config, detector_registry=empty_registry)
    
    print("Starting extreme path explosion benchmark...")
    start_time = time.time()
    
    result = executor.execute_function(extreme_path_explosion, {"x": "int", "y": "int"})
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"Explored {result.paths_explored} paths in {duration:.4f} seconds.")
    print(f"Pruned {result.paths_pruned} paths.")
    
    if duration > 10:
        print("FAIL: The benchmark took too long.")
        sys.exit(1)
    else:
        print("SUCCESS: The benchmark completed quickly.")
        sys.exit(0)
