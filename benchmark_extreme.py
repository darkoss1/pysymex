import time
import sys
import z3

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.analysis.detectors import Issue, IssueKind, Detector

# A synthetic example of path explosion.
# If CHTD pruning works, the engine shouldn't explore all paths when there's an early contradiction.
def extreme_path_explosion(x: int):
    # This contradiction should be extracted as an MUS
    if x > 100:
        if x < 0:
            # Inside here is UNSAT. 
            # If the engine fails to learn the MUS efficiently or calls Z3 too much,
            # this loop will explode or take a long time to prune.
            a = 0
            for i in range(20):
                if x == i:
                    a += 1
                else:
                    a -= 1
            if a == 10:
                raise AssertionError("Unreachable bug")

if __name__ == "__main__":
    # We set a short timeout to see if it times out or finishes instantly
    config = ExecutionConfig(
        max_paths=1000000, 
        timeout_seconds=10, 
        enable_chtd=True,
        strategy="adaptive"
    )
    executor = SymbolicExecutor(config)
    
    print("Starting extreme path explosion benchmark...")
    start_time = time.time()
    
    result = executor.execute_function(extreme_path_explosion, {"x": "int"})
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"Explored {result.paths_explored} paths in {duration:.4f} seconds.")
    print(f"Pruned {result.paths_pruned} paths.")
    print(f"Issues found: {len(result.issues)}")
    
    if duration > 5:
        print("FAIL: The benchmark took too long. O(1) pruning is not working as expected.")
        sys.exit(1)
    else:
        print("SUCCESS: The benchmark completed quickly.")
        sys.exit(0)
