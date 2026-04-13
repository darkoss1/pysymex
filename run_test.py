import time
import sys
from pysymex.core.solver.engine import IncrementalSolver
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
import benchmark_level2 as bl2

def bench():
    start = time.perf_counter()
    config = ExecutionConfig(
        max_depth=50,
        max_loop_iterations=10,
        timeout_seconds=30
    )
    engine = SymbolicExecutor(config=config)

    print("Running level2_nested_loops...")
    engine.execute_function(bl2.level2_nested_loops, {"x": "int", "y": "int"})
    
    elapsed = time.perf_counter() - start
    print(f"Finished in {elapsed:.3f}s")
    
    print("Running level2_string_verification...")
    engine.execute_function(bl2.level2_string_verification, {"input_str": "str"})

if __name__ == '__main__':
    bench()
