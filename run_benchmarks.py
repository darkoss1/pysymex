import time
import sys
from pysymex.core.solver.engine import IncrementalSolver
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
import benchmark_level2 as bl2
import benchmark_insane as bi

def bench_func(engine, func, kwargs, name):
    print(f"\\n--- Running {name} ---")
    start = time.perf_counter()
    try:
        engine.execute_function(func, kwargs)
        elapsed = time.perf_counter() - start
        print(f"[OK] {name} finished in {elapsed:.3f}s")
    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"[ERROR] {name} failed after {elapsed:.3f}s: {str(e)}")

def bench():
    print("Initializing PySyMex Engine...")
    config = ExecutionConfig(
        max_depth=50,
        max_loop_iterations=10,
        timeout_seconds=60
    )
    engine = SymbolicExecutor(config=config)
    
    print("\\n=== BENCHMARK LEVEL 2 ===")
    bench_func(engine, bl2.level2_string_verification, {"input_str": "str"}, "level2_string_verification")
    bench_func(engine, bl2.level2_array_sum, {"arr": "list[int]"}, "level2_array_sum")
    bench_func(engine, bl2.level2_sorted_check, {"arr": "list[int]"}, "level2_sorted_check")
    bench_func(engine, bl2.level2_nested_loops, {"x": "int", "y": "int"}, "level2_nested_loops")

    print("\\n=== BENCHMARK INSANE ===")
    # These are typically extremely aggressive paths
    bench_func(engine, bi.insane_math_puzzle, {"x": "int", "y": "int", "z": "int"}, "insane_math_puzzle")
    if hasattr(bi, "insane_path_explosion"):
        bench_func(engine, bi.insane_path_explosion, {"arr": "list[int]"}, "insane_path_explosion")
    if hasattr(bi, "insane_sha256_stub"):
        bench_func(engine, bi.insane_sha256_stub, {"data": "bytes"}, "insane_sha256_stub")

if __name__ == '__main__':
    bench()
