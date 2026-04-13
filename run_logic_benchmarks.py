import time
import psutil
import os
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.analysis.detectors import default_registry

def test_tier1_range(x: int):
    if x > 10 and x < 5:
        pass # unreachable

def test_tier2_antisymmetry(x: int, y: int):
    if x > y and y > x:
        pass # unreachable

def test_tier3_sequential_mod(x: int):
    y = x * 2
    if y % 2 == 1:
        pass # unreachable

FUNCTIONS = [
    test_tier1_range,
    test_tier2_antisymmetry,
    test_tier3_sequential_mod
]

def run_benchmarks():
    config = ExecutionConfig(
        max_paths=100,
        enable_chtd=True,
        timeout_seconds=30.0,
        verbose=False
    )
    
    executor = SymbolicExecutor(config=config, detector_registry=default_registry)
    print("All detectors in registry:", default_registry.list_available())
    print("Is logical-contradiction in registry?", "logical-contradiction" in default_registry._detectors)
    print("Can get logical-contradiction?", default_registry.get("logical-contradiction"))
    print("Active detectors:", [d.name for d in executor._active_detectors])
    
    print("="*60)
    print("Logical Contradiction Benchmarks (Tiers 1-5)")
    print("="*60)
    
    total_time = 0
    total_bugs = 0
    max_memory = 0
    chtd_runs = 0
    
    process = psutil.Process(os.getpid())
    
    for func in FUNCTIONS:
        print(f"Analyzing {func.__name__}...")
        start_time = time.time()
        
        result = executor.execute_function(func, {"x": "int", "y": "int"})
        
        elapsed = time.time() - start_time
        total_time += elapsed
        
        mem_info = process.memory_info().rss / (1024 * 1024)
        max_memory = max(max_memory, mem_info)
        
        logic_bugs = [i for i in result.issues if i.kind.name == "LOGICAL_CONTRADICTION"]
        total_bugs += len(logic_bugs)
        
        chtd_runs += result.solver_stats.get("chtd", {}).get("runs", 0)
        
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Memory: {mem_info:.2f} MB")
        print(f"  Logical Contradictions Found: {len(logic_bugs)}")
        for b in logic_bugs:
            print(f"    - {b.message}")
        print()

    print("="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total Time: {total_time:.3f}s")
    print(f"Peak Memory: {max_memory:.2f} MB")
    print(f"Total Logic Bugs Detected: {total_bugs}")
    print(f"Total CHTD Runs: {chtd_runs}")

if __name__ == '__main__':
    run_benchmarks()