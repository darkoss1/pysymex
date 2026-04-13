import z3
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.analysis.detectors import default_registry

# 1. Tier 1: Local Single-Variable Contradictions
def range_contradiction(x: int):
    if x > 10 and x < 5:
        print("Bug!")

def parity_contradiction(x: int):
    if x % 2 == 0 and x % 2 == 1:
        print("Bug!")

def arithmetic_impossibility(x: int):
    if x + x == 1:
        print("Bug!")

def self_contradiction(x: int):
    if x != x:
        print("Bug!")

# 2. Tier 2: Multi-Variable Contradictions
def antisymmetry_violation(x: int, y: int):
    if x > y and y > x:
        print("Bug!")

def sum_impossibility(x: int, y: int):
    if x > 0 and y > 0 and x + y == 0:
        print("Bug!")

# 3. Tier 3: Path-Accumulation (Sequential)
def sequential_modular(x: int):
    y = x * 2
    if y % 2 == 1:
        print("Bug!")

def narrowing_contradiction(x: int):
    if x > 100:
        if x < 50:
            print("Bug!")

TEST_CASES = [
    range_contradiction,
    parity_contradiction,
    arithmetic_impossibility,
    self_contradiction,
    antisymmetry_violation,
    sum_impossibility,
    sequential_modular,
    narrowing_contradiction
]

def run_tests():
    config = ExecutionConfig(max_paths=100, solver_timeout_ms=5000)
    executor = SymbolicExecutor(config=config, detector_registry=default_registry)
    
    print("\n" + "="*60)
    print("PySyMex Logical Bug Detection Verification")
    print("="*60)
    
    for func in TEST_CASES:
        print(f"Testing {func.__name__}...")
        result = executor.execute_function(func, {"x": "int", "y": "int"})
        
        logic_issues = [i for i in result.issues if i.kind.name == "LOGICAL_CONTRADICTION"]
        
        if logic_issues:
            print(f"  [SUCCESS] Detected {len(logic_issues)} contradiction(s):")
            for issue in logic_issues:
                print(f"    - {issue.message}")
        else:
            print("  [FAILED] No logical contradiction detected.")
        print("-" * 40)

if __name__ == "__main__":
    run_tests()
