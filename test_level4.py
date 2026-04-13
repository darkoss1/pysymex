import time
from pysymex.api import analyze
import benchmark_level4 as bl4
from pysymex.execution.types import ExecutionConfig

cfg = ExecutionConfig(max_paths=100, max_loop_iterations=10, timeout_seconds=15)

tests = [
    ("level4_simple_hash", bl4.level4_simple_hash, {"input_val": "int"}),
    ("level4_crc_like", bl4.level4_crc_like, {"data": "int"}),
    ("level4_nonlinear_equation", bl4.level4_nonlinear_equation, {"x": "int", "y": "int"}),
    ("level4_multiplicative_inverse", bl4.level4_multiplicative_inverse, {"x": "int"})
]

for name, func, args in tests:
    print(f"\\n--- RUNNING: {name} ---")
    start = time.time()
    try:
        analyze(func, args, config=cfg)
        print(f"DONE {name} in {time.time()-start:.2f}s")
    except Exception as e:
        print(f"FAIL {name}: {e}")
