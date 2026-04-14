from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
import sys

def simple_fork(x: int):
    if x > 0:
        pass
    else:
        pass

if __name__ == "__main__":
    config = ExecutionConfig(max_paths=100, timeout_seconds=10, enable_caching=False)
    executor = SymbolicExecutor(config)
    result = executor.execute_function(simple_fork, {"x": "int"})
    print(f"Explored {result.paths_explored} paths.")
