import logging
import sys

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

def simple_fork(x: int):
    if x > 0:
        return 1
    else:
        return 0

if __name__ == "__main__":
    config = ExecutionConfig(max_paths=100, timeout_seconds=10, enable_caching=False, verbose=True)
    executor = SymbolicExecutor(config)
    result = executor.execute_function(simple_fork, {"x": "int"})
    print(f"Explored {result.paths_explored} paths.")
    print(f"Issues: {result.issues}")
