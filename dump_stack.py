import time
import sys
import threading
import traceback
from pysymex.api import analyze
import benchmark_level4 as bl4
from pysymex.execution.types import ExecutionConfig

cfg = ExecutionConfig(max_paths=100, max_loop_iterations=10, timeout_seconds=15)

def run_it():
    try:
        analyze(bl4.level4_simple_hash, {"input_val": "int"}, config=cfg)
    except Exception as e:
        print("ERROR:", e)

t = threading.Thread(target=run_it)
t.daemon = True
t.start()

time.sleep(3)
print("\\n--- STACK TRACE AFTER 3s ---")
for thread_id, frame in sys._current_frames().items():
    if thread_id != threading.current_thread().ident:
        traceback.print_stack(frame)
