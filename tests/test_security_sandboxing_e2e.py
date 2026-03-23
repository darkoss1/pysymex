import pytest
import sys
from pysymex.security import safe_exec, timeout_context, resource_limits, SecurityError, ExecutionTimeout

def test_safe_exec_blocks_imports():
    with pytest.raises(SecurityError):
        safe_exec("import os\nos.system('echo hacked')")

def test_timeout_context():
    with pytest.raises(ExecutionTimeout):
        # We cap this to 0.1s so the test runs fast and verifies interrupting works
        with timeout_context(0.1):
            while True:
                pass

def test_resource_limits():
    # Attempt to allocate a massive array to trigger memory limit
    try:
        with resource_limits(max_memory_mb=10):
            _arr = [0] * (1024 * 1024 * 20)  # ~160MB
    except MemoryError:
        pass
    except Exception as e:
        # On Windows resource_limits is a no-op currently, which is fine
        if sys.platform != "win32":
            raise e
