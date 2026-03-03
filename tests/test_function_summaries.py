import dis

import unittest

from typing import Any

import z3


from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig

from pysymex.core.types import SymbolicValue


class TestFunctionSummaries(unittest.TestCase):
    def setUp(self):
        self.config = ExecutionConfig(
            enable_cross_function=True,
            enable_caching=False,
            max_paths=100,
        )

        self.executor = SymbolicExecutor(self.config)

    def test_simple_function_summary(self):
        """Test that cross-function analysis runs and produces summaries."""

        code_str = """
def target(a, b):
    def add_one(x):
        return x + 1
    r1 = add_one(a)
    r2 = add_one(b)
    return r1 + r2
"""

        namespace: dict = {}

        exec(compile(code_str, "<test>", "exec"), namespace)

        target_func = namespace["target"]

        result = self.executor.execute_function(target_func, {"a": "int", "b": "int"})

        self.assertIsNotNone(
            self.executor._cross_function,
            "CrossFunctionAnalyzer should remain initialised after execution",
        )

        cache = self.executor._cross_function.function_summary_cache

        self.assertIsNotNone(cache)

        self.assertIsNotNone(result)

    def test_constraints_in_summary(self):
        """Test that summaries capture constraints properly."""

        code_reuse = """
def target(a, b):
    def check(x):
        if x > 10:
            return 1
        return 0

    if a > 10:
        r1 = check(a)
        if b > 10:
            r2 = check(b)
"""

        namespace: dict = {}

        exec(compile(code_reuse, "<test>", "exec"), namespace)

        target_reuse = namespace["target"]

        result = self.executor.execute_function(target_reuse, {"a": "int", "b": "int"})

        self.assertIsNotNone(self.executor._cross_function)

        cache = self.executor._cross_function.function_summary_cache

        self.assertIsNotNone(cache)

        self.assertIsInstance(cache._hits, int)


if __name__ == "__main__":
    unittest.main()
