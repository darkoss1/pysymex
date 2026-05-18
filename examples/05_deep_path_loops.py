"""
05: Deep Path Loops

This example demonstrates how pysymex handles loop unrolling and deep paths to find
bugs that only trigger after many iterations.

To scan this example:
    pysymex scan examples/05_deep_path_loops.py
"""


def deep_loop_bug(iterations: int) -> int:
    """
    A bug that only triggers at a highly specific iteration.
    pysymex can explore loop paths to detect this division by zero.
    """
    total = 100
    for i in range(iterations):
        if i == 350:
            return total // 0  # Bug triggers only at iteration 350
    return total
