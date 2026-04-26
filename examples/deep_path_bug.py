"""Test function requiring 500 paths to reach the bug."""

def single_function_500_paths(n: int) -> int:
    """Single function requiring loop iterations to reach the bug."""
    # Bug only reachable after 300+ iterations
    for i in range(400):
        if i == 350:
            return 1000 // 0  # Division by zero at iteration 350
    return 1
