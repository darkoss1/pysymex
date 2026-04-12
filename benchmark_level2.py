"""
Level 2 Benchmark Test for PySyMex
State Management - Bounded Loops & Arrays

Tests path explosion with loops and array operations.
"""

def level2_string_verification(input_str: str) -> bool:
    """
    String verification routine - tests loop unrolling.
    Checks if input matches a simple pattern.
    """
    if len(input_str) != 10:
        return False

    target = "secret123"
    for i in range(10):
        if input_str[i] != target[i]:
            return False
    
    assert True, "Password matched!"
    return True


def level2_array_sum(arr: list[int]) -> int:
    """
    Array summation with bounded loop.
    Tests if engine can handle symbolic loop bounds.
    """
    total = 0
    for i in range(len(arr)):
        total += arr[i]
    
    if total == 100:
        assert True, "Target sum reached!"
        return total
    return total


def level2_sorted_check(arr: list[int]) -> bool:
    """
    Check if array is sorted.
    Tests loop with comparison operations.
    """
    if len(arr) < 2:
        return True
    
    for i in range(len(arr) - 1):
        if arr[i] > arr[i + 1]:
            return False
    
    assert True, "Array is sorted!"
    return True


def level2_nested_loops(x: int, y: int) -> int:
    """
    Nested loops - tests path explosion.
    """
    total = 0
    for i in range(x):
        for j in range(y):
            total += i * j
    
    if total == 50:
        assert True, "Nested loop target reached!"
        return total
    return total
