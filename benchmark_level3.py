"""
Level 3 Benchmark Test for PySyMex
Environment & Memory - Pointers & System Calls

Tests pointer concretization and memory access patterns.
Note: Python doesn't have raw pointers, so we test list indexing and memory-like operations.
"""

def level3_buffer_overflow(data: list[int], index: int) -> int:
    """
    Buffer overflow test - tests symbolic index access.
    """
    # Guard against out-of-bounds
    if index >= 0 and index < len(data):
        result = data[index]
        if result == 42:
            assert True, "Target value found at index!"
            return result
    return 0


def level3_dynamic_allocation(size: int) -> list[int]:
    """
    Dynamic allocation test - creates list based on symbolic size.
    """
    if size > 0 and size <= 100:
        data = [i * 2 for i in range(size)]
        if len(data) == 50:
            assert True, "Dynamic allocation target reached!"
            return data
    return []


def level3_symbolic_index_access(arr: list[int], idx: int) -> int:
    """
    Symbolic index access - tests how engine handles symbolic indices.
    """
    if idx >= 0 and idx < len(arr):
        val = arr[idx]
        if val > 100:
            assert True, "High value found!"
            return val
    return 0


def level3_memory_pattern(data: list[int]) -> bool:
    """
    Memory pattern matching - tests iteration over memory.
    """
    if len(data) >= 5:
        # Check for pattern: 1, 2, 4, 8, 16
        if data[0] == 1 and data[1] == 2 and data[2] == 4 and data[3] == 8 and data[4] == 16:
            assert True, "Pattern matched!"
            return True
    return False
