"""
Example functions demonstrating pysymex verification.
This file contains various functions with potential bugs that pysymex
can detect using Z3 formal verification.
"""


def unsafe_divide(x: int, y: int) -> int:
    """Division that can crash when y=0."""
    return x // y


def safe_divide(x: int, y: int) -> int:
    """Division protected by a guard."""
    if y == 0:
        return 0
    return x // y


def divide_by_constant(x: int) -> int:
    """Division by a known non-zero constant."""
    return x // 5


def unsafe_modulo(x: int, y: int) -> int:
    """Modulo that can crash when y=0."""
    return x % y


def safe_modulo(x: int, y: int) -> int:
    """Modulo protected by a guard."""
    if y != 0:
        return x % y
    return 0


def unsafe_left_shift(x: int, n: int) -> int:
    """Shift that can crash with negative n."""
    return x << n


def safe_left_shift(x: int, n: int) -> int:
    """Shift protected by a guard."""
    if n < 0:
        return 0
    return x << n


def shift_by_constant(x: int) -> int:
    """Shift by a known non-negative constant."""
    return x << 3


def nested_conditions(a: int, b: int, c: int) -> int:
    """Multiple nested conditions with division."""
    if a > 0:
        if b > 0:
            return a // b
        else:
            return a // c
    return 0


def guarded_chain(x: int, y: int, z: int) -> int:
    """Chained operations with guards."""
    if y == 0 or z == 0:
        return 0
    result = x // y
    return result % z


def conditional_paths(x: int, y: int) -> int:
    """Different paths with different safety."""
    if x > 10:
        return x // 2
    else:
        return x // y


def helper_divide(a: int, b: int) -> int:
    """Helper function with potential division by zero."""
    return a // b


def caller_function(x: int, y: int) -> int:
    """Calls helper_divide - interprocedural analysis detects the bug."""
    return helper_divide(x, y)


def safe_caller(x: int, y: int) -> int:
    """Safely calls helper with guard."""
    if y == 0:
        return 0
    return helper_divide(x, y)


def calculate_average(numbers: list) -> float:
    """Calculate average - can crash on empty list."""
    total = sum(numbers)
    return total / len(numbers)


def safe_average(numbers: list) -> float:
    """Safely calculate average with guard."""
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)


def percentage(part: int, whole: int) -> float:
    """Calculate percentage - can crash on zero whole."""
    return (part / whole) * 100


def safe_percentage(part: int, whole: int) -> float:
    """Safely calculate percentage."""
    if whole == 0:
        return 0.0
    return (part / whole) * 100
