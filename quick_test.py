"""
Challenging Bug Detection Benchmark for PySyMex
Tests various difficult-to-detect bugs
Each function contains a bug that PySyMex should detect
"""

# Test 1: Deep nested conditional with division by zero in rare path
def test_deep_nested_division_by_zero(x, y, z, w, a, b):
    """
    Bug: Division by zero occurs only when all conditions are true
    This requires exploring 2^6 = 64 paths to find the bug
    """
    if x > 0:
        if y > 0:
            if z > 0:
                if w > 0:
                    if a > 0:
                        if b > 0:
                            # Bug: division by zero when x*y*z*w*a*b - 1000000 = 0
                            denominator = x * y * z * w * a * b - 1000000
                            return 1000 // denominator
    return 0

# Test 2: Subtle index out of bounds with computed index
def test_index_out_of_bounds(arr, x, y):
    """
    Bug: Index out of bounds when (x + y) * (x - y) equals array length
    """
    index = (x + y) * (x - y)
    if index >= 0 and index < len(arr):
        return arr[index]
    return arr[0]  # Fallback that might still fail

# Test 3: Null/None dereference in complex control flow
def test_none_dereference(data, flag1, flag2, flag3):
    """
    Bug: None dereference when data is None but flags lead to access
    """
    if flag1:
        if flag2:
            if flag3:
                if data is not None:
                    return data.get('value', 0)
                else:
                    # Bug: accessing data when it's None
                    return data['value']
    return 0

# Test 4: Logic error in condition (off-by-one)
def test_off_by_one_loop(n):
    """
    Bug: Off-by-one error in loop condition
    Should iterate n times but iterates n+1 times
    """
    total = 0
    for i in range(n + 1):  # Bug: should be range(n)
        total += i
    return total

# Test 5: Exception handling with wrong exception type
def test_exception_handling(x):
    """
    Bug: Catching wrong exception type
    """
    try:
        result = 100 // x
        return result
    except ValueError:  # Bug: should catch ZeroDivisionError
        return -1

# Test 6: Complex loop with invariant violation
def test_loop_invariant(start, end, step):
    """
    Bug: Loop invariant violated when step is negative
    """
    total = 0
    i = start
    while i < end:  # Bug: infinite loop if step is negative
        total += i
        i += step
    return total

# Test 7: Nested function with closure bug
def test_closure_bug(x):
    """
    Bug: Late binding in closure
    """
    functions = []
    for i in range(5):
        def closure():
            return i + x  # Bug: i is bound at call time, not definition
        functions.append(closure)
    return functions[0]()

# Test 8: Complex dictionary key error
def test_dict_key_error(config, key, default):
    """
    Bug: KeyError when nested key doesn't exist
    """
    if 'settings' in config:
        settings = config['settings']
        if key in settings:
            return settings[key]
        else:
            # Bug: might not have 'default' key
            return config['default']
    return default

# Test 9: Bitwise operation edge case
def test_bitwise_edge_case(x, shift):
    """
    Bug: Shift amount too large causes undefined behavior in some languages
    """
    return (x << shift) & 0xFFFFFFFF

# Test 10: String encoding/decoding error
def test_encoding_error(data, encoding):
    """
    Bug: UnicodeDecodeError when encoding is wrong
    """
    try:
        return data.decode(encoding)
    except UnicodeDecodeError:
        # Bug: returns corrupted string instead of handling error
        return data.decode('utf-8', errors='ignore')

# Test 11: Recursion depth issue
def test_recursion_depth(n):
    """
    Bug: Recursion depth exceeded for large n
    """
    if n <= 0:
        return 0
    return 1 + test_recursion_depth(n - 1)

# Test 12: Complex list comprehension bug
def test_list_comprehension_bug(numbers):
    """
    Bug: List comprehension with side effect
    """
    result = []
    for i, n in enumerate(numbers):
        if n > 0:
            result.append(numbers[i])  # Bug: should append n, not numbers[i]
    return result

# Test 13: Arithmetic overflow simulation
def test_arithmetic_overflow(n):
    """
    Bug: Integer overflow in nested multiplication
    """
    result = n
    for _ in range(9):
        result = result * n
    return result % 2**32

# Test 14: Complex boolean logic
def test_boolean_contradiction(a, b, c, d):
    """
    Bug: Unreachable code due to contradictory conditions
    """
    if (a and b) or (c and d):
        if a and c:
            if b and d:
                return 1
        else:
            return 2
    else:
        return 3

# Test 15: Race condition pattern simulation
def test_race_condition_pattern(shared, iterations):
    """
    Bug: Simulates race condition where concurrent access could cause issues
    """
    for i in range(iterations):
        if i > 100 and len(shared) > 0:
            shared[0] = shared[0] + 1
    return shared[0] if shared else 0
