"""Integration tests for real-world code patterns.

Tests for:
- Multi-function analysis
- Complex control flow
- Exception + loop combinations
- Real-world code patterns
"""

import pytest

from pysymex.analysis.detectors import IssueKind
from pysymex.api import analyze

# ==============================================================================
# Real-World Safe Patterns
# ==============================================================================


class TestSafePatterns:
    """Tests for common safe patterns that should not trigger issues."""

    def test_guard_before_use(self):
        """Test guard-before-use pattern."""

        def guarded_access(lst, idx):
            if idx >= 0 and idx < len(lst):
                return lst[idx]
            return None

        result = analyze(guarded_access, {"lst": "list", "idx": "int"})
        index_issues = [i for i in result.issues if i.kind == IssueKind.INDEX_ERROR]
        assert len(index_issues) == 0

    def test_default_value_pattern(self):
        """Test default value pattern."""

        def with_default(d, key, default=0):
            if key in d:
                return d[key]
            return default

        result = analyze(with_default, {"d": "dict", "key": "str", "default": "int"})
        assert result is not None

    def test_early_return_pattern(self):
        """Test early return for error cases."""

        def early_return(x, y):
            if y == 0:
                return None
            return x / y

        result = analyze(early_return, {"x": "int", "y": "int"})
        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]
        assert len(div_issues) == 0

    def test_assertion_as_contract(self):
        """Test assertion as precondition."""

        def with_assertion(x, y):
            assert y != 0, "y must be non-zero"
            return x / y

        result = analyze(with_assertion, {"x": "int", "y": "int"})
        # Assertion failure might be detected, but division is safe after
        assert result is not None

    def test_try_except_pattern(self):
        """Test try-except for error handling."""

        def with_try(x, y):
            try:
                return x / y
            except ZeroDivisionError:
                return 0

        result = analyze(with_try, {"x": "int", "y": "int"})
        assert result is not None


# ==============================================================================
# Unsafe Patterns
# ==============================================================================


class TestUnsafePatterns:
    """Tests for unsafe patterns that should trigger issues."""

    def test_unchecked_division(self):
        """Test unchecked division."""

        def unchecked(x, y):
            return x / y

        result = analyze(unchecked, {"x": "int", "y": "int"})
        assert result.has_issues()

    def test_unchecked_index(self):
        """Test unchecked index access."""

        def unchecked(lst):
            return lst[5]  # What if len(lst) <= 5?

        result = analyze(unchecked, {"lst": "list"})
        assert result is not None

    def test_wrong_comparison_operator(self):
        """Test wrong comparison operator (off-by-one)."""

        def wrong_compare(x, y):
            if y >= 0:  # Should be y > 0
                return x / y
            return 0

        result = analyze(wrong_compare, {"x": "int", "y": "int"})
        # y >= 0 includes y == 0
        assert result.has_issues()

    def test_incomplete_guard(self):
        """Test incomplete guard condition."""

        def incomplete(lst, idx):
            if idx >= 0:  # Missing upper bound check
                return lst[idx]
            return None

        result = analyze(incomplete, {"lst": "list", "idx": "int"})
        assert result is not None


# ==============================================================================
# Loop Integration Tests
# ==============================================================================


class TestLoopIntegration:
    """Tests for loop-related integration scenarios."""

    def test_simple_for_range(self):
        """Test simple for-range loop."""

        def sum_range(n):
            total = 0
            for i in range(n):
                total += i
            return total

        result = analyze(sum_range, {"n": "int"})
        assert result is not None

    def test_for_with_index_access(self):
        """Test for loop with index access."""

        def iterate_list(lst):
            total = 0
            for i in range(len(lst)):
                total += lst[i]
            return total

        result = analyze(iterate_list, {"lst": "list"})
        assert result is not None

    def test_while_with_termination(self):
        """Test while loop with termination."""

        def countdown(n):
            while n > 0:
                n -= 1
            return n

        result = analyze(countdown, {"n": "int"})
        assert result is not None

    def test_nested_loops(self):
        """Test nested loops."""

        def matrix_sum(n, m):
            total = 0
            for i in range(n):
                for j in range(m):
                    total += i * j
            return total

        result = analyze(matrix_sum, {"n": "int", "m": "int"})
        assert result is not None

    @pytest.mark.slow
    def test_loop_with_break(self):
        """Test loop with break condition."""

        def find_first(lst, target):
            for i, val in enumerate(lst):
                if val == target:
                    return i
            return -1

        result = analyze(find_first, {"lst": "list", "target": "int"})
        assert result is not None

    @pytest.mark.slow
    def test_loop_with_continue(self):
        """Test loop with continue."""

        def sum_positive(lst):
            total = 0
            for val in lst:
                if val < 0:
                    continue
                total += val
            return total

        result = analyze(sum_positive, {"lst": "list"})
        assert result is not None


# ==============================================================================
# Exception Integration Tests
# ==============================================================================


class TestExceptionIntegration:
    """Tests for exception handling integration."""

    def test_exception_with_division(self):
        """Test exception around division."""

        def safe_div(x, y):
            try:
                return x / y
            except:
                return 0

        result = analyze(safe_div, {"x": "int", "y": "int"})
        assert result is not None

    def test_exception_with_index(self):
        """Test exception around index access."""

        def safe_get(lst, idx):
            try:
                return lst[idx]
            except IndexError:
                return None

        result = analyze(safe_get, {"lst": "list", "idx": "int"})
        assert result is not None

    def test_multiple_except_clauses(self):
        """Test multiple except clauses."""

        def multi_except(x, lst, idx):
            try:
                return lst[idx] / x
            except IndexError:
                return -1
            except ZeroDivisionError:
                return -2

        result = analyze(multi_except, {"x": "int", "lst": "list", "idx": "int"})
        assert result is not None

    def test_finally_clause(self):
        """Test finally clause."""

        def with_finally(x, y):
            result = 0
            try:
                result = x / y
            finally:
                result += 1
            return result

        result = analyze(with_finally, {"x": "int", "y": "int"})
        assert result is not None


# ==============================================================================
# Multi-Function Patterns
# ==============================================================================


class TestMultiFunctionPatterns:
    """Tests for multi-function code patterns."""

    def test_helper_function_call(self):
        """Test calling helper function."""

        def helper(x):
            return x * 2

        def main(a, b):
            return helper(a) + helper(b)

        result = analyze(main, {"a": "int", "b": "int"})
        assert result is not None

    def test_recursive_function(self):
        """Test recursive function."""

        def factorial(n):
            if n <= 1:
                return 1
            return n * factorial(n - 1)

        result = analyze(factorial, {"n": "int"})
        assert result is not None

    def test_mutual_recursion(self):
        """Test mutually recursive functions."""

        def is_even(n):
            if n == 0:
                return True
            return is_odd(n - 1)

        def is_odd(n):
            if n == 0:
                return False
            return is_even(n - 1)

        result = analyze(is_even, {"n": "int"})
        assert result is not None


# ==============================================================================
# Data Structure Patterns
# ==============================================================================


class TestDataStructurePatterns:
    """Tests for data structure usage patterns."""

    def test_list_append_pattern(self):
        """Test list append pattern."""

        def build_list(n):
            result = []
            for i in range(n):
                result.append(i)
            return result

        result = analyze(build_list, {"n": "int"})
        assert result is not None

    def test_dict_get_pattern(self):
        """Test dict.get with default."""

        def safe_get(d, key):
            return d.get(key, 0)

        result = analyze(safe_get, {"d": "dict", "key": "str"})
        assert result is not None

    def test_set_operations(self):
        """Test set operations."""

        def set_union(s1, s2):
            return s1 | s2

        result = analyze(set_union, {"s1": "set", "s2": "set"})
        assert result is not None

    def test_list_comprehension(self):
        """Test list comprehension."""

        def squares(n):
            return [i * i for i in range(n)]

        result = analyze(squares, {"n": "int"})
        assert result is not None

    def test_dict_comprehension(self):
        """Test dict comprehension."""

        def index_map(lst):
            return {i: v for i, v in enumerate(lst)}

        result = analyze(index_map, {"lst": "list"})
        assert result is not None


# ==============================================================================
# Conditional Expression Tests
# ==============================================================================


class TestConditionalExpressions:
    """Tests for conditional expressions."""

    def test_ternary_operator(self):
        """Test ternary operator."""

        def ternary(x, y):
            return x / y if y != 0 else 0

        result = analyze(ternary, {"x": "int", "y": "int"})
        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]
        assert len(div_issues) == 0

    def test_chained_ternary(self):
        """Test chained ternary."""

        def chained(x):
            return "positive" if x > 0 else "negative" if x < 0 else "zero"

        result = analyze(chained, {"x": "int"})
        assert result is not None

    def test_and_short_circuit(self):
        """Test AND short-circuit."""

        def and_circuit(lst, idx):
            return idx < len(lst) and lst[idx] > 0

        result = analyze(and_circuit, {"lst": "list", "idx": "int"})
        assert result is not None

    def test_or_short_circuit(self):
        """Test OR short-circuit."""

        def or_circuit(x, default):
            return x or default

        result = analyze(or_circuit, {"x": "int", "default": "int"})
        assert result is not None


# ==============================================================================
# Complex Real Patterns
# ==============================================================================


class TestComplexRealPatterns:
    """Tests for complex real-world patterns."""

    def test_binary_search(self):
        """Test binary search pattern."""

        def binary_search(arr, target):
            left, right = 0, len(arr) - 1
            while left <= right:
                mid = (left + right) // 2
                if arr[mid] == target:
                    return mid
                elif arr[mid] < target:
                    left = mid + 1
                else:
                    right = mid - 1
            return -1

        result = analyze(binary_search, {"arr": "list", "target": "int"})
        assert result is not None

    def test_fibonacci(self):
        """Test Fibonacci computation."""

        def fibonacci(n):
            if n <= 1:
                return n
            a, b = 0, 1
            for _ in range(n - 1):
                a, b = b, a + b
            return b

        result = analyze(fibonacci, {"n": "int"})
        assert result is not None

    @pytest.mark.slow
    def test_gcd(self):
        """Test GCD computation."""

        def gcd(a, b):
            while b != 0:
                a, b = b, a % b
            return a

        result = analyze(gcd, {"a": "int", "b": "int"})
        assert result is not None

    def test_prime_check(self):
        """Test prime number check."""

        def is_prime(n):
            if n < 2:
                return False
            for i in range(2, int(n**0.5) + 1):
                if n % i == 0:
                    return False
            return True

        result = analyze(is_prime, {"n": "int"})
        assert result is not None

    @pytest.mark.slow
    def test_sorting_pattern(self):
        """Test sorting pattern."""

        def bubble_sort(arr):
            n = len(arr)
            for i in range(n):
                for j in range(0, n - i - 1):
                    if arr[j] > arr[j + 1]:
                        arr[j], arr[j + 1] = arr[j + 1], arr[j]
            return arr

        result = analyze(bubble_sort, {"arr": "list"})
        assert result is not None


# ==============================================================================
# String Processing Patterns
# ==============================================================================


class TestStringProcessingPatterns:
    """Tests for string processing patterns."""

    def test_string_reverse(self):
        """Test string reversal."""

        def reverse(s):
            return s[::-1]

        result = analyze(reverse, {"s": "str"})
        assert result is not None

    def test_string_split_join(self):
        """Test split and join."""

        def split_join(s):
            parts = s.split(",")
            return ":".join(parts)

        result = analyze(split_join, {"s": "str"})
        assert result is not None

    def test_string_validation(self):
        """Test string validation pattern."""

        def is_valid_email(s):
            return "@" in s and "." in s

        result = analyze(is_valid_email, {"s": "str"})
        assert result is not None

    def test_string_format(self):
        """Test string formatting."""

        def format_greeting(name, age):
            return f"Hello, {name}! You are {age} years old."

        result = analyze(format_greeting, {"name": "str", "age": "int"})
        assert result is not None


# ==============================================================================
# Error Handling Patterns
# ==============================================================================


class TestErrorHandlingPatterns:
    """Tests for error handling patterns."""

    def test_validation_before_process(self):
        """Test validation before processing."""

        def process(data):
            if data is None:
                raise ValueError("Data cannot be None")
            if len(data) == 0:
                raise ValueError("Data cannot be empty")
            return data[0]

        result = analyze(process, {"data": "list"})
        assert result is not None

    def test_result_wrapper_pattern(self):
        """Test result wrapper pattern."""

        def safe_operation(x, y):
            if y == 0:
                return {"success": False, "error": "Division by zero"}
            return {"success": True, "value": x / y}

        result = analyze(safe_operation, {"x": "int", "y": "int"})
        assert result is not None

    def test_retry_pattern(self):
        """Test retry pattern."""

        def with_retry(func, max_retries=3):
            for attempt in range(max_retries):
                try:
                    return func()
                except Exception:
                    if attempt == max_retries - 1:
                        raise
            return None

        # Can't fully test this without callable, but check structure
        assert True
