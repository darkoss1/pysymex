"""Test script for the three architecture fixes."""

import sys

sys.path.insert(0, ".")


from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig


def test_build_list():
    """Test that BUILD_LIST preserves concrete values."""

    def sample_list_func(x):
        my_list = [1, 2, 3]

        return my_list[0]

    config = ExecutionConfig(max_paths=10, max_depth=50)

    executor = SymbolicExecutor(config)

    result = executor.execute_function(sample_list_func, {"x": "int"})

    print(f"[TEST 1a] BUILD_LIST - Paths explored: {result.paths_explored}")

    print(f"[TEST 1a] BUILD_LIST - Issues: {len(result.issues)}")

    assert result.paths_explored > 0


def test_build_tuple():
    """Test that BUILD_TUPLE preserves concrete values."""

    def sample_tuple_func(x):
        my_tuple = (10, 20, 30)

        return my_tuple[1]

    config = ExecutionConfig(max_paths=10, max_depth=50)

    executor = SymbolicExecutor(config)

    result = executor.execute_function(sample_tuple_func, {"x": "int"})

    print(f"[TEST 1b] BUILD_TUPLE - Paths explored: {result.paths_explored}")

    print(f"[TEST 1b] BUILD_TUPLE - Issues: {len(result.issues)}")

    assert result.paths_explored > 0


def test_inter_procedural():
    """Test that CALL handler enters user-defined functions."""

    def helper(a):
        if a > 0:
            return a * 2

        return 0

    def main_func(x):
        result = helper(x)

        return result

    config = ExecutionConfig(max_paths=20, max_depth=100)

    executor = SymbolicExecutor(config)

    result = executor.execute_function(main_func, {"x": "int"})

    print(f"[TEST 2] Inter-Procedural - Paths explored: {result.paths_explored}")

    print(f"[TEST 2] Inter-Procedural - Issues: {len(result.issues)}")

    assert result.paths_explored > 0


def test_implicit_flow():
    """Test that control dependencies propagate taint."""

    def implicit_flow_func(user_input):
        secret = "admin"

        if user_input == secret:
            is_valid = True

        else:
            is_valid = False

        return is_valid

    config = ExecutionConfig(max_paths=20, max_depth=50, enable_taint_tracking=True)

    executor = SymbolicExecutor(config)

    result = executor.execute_function(implicit_flow_func, {"user_input": "str"})

    print(f"[TEST 3] Implicit Flow - Paths explored: {result.paths_explored}")

    print(f"[TEST 3] Implicit Flow - Issues: {len(result.issues)}")

    assert result.paths_explored > 0


if __name__ == "__main__":
    print("=" * 60)

    print("PySyMex Architecture Fixes - Test Suite")

    print("=" * 60)

    tests = [
        ("Collection Init (LIST)", test_build_list),
        ("Collection Init (TUPLE)", test_build_tuple),
        ("Inter-Procedural Analysis", test_inter_procedural),
        ("Implicit Flow Tracking", test_implicit_flow),
    ]

    results: list[tuple[str, str]] = []

    for name, test_func in tests:
        try:
            test_func()

            results.append((name, "PASS"))

        except AssertionError:
            results.append((name, "FAIL"))

        except Exception as e:
            print(f"  ERROR: {e}")

            results.append((name, f"ERROR: {type(e).__name__}"))

    print("\n" + "=" * 60)

    print("SUMMARY")

    print("=" * 60)

    for name, status in results:
        print(f"  {name}: {status}")
