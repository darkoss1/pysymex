"""Regression tests for known bug patterns and fixed issues.

Tests for:
- Known bug patterns
- Fixed issues
- Boundary conditions
- Previously failing scenarios
"""

import pytest

import z3

from unittest.mock import MagicMock


from pysymex.api import analyze

from pysymex.core.state import VMState

from pysymex.analysis.detectors import IssueKind


class TestDivisionBugPatterns:
    """Regression tests for division-related bugs."""

    def test_divide_by_expression_zero(self):
        """Test division where expression evaluates to zero."""

        def divby_expr(x):
            return 10 / (x - x)

        result = analyze(divby_expr, {"x": "int"})

        assert result.has_issues()

    def test_divide_by_product(self):
        """Test division where product can be zero."""

        def divby_product(a, b):
            return 100 / (a * b)

        result = analyze(divby_product, {"a": "int", "b": "int"})

        assert result.has_issues()

    def test_divide_after_multiply_zero(self):
        """Test division after multiplying by zero."""

        def multiply_then_div(x, y):
            temp = x * 0

            return 10 / temp

        result = analyze(multiply_then_div, {"x": "int", "y": "int"})

        assert result.has_issues()

    def test_conditional_divide_regression(self):
        """Regression: conditional division bug."""

        def cond_div(x, y, flag):
            if flag:
                return x / y

            return x

        result = analyze(cond_div, {"x": "int", "y": "int", "flag": "bool"})

        assert result.has_issues()

    def test_loop_divide_regression(self):
        """Regression: division inside loop."""

        def loop_div(n, y):
            total = 0

            for i in range(n):
                total += i / y

            return total

        result = analyze(loop_div, {"n": "int", "y": "int"})

        assert result.has_issues()


class TestIndexBugPatterns:
    """Regression tests for index-related bugs."""

    def test_negative_index_regression(self):
        """Regression: negative index access."""

        def neg_idx(lst, n):
            return lst[n - 10]

        result = analyze(neg_idx, {"lst": "list", "n": "int"})

        assert result is not None

    def test_computed_index_regression(self):
        """Regression: computed index access."""

        def computed_idx(lst, a, b):
            idx = a * b

            return lst[idx]

        result = analyze(computed_idx, {"lst": "list", "a": "int", "b": "int"})

        assert result is not None

    def test_loop_index_regression(self):
        """Regression: loop counter as index."""

        def loop_idx(lst, n):
            result = 0

            for i in range(n):
                result += lst[i]

            return result

        result = analyze(loop_idx, {"lst": "list", "n": "int"})

        assert result is not None


class TestAssertionBugPatterns:
    """Regression tests for assertion-related bugs.

    Functions under analysis are compiled from strings to prevent pytest's
    assertion rewriting from transforming their bytecode.  Pytest replaces
    ``assert`` statements with its own introspection code, which removes
    ``LOAD_ASSERTION_ERROR``/``RAISE_VARARGS`` opcodes that the symbolic
    executor relies on for assertion-error detection.
    """

    @staticmethod
    def _compile_func(source: str, name: str):
        """Compile *source* and return the function named *name*.

        This avoids pytest assertion rewriting by going through ``compile()``.
        """

        ns: dict = {}

        exec(compile(source, "<test>", "exec"), ns)

        return ns[name]

    def test_assert_false_regression(self):
        """Regression: assert False."""

        fn = self._compile_func(
            "def assert_false():\n    assert False\n",
            "assert_false",
        )

        result = analyze(fn, {})

        assert result.has_issues()

    def test_assert_on_symbolic(self):
        """Regression: assert on symbolic value."""

        fn = self._compile_func(
            "def assert_symbolic(x):\n    assert x > 0\n    return x * 2\n",
            "assert_symbolic",
        )

        result = analyze(fn, {"x": "int"})

        assert result.has_issues()

    def test_assert_complex_condition(self):
        """Regression: assert with complex condition."""

        def assert_complex(x, y):
            assert x > 0 and y > 0, "Both must be positive"

            return x / y

        result = analyze(assert_complex, {"x": "int", "y": "int"})

        assert result is not None


class TestControlFlowBugPatterns:
    """Regression tests for control flow bugs."""

    def test_dead_code_after_return(self):
        """Regression: dead code after return."""

        def dead_code(x):
            return x

            y = 10 / 0

        result = analyze(dead_code, {"x": "int"})

        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

        assert len(div_issues) == 0

    def test_unreachable_branch(self):
        """Regression: unreachable branch."""

        def unreachable(x):
            if x > 0 and x < 0:
                return 10 / 0

            return x

        result = analyze(unreachable, {"x": "int"})

        assert result is not None

    def test_fallthrough_case(self):
        """Regression: fallthrough in conditionals."""

        def fallthrough(x, y):
            result = 0

            if x > 0:
                result = x

            if y > 0:
                result = result / y

            return result

        result = analyze(fallthrough, {"x": "int", "y": "int"})

        assert result is not None


class TestTypeBugPatterns:
    """Regression tests for type-related bugs."""

    def test_string_int_mix_regression(self):
        """Regression: string-int mix operations."""

        def str_int_mix(s, n):
            return s + str(n)

        result = analyze(str_int_mix, {"s": "str", "n": "int"})

        assert result is not None

    def test_none_operation_regression(self):
        """Regression: operation on None."""

        def none_op(x):
            if x is None:
                return None + 1

            return x

        result = analyze(none_op, {"x": "any"})

        assert result is not None


class TestBoundaryConditions:
    """Regression tests for boundary conditions."""

    def test_off_by_one_upper(self):
        """Regression: off-by-one at upper bound."""

        def upper_bound(lst, n):
            if n <= len(lst):
                return lst[n]

            return None

        result = analyze(upper_bound, {"lst": "list", "n": "int"})

        assert result is not None

    def test_off_by_one_lower(self):
        """Regression: off-by-one at lower bound."""

        def lower_bound(lst, n):
            if n > 0:
                return lst[n - 1]

            return None

        result = analyze(lower_bound, {"lst": "list", "n": "int"})

        assert result is not None

    def test_zero_vs_negative_one(self):
        """Regression: 0 vs -1 boundary."""

        def zero_neg(x):
            if x >= 0:
                return 10 / x

            return 0

        result = analyze(zero_neg, {"x": "int"})

        assert result.has_issues()

    def test_empty_collection_length(self):
        """Regression: empty collection length check."""

        def empty_check(lst):
            if len(lst) >= 0:
                return lst[0]

            return None

        result = analyze(empty_check, {"lst": "list"})

        assert result is not None


class TestLoopTerminationPatterns:
    """Regression tests for loop termination."""

    def test_while_true_with_break(self):
        """Regression: while True with break."""

        def infinite_with_break(n):
            i = 0

            while True:
                if i >= n:
                    break

                i += 1

            return i

        result = analyze(infinite_with_break, {"n": "int"})

        assert result is not None

    def test_decrement_loop(self):
        """Regression: decrementing loop."""

        def decrement(n):
            while n > 0:
                n -= 1

            return n

        result = analyze(decrement, {"n": "int"})

        assert result is not None


class TestMemoryPatterns:
    """Regression tests for memory patterns."""

    def test_list_aliasing(self):
        """Regression: list aliasing."""

        def aliasing(lst):
            alias = lst

            alias.append(1)

            return lst[-1]

        result = analyze(aliasing, {"lst": "list"})

        assert result is not None

    def test_nested_structure(self):
        """Regression: nested data structures."""

        def nested(data):
            return data[0][1]

        result = analyze(nested, {"data": "list"})

        assert result is not None


class TestFixedBugs:
    """Tests for specifically fixed bugs."""

    def test_state_merge_precision(self):
        """Fixed: state merge losing precision."""

        def merged_divide(x, y):
            if x > 0:
                result = 1

            else:
                result = 2

            return result / y

        result = analyze(merged_divide, {"x": "int", "y": "int"})

        assert result.has_issues()

    def test_path_constraint_propagation(self):
        """Fixed: path constraint not propagated."""

        def propagated(x, y):
            if y != 0:
                z = x / y

                return z * 2

            return 0

        result = analyze(propagated, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

        assert len(div_issues) == 0

    def test_symbolic_comparison_regression(self):
        """Fixed: symbolic comparison issues."""

        def compare(x, y):
            if x == y:
                return 0

            return x / (x - y)

        result = analyze(compare, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

        assert len(div_issues) == 0


class TestUserReportedEdgeCases:
    """Tests for edge cases reported by users."""

    def test_multiple_guards_same_var(self):
        """User report: multiple guards on same variable."""

        def multi_guard(x, y):
            if x > 0:
                if x > 5:
                    return y / x

            return 0

        result = analyze(multi_guard, {"x": "int", "y": "int"})

        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

        assert len(div_issues) == 0

    def test_guard_in_helper_function(self):
        """User report: guard in helper function."""

        def is_valid(x):
            return x != 0

        def use_validated(x, y):
            if is_valid(y):
                return x / y

            return 0

        result = analyze(use_validated, {"x": "int", "y": "int"})

        assert result is not None

    def test_complex_boolean_expression(self):
        """User report: complex boolean guard."""

        def complex_guard(a, b, c):
            if (a > 0 and b > 0) or c > 0:
                return 100 / (a + b + c)

            return 0

        result = analyze(complex_guard, {"a": "int", "b": "int", "c": "int"})

        assert result is not None


class TestPerformanceEdgeCases:
    """Tests for performance-related edge cases."""

    def test_many_branches(self):
        """Performance: many branches."""

        def many_branches(x):
            if x == 0:
                return 0

            elif x == 1:
                return 1

            elif x == 2:
                return 2

            elif x == 3:
                return 3

            elif x == 4:
                return 4

            else:
                return x

        result = analyze(many_branches, {"x": "int"})

        assert result is not None

    def test_deeply_nested(self):
        """Performance: deeply nested conditionals."""

        def deep_nest(a, b, c, d, e):
            if a > 0:
                if b > 0:
                    if c > 0:
                        if d > 0:
                            if e > 0:
                                return a / b / c / d / e

            return 0

        result = analyze(deep_nest, {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int"})

        div_issues = [i for i in result.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

        assert len(div_issues) == 0
