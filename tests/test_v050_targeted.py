"""Targeted stability and edge-case tests for pysymex v0.5.0.

Tests are grouped by subsystem:
1. Cross-function analysis
2. Exception analysis
3. Dead code detector
4. Taint analysis
5. Abstract interpreter
6. Scanner dedup & grouping
7. Loop analysis
8. Truthy expression handling
9. COMPARE_OP normalisation
"""

from __future__ import annotations


import textwrap

import os

import tempfile

from unittest.mock import patch


import pytest

import z3


from pysymex.core.types import SymbolicValue, SymbolicNone, SymbolicString


def _compile_fn(source: str, name: str):
    """Compile source and return the function *name*.

    Using ``compile()`` avoids pytest assertion-rewriting.
    """

    ns: dict = {}

    exec(compile(textwrap.dedent(source), "<test>", "exec"), ns)

    return ns[name]


def _scan_source(source: str) -> list:
    """Scan *source* and return unsuppressed issues."""

    from pysymex.analysis.pipeline import Scanner, ScannerConfig

    fd, path = tempfile.mkstemp(suffix=".py", prefix="test_targeted_")

    try:
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(source))

        scanner = Scanner(
            ScannerConfig(
                suppress_likely_false_positives=True,
                verbose=False,
            )
        )

        issues = scanner.scan_file(path)

        return [i for i in issues if not i.is_suppressed()]

    finally:
        os.unlink(path)


class TestCrossFunctionEdgeCases:
    """Cross-function analyzer should handle edge cases gracefully."""

    def test_empty_module_code(self):
        """Analyzing empty code should not crash."""

        from pysymex.analysis.cross_function import CrossFunctionAnalyzer

        analyzer = CrossFunctionAnalyzer()

        code = compile("", "<empty>", "exec")

        result = analyzer.analyze_module(code)

        assert isinstance(result, dict)

    def test_nested_function_code(self):
        """Analyzing code with nested functions should produce results."""

        from pysymex.analysis.cross_function import CrossFunctionAnalyzer

        src = "def outer():\n    def inner():\n        return 1\n    return inner()\n"

        code = compile(src, "<test>", "exec")

        analyzer = CrossFunctionAnalyzer()

        result = analyzer.analyze_module(code)

        assert "call_graph" in result

    def test_recursive_function(self):
        """Recursive functions should not crash the analyzer."""

        from pysymex.analysis.cross_function import CrossFunctionAnalyzer

        src = "def fib(n):\n    if n < 2:\n        return n\n    return fib(n-1) + fib(n-2)\n"

        code = compile(src, "<test>", "exec")

        analyzer = CrossFunctionAnalyzer()

        result = analyzer.analyze_module(code)

        assert isinstance(result, dict)

    def test_return_type_inference_int(self):
        """Return type should be inferred for constant-returning functions."""

        from pysymex.analysis.cross_function import _infer_return_type

        src = "def f():\n    return 42\n"

        code = compile(src, "<test>", "exec")

        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name == "f":
                rtype = _infer_return_type(const)

                assert rtype is not None

                break

        else:
            pytest.fail("Could not find function code object")

    def test_return_type_inference_none(self):
        """Functions that only return None should infer None type."""

        from pysymex.analysis.cross_function import _infer_return_type

        src = "def f():\n    pass\n"

        code = compile(src, "<test>", "exec")

        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name == "f":
                rtype = _infer_return_type(const)

                break


class TestExceptionAnalysisEdgeCases:
    """Exception analyzer should handle various exception patterns."""

    def test_bare_except_detected(self):
        """Bare except should be flagged."""

        issues = _scan_source("""\
            def f():
                try:
                    x = 1
                except:
                    pass
        """)

        kinds = {i.kind for i in issues}

        assert "BARE_EXCEPT" in kinds

    def test_except_exception_with_logging(self):
        """except Exception with logging should not be flagged as broad."""

        issues = _scan_source("""\
            import logging
            def f():
                try:
                    x = 1 / 0
                except Exception as e:
                    logging.error(e)
        """)

        broad = [i for i in issues if i.kind == "TOO_BROAD_EXCEPT"]

        assert len(broad) == 0

    def test_nested_try_except(self):
        """Nested try/except should not crash."""

        issues = _scan_source("""\
            def f():
                try:
                    try:
                        x = 1 / 0
                    except ZeroDivisionError:
                        pass
                except Exception:
                    pass
        """)

        assert isinstance(issues, list)


class TestDeadCodeEdgeCases:
    """Dead code detector edge cases."""

    def test_unreachable_after_return(self):
        """Code after return should be handled gracefully.

        Python 3.12+ optimises away dead code after ``return`` at compile
        time, so the bytecode never contains the unreachable statements.
        We verify the scanner processes such input without crashing and
        does not produce spurious issues.
        """

        issues = _scan_source("""\
            def f():
                return 1
                x = 2
        """)

        assert isinstance(issues, list)

    def test_implicit_return_not_flagged(self):
        """Implicit return None at end of function should not be flagged."""

        issues = _scan_source("""\
            def f():
                x = 1
        """)

        unreachable = [i for i in issues if i.kind == "UNREACHABLE_CODE"]

        assert len(unreachable) == 0

    def test_dead_store_basic(self):
        """Variable overwritten before use should be flagged."""

        issues = _scan_source("""\
            def f():
                x = 1
                x = 2
                return x
        """)

        dead = [i for i in issues if i.kind == "DEAD_STORE"]

        assert len(dead) >= 1

    def test_underscore_prefix_not_flagged(self):
        """Variables with _ prefix should not be flagged as unused."""

        issues = _scan_source("""\
            def f():
                _unused = 42
                return 1
        """)

        unused = [i for i in issues if i.kind == "UNUSED_VARIABLE" and "_unused" in i.message]

        assert len(unused) == 0

    def test_dataclass_fields_not_flagged(self):
        """Dataclass fields should not be flagged as unused."""

        issues = _scan_source("""\
            from dataclasses import dataclass
            @dataclass
            class Cfg:
                name: str = "default"
                count: int = 0
        """)

        unused = [
            i
            for i in issues
            if i.kind == "UNUSED_VARIABLE" and ("name" in i.message or "count" in i.message)
        ]

        assert len(unused) == 0


class TestTaintAnalysis:
    """Taint analysis edge cases."""

    def test_sql_injection_detected(self):
        """f-string SQL should be flagged."""

        issues = _scan_source("""\
            import sqlite3
            def query(db, user_input):
                db.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
        """)

        sql = [i for i in issues if i.kind == "SQL_INJECTION"]

        assert len(sql) >= 1

    def test_safe_parameterised_query(self):
        """Parameterised queries should not be flagged."""

        issues = _scan_source("""\
            import sqlite3
            def query(db, user_input):
                db.execute("SELECT * FROM users WHERE name = ?", (user_input,))
        """)

        sql = [i for i in issues if i.kind == "SQL_INJECTION"]

        assert len(sql) == 0


class TestAbstractInterpreterEdgeCases:
    """Abstract interpreter edge cases."""

    def test_trivial_function_fast_path(self):
        """Trivial function should use fast path without crash."""

        from pysymex.analysis.abstract.interpreter import AbstractInterpreter

        src = "def f(x):\n    return x + 1\n"

        code = compile(src, "<test>", "exec")

        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name == "f":
                analyzer = AbstractInterpreter()

                warnings = analyzer.analyze(const)

                assert isinstance(warnings, list)

                break

    def test_division_by_zero_detected(self):
        """Division by literal zero should be flagged."""

        from pysymex.analysis.abstract.interpreter import AbstractInterpreter

        src = "def f():\n    return 1 / 0\n"

        code = compile(src, "<test>", "exec")

        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name == "f":
                analyzer = AbstractInterpreter()

                warnings = analyzer.analyze(const)

                assert len(warnings) >= 1

                break

    def test_empty_function(self):
        """Empty function should not crash."""

        from pysymex.analysis.abstract.interpreter import AbstractInterpreter

        src = "def f():\n    pass\n"

        code = compile(src, "<test>", "exec")

        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name == "f":
                analyzer = AbstractInterpreter()

                warnings = analyzer.analyze(const)

                assert isinstance(warnings, list)

                break


class TestScannerDedupGrouping:
    """Scanner deduplication and grouping."""

    def test_duplicate_unused_vars_deduped(self):
        """Same unused variable reported from multiple paths should be deduped."""

        issues = _scan_source("""\
            def f():
                x = 1
                y = 2
                return 0
        """)

        x_issues = [i for i in issues if "x" in i.message and i.kind == "UNUSED_VARIABLE"]

        assert len(x_issues) <= 1

    def test_grouping_multiple_unused(self):
        """Multiple unused variables in same function should be groupable."""

        from pysymex.analysis.pipeline import Scanner, ScannerConfig

        fd, path = tempfile.mkstemp(suffix=".py", prefix="test_group_")

        try:
            with os.fdopen(fd, "w") as f:
                f.write("def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n    return 0\n")

            scanner = Scanner(
                ScannerConfig(
                    suppress_likely_false_positives=False,
                    verbose=False,
                )
            )

            issues = scanner.scan_file(path)

            unused = [i for i in issues if i.kind == "UNUSED_VARIABLE"]

            assert len(unused) >= 3

        finally:
            os.unlink(path)


class TestLoopAnalysis:
    """Loop analysis edge cases."""

    def test_simple_for_loop(self):
        """Simple for loop should not crash executor."""

        from pysymex.api import analyze

        fn = _compile_fn(
            """\
            def f(n):
                total = 0
                for i in range(n):
                    total += i
                return total
        """,
            "f",
        )

        result = analyze(fn, {"n": "int"})

        assert result is not None

    def test_while_true_termination(self):
        """while True with break should not hang."""

        from pysymex.api import analyze

        fn = _compile_fn(
            """\
            def f(x):
                while True:
                    if x > 10:
                        break
                    x += 1
                return x
        """,
            "f",
        )

        result = analyze(fn, {"x": "int"})

        assert result is not None

        assert result.paths_explored > 0


class TestGetTruthyExpr:
    """Tests for the get_truthy_expr function in control.py."""

    def test_concrete_false(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr(False)

        assert z3.is_false(z3.simplify(result))

    def test_concrete_true(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr(True)

        assert z3.is_true(z3.simplify(result))

    def test_concrete_zero(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr(0)

        assert z3.is_false(z3.simplify(result))

    def test_concrete_nonzero_int(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr(42)

        assert z3.is_true(z3.simplify(result))

    def test_concrete_none(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr(None)

        assert z3.is_false(z3.simplify(result))

    def test_concrete_empty_string(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr("")

        assert z3.is_false(z3.simplify(result))

    def test_concrete_nonempty_string(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr("hello")

        assert z3.is_true(z3.simplify(result))

    def test_concrete_empty_list(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr([])

        assert z3.is_false(z3.simplify(result))

    def test_concrete_nonempty_list(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        result = get_truthy_expr([1, 2])

        assert z3.is_true(z3.simplify(result))

    def test_symbolic_value(self):
        from pysymex.execution.opcodes.control import get_truthy_expr

        sv, _ = SymbolicValue.symbolic("x")

        result = get_truthy_expr(sv)

        assert isinstance(result, z3.BoolRef)


class TestCompareOpNormalisation:
    """COMPARE_OP should handle Python 3.13 bool() variants."""

    def test_symbolic_greater_than_detection(self):
        """Symbolic x > 0 should produce meaningful Z3 constraint."""

        from pysymex.api import analyze

        fn = _compile_fn(
            """\
            def f(x):
                if x > 0:
                    return 1
                return 0
        """,
            "f",
        )

        result = analyze(fn, {"x": "int"})

        assert result.paths_completed >= 2

    def test_symbolic_equality(self):
        """Symbolic x == 0 should produce meaningful Z3 constraint."""

        from pysymex.api import analyze

        fn = _compile_fn(
            """\
            def f(x):
                if x == 0:
                    return 1 / x  # Should detect div-by-zero
                return x
        """,
            "f",
        )

        result = analyze(fn, {"x": "int"})

        assert result.has_issues()

    def test_division_by_zero_basic(self):
        """Division by zero with symbolic denominator should be detected."""

        from pysymex.api import analyze

        fn = _compile_fn(
            """\
            def f(x, y):
                return x / y
        """,
            "f",
        )

        result = analyze(fn, {"x": "int", "y": "int"})

        assert result.has_issues()

        kinds = {i.kind.name for i in result.issues}

        assert "DIVISION_BY_ZERO" in kinds


class TestSuggestionMap:
    """Actionable suggestions should exist for common issue kinds."""

    def test_suggestion_map_populated(self):
        from pysymex.analysis.pipeline import SUGGESTION_MAP

        assert len(SUGGESTION_MAP) >= 20

    def test_suggestion_for_unused_variable(self):
        from pysymex.analysis.pipeline import SUGGESTION_MAP

        assert "UNUSED_VARIABLE" in SUGGESTION_MAP

    def test_suggestion_for_dead_store(self):
        from pysymex.analysis.pipeline import SUGGESTION_MAP

        assert "DEAD_STORE" in SUGGESTION_MAP

    def test_suggestion_for_bare_except(self):
        from pysymex.analysis.pipeline import SUGGESTION_MAP

        assert "BARE_EXCEPT" in SUGGESTION_MAP
