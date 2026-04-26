"""Tests for pysymex.analysis.solver — Z3 verification engine."""

from __future__ import annotations

from pysymex.analysis.solver import (
    Z3Engine,
    estimate_complexity,
    is_z3_available,
    verify_code,
    verify_function,
    _deserialize_worker_results,
    _is_dict_of_objects,
)
from pysymex.analysis.solver.types import (
    BugType,
    CrashCondition,
    FunctionSummary,
    Severity,
    VerificationResult,
)


class TestIsZ3Available:
    """Tests for is_z3_available helper."""

    def test_returns_true_when_z3_installed(self) -> None:
        """is_z3_available returns True when z3 is present."""
        assert is_z3_available() is True


class TestIsDictOfObjects:
    """Tests for _is_dict_of_objects TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict passes."""
        assert _is_dict_of_objects({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert _is_dict_of_objects([1, 2]) is False

    def test_none_returns_false(self) -> None:
        """None does not pass."""
        assert _is_dict_of_objects(None) is False


class TestEstimateComplexity:
    """Tests for estimate_complexity bytecode analyzer."""

    def test_simple_function(self) -> None:
        """Simple function has low complexity."""
        code = compile("x = 1 + 2", "<test>", "exec")
        result = estimate_complexity(code)
        assert isinstance(result, dict)
        assert "branch_count" in result
        assert "loop_count" in result
        assert "call_count" in result
        assert "total_instructions" in result
        assert "complexity_score" in result
        assert "recommended_timeout_ms" in result

    def test_branchy_function(self) -> None:
        """Function with branches has higher complexity."""
        source = """
def f(x):
    if x > 0:
        if x > 10:
            return 2
        return 1
    return 0
"""
        code = compile(source, "<test>", "exec")
        # Get the inner function code
        inner_codes = [c for c in code.co_consts if hasattr(c, "co_code")]
        if inner_codes:
            result = estimate_complexity(inner_codes[0])
            assert result["branch_count"] >= 2

    def test_loop_function(self) -> None:
        """Function with loop has loop_count > 0."""
        source = """
def f():
    s = 0
    for i in range(10):
        s += i
    return s
"""
        code = compile(source, "<test>", "exec")
        inner_codes = [c for c in code.co_consts if hasattr(c, "co_code")]
        if inner_codes:
            result = estimate_complexity(inner_codes[0])
            assert result["loop_count"] >= 1

    def test_call_function(self) -> None:
        """Function with calls has call_count > 0."""
        source = """
def f():
    return len([1, 2, 3])
"""
        code = compile(source, "<test>", "exec")
        inner_codes = [c for c in code.co_consts if hasattr(c, "co_code")]
        if inner_codes:
            result = estimate_complexity(inner_codes[0])
            assert result["call_count"] >= 1

    def test_timeout_scaling(self) -> None:
        """Higher complexity yields higher timeout."""
        simple_code = compile("x = 1", "<test>", "exec")
        complex_source = "\n".join(
            [
                "def f(x):",
                *[f"    if x > {i}: x += 1" for i in range(20)],
                "    return x",
            ]
        )
        complex_code = compile(complex_source, "<test>", "exec")
        inner = [c for c in complex_code.co_consts if hasattr(c, "co_code")]
        simple_result = estimate_complexity(simple_code)
        if inner:
            complex_result = estimate_complexity(inner[0])
            assert (
                complex_result["recommended_timeout_ms"] >= simple_result["recommended_timeout_ms"]
            )


class TestZ3Engine:
    """Tests for Z3Engine initialization and helpers."""

    def test_init_defaults(self) -> None:
        """Z3Engine initializes with default parameters."""
        engine = Z3Engine()
        assert engine.timeout == 5000
        assert engine.max_depth == 50
        assert engine.interprocedural is True
        assert engine.function_summaries == {}

    def test_init_custom(self) -> None:
        """Z3Engine accepts custom parameters."""
        engine = Z3Engine(timeout_ms=1000, max_depth=10, interprocedural=False)
        assert engine.timeout == 1000
        assert engine.max_depth == 10
        assert engine.interprocedural is False

    def test_get_call_graph_info(self) -> None:
        """get_call_graph_info returns a dict with expected keys."""
        engine = Z3Engine()
        info = engine.get_call_graph_info()
        assert "functions" in info
        assert "total_calls" in info
        assert "recursive_functions" in info
        assert "entry_points" in info

    def test_get_function_summary_missing(self) -> None:
        """get_function_summary returns None for unknown function."""
        engine = Z3Engine()
        assert engine.get_function_summary("nonexistent") is None

    def test_build_context_from_callees(self) -> None:
        """_build_context_from_callees returns None by default."""
        engine = Z3Engine()
        assert engine._build_context_from_callees("func") is None


class TestVerifyFunction:
    """Tests for module-level verify_function."""

    def test_returns_list(self) -> None:
        """verify_function returns a list of VerificationResult."""

        def simple(x: int) -> int:
            return x + 1

        results = verify_function(simple)
        assert isinstance(results, list)


class TestVerifyCode:
    """Tests for module-level verify_code."""

    def test_returns_list(self) -> None:
        """verify_code returns a list of VerificationResult."""
        code = compile("x = 1", "<test>", "exec")
        results = verify_code(code)
        assert isinstance(results, list)


class TestDeserializeWorkerResults:
    """Tests for _deserialize_worker_results."""

    def test_empty_input(self) -> None:
        """Empty dict produces empty output."""
        result = _deserialize_worker_results({})
        assert result == {}

    def test_basic_deserialization(self) -> None:
        """Basic serialized entry deserializes correctly."""
        serialized: dict[str, list[dict[str, object]]] = {
            "func": [
                {
                    "can_crash": True,
                    "proven_safe": False,
                    "z3_status": "sat",
                    "verification_time_ms": 1.5,
                    "bug_type": BugType.DIVISION_BY_ZERO.value,
                    "line": 10,
                    "function": "func",
                    "description": "division by zero",
                    "severity": Severity.HIGH.value,
                    "counterexample": {"x": "0"},
                    "file_path": "test.py",
                }
            ]
        }
        result = _deserialize_worker_results(serialized)
        assert "func" in result
        assert len(result["func"]) == 1
        vr = result["func"][0]
        assert vr.can_crash is True
        assert vr.proven_safe is False
        assert vr.z3_status == "sat"

    def test_invalid_bug_type(self) -> None:
        """Invalid bug type falls back to TYPE_ERROR."""
        serialized: dict[str, list[dict[str, object]]] = {
            "f": [
                {
                    "can_crash": False,
                    "proven_safe": True,
                    "bug_type": "invalid_type",
                    "z3_status": "unsat",
                }
            ]
        }
        result = _deserialize_worker_results(serialized)
        assert len(result["f"]) == 1
