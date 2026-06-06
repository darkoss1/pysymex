"""Tests for scanner core helper functions."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys

from pysymex.config import is_object_dict
from pysymex.analysis.scan.loading.discovery import collect_top_level_function_names
from pysymex.analysis.scan.loading.globals import build_module_globals
from pysymex.analysis.scan.loading.stdlib.imports import is_safe_stdlib_import
from pysymex.analysis.static.code_objects import get_code_objects_with_context
from pysymex.scanner.summary import descending_issue_count
from pysymex.scanner.symbolic_vars import (
    TypeHintExtractor,
    build_symbolic_vars,
    scanner_solver_timeout_ms,
)
from pysymex.scanner.workers import auto_worker_count, effective_worker_count


def test_scanner_solver_timeout_caps_z3_query_budget() -> None:
    """Large file scans should keep each SMT query bounded below the file/function timeout."""
    assert scanner_solver_timeout_ms(30.0) == 100
    assert scanner_solver_timeout_ms(0.25) == 100
    assert scanner_solver_timeout_ms(0.05) == 50
    assert scanner_solver_timeout_ms(0.0) == 1


def test_safe_stdlib_import_accepts_stdlib_modules() -> None:
    """Standard-library modules are eligible for optional concrete binding."""
    assert is_safe_stdlib_import("math") is True
    assert is_safe_stdlib_import("subprocess") is True


def test_default_scanner_module_identity_is_stable_across_python_hash_seeds() -> None:
    """Modeled stdlib identities must not vary between scanner worker processes."""
    script = (
        "from pysymex.analysis.scan.loading.environment import get_default_module_globals; "
        'print(get_default_module_globals()["os"].address)'
    )
    addresses: list[str] = []
    for seed in ("1", "2"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        address = subprocess.check_output(
            [sys.executable, "-c", script],
            env=environment,
            text=True,
        ).strip()
        addresses.append(address)

    assert addresses[0] == addresses[1]


def test_build_symbolic_vars_treats_iterator_hints_as_finite_list_inputs() -> None:
    """Iterator-shaped scanner inputs should use the existing bounded list model."""

    def target(values: object) -> None:
        _ = values

    symbolic_vars = build_symbolic_vars(
        target.__code__,
        type_hints={"values": "Iterator[CompiledConstraint]"},
        include_collection_heuristics=True,
    )

    assert symbolic_vars == {"values": "list"}


def test_type_hint_extractor_preserves_none_union_annotations() -> None:
    """Static scanner hints must not discard the nullable branch of PEP 604 unions."""
    extractor = TypeHintExtractor()
    extractor.visit(
        ast.parse(
            "def target(token: str | None, count: None | int, name: Optional[str]):\n"
            "    return token, count, name\n"
        )
    )

    assert extractor.hints[("target", None)] == {
        "token": "str | None",
        "count": "None | int",
        "name": "Optional[str]",
    }


def test_build_symbolic_vars_maps_optional_hints_to_nullable_carriers() -> None:
    """Optional scanner hints should retain None feasibility in executor input descriptors."""

    def target(token: object, count: object, flag: object, values: object) -> None:
        _ = token, count, flag, values

    symbolic_vars = build_symbolic_vars(
        target.__code__,
        type_hints={
            "token": "str | None",
            "count": "Optional[int]",
            "flag": "typing.Optional[bool]",
            "values": "list[int] | None",
        },
        include_collection_heuristics=True,
    )

    assert symbolic_vars == {
        "token": "optional:str",
        "count": "optional:int",
        "flag": "optional:bool",
        "values": "optional:list",
    }


def test_build_module_globals_binds_literal_top_level_constants(tmp_path: Path) -> None:
    """Literal top-level constants are safe globals for compile-only scans."""
    content = (
        "GLOBAL_NONE: object = None\nGLOBAL_COUNT = 3\n\ndef target():\n    return GLOBAL_NONE\n"
    )
    code = compile(content, str(tmp_path / "sample.py"), "exec")
    code_with_context = get_code_objects_with_context(code)

    module_globals = build_module_globals(
        content=content,
        file_path=tmp_path / "sample.py",
        full_module_name="sample",
        package_name="",
        all_code_with_context=code_with_context,
    )

    assert "GLOBAL_NONE" in module_globals
    assert module_globals["GLOBAL_NONE"] is None
    assert module_globals["GLOBAL_COUNT"] == 3


class TestDescendingIssueCount:
    """Tests for _descending_issue_count sort key."""

    def test_returns_negative(self) -> None:
        """Returns negated count for descending sort."""
        assert descending_issue_count(("file.py", 5)) == -5

    def test_zero(self) -> None:
        """Zero count returns zero."""
        assert descending_issue_count(("file.py", 0)) == 0


class TestBuildSymbolicVars:
    """Tests for _build_symbolic_vars parameter inference."""

    def test_simple_function(self) -> None:
        """Simple function parameters become 'int'."""
        code = compile("def f(x, y): return x + y", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {"x": "int", "y": "int"}

    def test_self_becomes_object(self) -> None:
        """'self' parameter becomes 'object'."""
        code = compile("class C:\n def m(self, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["self"] == "object"

    def test_cls_becomes_object(self) -> None:
        """'cls' parameter becomes 'object'."""
        code = compile("class C:\n @classmethod\n def m(cls, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["cls"] == "object"

    def test_collection_heuristics_list(self) -> None:
        """Parameter containing 'list' becomes 'list' with heuristics."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["items"] == "list"

    def test_collection_heuristics_dict(self) -> None:
        """Parameter containing 'config' becomes 'dict' with heuristics."""
        code = compile("def f(config): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["config"] == "dict"

    def test_no_heuristics_fallback(self) -> None:
        """Without heuristics, 'items' becomes 'int'."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result["items"] == "int"

    def test_no_args(self) -> None:
        """Function with no args returns empty dict."""
        code = compile("def f(): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {}


class TestIsObjectDict:
    """Tests for is_object_dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """Dict passes."""
        assert is_object_dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """List fails."""
        assert is_object_dict([1]) is False


class TestAutoWorkerCount:
    """Tests for _auto_worker_count."""

    def test_without_sandbox(self) -> None:
        """Without sandbox, cap is 4."""
        count = auto_worker_count(use_sandbox=False)
        assert 1 <= count <= 8

    def test_with_sandbox(self) -> None:
        """With sandbox, cap is 2."""
        count = auto_worker_count(use_sandbox=True)
        assert 1 <= count <= 4

    def test_with_file_count_clamps_to_useful_parallelism(self) -> None:
        """Auto worker selection should avoid over-parallelizing tiny file sets."""
        count = auto_worker_count(use_sandbox=False, file_count=2)
        assert count == 1

    def test_with_trace_enabled_reduces_workers(self) -> None:
        """Trace-heavy scans should not increase worker count relative to baseline."""
        baseline = auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=False)
        traced = auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=True)
        assert traced <= baseline


class TestEffectiveWorkerCount:
    """Tests for _effective_worker_count."""

    def test_single_file_forces_sequential(self) -> None:
        """One file should always resolve to one worker."""
        assert effective_worker_count(1, 16) == 1

    def test_file_limited_parallelism(self) -> None:
        """Large worker counts should be clamped by useful file-level parallelism."""
        assert effective_worker_count(6, 10) == 3


class TestGetCodeObjectsWithContext:
    """Tests for get_code_objects_with_context."""

    def test_module_level(self) -> None:
        """Module code has None path."""
        code = compile("x = 1", "<test>", "exec")
        items = get_code_objects_with_context(code)
        assert len(items) >= 1
        _, parent, full_path = items[0]
        assert parent is None
        assert full_path is None

    def test_nested_functions(self) -> None:
        """Nested functions have dotted paths."""
        src = """
def outer():
    def inner():
        return 1
    return inner()
"""
        code = compile(src, "<test>", "exec")
        items = get_code_objects_with_context(code)
        paths = {full for _, _, full in items if full is not None}
        assert "outer" in paths
        assert "outer.inner" in paths

    def test_nested_classes(self) -> None:
        """Nested classes have dotted paths."""
        src = """
class Outer:
    def method(self):
        def inner():
            return 1
        return inner()
"""
        code = compile(src, "<test>", "exec")
        items = get_code_objects_with_context(code)
        paths = {full for _, _, full in items if full is not None}
        assert "Outer" in paths
        assert "Outer.method" in paths
        assert "Outer.method.inner" in paths


class TestCollectTopLevelFunctionNames:
    """Tests for helper binding discovery."""

    def test_excludes_top_level_classes(self) -> None:
        """Class code objects must not be bound as helper functions."""
        src = """
class Kind:
    VALUE = 1

def helper(x: int) -> int:
    return x + 1
"""
        names = collect_top_level_function_names(src, Path("sample.py"))
        assert names == {"helper"}
