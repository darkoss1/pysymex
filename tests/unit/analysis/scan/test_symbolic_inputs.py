"""Tests for scan symbolic-input inference."""

from __future__ import annotations

import ast

from pysymex._internal.analysis.scan.symbolic_inputs import (
    TypeHintExtractor,
    build_symbolic_vars,
    scanner_solver_timeout_ms,
)


def test_scanner_solver_timeout_caps_z3_query_budget() -> None:
    """Large file scans keep each SMT query bounded below the file/function timeout."""
    assert scanner_solver_timeout_ms(30.0) == 100
    assert scanner_solver_timeout_ms(0.25) == 100
    assert scanner_solver_timeout_ms(0.05) == 50
    assert scanner_solver_timeout_ms(0.0) == 1


def test_build_symbolic_vars_treats_iterator_hints_as_finite_list_inputs() -> None:
    """Iterator-shaped scanner inputs use the existing bounded list model."""

    def target(values: object) -> None:
        _ = values

    symbolic_vars = build_symbolic_vars(
        target.__code__,
        type_hints={"values": "Iterator[CompiledConstraint]"},
        include_collection_heuristics=True,
    )

    assert symbolic_vars == {"values": "list"}


def test_build_symbolic_vars_preserves_fixed_tuple_shape() -> None:
    """Fixed tuple annotations retain arity and element input types."""

    def target(values: object) -> None:
        _ = values

    symbolic_vars = build_symbolic_vars(
        target.__code__,
        type_hints={"values": "tuple[int, str]"},
        include_collection_heuristics=True,
    )

    assert symbolic_vars == {"values": "tuple[int,str]"}


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
    """Optional scanner hints retain None feasibility in executor input descriptors."""

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


class TestBuildSymbolicVars:
    """Tests for parameter inference."""

    def test_simple_function(self) -> None:
        """Simple function parameters become int inputs."""
        code = compile("def f(x, y): return x + y", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {"x": "int", "y": "int"}

    def test_self_becomes_object(self) -> None:
        """self parameters become object inputs."""
        code = compile("class C:\n def m(self, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["self"] == "object"

    def test_cls_becomes_object(self) -> None:
        """cls parameters become object inputs."""
        code = compile("class C:\n @classmethod\n def m(cls, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["cls"] == "object"

    def test_collection_heuristics_list(self) -> None:
        """Parameter names containing list become list inputs with heuristics."""
        code = compile("def f(items, inputs): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["items"] == "list"
        assert result["inputs"] == "list"

    def test_collection_heuristics_dict(self) -> None:
        """Parameter names containing config become dict inputs with heuristics."""
        code = compile("def f(config): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["config"] == "dict"

    def test_no_heuristics_fallback(self) -> None:
        """Without heuristics, items falls back to int."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result["items"] == "int"

    def test_no_args(self) -> None:
        """Functions with no arguments return an empty input map."""
        code = compile("def f(): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {}
