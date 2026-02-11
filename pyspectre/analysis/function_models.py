"""
Enhanced Inter-Procedural Analysis for PySpectre.
This module extends the existing interprocedural.py with more advanced
capabilities for tracking information across function calls.
Features:
- Extended call graph with context sensitivity
- Function summaries with effect tracking
- Type propagation across calls
- Exception flow analysis
"""

from __future__ import annotations
import dis
from dataclasses import dataclass, field
from typing import (
    Any,
)
from .type_inference import PyType, TypeKind


@dataclass
class ParameterInfo:
    """Information about a function parameter."""

    name: str
    position: int
    declared_type: PyType | None = None
    inferred_types: set[PyType] = field(default_factory=set)
    is_used: bool = True
    is_mutated: bool = False
    has_default: bool = False
    default_value: Any | None = None


@dataclass
class FunctionSummary:
    """
    Summary of a function's behavior for inter-procedural analysis.
    Contains information about:
    - Parameter and return types
    - Side effects
    - Exceptions that may be raised
    - Preconditions and postconditions
    """

    name: str
    parameters: list[ParameterInfo] = field(default_factory=list)
    var_positional: str | None = None
    var_keyword: str | None = None
    return_type: PyType | None = None
    return_types_seen: set[PyType] = field(default_factory=set)
    may_return_none: bool = False
    always_returns: bool = True
    is_pure: bool = False
    is_readonly: bool = False
    may_raise: set[str] = field(default_factory=set)
    documented_raises: set[str] = field(default_factory=set)
    mutates_parameters: set[str] = field(default_factory=set)
    mutates_globals: set[str] = field(default_factory=set)
    is_analyzed: bool = False
    analysis_depth: int = 0

    def get_parameter(self, name: str) -> ParameterInfo | None:
        """Get parameter by name."""
        for param in self.parameters:
            if param.name == name:
                return param
        return None

    def get_parameter_type(self, name: str) -> PyType | None:
        """Get type of a parameter."""
        param = self.get_parameter(name)
        if param:
            return param.declared_type or (
                next(iter(param.inferred_types)) if param.inferred_types else None
            )
        return None


class BuiltinModels:
    """Pre-defined summaries for built-in functions."""

    _summaries: dict[str, FunctionSummary] = {}

    @classmethod
    def get(cls, name: str) -> FunctionSummary | None:
        """Get summary for a built-in function."""
        if not cls._summaries:
            cls._init_summaries()
        return cls._summaries.get(name)

    @classmethod
    def _init_summaries(cls) -> None:
        """Initialize built-in summaries."""
        cls._summaries["len"] = FunctionSummary(
            name="len",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["str"] = FunctionSummary(
            name="str",
            parameters=[ParameterInfo("obj", 0, has_default=True)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["int"] = FunctionSummary(
            name="int",
            parameters=[ParameterInfo("x", 0, has_default=True)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError", "TypeError"},
        )
        cls._summaries["float"] = FunctionSummary(
            name="float",
            parameters=[ParameterInfo("x", 0, has_default=True)],
            return_type=PyType.float_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError", "TypeError"},
        )
        cls._summaries["bool"] = FunctionSummary(
            name="bool",
            parameters=[ParameterInfo("x", 0, has_default=True)],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["list"] = FunctionSummary(
            name="list",
            parameters=[ParameterInfo("iterable", 0, has_default=True)],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["dict"] = FunctionSummary(
            name="dict",
            var_keyword="kwargs",
            return_type=PyType.dict_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["set"] = FunctionSummary(
            name="set",
            parameters=[ParameterInfo("iterable", 0, has_default=True)],
            return_type=PyType.set_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["tuple"] = FunctionSummary(
            name="tuple",
            parameters=[ParameterInfo("iterable", 0, has_default=True)],
            return_type=PyType.tuple_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["frozenset"] = FunctionSummary(
            name="frozenset",
            parameters=[ParameterInfo("iterable", 0, has_default=True)],
            return_type=PyType(kind=TypeKind.FROZENSET),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["range"] = FunctionSummary(
            name="range",
            parameters=[
                ParameterInfo("start_or_stop", 0),
                ParameterInfo("stop", 1, has_default=True),
                ParameterInfo("step", 2, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.RANGE),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError", "ValueError"},
        )
        cls._summaries["enumerate"] = FunctionSummary(
            name="enumerate",
            parameters=[
                ParameterInfo("iterable", 0),
                ParameterInfo("start", 1, has_default=True, default_value=0),
            ],
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["zip"] = FunctionSummary(
            name="zip",
            var_positional="iterables",
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["map"] = FunctionSummary(
            name="map",
            parameters=[ParameterInfo("func", 0)],
            var_positional="iterables",
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["filter"] = FunctionSummary(
            name="filter",
            parameters=[
                ParameterInfo("func", 0),
                ParameterInfo("iterable", 1),
            ],
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["sorted"] = FunctionSummary(
            name="sorted",
            parameters=[
                ParameterInfo("iterable", 0),
                ParameterInfo("key", 1, has_default=True),
                ParameterInfo("reverse", 2, has_default=True, default_value=False),
            ],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["reversed"] = FunctionSummary(
            name="reversed",
            parameters=[ParameterInfo("seq", 0)],
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["isinstance"] = FunctionSummary(
            name="isinstance",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("classinfo", 1),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["issubclass"] = FunctionSummary(
            name="issubclass",
            parameters=[
                ParameterInfo("cls", 0),
                ParameterInfo("classinfo", 1),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["type"] = FunctionSummary(
            name="type",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType(kind=TypeKind.TYPE),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["callable"] = FunctionSummary(
            name="callable",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["hasattr"] = FunctionSummary(
            name="hasattr",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("name", 1),
            ],
            return_type=PyType.bool_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["getattr"] = FunctionSummary(
            name="getattr",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("name", 1),
                ParameterInfo("default", 2, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=True,
            may_raise={"AttributeError"},
        )
        cls._summaries["setattr"] = FunctionSummary(
            name="setattr",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("name", 1),
                ParameterInfo("value", 2),
            ],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"obj"},
        )
        cls._summaries["delattr"] = FunctionSummary(
            name="delattr",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("name", 1),
            ],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"obj"},
            may_raise={"AttributeError"},
        )
        cls._summaries["abs"] = FunctionSummary(
            name="abs",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType(kind=TypeKind.NUMBER),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["round"] = FunctionSummary(
            name="round",
            parameters=[
                ParameterInfo("number", 0),
                ParameterInfo("ndigits", 1, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.NUMBER),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["sum"] = FunctionSummary(
            name="sum",
            parameters=[
                ParameterInfo("iterable", 0),
                ParameterInfo("start", 1, has_default=True, default_value=0),
            ],
            return_type=PyType(kind=TypeKind.NUMBER),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["min"] = FunctionSummary(
            name="min",
            var_positional="args",
            return_type=PyType.unknown(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError", "TypeError"},
        )
        cls._summaries["max"] = FunctionSummary(
            name="max",
            var_positional="args",
            return_type=PyType.unknown(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError", "TypeError"},
        )
        cls._summaries["pow"] = FunctionSummary(
            name="pow",
            parameters=[
                ParameterInfo("base", 0),
                ParameterInfo("exp", 1),
                ParameterInfo("mod", 2, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.NUMBER),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError", "ZeroDivisionError"},
        )
        cls._summaries["divmod"] = FunctionSummary(
            name="divmod",
            parameters=[
                ParameterInfo("a", 0),
                ParameterInfo("b", 1),
            ],
            return_type=PyType.tuple_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ZeroDivisionError"},
        )
        cls._summaries["any"] = FunctionSummary(
            name="any",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["all"] = FunctionSummary(
            name="all",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["id"] = FunctionSummary(
            name="id",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["hash"] = FunctionSummary(
            name="hash",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["repr"] = FunctionSummary(
            name="repr",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.str_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["ascii"] = FunctionSummary(
            name="ascii",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType.str_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["chr"] = FunctionSummary(
            name="chr",
            parameters=[ParameterInfo("i", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError"},
        )
        cls._summaries["ord"] = FunctionSummary(
            name="ord",
            parameters=[ParameterInfo("c", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["bin"] = FunctionSummary(
            name="bin",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["oct"] = FunctionSummary(
            name="oct",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["hex"] = FunctionSummary(
            name="hex",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["format"] = FunctionSummary(
            name="format",
            parameters=[
                ParameterInfo("value", 0),
                ParameterInfo("format_spec", 1, has_default=True, default_value=""),
            ],
            return_type=PyType.str_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["print"] = FunctionSummary(
            name="print",
            var_positional="values",
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["input"] = FunctionSummary(
            name="input",
            parameters=[ParameterInfo("prompt", 0, has_default=True)],
            return_type=PyType.str_type(),
            is_pure=False,
            is_readonly=True,
            may_raise={"EOFError", "KeyboardInterrupt"},
        )
        cls._summaries["open"] = FunctionSummary(
            name="open",
            parameters=[
                ParameterInfo("file", 0),
                ParameterInfo("mode", 1, has_default=True, default_value="r"),
                ParameterInfo("buffering", 2, has_default=True),
                ParameterInfo("encoding", 3, has_default=True),
                ParameterInfo("errors", 4, has_default=True),
                ParameterInfo("newline", 5, has_default=True),
                ParameterInfo("closefd", 6, has_default=True),
                ParameterInfo("opener", 7, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.FILE),
            is_pure=False,
            is_readonly=False,
            may_raise={"FileNotFoundError", "PermissionError", "OSError"},
        )
        cls._summaries["dir"] = FunctionSummary(
            name="dir",
            parameters=[ParameterInfo("obj", 0, has_default=True)],
            return_type=PyType.list_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["vars"] = FunctionSummary(
            name="vars",
            parameters=[ParameterInfo("obj", 0, has_default=True)],
            return_type=PyType.dict_type(),
            is_pure=False,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["globals"] = FunctionSummary(
            name="globals",
            return_type=PyType.dict_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["locals"] = FunctionSummary(
            name="locals",
            return_type=PyType.dict_type(),
            is_pure=False,
            is_readonly=True,
        )
        cls._summaries["iter"] = FunctionSummary(
            name="iter",
            parameters=[
                ParameterInfo("obj", 0),
                ParameterInfo("sentinel", 1, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.ITERATOR),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["next"] = FunctionSummary(
            name="next",
            parameters=[
                ParameterInfo("iterator", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            may_raise={"StopIteration"},
        )
        cls._summaries["slice"] = FunctionSummary(
            name="slice",
            parameters=[
                ParameterInfo("start_or_stop", 0),
                ParameterInfo("stop", 1, has_default=True),
                ParameterInfo("step", 2, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.SLICE),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["memoryview"] = FunctionSummary(
            name="memoryview",
            parameters=[ParameterInfo("obj", 0)],
            return_type=PyType(kind=TypeKind.MEMORYVIEW),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._summaries["bytes"] = FunctionSummary(
            name="bytes",
            parameters=[
                ParameterInfo("source", 0, has_default=True),
                ParameterInfo("encoding", 1, has_default=True),
                ParameterInfo("errors", 2, has_default=True),
            ],
            return_type=PyType.bytes_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["bytearray"] = FunctionSummary(
            name="bytearray",
            parameters=[
                ParameterInfo("source", 0, has_default=True),
                ParameterInfo("encoding", 1, has_default=True),
                ParameterInfo("errors", 2, has_default=True),
            ],
            return_type=PyType(kind=TypeKind.BYTEARRAY),
            is_pure=True,
            is_readonly=True,
        )
        cls._summaries["eval"] = FunctionSummary(
            name="eval",
            parameters=[
                ParameterInfo("expression", 0),
                ParameterInfo("globals", 1, has_default=True),
                ParameterInfo("locals", 2, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            may_raise={"SyntaxError", "TypeError", "NameError"},
        )
        cls._summaries["exec"] = FunctionSummary(
            name="exec",
            parameters=[
                ParameterInfo("object", 0),
                ParameterInfo("globals", 1, has_default=True),
                ParameterInfo("locals", 2, has_default=True),
            ],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            may_raise={"SyntaxError", "TypeError"},
        )
        cls._summaries["compile"] = FunctionSummary(
            name="compile",
            parameters=[
                ParameterInfo("source", 0),
                ParameterInfo("filename", 1),
                ParameterInfo("mode", 2),
            ],
            return_type=PyType(kind=TypeKind.CODE),
            is_pure=True,
            is_readonly=True,
            may_raise={"SyntaxError", "ValueError", "TypeError"},
        )


class MethodModels:
    """Pre-defined models for methods of common types."""

    _models: dict[tuple[TypeKind, str], FunctionSummary] = {}

    @classmethod
    def get(cls, type_kind: TypeKind, method_name: str) -> FunctionSummary | None:
        """Get model for a method."""
        if not cls._models:
            cls._init_models()
        return cls._models.get((type_kind, method_name))

    @classmethod
    def _init_models(cls) -> None:
        """Initialize method models."""
        cls._add_str_methods()
        cls._add_list_methods()
        cls._add_dict_methods()
        cls._add_set_methods()

    @classmethod
    def _add_str_methods(cls) -> None:
        """Add string method models."""
        str_pure_str = [
            ("upper", []),
            ("lower", []),
            ("capitalize", []),
            ("title", []),
            ("swapcase", []),
            ("casefold", []),
            ("strip", [ParameterInfo("chars", 0, has_default=True)]),
            ("lstrip", [ParameterInfo("chars", 0, has_default=True)]),
            ("rstrip", [ParameterInfo("chars", 0, has_default=True)]),
            ("center", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("ljust", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("rjust", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("zfill", [ParameterInfo("width", 0)]),
            (
                "replace",
                [
                    ParameterInfo("old", 0),
                    ParameterInfo("new", 1),
                    ParameterInfo("count", 2, has_default=True),
                ],
            ),
        ]
        for name, params in str_pure_str:
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name}",
                parameters=params,
                return_type=PyType.str_type(),
                is_pure=True,
                is_readonly=True,
            )
        cls._models[(TypeKind.STR, "split")] = FunctionSummary(
            name="str.split",
            parameters=[
                ParameterInfo("sep", 0, has_default=True),
                ParameterInfo("maxsplit", 1, has_default=True),
            ],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "rsplit")] = FunctionSummary(
            name="str.rsplit",
            parameters=[
                ParameterInfo("sep", 0, has_default=True),
                ParameterInfo("maxsplit", 1, has_default=True),
            ],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "splitlines")] = FunctionSummary(
            name="str.splitlines",
            parameters=[ParameterInfo("keepends", 0, has_default=True)],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        str_pure_bool = [
            "isalnum",
            "isalpha",
            "isascii",
            "isdecimal",
            "isdigit",
            "isidentifier",
            "islower",
            "isnumeric",
            "isprintable",
            "isspace",
            "istitle",
            "isupper",
        ]
        for name in str_pure_bool:
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name}",
                parameters=[],
                return_type=PyType.bool_type(),
                is_pure=True,
                is_readonly=True,
            )
        str_search_int = [
            (
                "find",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "rfind",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "index",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "rindex",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "count",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
        ]
        for name, params in str_search_int:
            may_raise = {"ValueError"} if "index" in name else set()
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name}",
                parameters=params,
                return_type=PyType.int_type(),
                is_pure=True,
                is_readonly=True,
                may_raise=may_raise,
            )
        cls._models[(TypeKind.STR, "join")] = FunctionSummary(
            name="str.join",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._models[(TypeKind.STR, "format")] = FunctionSummary(
            name="str.format",
            var_positional="args",
            var_keyword="kwargs",
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"KeyError", "IndexError", "ValueError"},
        )
        cls._models[(TypeKind.STR, "startswith")] = FunctionSummary(
            name="str.startswith",
            parameters=[
                ParameterInfo("prefix", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "endswith")] = FunctionSummary(
            name="str.endswith",
            parameters=[
                ParameterInfo("suffix", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "encode")] = FunctionSummary(
            name="str.encode",
            parameters=[
                ParameterInfo("encoding", 0, has_default=True, default_value="utf-8"),
                ParameterInfo("errors", 1, has_default=True, default_value="strict"),
            ],
            return_type=PyType.bytes_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"UnicodeEncodeError"},
        )

    @classmethod
    def _add_list_methods(cls) -> None:
        """Add list method models."""
        cls._models[(TypeKind.LIST, "append")] = FunctionSummary(
            name="list.append",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "extend")] = FunctionSummary(
            name="list.extend",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "insert")] = FunctionSummary(
            name="list.insert",
            parameters=[ParameterInfo("i", 0), ParameterInfo("x", 1)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "remove")] = FunctionSummary(
            name="list.remove",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"ValueError"},
        )
        cls._models[(TypeKind.LIST, "pop")] = FunctionSummary(
            name="list.pop",
            parameters=[ParameterInfo("i", 0, has_default=True, default_value=-1)],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"IndexError"},
        )
        cls._models[(TypeKind.LIST, "clear")] = FunctionSummary(
            name="list.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "sort")] = FunctionSummary(
            name="list.sort",
            parameters=[
                ParameterInfo("key", 0, has_default=True),
                ParameterInfo("reverse", 1, has_default=True, default_value=False),
            ],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "reverse")] = FunctionSummary(
            name="list.reverse",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "copy")] = FunctionSummary(
            name="list.copy",
            parameters=[],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.LIST, "index")] = FunctionSummary(
            name="list.index",
            parameters=[
                ParameterInfo("x", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError"},
        )
        cls._models[(TypeKind.LIST, "count")] = FunctionSummary(
            name="list.count",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
        )

    @classmethod
    def _add_dict_methods(cls) -> None:
        """Add dict method models."""
        cls._models[(TypeKind.DICT, "get")] = FunctionSummary(
            name="dict.get",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "setdefault")] = FunctionSummary(
            name="dict.setdefault",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "pop")] = FunctionSummary(
            name="dict.pop",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.DICT, "popitem")] = FunctionSummary(
            name="dict.popitem",
            parameters=[],
            return_type=PyType.tuple_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.DICT, "keys")] = FunctionSummary(
            name="dict.keys",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_KEYS),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "values")] = FunctionSummary(
            name="dict.values",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_VALUES),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "items")] = FunctionSummary(
            name="dict.items",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_ITEMS),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "update")] = FunctionSummary(
            name="dict.update",
            parameters=[ParameterInfo("other", 0, has_default=True)],
            var_keyword="kwargs",
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "clear")] = FunctionSummary(
            name="dict.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "copy")] = FunctionSummary(
            name="dict.copy",
            parameters=[],
            return_type=PyType.dict_type(),
            is_pure=True,
            is_readonly=True,
        )

    @classmethod
    def _add_set_methods(cls) -> None:
        """Add set method models."""
        cls._models[(TypeKind.SET, "add")] = FunctionSummary(
            name="set.add",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.SET, "remove")] = FunctionSummary(
            name="set.remove",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.SET, "discard")] = FunctionSummary(
            name="set.discard",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.SET, "pop")] = FunctionSummary(
            name="set.pop",
            parameters=[],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.SET, "clear")] = FunctionSummary(
            name="set.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        set_ops = [
            ("union", []),
            ("intersection", []),
            ("difference", []),
            ("symmetric_difference", [ParameterInfo("other", 0)]),
        ]
        for name, params in set_ops:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name}",
                parameters=params,
                var_positional="others" if not params else None,
                return_type=PyType.set_type(),
                is_pure=True,
                is_readonly=True,
            )
        set_comparisons = ["issubset", "issuperset", "isdisjoint"]
        for name in set_comparisons:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name}",
                parameters=[ParameterInfo("other", 0)],
                return_type=PyType.bool_type(),
                is_pure=True,
                is_readonly=True,
            )
        set_updates = [
            "update",
            "intersection_update",
            "difference_update",
            "symmetric_difference_update",
        ]
        for name in set_updates:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name}",
                var_positional="others",
                return_type=PyType.none_type(),
                is_pure=False,
                is_readonly=False,
                mutates_parameters={"self"},
            )
        cls._models[(TypeKind.SET, "copy")] = FunctionSummary(
            name="set.copy",
            parameters=[],
            return_type=PyType.set_type(),
            is_pure=True,
            is_readonly=True,
        )


class FunctionSummarizer:
    """Creates and caches function summaries."""

    def __init__(self) -> None:
        self.summaries: dict[str, FunctionSummary] = {}

    def get_summary(self, name: str) -> FunctionSummary | None:
        """Get summary for a function."""
        if name in self.summaries:
            return self.summaries[name]
        builtin_summary = BuiltinModels.get(name)
        if builtin_summary:
            self.summaries[name] = builtin_summary
            return builtin_summary
        return None

    def get_method_summary(
        self,
        type_kind: TypeKind,
        method_name: str,
    ) -> FunctionSummary | None:
        """Get summary for a method."""
        return MethodModels.get(type_kind, method_name)

    def summarize_code(self, code: Any, name: str) -> FunctionSummary:
        """Create summary from code object."""
        summary = FunctionSummary(name=name)
        varnames = code.co_varnames
        arg_count = code.co_argcount
        kwonly_count = code.co_kwonlyargcount
        flags = code.co_flags
        has_varargs = bool(flags & 0x04)
        has_kwargs = bool(flags & 0x08)
        pos = 0
        for i in range(arg_count):
            param_name = varnames[i]
            summary.parameters.append(
                ParameterInfo(
                    name=param_name,
                    position=pos,
                )
            )
            pos += 1
        for i in range(arg_count, arg_count + kwonly_count):
            param_name = varnames[i]
            summary.parameters.append(
                ParameterInfo(
                    name=param_name,
                    position=pos,
                )
            )
            pos += 1
        if has_varargs:
            summary.var_positional = varnames[arg_count + kwonly_count]
        if has_kwargs:
            idx = arg_count + kwonly_count + (1 if has_varargs else 0)
            if idx < len(varnames):
                summary.var_keyword = varnames[idx]
        self._analyze_effects(code, summary)
        summary.is_analyzed = True
        self.summaries[name] = summary
        return summary

    def _analyze_effects(self, code: Any, summary: FunctionSummary) -> None:
        """Analyze bytecode for effects."""
        instructions = list(dis.get_instructions(code))
        has_side_effects = False
        has_mutations = False
        for instr in instructions:
            if instr.opname in {"STORE_GLOBAL", "DELETE_GLOBAL"}:
                has_side_effects = True
                has_mutations = True
                summary.mutates_globals.add(instr.argval)
            if instr.opname in {"STORE_ATTR", "DELETE_ATTR", "STORE_SUBSCR", "DELETE_SUBSCR"}:
                has_mutations = True
            if instr.opname == "RAISE_VARARGS":
                summary.may_raise.add("Exception")
            if instr.opname == "BINARY_OP" and instr.argrepr in {"/", "//", "%"}:
                summary.may_raise.add("ZeroDivisionError")
            if instr.opname == "BINARY_SUBSCR":
                summary.may_raise.add("KeyError")
                summary.may_raise.add("IndexError")
            if instr.opname == "LOAD_ATTR":
                summary.may_raise.add("AttributeError")
            if instr.opname in {"RETURN_VALUE", "RETURN_CONST"}:
                summary.always_returns = True
            if instr.opname == "RETURN_CONST" and instr.argval is None:
                summary.may_return_none = True
        summary.is_pure = not has_side_effects and not has_mutations
        summary.is_readonly = not has_mutations
