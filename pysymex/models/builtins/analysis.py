# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Pre-defined summaries for Python built-in functions."""

from __future__ import annotations

from .functions import FunctionSummary, ParameterInfo
from pysymex.analysis.type_inference import PyType, TypeKind


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
