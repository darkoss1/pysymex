# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Enhanced Inter-Procedural Analysis for pysymex.
This module extends the existing interprocedural.py with more advanced
capabilities for tracking information across function calls.
Features:
- Extended call graph with context sensitivity
- Function summaries with effect tracking
- Type propagation across calls
- Exception flow analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import CodeType
from typing import TYPE_CHECKING

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

from .type_inference import PyType, TypeKind

if TYPE_CHECKING:
    from .builtin_models import BuiltinModels as BuiltinModels
    from .method_models import MethodModels as MethodModels


@dataclass
class ParameterInfo:
    """Information about a function parameter."""

    name: str
    position: int
    declared_type: PyType | None = None
    inferred_types: set[PyType] = field(default_factory=set[PyType])
    is_used: bool = True
    is_mutated: bool = False
    has_default: bool = False
    default_value: object | None = None


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
    parameters: list[ParameterInfo] = field(default_factory=list[ParameterInfo])
    var_positional: str | None = None
    var_keyword: str | None = None
    return_type: PyType | None = None
    return_types_seen: set[PyType] = field(default_factory=set[PyType])
    may_return_none: bool = False
    always_returns: bool = True
    is_pure: bool = False
    is_readonly: bool = False
    may_raise: set[str] = field(default_factory=set[str])
    documented_raises: set[str] = field(default_factory=set[str])
    mutates_parameters: set[str] = field(default_factory=set[str])
    mutates_globals: set[str] = field(default_factory=set[str])
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


class FunctionSummarizer:
    """Creates and caches function summaries."""

    def __init__(self) -> None:
        self.summaries: dict[str, FunctionSummary] = {}

    def get_summary(self, name: str) -> FunctionSummary | None:
        """Get summary for a function."""
        if name in self.summaries:
            return self.summaries[name]
        from .builtin_models import BuiltinModels

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
        from .method_models import MethodModels

        return MethodModels.get(type_kind, method_name)

    def summarize_code(self, code: CodeType, name: str) -> FunctionSummary:
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

    def _analyze_effects(self, code: CodeType, summary: FunctionSummary) -> None:
        """Analyze bytecode for effects."""
        instructions = _cached_get_instructions(code)
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


_EXPORTS: dict[str, tuple[str, str]] = {
    "BuiltinModels": ("pysymex.analysis.builtin_models", "BuiltinModels"),
    "MethodModels": ("pysymex.analysis.method_models", "MethodModels"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    _target = _EXPORTS.get(name)
    if _target is not None:
        import importlib

        _mod = importlib.import_module(_target[0])
        return getattr(_mod, _target[1])
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Dir."""
    _names = list(globals())
    _names.extend(_EXPORTS)
    return _names


__all__: list[str] = [
    "BuiltinModels",
    "FunctionSummarizer",
    "FunctionSummary",
    "MethodModels",
    "ParameterInfo",
]
