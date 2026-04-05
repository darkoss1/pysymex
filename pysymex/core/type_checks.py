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

"""Pure-function type predicates shared by execution and analysis layers.

This module lives in ``core`` (a leaf package) so that both
``pysymex.execution.opcodes`` and ``pysymex.analysis.detectors`` can import
from it without creating a circular dependency.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.types import SymbolicValue

_OVERLOAD_NAME_PARTS: frozenset[str] = frozenset(
    {
        "z3",
        "arith",
        "solver",
        "symbolic",
        "numpy",
        "np_",
        "decimal",
        "tensor",
        "torch",
        "jax",
        "array",
        "matrix",
        "vector",
        "z3_int",
        "z3_real",
        "z3_bool",
        "arithref",
    }
)

BUILTIN_TYPE_NAMES: frozenset[str] = frozenset(
    {
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
        "type",
        "bytes",
        "bytearray",
        "memoryview",
        "range",
        "slice",
        "property",
        "classmethod",
        "staticmethod",
        "super",
        "object",
        "str",
        "int",
        "float",
        "bool",
        "complex",
        "Optional",
        "Union",
        "Callable",
        "Literal",
        "Annotated",
        "ClassVar",
        "Final",
        "Type",
        "Generic",
        "Protocol",
        "ParamSpec",
        "TypeVar",
        "TypeAlias",
        "Sequence",
        "Mapping",
        "MutableMapping",
        "MutableSequence",
        "Iterable",
        "Iterator",
        "Generator",
        "Coroutine",
        "AsyncGenerator",
        "AsyncIterator",
        "Awaitable",
        "Collection",
        "Deque",
        "DefaultDict",
        "OrderedDict",
        "Counter",
        "ChainMap",
        "Pattern",
        "Match",
        "IO",
        "TextIO",
        "BinaryIO",
        "NamedTuple",
        "TypedDict",
        "Any",
    }
)


def is_overloaded_arithmetic(left: SymbolicValue, right: SymbolicValue) -> bool:
    """Return True if either operand appears to be from an operator-overloading
    type (Z3, numpy, Decimal, etc.) where ``/`` and ``%`` build expression trees
    rather than performing real numeric division.
    """
    for operand in (left, right):
        name = getattr(operand, "_name", "") or getattr(operand, "name", "") or ""
        name_lower = name.lower()
        if any(part in name_lower for part in _OVERLOAD_NAME_PARTS):
            return True
        model = getattr(operand, "model_name", None) or ""
        if model.lower() in {"z3", "numpy", "np", "decimal", "torch", "jax", "sympy"}:
            return True
        otype = getattr(operand, "_type", None) or ""
        if otype.lower() in {
            "z3",
            "arithref",
            "boolref",
            "numpy",
            "ndarray",
            "decimal",
            "tensor",
        }:
            return True
    return False


def is_type_subscription(container: object) -> bool:
    """Return True if *container* is a type object being subscripted for
    generic-alias syntax (e.g. ``list[int]``) rather than real indexing.
    """
    name: str = getattr(container, "_name", "") or getattr(container, "name", "") or ""

    if name.startswith("global_"):
        base = name[7:]
        if base in BUILTIN_TYPE_NAMES:
            return True

    if name.startswith("import_"):
        base = name[7:]
        if base in BUILTIN_TYPE_NAMES:
            return True

    model_name: str | None = getattr(container, "model_name", None)
    if model_name and model_name in BUILTIN_TYPE_NAMES:
        return True
    return False
