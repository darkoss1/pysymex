# pysymex: python symbolic execution & formal verification
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

"""Bytecode-based return type inference for cross-function analysis."""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.types import PyType, TypeKind
from pysymex.core.cache import get_instructions as cached_get_instructions

_PYTHON_TYPE_TO_PYTYPE: dict[type, PyType] = {
    int: PyType.int_(),
    float: PyType.float_(),
    str: PyType.str_(),
    bool: PyType.bool_(),
    bytes: PyType(kind=TypeKind.BYTES, name="bytes"),
    type(None): PyType.none(),
}

PYTHON_TYPE_TO_PYTYPE = _PYTHON_TYPE_TO_PYTYPE


def _py_type_for_constant(value: object) -> PyType | None:
    """Translate a Python constant to its corresponding PyType.

    Args:
        value (object): Constant value.

    Returns:
        PyType | None: Corresponding PyType, or None if unknown.
    """
    return _PYTHON_TYPE_TO_PYTYPE.get(type(value))


def infer_return_type(code: CodeType) -> PyType | None:
    """Infer the return type of a function from its bytecode."""
    return_types: list[PyType] = []
    instructions = cached_get_instructions(code)

    for i, instr in enumerate(instructions):
        opname = instr.opname
        if opname == "RETURN_CONST":
            value: object = instr.argval
            py_type = _py_type_for_constant(value)
            if py_type is not None:
                return_types.append(py_type)
        elif opname == "RETURN_VALUE" and i > 0:
            prev = instructions[i - 1]
            if prev.opname == "LOAD_CONST":
                value = prev.argval
                py_type = _py_type_for_constant(value)
                if py_type is not None:
                    return_types.append(py_type)

    if not return_types:
        return PyType.none()

    unique = list(dict.fromkeys(return_types))
    if len(unique) == 1:
        return unique[0]

    non_none = [t for t in unique if t.kind != TypeKind.NONE]
    has_none = any(t.kind == TypeKind.NONE for t in unique)
    if len(non_none) == 1 and has_none:
        return PyType(
            kind=non_none[0].kind,
            name=f"Optional[{non_none[0].name}]",
            nullable=True,
        )

    return None


__all__ = ["PYTHON_TYPE_TO_PYTYPE", "infer_return_type"]
