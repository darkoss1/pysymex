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

"""Convert loaded type stubs into PyType instances for the inference engine."""

from __future__ import annotations

from pysymex.analysis.static.types.kinds import PyType, TypeKind

_STUB_NAME_TO_KIND: dict[str, TypeKind] = {
    "Any": TypeKind.ANY,
    "None": TypeKind.NONE,
    "int": TypeKind.INT,
    "str": TypeKind.STR,
    "bool": TypeKind.BOOL,
    "float": TypeKind.FLOAT,
    "bytes": TypeKind.BYTES,
    "object": TypeKind.OBJECT,
    "list": TypeKind.LIST,
    "dict": TypeKind.DICT,
    "set": TypeKind.SET,
    "frozenset": TypeKind.FROZENSET,
    "tuple": TypeKind.TUPLE,
    "type": TypeKind.TYPE,
    "Callable": TypeKind.CALLABLE,
    "Iterator": TypeKind.ITERATOR,
    "Generator": TypeKind.GENERATOR,
    "Coroutine": TypeKind.COROUTINE,
    "Optional": TypeKind.OPTIONAL,
    "Union": TypeKind.UNION,
}


def convert_stub_to_pytype(stub: object) -> PyType:
    """Convert a StubType to PyType.

    The conversion belongs to type inference. ``type_stubs`` owns parsed stub
    records and intentionally stays independent of inferred ``PyType`` values.
    """
    from pysymex.analysis.static.stubs.types import StubType

    if not isinstance(stub, StubType):
        return PyType.any_()

    kind = _STUB_NAME_TO_KIND.get(stub.name, TypeKind.OBJECT)

    if stub.is_optional:
        arg_types = tuple(convert_stub_to_pytype(arg) for arg in stub.type_args)
        return PyType(kind, name=stub.name, params=arg_types, nullable=True)

    if stub.is_union:
        member_types = frozenset(convert_stub_to_pytype(member) for member in stub.union_members)
        return PyType(kind, name=stub.name, union_members=member_types)

    if stub.type_args:
        arg_types = tuple(convert_stub_to_pytype(arg) for arg in stub.type_args)
        return PyType(kind, name=stub.name, params=arg_types)

    return PyType(kind, name=stub.name)


__all__ = ["convert_stub_to_pytype"]
