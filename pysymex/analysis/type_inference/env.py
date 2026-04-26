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

"""
Type environment for tracking variable types across scopes.

Contains:
- TypeEnvironment: Dataclass tracking variable types, refinements,
  and definite/maybe assignment in nested scope hierarchies
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.type_inference.kinds import PyType, TypeKind


@dataclass
class TypeEnvironment:
    """
    Tracks type information for variables in a scope.
    Supports:
    - Variable type assignments
    - Type narrowing from control flow
    - Scope hierarchies (local, enclosing, global, builtin)
    """

    types: dict[str, PyType] = field(default_factory=dict[str, PyType])
    parent: TypeEnvironment | None = None
    globals: dict[str, PyType] = field(default_factory=dict[str, PyType])
    refinements: dict[str, PyType] = field(default_factory=dict[str, PyType])
    definitely_assigned: set[str] = field(default_factory=set[str])
    maybe_assigned: set[str] = field(default_factory=set[str])
    analyzer: object = field(default=None, compare=False, repr=False)

    def get_type(self, name: str) -> PyType:
        """Look up type for a variable."""
        if name in self.refinements:
            return self.refinements[name]
        if name in self.types:
            return self.types[name]
        if self.parent:
            return self.parent.get_type(name)
        if name in self.globals:
            return self.globals[name]
        builtin_type = self._get_builtin_type(name)
        if builtin_type:
            return builtin_type
        return PyType.unknown()

    def set_type(self, name: str, typ: PyType) -> None:
        """Set type for a variable."""
        self.types[name] = typ
        self.definitely_assigned.add(name)
        self.maybe_assigned.add(name)

    def refine_type(self, name: str, typ: PyType) -> None:
        """Refine type based on control flow (isinstance, etc.)."""
        current = self.get_type(name)
        refined = current.meet(typ)
        if refined.kind != TypeKind.BOTTOM:
            self.refinements[name] = refined

    def clear_refinement(self, name: str) -> None:
        """Clear type refinement for a variable."""
        self.refinements.pop(name, None)

    def copy(self) -> TypeEnvironment:
        """Create a copy of this environment."""
        return TypeEnvironment(
            types=dict(self.types),
            parent=self.parent,
            globals=self.globals,
            refinements=dict(self.refinements),
            definitely_assigned=set(self.definitely_assigned),
            maybe_assigned=set(self.maybe_assigned),
        )

    def join(self, other: TypeEnvironment) -> TypeEnvironment:
        """Join two environments (for control flow merge points)."""
        result = TypeEnvironment(
            parent=self.parent,
            globals=self.globals,
        )
        all_vars = set(self.types.keys()) | set(other.types.keys())
        for var in all_vars:
            t1 = self.get_type(var)
            t2 = other.get_type(var)
            result.types[var] = t1.join(t2)
        result.definitely_assigned = self.definitely_assigned & other.definitely_assigned
        result.maybe_assigned = self.maybe_assigned | other.maybe_assigned
        return result

    def enter_scope(self) -> TypeEnvironment:
        """Create a new child scope."""
        return TypeEnvironment(parent=self, globals=self.globals)

    def _get_builtin_type(self, name: str) -> PyType | None:
        """Get type for a builtin name."""
        builtin_types = {
            "int": PyType(kind=TypeKind.CLASS, name="int", class_name="int"),
            "str": PyType(kind=TypeKind.CLASS, name="str", class_name="str"),
            "float": PyType(kind=TypeKind.CLASS, name="float", class_name="float"),
            "bool": PyType(kind=TypeKind.CLASS, name="bool", class_name="bool"),
            "list": PyType(kind=TypeKind.CLASS, name="list", class_name="list"),
            "dict": PyType(kind=TypeKind.CLASS, name="dict", class_name="dict"),
            "set": PyType(kind=TypeKind.CLASS, name="set", class_name="set"),
            "tuple": PyType(kind=TypeKind.CLASS, name="tuple", class_name="tuple"),
            "bytes": PyType(kind=TypeKind.CLASS, name="bytes", class_name="bytes"),
            "type": PyType(kind=TypeKind.CLASS, name="type", class_name="type"),
            "object": PyType(kind=TypeKind.CLASS, name="object", class_name="object"),
            "None": PyType.none(),
            "True": PyType.literal_(True),
            "False": PyType.literal_(False),
            "Ellipsis": PyType(kind=TypeKind.INSTANCE, name="ellipsis"),
            "NotImplemented": PyType(kind=TypeKind.INSTANCE, name="NotImplementedType"),
            "len": PyType.callable_([PyType.any_()], PyType.int_()),
            "range": PyType.callable_([PyType.int_()], PyType.instance("range")),
            "enumerate": PyType.callable_([PyType.any_()], PyType.instance("enumerate")),
            "zip": PyType.callable_([PyType.any_()], PyType.instance("zip")),
            "map": PyType.callable_([PyType.any_(), PyType.any_()], PyType.instance("map")),
            "filter": PyType.callable_([PyType.any_(), PyType.any_()], PyType.instance("filter")),
            "sorted": PyType.callable_([PyType.any_()], PyType.list_()),
            "reversed": PyType.callable_([PyType.any_()], PyType.instance("reversed")),
            "min": PyType.callable_([PyType.any_()], PyType.any_()),
            "max": PyType.callable_([PyType.any_()], PyType.any_()),
            "sum": PyType.callable_([PyType.any_()], PyType.union_(PyType.int_(), PyType.float_())),
            "abs": PyType.callable_([PyType.any_()], PyType.union_(PyType.int_(), PyType.float_())),
            "round": PyType.callable_([PyType.float_()], PyType.int_()),
            "pow": PyType.callable_([PyType.any_(), PyType.any_()], PyType.any_()),
            "divmod": PyType.callable_(
                [PyType.any_(), PyType.any_()], PyType.tuple_(PyType.any_(), PyType.any_())
            ),
            "hash": PyType.callable_([PyType.any_()], PyType.int_()),
            "id": PyType.callable_([PyType.any_()], PyType.int_()),
            "isinstance": PyType.callable_([PyType.any_(), PyType.any_()], PyType.bool_()),
            "issubclass": PyType.callable_([PyType.any_(), PyType.any_()], PyType.bool_()),
            "callable": PyType.callable_([PyType.any_()], PyType.bool_()),
            "hasattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.bool_()),
            "getattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.any_()),
            "setattr": PyType.callable_(
                [PyType.any_(), PyType.str_(), PyType.any_()], PyType.none()
            ),
            "delattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.none()),
            "repr": PyType.callable_([PyType.any_()], PyType.str_()),
            "print": PyType.callable_([], PyType.none()),
            "input": PyType.callable_([], PyType.str_()),
            "open": PyType.callable_([PyType.str_()], PyType.instance("TextIOWrapper")),
            "iter": PyType.callable_([PyType.any_()], PyType.instance("iterator")),
            "next": PyType.callable_([PyType.any_()], PyType.any_()),
            "all": PyType.callable_([PyType.any_()], PyType.bool_()),
            "any": PyType.callable_([PyType.any_()], PyType.bool_()),
            "ord": PyType.callable_([PyType.str_()], PyType.int_()),
            "chr": PyType.callable_([PyType.int_()], PyType.str_()),
            "hex": PyType.callable_([PyType.int_()], PyType.str_()),
            "oct": PyType.callable_([PyType.int_()], PyType.str_()),
            "bin": PyType.callable_([PyType.int_()], PyType.str_()),
            "format": PyType.callable_([PyType.any_()], PyType.str_()),
            "vars": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "dir": PyType.callable_([], PyType.list_(PyType.str_())),
            "globals": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "locals": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "exec": PyType.callable_([PyType.str_()], PyType.none()),
            "eval": PyType.callable_([PyType.str_()], PyType.any_()),
            "compile": PyType.callable_([PyType.str_()], PyType.instance("code")),
            "super": PyType.callable_([], PyType.instance("super")),
            "property": PyType.callable_([], PyType.instance("property")),
            "staticmethod": PyType.callable_([PyType.any_()], PyType.instance("staticmethod")),
            "classmethod": PyType.callable_([PyType.any_()], PyType.instance("classmethod")),
            "slice": PyType.callable_([], PyType.instance("slice")),
            "memoryview": PyType.callable_([PyType.bytes_()], PyType.instance("memoryview")),
            "bytearray": PyType.callable_([], PyType.instance("bytearray")),
            "frozenset": PyType.callable_([], PyType(kind=TypeKind.FROZENSET, name="frozenset")),
            "complex": PyType.callable_([], PyType(kind=TypeKind.COMPLEX, name="complex")),
            "Exception": PyType(kind=TypeKind.CLASS, name="Exception", class_name="Exception"),
            "BaseException": PyType(
                kind=TypeKind.CLASS, name="BaseException", class_name="BaseException"
            ),
            "ValueError": PyType(kind=TypeKind.CLASS, name="ValueError", class_name="ValueError"),
            "TypeError": PyType(kind=TypeKind.CLASS, name="TypeError", class_name="TypeError"),
            "KeyError": PyType(kind=TypeKind.CLASS, name="KeyError", class_name="KeyError"),
            "IndexError": PyType(kind=TypeKind.CLASS, name="IndexError", class_name="IndexError"),
            "AttributeError": PyType(
                kind=TypeKind.CLASS, name="AttributeError", class_name="AttributeError"
            ),
            "RuntimeError": PyType(
                kind=TypeKind.CLASS, name="RuntimeError", class_name="RuntimeError"
            ),
            "StopIteration": PyType(
                kind=TypeKind.CLASS, name="StopIteration", class_name="StopIteration"
            ),
        }
        return builtin_types.get(name)
