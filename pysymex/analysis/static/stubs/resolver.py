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

"""Resolve type names to PyType instances using loaded type stubs."""

from __future__ import annotations

from dataclasses import replace

from pysymex.analysis.static.stubs.repository import StubRepository
from pysymex.analysis.static.stubs.types import FunctionStub, StubType


def _bind_typevar(bindings: dict[str, StubType], name: str, value: StubType) -> None:
    existing = bindings.get(name)
    if existing is None:
        bindings[name] = value
    elif existing != value:
        bindings[name] = StubType.any_type()


def _collect_typevar_bindings(
    expected: StubType,
    actual: StubType,
    bindings: dict[str, StubType],
) -> None:
    if expected.is_typevar:
        _bind_typevar(bindings, expected.name, actual)
        return

    for expected_arg, actual_arg in zip(expected.type_args, actual.type_args, strict=False):
        _collect_typevar_bindings(expected_arg, actual_arg, bindings)

    for expected_arg, actual_arg in zip(expected.union_members, actual.union_members, strict=False):
        _collect_typevar_bindings(expected_arg, actual_arg, bindings)

    for expected_arg, actual_arg in zip(expected.param_types, actual.param_types, strict=False):
        _collect_typevar_bindings(expected_arg, actual_arg, bindings)

    if expected.return_type is not None and actual.return_type is not None:
        _collect_typevar_bindings(expected.return_type, actual.return_type, bindings)


def _substitute_typevars(stub_type: StubType, bindings: dict[str, StubType]) -> StubType:
    if stub_type.is_typevar:
        return bindings.get(stub_type.name, stub_type)

    type_args = tuple(_substitute_typevars(arg, bindings) for arg in stub_type.type_args)
    union_members = tuple(_substitute_typevars(arg, bindings) for arg in stub_type.union_members)
    param_types = tuple(_substitute_typevars(arg, bindings) for arg in stub_type.param_types)
    return_type = (
        _substitute_typevars(stub_type.return_type, bindings)
        if stub_type.return_type is not None
        else None
    )

    if (
        type_args == stub_type.type_args
        and union_members == stub_type.union_members
        and param_types == stub_type.param_types
        and return_type == stub_type.return_type
    ):
        return stub_type

    return replace(
        stub_type,
        type_args=type_args,
        union_members=union_members,
        param_types=param_types,
        return_type=return_type,
    )


def _resolve_stub_return(
    stub: FunctionStub,
    arg_types: list[StubType] | None,
    *,
    skip_bound_receiver: bool = False,
) -> StubType | None:
    return_type = stub.return_type
    if return_type is None or not arg_types:
        return return_type

    param_items = list(stub.params.items())
    if (
        skip_bound_receiver
        and len(param_items) == len(arg_types) + 1
        and param_items[0][0] in {"self", "cls"}
    ):
        param_items = param_items[1:]

    bindings: dict[str, StubType] = {}
    for (_param_name, param_type), arg_type in zip(param_items, arg_types, strict=False):
        _collect_typevar_bindings(param_type, arg_type, bindings)
    if bindings:
        return _substitute_typevars(return_type, bindings)
    return return_type


class StubBasedTypeResolver:
    """
    Resolves types using stub information.
    """

    def __init__(self, repository: StubRepository | None = None) -> None:
        self.repository = repository or StubRepository()

    def resolve_function_return(
        self,
        module: str,
        function: str,
        arg_types: list[StubType] | None = None,
    ) -> StubType | None:
        """Resolve the return type of a function call."""
        func = self.repository.get_function_type(module, function)
        if not func:
            return None
        return _resolve_stub_return(func, arg_types)

    def resolve_method_return(
        self,
        module: str,
        class_name: str,
        method: str,
        arg_types: list[StubType] | None = None,
    ) -> StubType | None:
        """Resolve the return type of a method call."""
        method_stub = self.repository.get_method_type(module, class_name, method)
        if not method_stub:
            return None
        return _resolve_stub_return(method_stub, arg_types, skip_bound_receiver=True)

    def resolve_attribute(
        self,
        module: str,
        class_name: str,
        attribute: str,
    ) -> StubType | None:
        """Resolve the type of a class attribute."""
        class_stub = self.repository.get_class_type(module, class_name)
        if not class_stub:
            return None
        if attribute in class_stub.attributes:
            return class_stub.attributes[attribute]
        if attribute in class_stub.class_vars:
            return class_stub.class_vars[attribute]
        if attribute in class_stub.methods:
            method = class_stub.methods[attribute]
            if method.is_property:
                return method.return_type
        return None

    def check_assignable(
        self,
        source: StubType,
        target: StubType,
    ) -> bool:
        """Check if source type is assignable to target type."""
        if source.name == "Any" or target.name == "Any":
            return True
        if source.name == "None":
            return target.is_optional or target.name == "None"
        if target.is_union:
            return any(self.check_assignable(source, member) for member in target.union_members)
        if source.is_union:
            return all(self.check_assignable(member, target) for member in source.union_members)
        if target.is_optional:
            if target.type_args:
                inner = target.type_args[0]
                return source.name == "None" or self.check_assignable(source, inner)
        if source.name == target.name:
            if not target.type_args:
                return True
            if len(source.type_args) != len(target.type_args):
                return False
            return all(
                self.check_assignable(s, t)
                for s, t in zip(source.type_args, target.type_args, strict=False)
            )
        subtype_relations = {
            "bool": {"int"},
            "int": {"float", "complex"},
            "float": {"complex"},
            "str": {"object"},
            "list": {"Sequence", "Iterable", "Collection"},
            "dict": {"Mapping", "Collection"},
            "set": {"Set", "Collection"},
        }
        if source.name in subtype_relations:
            if target.name in subtype_relations[source.name]:
                return True
        if target.name == "object":
            return True
        return False


__all__ = ["StubBasedTypeResolver"]
