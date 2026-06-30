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

"""Static class metadata for compile-only scan loading."""

from __future__ import annotations

import ast

from pysymex._internal.analysis.scan.loading.classes.declarations import (
    bounded_subclass_registry_entries,
    bounded_subclass_registry_spec,
)
from pysymex._internal.analysis.scan.loading.stdlib.declarations import (
    annotation_only_named_tuple_fields,
    bounded_dataclass_spec,
    literal_enum_members,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue


def attach_static_class_metadata(
    node: ast.ClassDef,
    tree_body: list[ast.stmt],
    class_values: dict[str, SymbolicValue],
    module_globals: dict[str, object],
) -> None:
    """Attach static class metadata discovered from the class AST."""
    class_value = class_values[node.name]
    bases_complete, modeled_bases = _modeled_base_values(node, module_globals)
    class_value.set_class_bases(bases_complete, modeled_bases if bases_complete else ())
    enum_members = literal_enum_members(node, module_globals)
    if enum_members:
        class_value.set_literal_enum_members(enum_members)
    named_tuple_fields = annotation_only_named_tuple_fields(node, module_globals)
    if named_tuple_fields is not None:
        class_value.set_named_tuple_fields(named_tuple_fields)
    dataclass_spec = bounded_dataclass_spec(node, module_globals)
    if dataclass_spec is not None:
        fields, frozen = dataclass_spec
        class_value.set_dataclass_metadata(fields, frozen)
    descriptor_assignments = _descriptor_assignments(node, module_globals)
    if descriptor_assignments:
        class_value.set_descriptor_assignments(descriptor_assignments)
    registry_spec = bounded_subclass_registry_spec(node)
    if registry_spec is not None:
        registry_entries = bounded_subclass_registry_entries(
            node.name,
            registry_spec,
            tree_body,
            class_values,
        )
        if registry_entries is not None:
            class_value.set_static_class_attrs({registry_spec.attribute: registry_entries})


def _literal_descriptor_constructor_args(call: ast.Call) -> tuple[object, ...] | None:
    """Retain primitive positional constructor literals for bounded descriptors."""
    if call.keywords:
        return None
    values: list[object] = []
    for argument in call.args:
        if not isinstance(argument, ast.Constant) or not isinstance(
            argument.value,
            (bool, int, float, str, bytes, type(None)),
        ):
            return None
        values.append(argument.value)
    return tuple(values)


def _modeled_base_values(
    node: ast.ClassDef,
    module_globals: dict[str, object],
) -> tuple[bool, tuple[object, ...]]:
    """Return whether all bases are modeled plus resolved base values."""
    modeled_bases: list[object] = []
    for base in node.bases:
        if not isinstance(base, ast.Name):
            break
        base_value = module_globals.get(base.id)
        if not isinstance(base_value, SymbolicValue):
            break
        modeled_bases.append(base_value)
    return len(modeled_bases) == len(node.bases), tuple(modeled_bases)


def _descriptor_assignments(
    node: ast.ClassDef,
    module_globals: dict[str, object],
) -> dict[str, tuple[object, tuple[object, ...] | None]]:
    """Collect supported literal descriptor assignments from a class body."""
    assignments: dict[str, tuple[object, tuple[object, ...] | None]] = {}
    for statement in node.body:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
            or not isinstance(statement.value, ast.Call)
            or not isinstance(statement.value.func, ast.Name)
        ):
            continue
        assigned_value = module_globals.get(statement.value.func.id)
        if isinstance(assigned_value, SymbolicValue):
            assignments[statement.targets[0].id] = (
                assigned_value,
                _literal_descriptor_constructor_args(statement.value),
            )
    return assignments
