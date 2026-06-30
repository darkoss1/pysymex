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

"""Bounded standard-library declaration recognition for compile-only loading.

Statically parses class and function definition ASTs to recognize standard
library constructs (Enums, NamedTuples, and Dataclasses) and mock their runtime
types without executing target module code.
"""

from __future__ import annotations

import ast
import collections
import dataclasses
import enum
import typing
from typing import cast

DataclassFieldSpec = tuple[str, str | None, bool, object, str | None]
DataclassSpec = tuple[tuple[DataclassFieldSpec, ...], bool]


def literal_enum_members(
    node: ast.ClassDef,
    module_globals: dict[str, object],
) -> dict[str, enum.Enum]:
    """Construct faithful members for a plain direct literal-only enum class.

    Inspects an AST class definition to verify it inherits from a standard Enum/IntEnum,
    then parses each assignment to extract integer members and builds a concrete
    enum class.

    Args:
        node: The class definition AST node.
        module_globals: Global namespace dictionary containing resolved bases.

    Returns:
        A dictionary mapping member names to concrete resolved enum values.

    Limitations:
        Only resolves direct subclass definitions with literal-only integer values.
        Dynamic, string-based, or computed enum keys are not supported.

    """
    if len(node.bases) != 1 or node.keywords or node.decorator_list:
        return {}
    base_type = _stdlib_enum_base(node.bases[0], module_globals)
    if base_type is None:
        return {}
    literal_members: dict[str, int] = {}
    for statement in node.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
            or statement.targets[0].id.startswith("_")
        ):
            return {}
        try:
            value = ast.literal_eval(statement.value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return {}
        if type(value) is not int:
            return {}
        literal_members[statement.targets[0].id] = value
    if not literal_members:
        return {}
    concrete_type = (
        enum.IntEnum(node.name, literal_members)
        if base_type is enum.IntEnum
        else enum.Enum(node.name, literal_members)
    )
    return {name: cast("enum.Enum", getattr(concrete_type, name)) for name in literal_members}


def annotation_only_named_tuple_fields(
    node: ast.ClassDef,
    module_globals: dict[str, object],
) -> tuple[str, ...] | None:
    """Return fields for the bounded annotation-only ``NamedTuple`` class form.

    Inspects class annotations to extract fields for classes inheriting from ``NamedTuple``.

    Args:
        node: The class definition AST node.
        module_globals: Global namespace dictionary containing resolved bases.

    Returns:
        A tuple of string field names, or ``None`` if base checks or constraints fail.

    Limitations:
        Only supports NamedTuples defined via class syntax where all fields are
        annotation-only (no default value assignments).

    """
    if (
        len(node.bases) != 1
        or node.keywords
        or node.decorator_list
        or not _is_stdlib_named_tuple_base(node.bases[0], module_globals)
    ):
        return None
    fields: list[str] = []
    for statement in node.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if (
            not isinstance(statement, ast.AnnAssign)
            or not isinstance(statement.target, ast.Name)
            or statement.value is not None
            or statement.target.id.startswith("_")
        ):
            return None
        fields.append(statement.target.id)
    return tuple(fields) if fields else None


def bounded_dataclass_spec(
    node: ast.ClassDef,
    module_globals: dict[str, object],
) -> DataclassSpec | None:
    """Return metadata for direct dataclasses with bounded generated initialization.

    Statically extracts field specifications and freezing behavior for class definitions decorated
    with ``@dataclass``.

    Args:
        node: The class definition AST node.
        module_globals: Global namespace dictionary containing resolved decorators.

    Returns:
        A tuple containing field specifications and frozen status, or ``None`` if not a dataclass.

    Limitations:
        Does not support inheritance, custom init methods, or default factory methods other than
        simple collections (e.g. ``list``).

    """
    frozen = _dataclass_frozen_option(node, module_globals)
    if frozen is None or node.bases or node.keywords:
        return None
    fields: list[DataclassFieldSpec] = []
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass)):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if not isinstance(statement, ast.AnnAssign) or not isinstance(statement.target, ast.Name):
            return None
        field_spec = _dataclass_field_spec(statement, module_globals)
        if field_spec is None:
            return None
        fields.append(field_spec)
    return (tuple(fields), frozen) if fields else None


def literal_named_tuple_factory(
    statement: ast.stmt,
    module_globals: dict[str, object],
) -> tuple[str, type[object]] | None:
    """Construct a concrete type for a literal top-level ``namedtuple`` declaration.

    Detects namedtuple factory calls at assignment statement nodes and dynamically creates
    the standard collection class statically.

    Args:
        statement: Sibling AST assignment statement.
        module_globals: Global namespace dictionary.

    Returns:
        A tuple ``(assigned_name, created_type)``, or ``None`` if it does not match namedtuple.

    Limitations:
        Only matches direct top-level assignments of ``collections.namedtuple(...)`` or
        ``namedtuple(...)`` containing primitive constant parameters.

    """
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or not isinstance(statement.value, ast.Call)
        or statement.value.keywords
        or len(statement.value.args) != 2
    ):
        return None
    func = statement.value.func
    is_factory = (
        isinstance(func, ast.Name) and module_globals.get(func.id) is collections.namedtuple
    )
    is_factory = is_factory or (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and module_globals.get(func.value.id) is collections
        and func.attr == "namedtuple"
    )
    if not is_factory:
        return None
    try:
        typename = ast.literal_eval(statement.value.args[0])
        raw_fields = ast.literal_eval(statement.value.args[1])
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    if not isinstance(typename, str) or not isinstance(raw_fields, (list, tuple)):
        return None
    fields = cast("list[object] | tuple[object, ...]", raw_fields)
    if not fields or not all(isinstance(field, str) for field in fields):
        return None
    names = tuple(cast("str", field) for field in fields)
    try:
        namedtuple_factory = cast(
            "typing.Callable[[str, tuple[str, ...]], type[object]]",
            collections.namedtuple,
        )
        created = namedtuple_factory(typename, names)
    except (TypeError, ValueError):
        return None
    return statement.targets[0].id, created


def _dataclass_frozen_option(node: ast.ClassDef, module_globals: dict[str, object]) -> bool | None:
    if len(node.decorator_list) != 1:
        return None
    decorator = node.decorator_list[0]
    if _is_stdlib_dataclass_decorator(decorator, module_globals):
        return False
    if not isinstance(decorator, ast.Call) or not _is_stdlib_dataclass_decorator(
        decorator.func,
        module_globals,
    ):
        return None
    if decorator.args or any(keyword.arg != "frozen" for keyword in decorator.keywords):
        return None
    if not decorator.keywords:
        return False
    value = decorator.keywords[0].value
    return (
        value.value if isinstance(value, ast.Constant) and isinstance(value.value, bool) else None
    )


def _dataclass_field_spec(
    statement: ast.AnnAssign,
    module_globals: dict[str, object],
) -> DataclassFieldSpec | None:
    if not isinstance(statement.target, ast.Name):
        return None
    name = statement.target.id
    type_hint = (
        statement.annotation.id.lower() if isinstance(statement.annotation, ast.Name) else None
    )
    if statement.value is None:
        return name, type_hint, False, None, None
    if isinstance(statement.value, ast.Call):
        default_factory = _dataclass_default_factory(statement.value, module_globals)
        if default_factory is None:
            return None
        return name, type_hint, False, None, default_factory
    try:
        return name, type_hint, True, ast.literal_eval(statement.value), None
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _dataclass_default_factory(call: ast.Call, module_globals: dict[str, object]) -> str | None:
    if call.args or len(call.keywords) != 1 or call.keywords[0].arg != "default_factory":
        return None
    if not _is_stdlib_field_function(call.func, module_globals):
        return None
    factory = call.keywords[0].value
    if isinstance(factory, ast.Name) and module_globals.get(factory.id) is list:
        return "list"
    return None


def _is_stdlib_dataclass_decorator(value: ast.expr, module_globals: dict[str, object]) -> bool:
    if isinstance(value, ast.Name):
        return module_globals.get(value.id) is dataclasses.dataclass
    return (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and module_globals.get(value.value.id) is dataclasses
        and value.attr == "dataclass"
    )


def _is_stdlib_field_function(value: ast.expr, module_globals: dict[str, object]) -> bool:
    if isinstance(value, ast.Name):
        return module_globals.get(value.id) is dataclasses.field
    return (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and module_globals.get(value.value.id) is dataclasses
        and value.attr == "field"
    )


def _stdlib_enum_base(base: ast.expr, module_globals: dict[str, object]) -> type[enum.Enum] | None:
    """Resolve a direct standard-library ``Enum`` or ``IntEnum`` base."""
    if isinstance(base, ast.Name):
        value = module_globals.get(base.id)
    elif isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
        module = module_globals.get(base.value.id)
        value = getattr(module, base.attr, None) if module is enum else None
    else:
        value = None
    if value is enum.Enum or value is enum.IntEnum:
        return cast("type[enum.Enum]", value)
    return None


def _is_stdlib_named_tuple_base(base: ast.expr, module_globals: dict[str, object]) -> bool:
    """Return whether a class base resolves directly to ``typing.NamedTuple``."""
    if isinstance(base, ast.Name):
        return module_globals.get(base.id) is typing.NamedTuple
    if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
        return module_globals.get(base.value.id) is typing and base.attr == "NamedTuple"
    return False
