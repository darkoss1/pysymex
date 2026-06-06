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

"""Source and code-object discovery for compile-only scan loading.

Parses target source to discover nested bytecode, package context, and static
class/dataclass/enum bindings used before symbolic execution.
"""

from __future__ import annotations

import ast
import functools
import types
from pathlib import Path

from pysymex.analysis.scan.loading.class_declarations import (
    bounded_subclass_registry_entries,
    bounded_subclass_registry_spec,
)
from pysymex.analysis.scan.loading.stdlib.declarations import (
    annotation_only_named_tuple_fields,
    bounded_dataclass_spec,
    literal_enum_members,
    literal_named_tuple_factory,
)
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO


def is_test_file(file_path: Path) -> bool:
    """Return True when a path looks like a pytest test module."""
    return file_path.name.startswith("test_") or any(part == "tests" for part in file_path.parts)


def should_scan_source_function(name: str, file_path: Path) -> bool:
    """Return whether the scanner should analyze a source-level function body.

    Filters out names prefixed with ``_`` and ``test_*`` functions in test modules.

    Args:
        name: Name of the function.
        file_path: File path of the module containing the function.

    Returns:
        ``True`` if the function should be scanned, ``False`` otherwise.
    """
    if name.startswith("_"):
        return False
    if is_test_file(file_path) and name.startswith("test_"):
        return False
    return True


def collect_source_scan_paths(content: str, file_path: Path) -> set[str]:
    """Collect callable code-object paths that can be scanned out of module context.

    Parses the AST structure of the module and yields dotted path identifiers
    for all functions and methods matching scanning eligibility criteria.

    Args:
        content: The raw source code of the module.
        file_path: The file path of the module.

    Returns:
        A set of eligible callable dotted path strings.
    """
    tree = ast.parse(content)
    paths: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if should_scan_source_function(node.name, file_path):
                paths.add(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if should_scan_source_function(child.name, file_path):
                        paths.add(f"{node.name}.{child.name}")
    return paths


def collect_top_level_function_names(content: str, file_path: Path) -> set[str]:
    """Collect every top-level function name declared in module AST.

    Unlike :func:`collect_source_scan_paths`, does not apply
    :func:`should_scan_source_function` eligibility filtering. Callers decide which
    names to bind as concrete :class:`types.FunctionType` objects.

    Args:
        content: The raw source code of the module.
        file_path: Unused; kept for symmetry with other discovery helpers.

    Returns:
        All top-level ``def`` / ``async def`` names, including private names.
    """
    _ = file_path
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
    return names


def collect_top_level_class_names(content: str) -> set[str]:
    """Collect top-level class names that can be bound without executing module code.

    Args:
        content: The raw source code of the module.

    Returns:
        A set of non-dunder top-level class names.
    """
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and not (
            node.name.startswith("__") and node.name.endswith("__")
        ):
            names.add(node.name)
    return names


def _collect_plain_top_level_class_names(content: str) -> set[str]:
    """Collect classes whose construction is not altered by bases or decorators."""
    tree = ast.parse(content)
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and not node.bases
        and not node.keywords
        and not node.decorator_list
    }


def _literal_descriptor_constructor_args(call: ast.Call) -> tuple[object, ...] | None:
    """Retain primitive positional constructor literals for bounded descriptors."""
    if call.keywords:
        return None
    values: list[object] = []
    for argument in call.args:
        if not isinstance(argument, ast.Constant) or not isinstance(
            argument.value, (bool, int, float, str, bytes, type(None))
        ):
            return None
        values.append(argument.value)
    return tuple(values)


def bind_top_level_class_definitions(
    content: str,
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
    module_globals: dict[str, object],
) -> None:
    """Bind source-defined classes as symbolic class values for function scans.

    Analyzes AST definitions to statically resolve class bases, enums, named tuples,
    dataclass specifiers, descriptors, and subclass registry specifications, and binds
    them to the global namespace map.

    Args:
        content: Raw source code string of the module.
        all_code_with_context: List of code objects with enclosing class and path.
        module_globals: Global namespace dict to update in-place.

    Side Effects:
        Mutates ``module_globals`` by setting class mock variables.
    """
    from pysymex.core.types.scalars.values import SymbolicValue

    tree = ast.parse(content)
    for statement in tree.body:
        factory_binding = literal_named_tuple_factory(statement, module_globals)
        if factory_binding is not None:
            assigned_name, generated_type = factory_binding
            module_globals.setdefault(assigned_name, generated_type)
    class_names = collect_top_level_class_names(content)
    if not class_names:
        return
    plain_class_names = _collect_plain_top_level_class_names(content)
    class_values: dict[str, SymbolicValue] = {}

    for code, _class_name, full_path in all_code_with_context:
        if code.co_name not in class_names or full_path != code.co_name or code.co_freevars:
            continue
        class_val = SymbolicValue(
            _name=code.co_name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_obj=Z3_TRUE,
            is_none=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type="type",
        )
        class_val.attach_modeled_object(code)
        if module_globals.get("functools") is functools:
            setattr(class_val, "_pysymex_trusted_cached_property", True)
        if code.co_name in plain_class_names:
            setattr(class_val, "_pysymex_plain_class_definition", True)
        module_globals.setdefault(code.co_name, class_val)
        class_values[code.co_name] = class_val

    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in class_values:
            continue
        modeled_bases: list[SymbolicValue] = []
        for base in node.bases:
            if not isinstance(base, ast.Name):
                break
            base_value = module_globals.get(base.id)
            if not isinstance(base_value, SymbolicValue):
                break
            modeled_bases.append(base_value)
        bases_complete = len(modeled_bases) == len(node.bases)
        setattr(class_values[node.name], "_pysymex_bases_complete", bases_complete)
        if bases_complete:
            setattr(class_values[node.name], "_pysymex_base_values", tuple(modeled_bases))
        enum_members = literal_enum_members(node, module_globals)
        if enum_members:
            setattr(class_values[node.name], "_pysymex_literal_enum_members", enum_members)
        named_tuple_fields = annotation_only_named_tuple_fields(node, module_globals)
        if named_tuple_fields is not None:
            setattr(class_values[node.name], "_pysymex_named_tuple_fields", named_tuple_fields)
        dataclass_spec = bounded_dataclass_spec(node, module_globals)
        if dataclass_spec is not None:
            fields, frozen = dataclass_spec
            setattr(class_values[node.name], "_pysymex_dataclass_fields", fields)
            setattr(class_values[node.name], "_pysymex_dataclass_frozen", frozen)
        descriptor_assignments: dict[str, tuple[SymbolicValue, tuple[object, ...] | None]] = {}
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
                descriptor_assignments[statement.targets[0].id] = (
                    assigned_value,
                    _literal_descriptor_constructor_args(statement.value),
                )
        if descriptor_assignments:
            setattr(
                class_values[node.name], "_pysymex_descriptor_assignments", descriptor_assignments
            )
        registry_spec = bounded_subclass_registry_spec(node)
        if registry_spec is not None:
            registry_entries = bounded_subclass_registry_entries(
                node.name, registry_spec, tree.body, class_values
            )
            if registry_entries is not None:
                setattr(
                    class_values[node.name],
                    "_pysymex_static_class_attrs",
                    {registry_spec.attribute: registry_entries},
                )


def detect_package_name(file_path: Path) -> tuple[str, str]:
    """Detect the module name and package name for a given file.

    Walks up the directory tree looking for ``__init__.py`` files to determine the
    dotted module and package names.

    Args:
        file_path: Path to the target source file.

    Returns:
        A tuple of ``(full_module_name, package_name)``.
    """
    parts: list[str] = [file_path.stem]
    current = file_path.parent
    package_parts: list[str] = []

    while current and (current / "__init__.py").exists():
        parts.insert(0, current.name)
        package_parts.insert(0, current.name)
        current = current.parent

    full_name = ".".join(parts)
    package_name = ".".join(package_parts)
    return full_name, package_name


def find_package_root(file_path: Path) -> Path | None:
    """Find the root of the package containing the given file.

    Args:
        file_path: Path to the target source file.

    Returns:
        The package root directory path, or ``None`` if not part of a package.
    """
    current = file_path.resolve().parent
    root = None
    while current and (current / "__init__.py").exists():
        root = current.parent
        current = current.parent
    return root
