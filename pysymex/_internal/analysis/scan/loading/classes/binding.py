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

"""Static top-level class binding for compile-only scan loading."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.loading.classes.metadata import attach_static_class_metadata
from pysymex._internal.analysis.scan.loading.classes.values import bind_symbolic_class_values
from pysymex._internal.analysis.scan.loading.source.paths import SourceScanPaths
from pysymex._internal.analysis.scan.loading.stdlib.declarations import literal_named_tuple_factory

if TYPE_CHECKING:
    import types


def _bind_literal_named_tuple_factories(
    tree: ast.Module,
    module_globals: dict[str, object],
) -> None:
    """Bind supported literal ``NamedTuple`` factory assignments."""
    for statement in tree.body:
        factory_binding = literal_named_tuple_factory(statement, module_globals)
        if factory_binding is not None:
            assigned_name, generated_type = factory_binding
            module_globals.setdefault(assigned_name, generated_type)


def _bind_definitions(
    content: str,
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
    module_globals: dict[str, object],
) -> None:
    """Bind source-defined classes as symbolic class values for function scans.

    Analyzes AST definitions to statically resolve class bases, enums, named tuples,
    dataclass specifiers, descriptors, and subclass registry specifications, and binds
    them to the global namespace map.

    Side Effects:
        Mutates ``module_globals`` by setting class mock variables.
    """
    tree = ast.parse(content)
    _bind_literal_named_tuple_factories(tree, module_globals)
    class_names = SourceScanPaths.top_level_classes(content)
    if not class_names:
        return
    plain_class_names = SourceScanPaths.plain_top_level_classes(content)
    class_values = bind_symbolic_class_values(
        class_names,
        plain_class_names,
        all_code_with_context,
        module_globals,
    )

    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in class_values:
            continue
        attach_static_class_metadata(node, tree.body, class_values, module_globals)


class TopLevelClasses:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    bind_definitions = staticmethod(_bind_definitions)
