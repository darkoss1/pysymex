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

"""Safe concrete stdlib import binding for compile-only target loading.

Analyzes target source import statements to import and bind standard-library
modules concretely when they belong to the supported stdlib surface.
"""

from __future__ import annotations

import ast
import importlib
import sys

from pysymex.logger import get_logger

logger = get_logger(__name__)


def stdlib_root(module_name: str) -> str:
    """Return the root package name for an import target."""
    return module_name.partition(".")[0]


def is_safe_stdlib_import(module_name: str) -> bool:
    """Return True for import targets compile-only loading may bind concretely.

    Checks that the root package belongs to the standard library or builtins.

    Args:
        module_name: The dotted module import name to check.

    Returns:
        ``True`` if the module is safe to import concretely, ``False`` otherwise.
    """
    root = stdlib_root(module_name)
    stdlib_names = getattr(sys, "stdlib_module_names", frozenset[str]())
    return root in stdlib_names or root in {"builtins", "__future__"}


def populate_concrete_stdlib_imports(content: str, globals_map: dict[str, object]) -> None:
    """Populate module globals with concrete stdlib imports used by the file.

    Parses AST import statements, resolves safe standard library packages, and
    dynamically binds modules or imported symbols directly into the provided global map.

    Args:
        content: Raw source code string of the module.
        globals_map: Target global namespace dictionary to update.

    Side Effects:
        Mutates ``globals_map`` in-place. May trigger dynamic module imports.
    """
    tree = ast.parse(content)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not is_safe_stdlib_import(alias.name):
                    continue
                try:
                    module = importlib.import_module(alias.name)
                except (ImportError, AttributeError, TypeError, ValueError):
                    logger.debug(
                        "Skipped compile-only stdlib import: %s", alias.name, exc_info=True
                    )
                    continue
                globals_map[alias.asname or alias.name.partition(".")[0]] = module
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or not is_safe_stdlib_import(node.module):
                continue
            try:
                module = importlib.import_module(node.module)
            except (ImportError, AttributeError, TypeError, ValueError):
                logger.debug(
                    "Skipped compile-only stdlib from-import: %s", node.module, exc_info=True
                )
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                try:
                    globals_map[alias.asname or alias.name] = getattr(module, alias.name)
                except AttributeError:
                    logger.debug(
                        "Skipped compile-only stdlib import attribute: %s.%s",
                        node.module,
                        alias.name,
                        exc_info=True,
                    )
                    continue
