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

"""Module global namespace setup for compile-only symbolic scans.

Scopes package import paths and builds globals with statically bound functions
and class definitions without executing target module code.
"""

from __future__ import annotations

import ast
import contextlib
import sys
import threading
import types
from collections.abc import Generator
from pathlib import Path

from pysymex.analysis.scan.loading.discovery import (
    bind_top_level_class_definitions,
    collect_top_level_function_names,
    find_package_root,
)
from pysymex.analysis.scan.loading.environment import get_default_module_globals
from pysymex.analysis.scan.loading.stdlib.imports import populate_concrete_stdlib_imports

_PACKAGE_IMPORT_PATH_LOCK = threading.RLock()


def _literal_top_level_defaults(
    content: str,
) -> dict[str, tuple[tuple[object, ...] | None, dict[str, object] | None]]:
    """Return defaults safe to bind without executing target module expressions."""
    defaults_by_name: dict[str, tuple[tuple[object, ...] | None, dict[str, object] | None]] = {}
    for node in ast.parse(content).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positional: tuple[object, ...] | None
        try:
            positional = tuple(ast.literal_eval(default) for default in node.args.defaults)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            positional = None
        keyword: dict[str, object] | None = {}
        for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            if default is None:
                continue
            try:
                keyword[argument.arg] = ast.literal_eval(default)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                keyword = None
                break
        defaults_by_name[node.name] = (positional, keyword)
    return defaults_by_name


def _literal_top_level_bindings(content: str) -> dict[str, object]:
    """Return top-level literal name bindings safe to model without executing code."""
    bindings: dict[str, object] = {}
    for node in ast.parse(content).body:
        targets: list[ast.expr]
        value_node: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value_node = node.value
        else:
            continue
        if value_node is None:
            continue
        try:
            value = ast.literal_eval(value_node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = value
    return bindings


@contextlib.contextmanager
def scoped_package_import_path(file_path: Path) -> Generator[None, None, None]:
    """Expose a target package root only for the lifetime of one file scan.

    Finds the package root directory for the given file and inserts it at the
    head of ``sys.path`` to allow resolution of sibling and relative imports.
    Ensures safe concurrent modifications using a re-entrant lock.

    Args:
        file_path: Path to the target source file being scanned.

    Side Effects:
        Temporarily modifies ``sys.path`` during the context block.
    """
    package_root = find_package_root(file_path)
    if package_root is None:
        yield
        return

    root_text = str(package_root)
    with _PACKAGE_IMPORT_PATH_LOCK:
        inserted = root_text not in sys.path
        if inserted:
            sys.path.insert(0, root_text)
        try:
            yield
        finally:
            if inserted and root_text in sys.path:
                sys.path.remove(root_text)


def build_module_globals(
    *,
    content: str,
    file_path: Path,
    full_module_name: str,
    package_name: str,
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
) -> dict[str, object]:
    """Build globals used when scanning a source module and its functions.

    Initializes module-level constants (``__file__``, ``__name__``, ``__package__``),
    constructs bound ``FunctionType`` and
    ``ClassDef`` mocks statically so the symbolic execution VM can reference them.

    Args:
        content: The raw source code string of the module.
        file_path: The file path to the module.
        full_module_name: Fully qualified name of the module.
        package_name: Enclosing package name.
        all_code_with_context: List of code objects with enclosing class and path.

    Returns:
        A dictionary containing the populated global namespace for scanning.

    Side Effects:
        Binds static class/function definitions in-place.
    """
    module_globals = get_default_module_globals()
    populate_concrete_stdlib_imports(content, module_globals)
    module_globals["__file__"] = str(file_path)
    module_globals["__name__"] = full_module_name
    module_globals["__package__"] = package_name
    module_globals.update(_literal_top_level_bindings(content))
    top_level_function_names = collect_top_level_function_names(content, file_path)
    literal_defaults = _literal_top_level_defaults(content)
    for code, _class_name, full_path in all_code_with_context:
        if (
            full_path is None
            or "." in full_path
            or code.co_name not in top_level_function_names
            or code.co_freevars
        ):
            continue
        defaults, kwdefaults = literal_defaults.get(code.co_name, (None, None))
        bound_function = types.FunctionType(
            code,
            module_globals,
            code.co_name,
            defaults if defaults else None,
        )
        if kwdefaults:
            bound_function.__kwdefaults__ = kwdefaults
        module_globals.setdefault(
            code.co_name,
            bound_function,
        )
    bind_top_level_class_definitions(content, all_code_with_context, module_globals)

    return module_globals
