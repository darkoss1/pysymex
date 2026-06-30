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

"""Source scan-path and top-level symbol discovery for compile-only loading."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _is_test_file(file_path: Path) -> bool:
    """Return True when a path looks like a pytest test module."""
    return file_path.name.startswith("test_") or any(part == "tests" for part in file_path.parts)


def _should_scan_function(name: str, file_path: Path) -> bool:
    """Return whether the scanner should analyze a source-level function body.

    Filters out names prefixed with ``_`` and ``test_*`` functions in test modules.
    """
    if name.startswith("_"):
        return False
    return not (SourceScanPaths.is_test_file(file_path) and name.startswith("test_"))


def _collect(content: str, file_path: Path) -> set[str]:
    """Collect callable code-object paths that can be scanned out of module context."""
    tree = ast.parse(content)
    paths: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if SourceScanPaths.should_scan_function(node.name, file_path):
                paths.add(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if SourceScanPaths.should_scan_function(child.name, file_path):
                        paths.add(f"{node.name}.{child.name}")
    return paths


def _top_level_functions(content: str, file_path: Path) -> set[str]:
    """Collect every top-level function name declared in module AST."""
    _ = file_path
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
    return names


def _top_level_classes(content: str) -> set[str]:
    """Collect top-level class names that can be bound without executing module code."""
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and not (
            node.name.startswith("__") and node.name.endswith("__")
        ):
            names.add(node.name)
    return names


def _plain_top_level_classes(content: str) -> set[str]:
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


class SourceScanPaths:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    is_test_file = staticmethod(_is_test_file)
    should_scan_function = staticmethod(_should_scan_function)
    collect = staticmethod(_collect)
    top_level_functions = staticmethod(_top_level_functions)
    top_level_classes = staticmethod(_top_level_classes)
    plain_top_level_classes = staticmethod(_plain_top_level_classes)
