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

"""Detect imported names that are never referenced elsewhere in the source file."""

from __future__ import annotations

import ast

from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind
from pysymex.logger import get_logger

logger = get_logger(__name__)


class UnusedImportDetector:
    """Detects imports that are never used from source code."""

    def detect_from_source(self, source: str, file_path: str = "<unknown>") -> list[DeadCode]:
        """Parse *source* with the AST to find imports whose names are never used."""
        dead_code: list[DeadCode] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            logger.debug("Unused-import detector could not parse %s", file_path, exc_info=True)
            return dead_code
        imports: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        imports[alias.asname or alias.name] = node.lineno

        used: set[str] = set()

        class NameCollector(ast.NodeVisitor):
            """Visitor for collecting variable names from an AST node."""

            def visit_Name(self, node: ast.Name) -> None:
                used.add(node.id)
                self.generic_visit(node)

            def visit_Attribute(self, node: ast.Attribute) -> None:
                if isinstance(node.value, ast.Name):
                    used.add(node.value.id)
                self.generic_visit(node)

        NameCollector().visit(tree)
        for name, line in imports.items():
            base_name = name.split(".")[0]
            if base_name not in used and name not in used:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_IMPORT,
                        file=file_path,
                        line=line,
                        name=name,
                        message=f"Import '{name}' is never used",
                        confidence=0.95,
                    )
                )
        return dead_code


__all__ = ["UnusedImportDetector"]
