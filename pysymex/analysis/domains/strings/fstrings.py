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

"""Analyse f-string expressions from source for embedded errors."""

from __future__ import annotations

import ast

from pysymex.analysis.domains.strings.types import StringWarning


class FStringAnalyzer:
    """
    Analyzes f-string usage.
    Note: f-strings are compiled differently, so we analyze at AST level.
    """

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze f-strings in source."""
        warnings: list[StringWarning] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return warnings

        class FStringVisitor(ast.NodeVisitor):
            """AST visitor for analyzing f-string components."""

            def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
                """Visit joinedstr."""
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        if value.format_spec and isinstance(value.format_spec, ast.JoinedStr):
                            self.generic_visit(value.format_spec)
                self.generic_visit(node)

        visitor = FStringVisitor()
        visitor.visit(tree)
        return warnings
