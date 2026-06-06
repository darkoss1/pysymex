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

"""Detect source-level string security issues (SQL injection, shell injection patterns)."""

from __future__ import annotations

import ast

from pysymex.analysis.domains.strings.types import StringWarning, StringWarningKind

SQL_KEYWORDS = (
    "select ",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "alter ",
    "create ",
    "replace ",
)


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(value) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return f"{_literal_text(node.left)} {_literal_text(node.right)}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _literal_text(node.func.value)
    return ""


def _has_dynamic_part(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _has_dynamic_part(node.left) or _has_dynamic_part(node.right)
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Subscript):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return bool(node.args) or bool(node.keywords)
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _has_sql_keyword(node: ast.AST) -> bool:
    text = _literal_text(node).lower()
    return any(keyword in text for keyword in SQL_KEYWORDS)


def _has_traversal_literal(node: ast.AST) -> bool:
    return ".." in _literal_text(node)


class SQLInjectionAnalyzer:
    """
    Detects potential SQL injection in string operations.
    """

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for SQL injection patterns."""
        warnings: list[StringWarning] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return warnings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node.func) not in {"execute", "executemany"}:
                continue
            if not node.args:
                continue
            query = node.args[0]
            if _has_sql_keyword(query) and _has_dynamic_part(query):
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.SQL_INJECTION,
                        file=file_path,
                        line=node.lineno,
                        message="Dynamic SQL string passed to database execution sink",
                        severity="error",
                    )
                )
        return warnings


class PathTraversalAnalyzer:
    """
    Detects potential path traversal vulnerabilities.
    """

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for path traversal patterns."""
        warnings: list[StringWarning] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return warnings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = _call_name(node.func)
            if call_name not in {"open", "join", "joinpath"}:
                continue
            args = list(node.args)
            if not args:
                continue
            if any(_has_traversal_literal(arg) for arg in args) and any(
                _has_dynamic_part(arg) for arg in args
            ):
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.PATH_TRAVERSAL,
                        file=file_path,
                        line=node.lineno,
                        message="Dynamic path construction includes parent-directory traversal",
                        severity="error",
                    )
                )
        return warnings
