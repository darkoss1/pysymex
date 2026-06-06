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

"""Analyse exception chaining (``raise ... from ...``) for flow completeness."""

from __future__ import annotations

import ast

from pysymex.analysis.domains.exceptions.types import ExceptionWarning, ExceptionWarningKind


def _exception_name(node: ast.expr | None) -> str | None:
    """Extract the name of the exception class from an AST expression node.

    Args:
        node (ast.expr | None): The AST expression representing the exception.

    Returns:
        str | None: The exception name string if resolvable, otherwise None.
    """
    if node is None:
        return "BaseException"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _exception_name(node.func)
    return None


def _handler_exception_names(handler: ast.ExceptHandler) -> set[str]:
    """Extract the set of exception type names caught by a try-except handler.

    Args:
        handler (ast.ExceptHandler): The AST exception handler node.

    Returns:
        set[str]: A set of caught exception name strings.
    """
    if handler.type is None:
        return {"BaseException"}
    if isinstance(handler.type, ast.Tuple):
        names = {_exception_name(item) for item in handler.type.elts}
        return {name for name in names if name is not None}
    name = _exception_name(handler.type)
    return {name} if name is not None else set()


class ExceptionChainAnalyzer:
    """Analyzes exception chaining patterns (raise from)."""

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[ExceptionWarning]:
        """Analyze exception chaining in source."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        warnings: list[ExceptionWarning] = []
        for try_node in (node for node in ast.walk(tree) if isinstance(node, ast.Try)):
            for handler in try_node.handlers:
                caught_names = _handler_exception_names(handler)
                for raise_node in (
                    node for node in ast.walk(handler) if isinstance(node, ast.Raise)
                ):
                    if raise_node.exc is None or raise_node.cause is not None:
                        continue
                    raised_name = _exception_name(raise_node.exc)
                    if raised_name is None or raised_name in caught_names:
                        continue
                    warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.RERAISE_DIFFERENT_TYPE,
                            file=file_path,
                            line=raise_node.lineno,
                            message=(
                                f"Raising '{raised_name}' from handler for "
                                f"{', '.join(sorted(caught_names)) or 'unknown exception'} "
                                "without explicit 'from' chaining"
                            ),
                            exception_type=raised_name,
                        )
                    )
        return warnings


__all__ = ["ExceptionChainAnalyzer"]
