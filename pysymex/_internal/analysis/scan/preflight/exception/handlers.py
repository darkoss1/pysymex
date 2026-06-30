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

"""Source-level exception-handler helpers for AST preflight diagnostics."""

from __future__ import annotations

import ast

_CATCH_ALL_NAMES = frozenset(("BaseException", "Exception"))


def try_suppresses_exception(statement: ast.Try, exception_name: str) -> bool:
    """Return whether *statement* has a local handler that consumes *exception_name*."""
    return any(
        _handler_catches(handler, exception_name) and not _handler_has_bare_reraise(handler)
        for handler in statement.handlers
    )


def _handler_catches(handler: ast.ExceptHandler, exception_name: str) -> bool:
    if handler.type is None:
        return True
    return _exception_expr_catches(handler.type, exception_name)


def _exception_expr_catches(expression: ast.expr, exception_name: str) -> bool:
    if isinstance(expression, ast.Name):
        return expression.id in {exception_name, *_CATCH_ALL_NAMES}
    if isinstance(expression, ast.Attribute):
        return expression.attr in {exception_name, *_CATCH_ALL_NAMES}
    if isinstance(expression, ast.Tuple):
        return any(_exception_expr_catches(item, exception_name) for item in expression.elts)
    return False


def _handler_has_bare_reraise(handler: ast.ExceptHandler) -> bool:
    visitor = _BareReraiseVisitor()
    for statement in handler.body:
        visitor.visit(statement)
        if visitor.found:
            return True
    return False


class _BareReraiseVisitor(ast.NodeVisitor):
    """Find direct bare re-raises while ignoring nested definitions."""

    def __init__(self) -> None:
        self.found = False

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc is None:
            self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None
