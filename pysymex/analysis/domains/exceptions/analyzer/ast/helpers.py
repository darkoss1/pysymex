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

"""AST visitor helpers for exception-flow node traversal."""

from __future__ import annotations

import ast

from pysymex.analysis.domains.exceptions.types import KNOWN_CRASHY_APIS, HandlerIntent


def try_body_calls_crashy_api(try_node: ast.Try) -> bool:
    """Check if the try body calls a known-crashy API."""
    for stmt in try_node.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                func = node.func

                if isinstance(func, ast.Name) and func.id in KNOWN_CRASHY_APIS:
                    return True

                if isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id in KNOWN_CRASHY_APIS:
                        return True

            if isinstance(node, ast.Name) and node.id in KNOWN_CRASHY_APIS:
                pass
    return False


def classify_handler_intent(handler: ast.ExceptHandler) -> HandlerIntent:
    """Classify the intent of an exception handler body."""
    has_return = False
    has_raise = False
    has_logging = False
    has_pass = not handler.body

    for stmt in handler.body:
        if isinstance(stmt, ast.Return):
            has_return = True
        if isinstance(stmt, ast.Pass):
            has_pass = True
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                has_raise = True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {
                        "error",
                        "exception",
                        "warning",
                        "critical",
                        "debug",
                        "info",
                    }:
                        has_logging = True
                elif isinstance(node.func, ast.Name):
                    if node.func.id in {"print", "logging"}:
                        has_logging = True

    if has_raise:
        return HandlerIntent.SAFETY_NET
    if has_logging and not has_pass:
        return HandlerIntent.LOGGED
    if has_return or has_logging:
        return HandlerIntent.SAFETY_NET
    return HandlerIntent.SILENCED


__all__ = [
    "classify_handler_intent",
    "try_body_calls_crashy_api",
]
