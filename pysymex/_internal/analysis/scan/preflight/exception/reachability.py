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

"""Reachability helpers for source preflight diagnostics."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.exception.handlers import try_suppresses_exception

if TYPE_CHECKING:
    from collections.abc import Callable

_TERMINAL_BUILTIN_EXCEPTIONS = frozenset(("ValueError", "TypeError"))


def statement_may_complete_normally(statement: ast.stmt) -> bool:
    """Return whether *statement* can fall through to the next statement.

    This is a narrow CPython reachability approximation for source preflight
    diagnostics. It only treats explicit terminal statements and whitelisted
    literal builtin calls as non-fallthrough; unsupported expressions remain
    conservatively reachable.
    """
    if isinstance(statement, (ast.Return, ast.Raise)):
        return False
    if isinstance(statement, ast.Assign):
        return _expression_may_complete_normally(statement.value)
    if isinstance(statement, ast.AnnAssign):
        return statement.value is None or _expression_may_complete_normally(statement.value)
    if isinstance(statement, ast.Expr):
        return _expression_may_complete_normally(statement.value)
    if isinstance(statement, ast.If):
        return _block_may_complete_normally(statement.body) or _block_may_complete_normally(
            statement.orelse,
        )
    if isinstance(statement, ast.Try):
        return _try_may_complete_normally(statement)
    return True


def _block_may_complete_normally(statements: list[ast.stmt]) -> bool:
    return all(statement_may_complete_normally(statement) for statement in statements)


def _try_may_complete_normally(statement: ast.Try) -> bool:
    finalbody_may_complete = _block_may_complete_normally(statement.finalbody)
    if not finalbody_may_complete:
        return False

    terminal_exception = _block_terminal_modeled_exception(statement.body)
    if terminal_exception is None:
        return _block_may_complete_normally(statement.body) and _block_may_complete_normally(
            statement.orelse,
        )
    if not try_suppresses_exception(statement, terminal_exception):
        return False

    return any(
        _handler_catches(handler, terminal_exception) and _block_may_complete_normally(handler.body)
        for handler in statement.handlers
    )


def _block_terminal_modeled_exception(statements: list[ast.stmt]) -> str | None:
    for statement in statements:
        exception_name = _statement_terminal_modeled_exception(statement)
        if exception_name is not None:
            return exception_name
        if not statement_may_complete_normally(statement):
            return None
    return None


def _statement_terminal_modeled_exception(statement: ast.stmt) -> str | None:
    if isinstance(statement, ast.Assign):
        return _expression_terminal_modeled_exception(statement.value)
    if isinstance(statement, ast.AnnAssign) and statement.value is not None:
        return _expression_terminal_modeled_exception(statement.value)
    if isinstance(statement, ast.Expr):
        return _expression_terminal_modeled_exception(statement.value)
    if isinstance(statement, ast.If):
        body_exception = _block_terminal_modeled_exception(statement.body)
        else_exception = _block_terminal_modeled_exception(statement.orelse)
        return body_exception if body_exception == else_exception else None
    return None


def _expression_may_complete_normally(expression: ast.expr) -> bool:
    return _expression_terminal_modeled_exception(expression) is None


def _expression_terminal_modeled_exception(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Call):
        call_exception = _literal_builtin_call_exception(expression)
        if call_exception in _TERMINAL_BUILTIN_EXCEPTIONS:
            return call_exception
    for child in ast.iter_child_nodes(expression):
        if isinstance(child, ast.expr):
            child_exception = _expression_terminal_modeled_exception(child)
            if child_exception is not None:
                return child_exception
    return None


def _literal_builtin_call_exception(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        if call.func.id in {"int", "builtin_int"}:
            return _safe_literal_call_exception(int, call)
        if call.func.id == "float":
            return _safe_literal_call_exception(float, call)
        if call.func.id in {"min", "max"} and _is_empty_single_iterable_call(call):
            return "ValueError"
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "fromhex"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in {"bytes", "bytearray"}
    ):
        target = bytes.fromhex if call.func.value.id == "bytes" else bytearray.fromhex
        return _safe_literal_call_exception(target, call)
    return None


def _safe_literal_call_exception(func: Callable[..., object], call: ast.Call) -> str | None:
    args: list[object] = []
    kwargs: dict[str, object] = {}
    for arg in call.args:
        literal = _literal_value(arg)
        if literal is _UNSUPPORTED_LITERAL:
            return None
        args.append(literal)
    for keyword in call.keywords:
        if keyword.arg is None:
            return None
        literal = _literal_value(keyword.value)
        if literal is _UNSUPPORTED_LITERAL:
            return None
        kwargs[keyword.arg] = literal
    try:
        func(*args, **kwargs)
    except Exception as exc:
        return type(exc).__name__
    return None


def _is_empty_single_iterable_call(call: ast.Call) -> bool:
    if len(call.args) != 1 or any(keyword.arg == "default" for keyword in call.keywords):
        return False
    arg = call.args[0]
    return isinstance(arg, (ast.List, ast.Tuple, ast.Set)) and not arg.elts


_UNSUPPORTED_LITERAL = object()


def _literal_value(node: ast.expr) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        values = [_literal_value(item) for item in node.elts]
        return (
            _UNSUPPORTED_LITERAL
            if any(value is _UNSUPPORTED_LITERAL for value in values)
            else tuple(values)
        )
    if isinstance(node, ast.List):
        values = [_literal_value(item) for item in node.elts]
        return (
            _UNSUPPORTED_LITERAL
            if any(value is _UNSUPPORTED_LITERAL for value in values)
            else list(values)
        )
    return _UNSUPPORTED_LITERAL


def _handler_catches(handler: ast.ExceptHandler, exception_name: str) -> bool:
    if handler.type is None:
        return True
    return _exception_expr_catches(handler.type, exception_name)


def _exception_expr_catches(expression: ast.expr, exception_name: str) -> bool:
    if isinstance(expression, ast.Name):
        return expression.id in {exception_name, "Exception", "BaseException"}
    if isinstance(expression, ast.Attribute):
        return expression.attr in {exception_name, "Exception", "BaseException"}
    if isinstance(expression, ast.Tuple):
        return any(_exception_expr_catches(item, exception_name) for item in expression.elts)
    return False
