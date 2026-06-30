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

"""Literal top-level bindings for compile-only scan globals."""

from __future__ import annotations

import ast
import copy
import types


def _defaults(
    content: str,
    bindings: dict[str, object],
) -> dict[str, tuple[tuple[object, ...] | None, dict[str, object] | None]]:
    """Return defaults safe to bind without executing target module expressions."""
    defaults_by_name: dict[str, tuple[tuple[object, ...] | None, dict[str, object] | None]] = {}
    for node in ast.parse(content).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positional: tuple[object, ...] | None
        try:
            positional = tuple(
                _safe_default_value(default, bindings) for default in node.args.defaults
            )
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            positional = None
        keyword: dict[str, object] | None = {}
        for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            if default is None:
                continue
            try:
                keyword[argument.arg] = _safe_default_value(default, bindings)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                keyword = None
                break
        defaults_by_name[node.name] = (positional, keyword)
    return defaults_by_name


def _bindings(content: str) -> dict[str, object]:
    """Return top-level literal name bindings safe to model without executing code."""
    tree = ast.parse(content)
    safe_class_attrs = _safe_top_level_class_attrs(tree)
    bindings: dict[str, object] = {}
    for node in tree.body:
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
            value = _safe_top_level_binding_value(value_node, bindings, safe_class_attrs)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = value
    return bindings


def _safe_default_value(node: ast.expr, bindings: dict[str, object]) -> object:
    """Return a compile-time-safe default expression value."""
    if isinstance(node, ast.Name) and node.id in bindings:
        return bindings[node.id]
    return ast.literal_eval(node)


def _safe_top_level_binding_value(
    node: ast.expr,
    bindings: dict[str, object],
    safe_class_attrs: dict[str, dict[str, object]],
) -> object:
    """Return a non-executing top-level binding value for scan globals."""
    if isinstance(node, ast.Name) and node.id in bindings:
        return bindings[node.id]
    if _is_safe_zero_arg_constructor(node, safe_class_attrs):
        assert isinstance(node, ast.Call)
        assert isinstance(node.func, ast.Name)
        attrs = {
            name: copy.deepcopy(value) for name, value in safe_class_attrs[node.func.id].items()
        }
        return types.SimpleNamespace(**attrs)
    return ast.literal_eval(node)


def _safe_top_level_class_attrs(tree: ast.Module) -> dict[str, dict[str, object]]:
    """Return literal instance attributes for safe zero-argument top-level classes."""
    attrs_by_class: dict[str, dict[str, object]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        attrs = _safe_class_instance_attrs(node)
        if attrs is not None:
            attrs_by_class[node.name] = attrs
    return attrs_by_class


def _safe_class_instance_attrs(node: ast.ClassDef) -> dict[str, object] | None:
    if node.bases or node.keywords or node.decorator_list:
        return None
    attrs: dict[str, object] = {}
    init_seen = False
    for statement in node.body:
        if _is_docstring_or_pass(statement):
            continue
        if not isinstance(statement, ast.FunctionDef) or statement.name != "__init__":
            return None
        if init_seen:
            return None
        init_seen = True
        init_attrs = _safe_init_attrs(statement)
        if init_attrs is None:
            return None
        attrs.update(init_attrs)
    return attrs


def _safe_init_attrs(node: ast.FunctionDef) -> dict[str, object] | None:
    args = node.args
    if (
        len(args.args) != 1
        or args.args[0].arg != "self"
        or args.posonlyargs
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or node.decorator_list
    ):
        return None
    attrs: dict[str, object] = {}
    for statement in node.body:
        if _is_docstring_or_pass(statement):
            continue
        assignment = _self_attr_literal_assignment(statement)
        if assignment is None:
            return None
        name, value = assignment
        attrs[name] = value
    return attrs


def _self_attr_literal_assignment(statement: ast.stmt) -> tuple[str, object] | None:
    target: ast.expr
    value_node: ast.expr | None
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target = statement.targets[0]
        value_node = statement.value
    elif isinstance(statement, ast.AnnAssign):
        target = statement.target
        value_node = statement.value
    else:
        return None
    if (
        value_node is None
        or not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
        or target.value.id != "self"
        or target.attr.startswith("_")
    ):
        return None
    try:
        return target.attr, ast.literal_eval(value_node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _is_docstring_or_pass(statement: ast.stmt) -> bool:
    return isinstance(statement, ast.Pass) or (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_safe_zero_arg_constructor(
    node: ast.expr,
    safe_class_attrs: dict[str, dict[str, object]],
) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in safe_class_attrs
        and not node.args
        and not node.keywords
    )


class TopLevelLiterals:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    defaults = staticmethod(_defaults)
    bindings = staticmethod(_bindings)
