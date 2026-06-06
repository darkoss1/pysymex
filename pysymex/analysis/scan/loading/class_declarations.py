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

"""Bounded ordinary class declaration recognition for compile-only loading.

Statically identifies class declarations and subclass registry patterns (such as
standard ``__init_subclass__`` hooks) via AST analysis to reconstruct registries
without executing target code.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SubclassRegistrySpec:
    """Static subclass registry created by a canonical ``__init_subclass__`` hook.

    Specifies the attribute, parameter name, and default tag for subclass matching.
    """

    attribute: str
    tag_parameter: str
    default_tag: object


def bounded_subclass_registry_spec(node: ast.ClassDef) -> SubclassRegistrySpec | None:
    """Return a safe static registry description for a canonical append-only hook.

    Analyzes the AST structure of a class definition's body to detect if it
    defines an empty registry list and a matching ``__init_subclass__`` method.

    Args:
        node: The class definition AST node to inspect.

    Returns:
        The detected registry spec, or ``None`` if it does not match the expected structure.

    Limitations:
        Only detects canonical, simple ``__init_subclass__`` implementations that append
        a ``(tag, cls)`` tuple to a class-level list. Complex logic or indirect writes
        are ignored.
    """
    empty_lists = {
        statement.targets[0].id
        for statement in node.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.List)
        and not statement.value.elts
    }
    empty_lists.update(
        statement.target.id
        for statement in node.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and isinstance(statement.value, ast.List)
        and not statement.value.elts
    )
    hook = next(
        (
            statement
            for statement in node.body
            if isinstance(statement, ast.FunctionDef) and statement.name == "__init_subclass__"
        ),
        None,
    )
    if hook is None or len(hook.args.args) != 2 or len(hook.args.defaults) != 1:
        return None
    cls_parameter = hook.args.args[0].arg
    tag_parameter = hook.args.args[1].arg
    try:
        default_tag = ast.literal_eval(hook.args.defaults[0])
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None

    appended_attribute: str | None = None
    for statement in hook.body:
        if _is_forwarding_super_call(statement, hook):
            continue
        attribute = _subclass_append_attribute(
            statement,
            owner=node.name,
            tag_parameter=tag_parameter,
            cls_parameter=cls_parameter,
        )
        if attribute is None or appended_attribute is not None:
            return None
        appended_attribute = attribute
    if appended_attribute not in empty_lists:
        return None
    return SubclassRegistrySpec(appended_attribute, tag_parameter, default_tag)


def bounded_subclass_registry_entries(
    owner: str,
    spec: SubclassRegistrySpec,
    nodes: list[ast.stmt],
    class_values: Mapping[str, object],
) -> list[tuple[object, object]] | None:
    """Return concrete declared registry items for supported direct subclasses.

    Iterates over AST sibling statements to find classes subclassing ``owner``
    and matches their keywords against the ``spec``.

    Args:
        owner: The name of the registry owner class.
        spec: The subclass registry spec containing expected tags/parameters.
        nodes: Sibling AST statements to scan for subclasses.
        class_values: Concrete evaluated class values, keyed by class name.

    Returns:
        A list of resolved ``(tag, class_value)`` pairs, or ``None`` if unsupported subclass
        constructs (e.g. subclass decorators or multiple inheritance) are encountered.
    """
    entries: list[tuple[object, object]] = []
    for node in nodes:
        if not isinstance(node, ast.ClassDef) or node.name == owner:
            continue
        directly_mentions_owner = any(
            isinstance(base, ast.Name) and base.id == owner for base in node.bases
        )
        if not directly_mentions_owner:
            continue
        if not (
            len(node.bases) == 1
            and isinstance(node.bases[0], ast.Name)
            and node.bases[0].id == owner
            and not node.decorator_list
        ):
            return None
        tag = spec.default_tag
        for keyword in node.keywords:
            if keyword.arg != spec.tag_parameter:
                return None
            try:
                tag = ast.literal_eval(keyword.value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                return None
        class_value = class_values.get(node.name)
        if class_value is None:
            return None
        entries.append((tag, class_value))
    return entries


def _is_forwarding_super_call(statement: ast.stmt, hook: ast.FunctionDef) -> bool:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "__init_subclass__"
        and isinstance(func.value, ast.Call)
        and isinstance(func.value.func, ast.Name)
        and func.value.func.id == "super"
        and not func.value.args
        and not func.value.keywords
        and not call.args
        and len(call.keywords) == 1
        and call.keywords[0].arg is None
        and isinstance(call.keywords[0].value, ast.Name)
        and hook.args.kwarg is not None
        and call.keywords[0].value.id == hook.args.kwarg.arg
    )


def _subclass_append_attribute(
    statement: ast.stmt,
    *,
    owner: str,
    tag_parameter: str,
    cls_parameter: str,
) -> str | None:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    func = call.func
    if (
        not isinstance(func, ast.Attribute)
        or func.attr != "append"
        or not isinstance(func.value, ast.Attribute)
        or not isinstance(func.value.value, ast.Name)
        or func.value.value.id != owner
        or call.keywords
        or len(call.args) != 1
    ):
        return None
    item = call.args[0]
    if (
        not isinstance(item, ast.Tuple)
        or len(item.elts) != 2
        or not isinstance(item.elts[0], ast.Name)
        or item.elts[0].id != tag_parameter
        or not isinstance(item.elts[1], ast.Name)
        or item.elts[1].id != cls_parameter
    ):
        return None
    return func.value.attr
