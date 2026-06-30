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

"""Derive bounded concrete string calls from source equality guards.

This module owns candidate construction only. The sibling witness interpreter
must execute each candidate before any issue is reportable.
"""

from __future__ import annotations

import ast
import itertools
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def equality_derived_string_calls(
    tree: ast.Module,
    can_resolve: Callable[[ast.Call], bool],
) -> list[tuple[ast.Call, dict[str, object]]]:
    """Return bounded calls whose string arguments are fully pinned by guards."""
    invocations: list[tuple[ast.Call, dict[str, object]]] = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        if function.args.posonlyargs or function.args.kwonlyargs or function.args.vararg:
            continue
        candidate_sets = [
            _inferred_string_candidates(function, argument.arg) for argument in function.args.args
        ]
        if not candidate_sets or any(not candidates for candidates in candidate_sets):
            continue
        for values in itertools.product(*candidate_sets):
            call = ast.copy_location(
                ast.Call(
                    func=ast.Name(id=function.name, ctx=ast.Load()),
                    args=[ast.Constant(value=value) for value in values],
                    keywords=[],
                ),
                function,
            )
            if can_resolve(call):
                assignments: dict[str, object] = {
                    argument.arg: value
                    for argument, value in zip(function.args.args, values, strict=True)
                }
                invocations.append((call, assignments))
    return invocations


def _inferred_string_candidates(function: ast.FunctionDef, argument_name: str) -> tuple[str, ...]:
    exact_values: set[str] = set()
    lengths: set[int] = set()
    indexed_values: dict[int, set[str]] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        if not isinstance(node.ops[0], ast.Eq):
            continue
        left, right = node.left, node.comparators[0]
        exact = _name_string_equality(left, right, argument_name)
        if exact is None:
            exact = _name_string_equality(right, left, argument_name)
        if exact is not None:
            exact_values.add(exact)
            continue
        length = _string_length_equality(left, right, argument_name)
        if length is None:
            length = _string_length_equality(right, left, argument_name)
        if length is not None and length >= 0:
            lengths.add(length)
            continue
        indexed = _string_index_equality(left, right, argument_name)
        if indexed is None:
            indexed = _string_index_equality(right, left, argument_name)
        if indexed is not None:
            index, character = indexed
            indexed_values.setdefault(index, set()).add(character)

    candidates = set(exact_values)
    for length in lengths:
        if all(
            index in indexed_values and len(indexed_values[index]) == 1 for index in range(length)
        ):
            candidates.add("".join(next(iter(indexed_values[index])) for index in range(length)))
    return tuple(sorted(candidates))


def _name_string_equality(left: ast.AST, right: ast.AST, name: str) -> str | None:
    if isinstance(left, ast.Name) and left.id == name:
        if isinstance(right, ast.Constant) and isinstance(right.value, str):
            return right.value
    return None


def _string_length_equality(left: ast.AST, right: ast.AST, name: str) -> int | None:
    if not isinstance(left, ast.Call) or not isinstance(left.func, ast.Name):
        return None
    if left.func.id != "len" or len(left.args) != 1 or left.keywords:
        return None
    argument = left.args[0]
    if not isinstance(argument, ast.Name) or argument.id != name:
        return None
    if isinstance(right, ast.Constant) and isinstance(right.value, int):
        return right.value
    return None


def _string_index_equality(
    left: ast.AST,
    right: ast.AST,
    name: str,
) -> tuple[int, str] | None:
    if not isinstance(left, ast.Subscript) or not isinstance(left.value, ast.Name):
        return None
    if left.value.id != name or not isinstance(left.slice, ast.Constant):
        return None
    index = left.slice.value
    if not isinstance(index, int) or index < 0:
        return None
    if not isinstance(right, ast.Constant) or not isinstance(right.value, str):
        return None
    if len(right.value) != 1:
        return None
    return index, right.value
