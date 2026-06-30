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

"""Symbolic input inference for source scans.

Owns scan-time annotation extraction, runtime annotation normalization, and
conversion from source/code-object hints into symbolic executor input carriers.
The scanner orchestrates these helpers but does not own their semantic policy.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from pysymex._internal.config.values import ConfigValues
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import types

_LIST_VAR_RE = re.compile(r"collection|items|sequence|data|arr|list|inputs?")
_DICT_VAR_RE = re.compile(r"mapping|config|settings|dict|map")
_NULLABLE_VAR_RE = re.compile(r"(^obj$|object|instance|target|receiver|node)")
# Scanner queries stay well below the file/function timeout so a few hard SMT
# unknowns cannot consume the whole scan before sibling paths are explored.
_MAX_SCANNER_SOLVER_TIMEOUT_MS = 100


def merge_runtime_annotations(hints: dict[str, str], func_val: object) -> None:
    """Merge runtime annotation values into scanner type-hint strings."""
    annotations = getattr(func_val, "__annotations__", None)
    if annotations is None and isinstance(func_val, SymbolicValue):
        annotations = getattr(func_val, "annotations", None)
    if not ConfigValues.is_object_dict(annotations):
        return
    for key_obj, value in annotations.items():
        if not isinstance(key_obj, str):
            continue
        key = key_obj
        if isinstance(value, str):
            hints[key] = value
            continue
        if isinstance(value, SymbolicString):
            symbolic_name = value.name.strip()
            if symbolic_name:
                hints[key] = symbolic_name
            continue
        if isinstance(value, type):
            hints[key] = value.__name__
            continue
        hints[key] = str(value)


def scanner_solver_timeout_ms(timeout_seconds: float | None) -> int:
    """Return the per-query SMT timeout used during scanner execution."""
    if timeout_seconds is None:
        return _MAX_SCANNER_SOLVER_TIMEOUT_MS
    return min(_MAX_SCANNER_SOLVER_TIMEOUT_MS, max(1, int(timeout_seconds * 1000)))


class TypeHintExtractor(ast.NodeVisitor):
    """AST visitor that extracts source-level parameter type hints."""

    def __init__(self) -> None:
        self.hints: dict[tuple[str, str | None], dict[str, str]] = {}
        self.current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        arg_hints: dict[str, str] = {}
        for arg in node.args.args:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)
        for arg in node.args.kwonlyargs:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)

        self.hints[(node.name, self.current_class)] = arg_hints
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_type_str(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if node.value is None:
                return "None"
        if isinstance(node, ast.Subscript):
            return ast.unparse(node)
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._get_type_str(node.left)
            right = self._get_type_str(node.right)
            return f"{left} | {right}"
        return "any"


def build_symbolic_vars(
    code: types.CodeType,
    class_name: str | None = None,
    type_hints: dict[str, str] | None = None,
    *,
    include_collection_heuristics: bool,
) -> dict[str, str]:
    """Build symbolic executor input hints from a code object and scan hints."""
    symbolic_vars: dict[str, str] = {}
    hints = type_hints or {}

    for index, name in enumerate(code.co_varnames[: code.co_argcount]):
        if index == 0 and name in {"self", "cls"}:
            if name == "self" and class_name:
                symbolic_vars[name] = _instance_type_hint(class_name, hints)
            else:
                symbolic_vars[name] = "object"
            continue

        hint = hints.get(name)
        if hint:
            hint_name = str(hint)
            hint_lower = str(hint).lower()
            optional_type = _optional_symbolic_type_from_hint(hint_lower, hint_name)
            if optional_type is not None:
                symbolic_vars[name] = optional_type
            elif (symbolic_type := _symbolic_type_from_hint(hint_lower, hint_name)) is not None:
                symbolic_vars[name] = symbolic_type
            else:
                symbolic_vars[name] = "object"
            continue

        if include_collection_heuristics:
            name_lower = name.lower()
            if _NULLABLE_VAR_RE.search(name_lower):
                symbolic_vars[name] = "nullable"
                continue
            if _LIST_VAR_RE.search(name_lower):
                symbolic_vars[name] = "list"
                continue
            if _DICT_VAR_RE.search(name_lower):
                symbolic_vars[name] = "dict"
                continue
        symbolic_vars[name] = "int"
    return symbolic_vars


def _hint_has_token(hint_lower: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", hint_lower) is not None


def _hint_allows_none(hint_lower: str) -> bool:
    return (
        "optional[" in hint_lower
        or _hint_has_token(hint_lower, "none")
        or _hint_has_token(hint_lower, "nonetype")
    )


def _symbolic_type_from_hint(hint_lower: str, hint_name: str) -> str | None:
    fixed_tuple_type = _fixed_tuple_type_from_hint(hint_name)
    if fixed_tuple_type is not None:
        return fixed_tuple_type
    if _hint_has_token(hint_lower, "bytearray"):
        return "bytearray"
    if (
        "list" in hint_lower
        or "sequence" in hint_lower
        or "iterable" in hint_lower
        or "iterator" in hint_lower
    ):
        return "list"
    if "dict" in hint_lower or "mapping" in hint_lower:
        container_count = hint_lower.count("dict") + hint_lower.count("mapping")
        return "dict:nested" if container_count > 1 else "dict"
    if _hint_has_token(hint_lower, "bool"):
        return "bool"
    if _hint_has_token(hint_lower, "int"):
        return "int"
    if _hint_has_token(hint_lower, "str"):
        return "str"
    if _hint_has_token(hint_lower, "bytes"):
        return "bytes"
    if _hint_has_token(hint_lower, "float") or _hint_has_token(hint_lower, "real"):
        return "float"
    if hint_lower in {"none", "nonetype"}:
        return "none"
    if hint_name.isidentifier() and hint_name not in {"Any", "object", "None", "NoneType"}:
        return f"instance:{hint_name}"
    return None


def _fixed_tuple_type_from_hint(hint_name: str) -> str | None:
    """Return a fixed tuple execution descriptor from a source annotation."""
    try:
        annotation = ast.parse(hint_name, mode="eval").body
    except SyntaxError:
        return None
    return _fixed_tuple_type_from_annotation(annotation)


def _fixed_tuple_type_from_annotation(annotation: ast.expr) -> str | None:
    """Return a tuple descriptor for a direct or nullable fixed tuple annotation."""
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _fixed_tuple_type_from_annotation(
            annotation.left,
        ) or _fixed_tuple_type_from_annotation(annotation.right)
    if not isinstance(annotation, ast.Subscript):
        return None
    owner_name = _annotation_owner_name(annotation.value)
    if owner_name is None or owner_name.lower().split(".")[-1] != "tuple":
        return None
    elements = (
        annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    )
    if any(isinstance(element, ast.Constant) and element.value is Ellipsis for element in elements):
        return None
    return f"tuple[{','.join(ast.unparse(element) for element in elements)}]"


def _annotation_owner_name(annotation: ast.expr) -> str | None:
    """Return a dotted annotation owner name without executing the annotation."""
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        owner = _annotation_owner_name(annotation.value)
        return f"{owner}.{annotation.attr}" if owner is not None else annotation.attr
    return None


def _optional_symbolic_type_from_hint(hint_lower: str, hint_name: str) -> str | None:
    if not _hint_allows_none(hint_lower):
        return None
    non_null_type = _symbolic_type_from_hint(hint_lower, hint_name)
    if non_null_type == "none":
        return "none"
    if non_null_type is None or non_null_type.startswith("instance:"):
        return "nullable"
    return f"optional:{non_null_type}"


def _instance_type_hint(class_name: str, hints: dict[str, str]) -> str:
    parts: list[str] = []
    for key, hint in sorted(hints.items()):
        if not key.startswith("__init__."):
            continue
        param_name = key.split(".", 1)[1]
        if param_name.isidentifier():
            parts.append(f"{param_name}={hint}")
    if not parts:
        return f"instance:{class_name}"
    return f"instance:{class_name}|{','.join(parts)}"
