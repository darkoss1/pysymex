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

"""Symbolic input inference helpers for scanner execution.

Part of the scanner setup phase. Traverses AST nodes to extract parameter annotations,
handles solver timeouts, and infers type descriptors for symbolic executor arguments.
"""

from __future__ import annotations

import ast
import re
import types

_LIST_VAR_RE = re.compile(r"collection|items|sequence|data|arr|list")
_DICT_VAR_RE = re.compile(r"mapping|config|settings|dict|map")
_NULLABLE_VAR_RE = re.compile(r"(^obj$|object|instance|target|receiver|node)")
# Scanner queries stay well below the file/function timeout so a few hard SMT
# unknowns cannot consume the whole scan before sibling paths are explored.
_MAX_SCANNER_SOLVER_TIMEOUT_MS = 100


def _hint_has_token(hint_lower: str, token: str) -> bool:
    """Return whether a type-hint string contains *token* as a standalone word."""
    return re.search(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", hint_lower) is not None


def _hint_allows_none(hint_lower: str) -> bool:
    """Return whether a type-hint string includes ``None`` as an allowed value."""
    return (
        "optional[" in hint_lower
        or _hint_has_token(hint_lower, "none")
        or _hint_has_token(hint_lower, "nonetype")
    )


def _symbolic_type_from_hint(hint_lower: str, hint_name: str) -> str | None:
    """Resolve the non-null symbolic carrier descriptor for a type-hint string."""
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


def _optional_symbolic_type_from_hint(hint_lower: str, hint_name: str) -> str | None:
    """Resolve an optional/nullable symbolic carrier descriptor if the hint permits None."""
    if not _hint_allows_none(hint_lower):
        return None
    non_null_type = _symbolic_type_from_hint(hint_lower, hint_name)
    if non_null_type == "none":
        return "none"
    if non_null_type is None or non_null_type.startswith("instance:"):
        return "nullable"
    return f"optional:{non_null_type}"


class TypeHintExtractor(ast.NodeVisitor):
    """AST visitor to extract type hints from function signatures.

    Traverses classes and functions in a module's AST to gather type hint
    annotations for all parameters, mapping them by function and class name.

    Attributes:
        hints: Mapping of ``(function_name, class_name)`` to ``{parameter_name: type_string}``.
        current_class: The active enclosing class name during traversal.
    """

    def __init__(self) -> None:
        """Initialize the type hint extractor visitor."""
        self.hints: dict[tuple[str, str | None], dict[str, str]] = {}
        self.current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition node to track the current class scope during AST traversal.

        Args:
            node (ast.ClassDef): The class definition AST node.
        """
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function definition node to extract type hints from its arguments.

        Args:
            node (ast.FunctionDef | ast.AsyncFunctionDef): The function definition AST node.
        """
        arg_hints: dict[str, str] = {}
        for arg in node.args.args:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)
                # Also handle kwonlyargs
        for arg in node.args.kwonlyargs:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)

        self.hints[(node.name, self.current_class)] = arg_hints
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_type_str(self, node: ast.expr) -> str:
        """Convert an annotation AST expression into a string representation of the type hint.

        Args:
            node (ast.expr): The AST node representing the type annotation.

        Returns:
            str: The extracted type hint string.
        """
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


def scanner_solver_timeout_ms(timeout_seconds: float) -> int:
    """Return the per-query SMT timeout used during scanner execution.

    Caps the timeout value to prevent execution hangs.

    Args:
        timeout_seconds: Timeout interval in seconds.

    Returns:
        The resolved timeout in milliseconds, bounded between ``1`` and ``_MAX_SCANNER_SOLVER_TIMEOUT_MS``.
    """
    return min(_MAX_SCANNER_SOLVER_TIMEOUT_MS, max(1, int(timeout_seconds * 1000)))


def _instance_type_hint(class_name: str, hints: dict[str, str]) -> str:
    """Build a string representation of an instance type hint with constructor parameters.

    Args:
        class_name (str): The name of the class.
        hints (dict[str, str]): Type hint mappings extracted from parameters.

    Returns:
        str: The formatted instance type hint string.
    """
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


def build_symbolic_vars(
    code: types.CodeType,
    class_name: str | None = None,
    type_hints: dict[str, str] | None = None,
    *,
    include_collection_heuristics: bool,
) -> dict[str, str]:
    """Build symbolic argument type hints from code object parameter names and opcode-captured hints.

    Inspects code arguments, matching them against provided type hints and falls back to
    variable name matching heuristics when enabled, returning a map of symbolic types.

    Args:
        code: Compiled code object containing parameter details.
        class_name: Enclosing class name of the function, if any.
        type_hints: Explicit type annotation strings for parameters.
        include_collection_heuristics: If ``True``, fallback to name-based regex cues.

    Returns:
        A dictionary mapping parameter names to symbolic type description strings (e.g. ``"int"``).
    """
    symbolic_vars: dict[str, str] = {}
    hints = type_hints or {}

    for i, name in enumerate(code.co_varnames[: code.co_argcount]):
        if i == 0 and name in {"self", "cls"}:
            if name == "self" and class_name:
                symbolic_vars[name] = _instance_type_hint(class_name, hints)
            else:
                symbolic_vars[name] = "object"
            continue

            # Use opcode-captured hint if available
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
                # Likely a class or complex object
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
