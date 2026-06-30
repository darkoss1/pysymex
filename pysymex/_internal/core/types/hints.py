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

"""Canonical symbolic type-hint categories shared by input builders."""

from __future__ import annotations

import ast
from enum import StrEnum


class SymbolicHintKind(StrEnum):
    """Canonical input categories understood by symbolic input factories."""

    ANY = "any"
    BOOL = "bool"
    BYTEARRAY = "bytearray"
    BYTES = "bytes"
    DICT = "dict"
    FLOAT = "float"
    FROZENSET = "frozenset"
    INSTANCE = "instance"
    INT = "int"
    LIST = "list"
    OBJECT = "object"
    PATH = "path"
    SET = "set"
    STR = "str"
    TUPLE = "tuple"
    UNKNOWN = "unknown"


_HINT_ALIASES = {
    "array": SymbolicHintKind.LIST,
    "boolean": SymbolicHintKind.BOOL,
    "integer": SymbolicHintKind.INT,
    "iterable": SymbolicHintKind.LIST,
    "kwargs": SymbolicHintKind.DICT,
    "mapping": SymbolicHintKind.DICT,
    "pathlib.path": SymbolicHintKind.PATH,
    "real": SymbolicHintKind.FLOAT,
    "sequence": SymbolicHintKind.LIST,
    "string": SymbolicHintKind.STR,
}


def canonicalize_symbolic_type_hint(type_hint: str) -> str:
    """Canonicalize aliases while retaining optional and fixed-tuple structure."""
    normalized = "".join(type_hint.strip().lower().split())
    nullable_prefix, separator, inner = normalized.partition(":")
    if separator and nullable_prefix in {"nullable", "optional"}:
        canonical_inner = canonicalize_symbolic_type_hint(inner or "any")
        return f"optional:{canonical_inner}"
    fixed_tuple = parse_fixed_tuple_type_hint(normalized)
    if fixed_tuple is not None:
        elements = ",".join(canonicalize_symbolic_type_hint(element) for element in fixed_tuple)
        return f"tuple[{elements}]"
    if normalized.startswith("instance:"):
        return normalized
    owner, bracket, suffix = normalized.partition("[")
    canonical_owner = str(_HINT_ALIASES.get(owner, owner))
    if bracket:
        return f"{canonical_owner}[{suffix}"
    return canonical_owner


def symbolic_hint_kind(type_hint: str) -> SymbolicHintKind:
    """Classify a normalized or user-supplied symbolic input hint."""
    normalized = canonicalize_symbolic_type_hint(type_hint)
    if normalized.startswith("optional:"):
        normalized = normalized.split(":", 1)[1]
    if normalized.startswith("instance:"):
        return SymbolicHintKind.INSTANCE
    owner = normalized.split("[", 1)[0].split(":", 1)[0]
    try:
        return SymbolicHintKind(owner)
    except ValueError:
        return SymbolicHintKind.UNKNOWN


def parse_fixed_tuple_type_hint(type_hint: str) -> tuple[str, ...] | None:
    """Parse a fixed ``tuple[...]`` symbolic hint into element hints."""
    try:
        annotation = ast.parse(type_hint, mode="eval").body
    except SyntaxError:
        return None
    if not isinstance(annotation, ast.Subscript):
        return None
    owner = annotation.value
    if not isinstance(owner, ast.Name) or owner.id != "tuple":
        return None
    elements = (
        annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    )
    if any(isinstance(element, ast.Constant) and element.value is Ellipsis for element in elements):
        return None
    return tuple(ast.unparse(element) for element in elements)
