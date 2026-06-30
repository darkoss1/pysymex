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

"""Parse quantifier invocation strings into structured records.

Used by :mod:`pysymex._internal.contracts.quantifiers.lowering` and
:mod:`pysymex._internal.contracts.quantifiers.factories` to build
:class:`~pysymex._internal.contracts.quantifiers.types.Quantifier` values. Does not run solver
checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import z3

from pysymex._internal.contracts.quantifiers.translator import parse_condition_to_z3
from pysymex._internal.contracts.quantifiers.types import (
    BoundSpec,
    Quantifier,
    QuantifierKind,
    QuantifierVar,
)
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)

_IDENTIFIER_PATTERN = re.compile(r"\w+\Z")
_QUANTIFIER_KEYWORDS = ("exists!", "forall", "exists")
_RANGE_PATTERN = re.compile(r"(-?\d+|\w+)\s*(<=?)\s*(\w+)\s*(<|<=)\s*(-?\d+|\w+|\w+\([^)]+\))")
_IN_PATTERN = re.compile(r"(\w+)\s+in\s+(\w+)")


@dataclass(frozen=True, slots=True)
class QuantifierSyntax:
    """Source-level quantifier call split into top-level arguments."""

    kind_text: str
    variable: str
    bound_source: str
    body_source: str


def parse_quantifier_syntax(text: str) -> QuantifierSyntax | None:
    """Split one ``forall``/``exists`` invocation without regex body matching."""
    stripped = text.strip()
    for keyword in _QUANTIFIER_KEYWORDS:
        if not stripped.startswith(keyword):
            continue
        remainder = stripped[len(keyword) :].lstrip()
        if not remainder.startswith("("):
            return None
        close_index = _matching_closing_paren(remainder, 0)
        if close_index != len(remainder) - 1:
            return None
        parts = _split_top_level_args(remainder[1:close_index])
        if len(parts) != 3:
            return None
        variable = parts[0].strip()
        if not _IDENTIFIER_PATTERN.fullmatch(variable):
            return None
        return QuantifierSyntax(
            kind_text=keyword,
            variable=variable,
            bound_source=parts[1].strip(),
            body_source=parts[2].strip(),
        )
    return None


def _matching_closing_paren(text: str, open_index: int) -> int:
    """Return the matching ``)`` index for ``text[open_index]``."""
    if open_index >= len(text) or text[open_index] != "(":
        return -1
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_top_level_args(text: str) -> list[str]:
    """Split comma-separated arguments while preserving nested call commas."""
    parts: list[str] = []
    depth = 0
    start = 0
    opening = {"(", "[", "{"}
    closing = {")", "]", "}"}
    for index, char in enumerate(text):
        if char in opening:
            depth += 1
        elif char in closing:
            depth -= 1
            if depth < 0:
                return []
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    if depth != 0:
        return []
    parts.append(text[start:])
    return parts


class QuantifierParser:
    """Parses quantifier expressions from contract strings.

    Translates string quantified conditions into structured ``Quantifier``
    objects. Supports range specifications and array membership constraints.

    Supported Syntax:
        - Range: ``forall(var, lower <= var < upper, condition)``
        - Membership: ``forall(var, var in collection, condition)``
        - Existence: ``exists(var, lower <= var < upper, condition)``
        - Unique Existence: ``exists!(var, range, condition)``

    Attributes:
        context: Active variable mapping to resolve identifiers inside bounds
            or bodies.

    """

    def __init__(self, context: dict[str, z3.ExprRef] | None = None) -> None:
        """Initialize the quantifier parser.

        Args:
            context: A mapping from variable names to their active Z3 expression
                references in the current path. Defaults to an empty dictionary.

        """
        self.context = context or {}

    def parse(self, text: str) -> Quantifier | None:
        """Parse a quantifier expression string.

        Args:
            text: The raw quantifier text to parse.

        Returns:
            A structured ``Quantifier`` if successfully parsed, otherwise ``None``.

        """
        text = text.strip()
        syntax = parse_quantifier_syntax(text)
        if syntax is None:
            return None
        if syntax.kind_text == "forall":
            kind = QuantifierKind.FORALL
        elif syntax.kind_text == "exists":
            kind = QuantifierKind.EXISTS
        elif syntax.kind_text == "exists!":
            kind = QuantifierKind.UNIQUE
        else:
            return None
        var = QuantifierVar(name=syntax.variable, sort=z3.IntSort())
        bounds = self._parse_bounds(syntax.bound_source, syntax.variable)
        body = self._parse_body(syntax.body_source, {syntax.variable: var.z3_var})
        return Quantifier(
            kind=kind,
            variables=[var],
            bounds=[bounds],
            body=body,
            original_text=text,
        )

    def _parse_bounds(self, range_str: str, var_name: str) -> BoundSpec:
        """Parse range boundaries or membership domain bounds.

        Args:
            range_str: String representation of the range/bounds.
            var_name: Name of the bound quantifier variable.

        Returns:
            The parsed ``BoundSpec``.

        Raises:
            ValueError: If the bound variable name mismatches or boundaries are
                unsupported.

        """
        range_str = range_str.strip()
        range_match = _RANGE_PATTERN.fullmatch(range_str)
        if range_match:
            lower_val, lower_op, matched_var, upper_op, upper_val = range_match.groups()
            if matched_var != var_name:
                msg = f"Quantifier bound variable {matched_var!r} does not match {var_name!r}"
                raise ValueError(
                    msg,
                )
            return BoundSpec(
                lower=self._parse_expr(lower_val),
                upper=self._parse_expr(upper_val),
                lower_inclusive=(lower_op == "<="),
                upper_inclusive=(upper_op == "<="),
            )
        in_match = _IN_PATTERN.fullmatch(range_str)
        if in_match:
            matched_var, collection = in_match.groups()
            if matched_var != var_name:
                msg = f"Quantifier bound variable {matched_var!r} does not match {var_name!r}"
                raise ValueError(
                    msg,
                )
            collection_expr = self.context.get(collection)
            if collection_expr is None:
                msg = f"Unbound quantifier collection: {collection}"
                raise ValueError(msg)
            return BoundSpec(in_collection=collection_expr)
        msg = f"Unsupported quantifier bounds: {range_str!r}"
        raise ValueError(msg)

    def _parse_expr(self, expr_str: str) -> z3.ExprRef:
        """Parse a numeric boundary or identifier to a Z3 expression.

        Args:
            expr_str: The boundary string expression.

        Returns:
            The compiled Z3 expression.

        Raises:
            ValueError: If the expression cannot be resolved or is unbound.

        """
        expr_str = expr_str.strip()
        if expr_str in self.context:
            return self.context[expr_str]
        try:
            return ConstraintValues.int(int(expr_str))
        except ValueError:
            logger.trace("Quantifier expression is not an integer literal: %s", expr_str)
        if expr_str.startswith("len(") and expr_str.endswith(")"):
            inner = expr_str[4:-1]
            length_expr = self.context.get(f"len_{inner}")
            if length_expr is not None:
                return length_expr
        msg = f"Unbound quantifier bound expression: {expr_str}"
        raise ValueError(msg)

    def _parse_body(self, body_str: str, local_vars: dict[str, z3.ExprRef | None]) -> z3.BoolRef:
        """Parse the quantified predicate body string to Z3.

        Args:
            body_str: The body string expression.
            local_vars: Extra bound variables to inject into the parser context.

        Returns:
            A ``z3.BoolRef`` representing the compiled body.

        Raises:
            ValueError: If the body expression is not boolean.

        """
        body_str = body_str.strip()
        full_context: dict[str, z3.ExprRef] = dict(self.context)
        for k, v in local_vars.items():
            if v is not None:
                full_context[k] = v
        res = parse_condition_to_z3(body_str, full_context)
        if not z3.is_bool(res):
            msg = f"Quantifier body is not boolean: {body_str!r}"
            raise ValueError(msg)
        return res
