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

"""Counterexample extraction helpers for detector issues."""

from __future__ import annotations

import re

import z3

from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)
_NO_COUNTEREXAMPLE_VALUE = object()
_DERIVED_LENGTH_EXPR_LIMIT = 128
_DERIVED_LENGTH_NODE_LIMIT = 4096
_DERIVED_LENGTH_OPS = (z3.Z3_OP_ADD, z3.Z3_OP_SUB, z3.Z3_OP_MUL)


def _extract_model_declarations(model: z3.ModelRef) -> dict[str, object]:
    """Extract Z3 model declarations into Python values."""
    fields_by_base: dict[str, dict[str, object]] = {}
    for decl in sorted(model.decls(), key=lambda model_decl: model_decl.name()):
        name = decl.name()
        field = _counterexample_field_name(name)
        if field is None:
            continue
        base_name, field_name = field
        fields_by_base.setdefault(base_name, {})[field_name] = _z3_value_to_python(model[decl])

    counterexample: dict[str, object] = {}
    for base_name in sorted(fields_by_base):
        resolved = _resolve_counterexample_fields(fields_by_base[base_name])
        if resolved is not _NO_COUNTEREXAMPLE_VALUE:
            counterexample[base_name] = resolved
    return counterexample


def _counterexample_field_name(name: str) -> tuple[str, str] | None:
    """Parse Z3 variable names into base name and field type suffix."""
    for suffix, field_name in (
        ("_is_none", "is_none"),
        ("_is_int", "is_int"),
        ("_is_bool", "is_bool"),
        ("_is_str", "is_str"),
        ("_int", "int"),
        ("_bool", "bool"),
        ("_str", "str"),
    ):
        if name.endswith(suffix):
            base_name = _base_counterexample_name(name[: -len(suffix)])
            if base_name is None:
                return None
            return base_name, field_name

    base_name = _base_counterexample_name(name)
    if base_name is None:
        return None
    return base_name, "plain"


def _resolve_counterexample_fields(fields: dict[str, object]) -> object:
    """Resolve grouped field values into one Python value."""
    if fields.get("is_none") is True:
        return None
    for discriminator, value_field in (
        ("is_str", "str"),
        ("is_bool", "bool"),
        ("is_int", "int"),
    ):
        if fields.get(discriminator) is True and value_field in fields:
            return fields[value_field]

    if "plain" in fields:
        return fields["plain"]

    for value_field in ("str", "int", "bool"):
        if value_field in fields and fields.get(f"is_{value_field}") is not False:
            return fields[value_field]
    return _NO_COUNTEREXAMPLE_VALUE


def _base_counterexample_name(name: str) -> str | None:
    """Extract the user-facing base name for a counterexample variable."""
    base_name = name
    for suffix in ("_is_int", "_is_bool", "_is_none", "_is_str", "_int", "_bool", "_str"):
        if name.endswith(suffix):
            base_name = name[: -len(suffix)]
            break

    match = re.search(r"^(.*)_\d+$", base_name)
    if match:
        base_name = match.group(1)

    if base_name.startswith("_"):
        return None
    if "_is_" in name and not any(name.endswith(s) for s in ("_int", "_bool", "_str")):
        return None
    return base_name


def _z3_value_to_python(value: object) -> object:
    """Convert a Z3 literal value object to a Python value."""
    try:
        if isinstance(value, z3.IntNumRef):
            return value.as_long()
        if isinstance(value, z3.BoolRef) and z3.is_true(value):
            return True
        if isinstance(value, z3.BoolRef) and z3.is_false(value):
            return False
        if isinstance(value, z3.SeqRef):
            return value.as_string()
        return str(value)
    except (z3.Z3Exception, TypeError, ValueError):
        return str(value)


def _extract_missing_constraint_values(
    model: z3.ModelRef,
    constraints: list[z3.BoolRef],
    counterexample: dict[str, object],
) -> None:
    """Extract additional variable values from path comparison constraints."""
    for constraint in constraints:
        if not z3.is_app(constraint):
            continue
        decl = constraint.decl()
        if decl.kind() not in (
            z3.Z3_OP_GT,
            z3.Z3_OP_LT,
            z3.Z3_OP_EQ,
            z3.Z3_OP_GE,
            z3.Z3_OP_LE,
        ):
            continue
        if constraint.num_args() < 2:
            continue
        left = constraint.arg(0)
        if not z3.is_const(left):
            continue
        var_name = left.decl().name()
        if var_name in counterexample or var_name.startswith("_"):
            continue
        try:
            counterexample[var_name] = _z3_value_to_python(model.eval(left))
        except (z3.Z3Exception, TypeError, ValueError):
            logger.debug("Failed to evaluate counterexample expression", exc_info=True)


def _extract_derived_lengths(
    model: z3.ModelRef,
    constraints: list[z3.BoolRef],
    counterexample: dict[str, object],
) -> None:
    """Evaluate bounded arithmetic constraints to infer sequence lengths."""
    exprs_to_eval: list[z3.ExprRef] = []
    visited: set[int] = set()
    for constraint in constraints:
        _collect_arithmetic_exprs(
            constraint,
            exprs_to_eval,
            visited=visited,
        )
        if (
            len(exprs_to_eval) >= _DERIVED_LENGTH_EXPR_LIMIT
            or len(visited) >= _DERIVED_LENGTH_NODE_LIMIT
        ):
            break

    max_len_val = 0
    for expr in exprs_to_eval:
        try:
            val = model.eval(expr)
            if isinstance(val, z3.IntNumRef):
                max_len_val = max(max_len_val, val.as_long())
        except (z3.Z3Exception, TypeError, ValueError):
            logger.debug("Failed to evaluate derived counterexample expression", exc_info=True)

    if max_len_val > 0:
        counterexample["list_len"] = max_len_val


def _collect_arithmetic_exprs(
    expr: z3.ExprRef,
    exprs_to_eval: list[z3.ExprRef],
    *,
    visited: set[int] | None = None,
) -> None:
    """Collect arithmetic sub-expressions with a hard traversal budget."""
    seen: set[int] = visited if visited is not None else set()
    pending: list[z3.ExprRef] = [expr]
    while (
        pending
        and len(exprs_to_eval) < _DERIVED_LENGTH_EXPR_LIMIT
        and len(seen) < _DERIVED_LENGTH_NODE_LIMIT
    ):
        current = pending.pop()
        try:
            node_id = current.get_id()
        except (AttributeError, z3.Z3Exception):
            continue
        if node_id in seen or not z3.is_app(current):
            continue
        seen.add(node_id)
        try:
            if current.decl().kind() in _DERIVED_LENGTH_OPS:
                exprs_to_eval.append(current)
            pending.extend(current.arg(index) for index in range(current.num_args()))
        except z3.Z3Exception:
            logger.debug("Failed to inspect counterexample expression", exc_info=True)


class CounterexampleExtractor:
    """Extract stable, user-facing model values from Z3 detector evidence."""

    def __init__(
        self,
        model: z3.ModelRef | dict[str, object],
        constraints: list[z3.BoolRef],
    ) -> None:
        """Initialise with a Z3 model or a pre-extracted dict."""
        if isinstance(model, dict):
            self._dict_model: dict[str, object] | None = model
            self._z3_model: z3.ModelRef | None = None
        else:
            self._dict_model = None
            self._z3_model = model
        self.constraints = constraints

    def extract(self) -> dict[str, object]:
        """Build and return a deterministic counterexample dictionary."""
        if self._dict_model is not None:
            return self._dict_model
        if self._z3_model is None:
            return {}

        counterexample = _extract_model_declarations(self._z3_model)
        _extract_missing_constraint_values(self._z3_model, self.constraints, counterexample)
        _extract_derived_lengths(self._z3_model, self.constraints, counterexample)
        return counterexample
