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

"""Model value extraction helpers for property analyses."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import z3

from pysymex.logger import get_logger

logger = get_logger(__name__)
_MODEL_VALUE_ERRORS = (z3.Z3Exception, AttributeError, RuntimeError, TypeError, ValueError)

ModelVariableSet = Mapping[str, z3.ExprRef] | Sequence[z3.ExprRef]


@dataclass(frozen=True, slots=True)
class ModelValueExtraction:
    """Counterexample values extracted from a model plus completeness evidence."""

    values: dict[str, object]
    complete: bool
    failed_variables: tuple[str, ...] = ()


def extract_model_values_result(
    model: z3.ModelRef | None,
    variables: ModelVariableSet,
) -> ModelValueExtraction:
    """Extract typed Python values and report whether all requested values succeeded."""
    if model is None:
        return ModelValueExtraction(values={}, complete=False)
    if isinstance(variables, Mapping):
        items: Iterable[tuple[str, z3.ExprRef]] = variables.items()
    else:
        items = ((str(expr), expr) for expr in variables)
    result: dict[str, object] = {}
    failed_variables: list[str] = []
    complete = True
    for name, expr in items:
        try:
            val = model.eval(expr, model_completion=True)
            if z3.is_int_value(val):
                result[name] = val.as_long()
            elif z3.is_rational_value(val):
                frac = val.as_fraction()
                try:
                    result[name] = float(frac)
                except OverflowError:
                    result[name] = str(frac)
            elif z3.is_true(val):
                result[name] = True
            elif z3.is_false(val):
                result[name] = False
            else:
                result[name] = str(val)
        except _MODEL_VALUE_ERRORS:
            complete = False
            failed_variables.append(name)
            logger.debug("Model eval failed for variable %s", name, exc_info=True)
    return ModelValueExtraction(
        values=result,
        complete=complete,
        failed_variables=tuple(failed_variables),
    )
