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

"""Solver-backed diagnostics for Z3 FP symbolic floating-point values."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.config.floats import FloatConfig, FloatPrecision, get_fp_sort
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.solver.engine.results import SolverResult
    from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

FloatIssue = dict[str, object]
logger = get_logger(__name__)


def _model_backed_condition_result(constraints: list[z3.BoolRef]) -> SolverResult:
    """Return structured model evidence for a floating-point diagnostic query."""
    from pysymex.core.solver.engine.queries import get_model_result

    result = get_model_result(constraints)
    if result.is_unknown:
        logger.debug("Floating-point diagnostic query was inconclusive")
    return result


def _append_model_backed_issue(
    issues: list[FloatIssue],
    constraints: list[z3.BoolRef],
    issue_type: str,
    message: str,
) -> None:
    """Append an issue only when Z3 provides a satisfying model."""
    result = _model_backed_condition_result(constraints)
    if not result.is_sat or result.model is None:
        return

    issues.append({"type": issue_type, "message": message, "model": result.model})


class FloatAnalyzer:
    """Collect model-backed possibilities for selected FP result conditions.

    A recorded issue proves that a satisfying model was returned for the
    corresponding condition. Unsatisfiable or solver-unknown checks are not
    reported as definite issues by this analyzer.
    """

    def __init__(self, config: FloatConfig | None = None) -> None:
        """Initialize issue collection with the selected float checks."""
        self.config = config or FloatConfig()
        self.issues: list[FloatIssue] = []

    def check_operation(
        self,
        op: str,
        result: AdvancedSymbolicFloat,
        operands: list[AdvancedSymbolicFloat],
        constraints: list[z3.BoolRef],
    ) -> list[dict[str, object]]:
        """Return model-backed NaN, infinity, zero-divisor, or denormal results.

        Notes:
            Enabled checks are controlled by :class:`FloatConfig`; the method
            does not prove that every execution exhibits a reported condition.
        """
        issues: list[FloatIssue] = []

        if self.config.check_nan:
            nan_check = [*constraints, result.is_nan()]
            _append_model_backed_issue(
                issues,
                nan_check,
                "NaN_RESULT",
                f"Operation {op} may produce NaN",
            )
        if self.config.check_infinity:
            inf_check = [*constraints, result.is_infinity()]
            _append_model_backed_issue(
                issues,
                inf_check,
                "INFINITY_RESULT",
                f"Operation {op} may produce infinity",
            )
        if op in ("div", "truediv", "/") and len(operands) >= 2:
            div_zero = [*constraints, operands[1].is_zero()]
            _append_model_backed_issue(
                issues,
                div_zero,
                "FP_DIVISION_BY_ZERO",
                "Floating-point division by zero",
            )
        if self.config.check_denormal:
            denorm_check = [*constraints, result.is_denormal()]
            _append_model_backed_issue(
                issues,
                denorm_check,
                "DENORMAL_RESULT",
                f"Operation {op} may produce denormalized number",
            )
        self.issues.extend(issues)
        return issues

    def check_comparison(
        self,
        left: AdvancedSymbolicFloat,
        right: AdvancedSymbolicFloat,
        constraints: list[z3.BoolRef],
    ) -> list[dict[str, object]]:
        """Return a model-backed diagnostic when either compared value can be NaN."""
        issues: list[FloatIssue] = []

        nan_cmp = [*constraints, z3.Or(left.is_nan(), right.is_nan())]
        _append_model_backed_issue(
            issues,
            nan_cmp,
            "NAN_COMPARISON",
            "Comparing with NaN always returns False",
        )
        self.issues.extend(issues)
        return issues

    def get_all_issues(self) -> list[dict[str, object]]:
        """Return a copy of accumulated model-backed diagnostics."""
        return list(self.issues)


class AccuracyAnalyzer:
    """Build FP accuracy expressions and detect model-backed cancellation cases."""

    def __init__(self, precision: FloatPrecision = FloatPrecision.DOUBLE) -> None:
        """Initialize the encoded floating-point sort and machine epsilon."""
        self.precision = precision
        self._sort = get_fp_sort(precision)
        if precision == FloatPrecision.SINGLE:
            self.epsilon = 2**-23
        else:
            self.epsilon = 2**-52

    def ulp_difference(
        self,
        computed: AdvancedSymbolicFloat,
        exact: AdvancedSymbolicFloat,
    ) -> z3.FPRef:
        """Compute absolute floating-point difference between two values.

        Note: Despite the name, this returns ``|computed - exact|`` (the
        absolute difference in the value domain), **not** the difference
        measured in ULP units.  A true ULP-distance would require dividing
        by ``ulp(exact)``, which depends on the exponent and is non-trivial
        to express in Z3 FP arithmetic.
        """
        diff = computed - exact
        return z3.fpAbs(diff.z3_expr)

    def relative_error(
        self,
        computed: AdvancedSymbolicFloat,
        exact: AdvancedSymbolicFloat,
    ) -> AdvancedSymbolicFloat:
        """Return ``abs(computed - exact) / abs(exact)`` in FP arithmetic.

        Limitations:
            No nonzero constraint is added for ``exact``; FP zero, infinity,
            or NaN outcomes remain representable in the returned expression.
        """
        diff = computed - exact
        return type(computed)(
            z3_expr=z3.fpDiv(
                z3.RNE(),
                z3.fpAbs(diff.z3_expr),
                z3.fpAbs(exact.z3_expr),
            ),
            config=computed.config,
        )

    def check_catastrophic_cancellation(
        self,
        a: AdvancedSymbolicFloat,
        b: AdvancedSymbolicFloat,
        result: AdvancedSymbolicFloat,
        constraints: list[z3.BoolRef],
    ) -> bool:
        """Return whether Z3 produced a model satisfying the cancellation heuristic.

        A ``False`` result also covers unsatisfiable and solver-unknown checks;
        it is not proof that cancellation cannot occur. Use
        :meth:`check_catastrophic_cancellation_result` when callers need to
        distinguish UNSAT from UNKNOWN.
        """
        return self.check_catastrophic_cancellation_result(a, b, result, constraints).is_sat

    def check_catastrophic_cancellation_result(
        self,
        a: AdvancedSymbolicFloat,
        b: AdvancedSymbolicFloat,
        result: AdvancedSymbolicFloat,
        constraints: list[z3.BoolRef],
    ) -> SolverResult:
        """Return structured model evidence for the cancellation heuristic."""
        sum_mag = z3.fpAdd(z3.RNE(), z3.fpAbs(a.z3_expr), z3.fpAbs(b.z3_expr))
        diff_mag = z3.fpAbs(result.z3_expr)
        ratio_check = [
            *constraints,
            z3.fpLT(
                diff_mag,
                z3.fpMul(z3.RNE(), sum_mag, z3.FPVal(0.001, get_fp_sort(a.config.precision))),
            ),
        ]
        return _model_backed_condition_result(ratio_check)
