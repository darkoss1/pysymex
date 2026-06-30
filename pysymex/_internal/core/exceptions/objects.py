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

"""Symbolic exception objects and handler block models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.exceptions.categories import ExceptionCategory, get_exception_category
from pysymex._internal.core.solver.scoped import check_scoped_constraints


class ExceptionOccurrenceStatus(Enum):
    """Truth status for a symbolic exception occurrence query."""

    ESTABLISHED = auto()
    REFUTED = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class ExceptionOccurrenceResult:
    """Structured occurrence evidence without collapsing solver UNKNOWN."""

    status: ExceptionOccurrenceStatus
    reason: str | None = None

    @property
    def is_established(self) -> bool:
        """Return true only when the queried occurrence predicate is established."""
        return self.status is ExceptionOccurrenceStatus.ESTABLISHED

    @property
    def is_unknown(self) -> bool:
        """Return true when solver uncertainty prevented a definite answer."""
        return self.status is ExceptionOccurrenceStatus.UNKNOWN

    @staticmethod
    def established() -> ExceptionOccurrenceResult:
        """Create an established occurrence result."""
        return ExceptionOccurrenceResult(ExceptionOccurrenceStatus.ESTABLISHED)

    @staticmethod
    def refuted(reason: str | None = None) -> ExceptionOccurrenceResult:
        """Create a refuted occurrence result."""
        return ExceptionOccurrenceResult(ExceptionOccurrenceStatus.REFUTED, reason)

    @staticmethod
    def unknown(reason: str = "solver_unknown") -> ExceptionOccurrenceResult:
        """Create an inconclusive occurrence result."""
        return ExceptionOccurrenceResult(ExceptionOccurrenceStatus.UNKNOWN, reason)


@dataclass(frozen=True, slots=True)
class SymbolicException:
    """Model an exception type with an optional occurrence condition.

    A ``None`` or literal-true condition is treated as unconditional. Other
    Boolean expressions describe paths on which the exception may occur.
    """

    exc_type: type[BaseException] | str
    args: tuple[object, ...] = ()
    message: str | None = None
    traceback: list[int] | None = None
    raised_at: int = 0
    condition: z3.BoolRef | None = None
    category: ExceptionCategory = ExceptionCategory.RUNTIME
    line_number: int | None = None
    column: int | None = None

    @classmethod
    def concrete(
        cls,
        exc_type: type[BaseException],
        *args: object,
        raised_at: int = 0,
        line_number: int | None = None,
        column: int | None = None,
    ) -> SymbolicException:
        """Create an unconditional exception with a literal-true condition."""
        category = get_exception_category(exc_type)
        message = str(args[0]) if args else None
        return cls(
            exc_type=exc_type,
            args=args,
            message=message,
            raised_at=raised_at,
            condition=Z3_TRUE,
            category=category,
            line_number=line_number,
            column=column,
        )

    @classmethod
    def symbolic(
        cls,
        name: str,
        exc_type: type[BaseException] | str,
        condition: z3.BoolRef,
        raised_at: int = 0,
        line_number: int | None = None,
        column: int | None = None,
    ) -> SymbolicException:
        """Create a conditionally occurring exception model.

        Notes:
            ``name`` is accepted for call-site naming symmetry but is not
            stored in the resulting object.

        """
        if isinstance(exc_type, type):
            category = get_exception_category(exc_type)
        else:
            category = ExceptionCategory.CUSTOM
        return cls(
            exc_type=exc_type,
            condition=condition,
            raised_at=raised_at,
            category=category,
            line_number=line_number,
            column=column,
        )

    @property
    def type_name(self) -> str:
        """Return the concrete class name or symbolic exception type label."""
        if isinstance(self.exc_type, type):
            return self.exc_type.__name__
        return str(self.exc_type)

    @property
    def value(self) -> object:
        """Return CPython's ``StopIteration.value`` payload.

        Raises:
            AttributeError: If this exception is not a ``StopIteration`` model.

        """
        if self.type_name != "StopIteration":
            msg = "value"
            raise AttributeError(msg)
        return self.args[0] if self.args else None

    def is_unconditional(self) -> bool:
        """Return whether occurrence is represented as unconditional."""
        if self.condition is None:
            return True
        return bool(z3.is_true(self.condition))

    def may_occur(self, solver: z3.Solver) -> bool:
        """Return whether occurrence is not disproved by ``solver``.

        Limitations:
            Solver ``unknown`` and scoped query failures are treated as
            possible occurrence, not proof of feasibility.
        """
        result = self.may_occur_result(solver)
        return result.is_established or result.is_unknown

    def may_occur_result(self, solver: z3.Solver) -> ExceptionOccurrenceResult:
        """Return structured evidence for possible exception occurrence."""
        if self.condition is None:
            return ExceptionOccurrenceResult.established()
        result = check_scoped_constraints(solver, (self.condition,))
        if result == z3.sat:
            return ExceptionOccurrenceResult.established()
        if result == z3.unsat:
            return ExceptionOccurrenceResult.refuted("condition_unsat")
        return ExceptionOccurrenceResult.unknown()

    def must_occur(self, solver: z3.Solver) -> bool:
        """Return whether negating the occurrence condition is unsatisfiable.

        Limitations:
            Solver ``unknown`` and scoped query failures return ``False``
            rather than proving either mandatory or impossible occurrence.
        """
        return self.must_occur_result(solver).is_established

    def must_occur_result(self, solver: z3.Solver) -> ExceptionOccurrenceResult:
        """Return structured evidence for mandatory exception occurrence."""
        if self.condition is None:
            return ExceptionOccurrenceResult.established()
        result = check_scoped_constraints(solver, (z3.Not(self.condition),))
        if result == z3.unsat:
            return ExceptionOccurrenceResult.established()
        if result == z3.sat:
            return ExceptionOccurrenceResult.refuted("negated_condition_sat")
        return ExceptionOccurrenceResult.unknown()

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        cond = f" when {self.condition}" if self.condition and not self.is_unconditional() else ""
        return f"{self.type_name}({self.message or ''}){cond}"
