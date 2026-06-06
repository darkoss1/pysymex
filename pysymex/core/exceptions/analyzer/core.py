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

"""Core exception analyzer implementation."""

from __future__ import annotations

from dataclasses import replace
from typing import TypeGuard

import z3

from pysymex.core.constants import Z3_TRUE
from pysymex.core.exceptions.analyzer.protocols import (
    ContainsKeyProtocol,
    CouldBeFalsyProtocol,
    HasAttributeProtocol,
    HasLengthProtocol,
)
from pysymex.core.exceptions.contracts import RaisesContract
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.exceptions.state import ExceptionPath, ExceptionState
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.solver.independence.protocols import has_to_z3


def _has_length(value: object) -> TypeGuard[HasLengthProtocol]:
    """Return whether ``value`` exposes analyzer-visible length data."""
    return hasattr(value, "length")


def _has_contains_key(value: object) -> TypeGuard[ContainsKeyProtocol]:
    """Return whether ``value`` exposes callable key-membership analysis."""
    return hasattr(value, "contains_key") and callable(getattr(value, "contains_key", None))


def _has_attribute_checker(value: object) -> TypeGuard[HasAttributeProtocol]:
    """Return whether ``value`` exposes callable attribute-membership analysis."""
    return hasattr(value, "has_attribute") and callable(getattr(value, "has_attribute", None))


def _has_could_be_falsy(value: object) -> TypeGuard[CouldBeFalsyProtocol]:
    """Return whether ``value`` exposes a symbolic falsiness predicate."""
    return hasattr(value, "could_be_falsy") and callable(getattr(value, "could_be_falsy", None))


class ExceptionAnalyzer:
    """Collect and query modeled exception occurrences.

    Limitations:
        The analyzer generates fresh Boolean predicates for unsupported
        division, key, and assertion evidence; those predicates represent
        possibility rather than proven CPython failure behavior.
    """

    def __init__(self, solver: IncrementalSolver | None = None) -> None:
        """Initialize exception observations with an incremental solver."""
        self.solver = solver or IncrementalSolver()
        self._exception_paths: list[ExceptionPath] = []
        self._potential_exceptions: list[SymbolicException] = []

    def add_potential_exception(
        self,
        exc: SymbolicException,
        path_condition: z3.BoolRef | None = None,
    ) -> None:
        """Record ``exc``, conjoining ``path_condition`` into its condition."""
        if path_condition is not None:
            exc = replace(exc, condition=z3.And(exc.condition or Z3_TRUE, path_condition))
        self._potential_exceptions.append(exc)

    def get_potential_exceptions(self) -> list[SymbolicException]:
        """Return the analyzer's mutable list of recorded exception models."""
        return self._potential_exceptions

    def get_exceptions_of_type(
        self,
        exc_type: type[BaseException],
    ) -> list[SymbolicException]:
        """Return recorded exceptions compatible with concrete ``exc_type``."""
        result: list[SymbolicException] = []
        for exc in self._potential_exceptions:
            if isinstance(exc.exc_type, type):
                if issubclass(exc.exc_type, exc_type):
                    result.append(exc)
            elif exc.type_name == exc_type.__name__:
                result.append(exc)
        return result

    def _check_exception_condition(
        self,
        context_constraints: list[z3.BoolRef],
        condition: z3.BoolRef,
    ) -> SolverResult:
        """Check one symbolic exception condition while preserving solver uncertainty."""
        return self.solver.check_sat_result([*context_constraints, condition])

    def verify_raises_contract(
        self,
        contract: RaisesContract,
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """Check whether a matching modeled exception is feasible.

        Returns:
            A success flag and an explanatory failure or inconclusive message.

        Limitations:
            With no context constraints, matching metadata is accepted without
            a solver feasibility query.
        """
        matching_exceptions = [exc for exc in self._potential_exceptions if contract.matches(exc)]
        if not matching_exceptions:
            return False, f"No {contract.type_name} exceptions found"

        if not context_constraints:
            return True, None

        feasible: list[SymbolicException] = []
        unknown_seen = False
        for exc in matching_exceptions:
            if exc.condition is None or z3.is_true(exc.condition):
                feasible.append(exc)
                continue

            result = self._check_exception_condition(context_constraints, exc.condition)
            if result.is_sat:
                feasible.append(exc)
            elif result.is_unknown:
                unknown_seen = True

        if not feasible:
            if unknown_seen:
                return (
                    False,
                    f"{contract.type_name} raises contract inconclusive: solver returned unknown",
                )
            return (
                False,
                f"No {contract.type_name} exceptions are feasible under the given path constraints",
            )
        return True, None

    def check_unhandled_exceptions(
        self,
        exc_state: ExceptionState,
    ) -> list[SymbolicException]:
        """Return exceptions on paths already marked as propagated."""
        unhandled: list[SymbolicException] = []
        for path in exc_state.exception_paths:
            if path.propagated:
                unhandled.append(path.exception)
        return unhandled

    def analyze_division(
        self,
        divisor: object,
        pc: int,
    ) -> SymbolicException | None:
        """Model division-by-zero occurrence for a divisor value.

        Limitations:
            Unsupported divisor values yield an unconstrained possible error.
        """
        if isinstance(divisor, (int, float)):
            if divisor == 0:
                return SymbolicException.concrete(
                    ZeroDivisionError,
                    "division by zero",
                    raised_at=pc,
                )
            return None
        if has_to_z3(divisor):
            z3_val: z3.ExprRef = divisor.to_z3()
            condition: z3.BoolRef = z3_val == 0
            return SymbolicException.symbolic(
                f"div_zero_{pc}",
                ZeroDivisionError,
                condition,
                pc,
            )
        return SymbolicException.symbolic(
            f"div_zero_{pc}",
            ZeroDivisionError,
            z3.Bool(f"may_zero_{pc}"),
            pc,
        )

    def analyze_index_access(
        self,
        container: object,
        index: object,
        pc: int,
    ) -> SymbolicException | None:
        """Model out-of-range access when container length is observable."""
        if _has_length(container):
            length = container.length
            if isinstance(index, int):
                if has_to_z3(length):
                    z3_len = length.to_z3()
                    condition_i: z3.BoolRef = z3.Or(
                        get_int_val(index) >= z3_len,
                        get_int_val(index) < -z3_len,
                    )
                    return SymbolicException.symbolic(
                        f"index_error_{pc}",
                        IndexError,
                        condition_i,
                        pc,
                    )
                if isinstance(length, int):
                    if index >= length or index < -length:
                        return SymbolicException.concrete(
                            IndexError,
                            "index out of range",
                            raised_at=pc,
                        )
                    return None
            if has_to_z3(index):
                z3_idx: z3.ExprRef = index.to_z3()
                if has_to_z3(length):
                    z3_len2 = length.to_z3()
                    condition_s: z3.BoolRef = z3.Or(z3_idx >= z3_len2, z3_idx < -z3_len2)
                else:
                    if not isinstance(length, int):
                        return None
                    condition_s = z3.Or(
                        z3_idx >= get_int_val(length),
                        z3_idx < get_int_val(-length),
                    )
                return SymbolicException.symbolic(
                    f"index_error_{pc}",
                    IndexError,
                    condition_s,
                    pc,
                )
        return None

    def analyze_key_access(
        self,
        container: object,
        key: object,
        pc: int,
    ) -> SymbolicException | None:
        """Model missing-key access when membership is concrete.

        Limitations:
            Non-concrete membership results produce an unconstrained possible
            ``KeyError``.
        """
        if _has_contains_key(container):
            contains_result = container.contains_key(key)
            if isinstance(contains_result, bool):
                if not contains_result:
                    return SymbolicException.concrete(
                        KeyError,
                        str(key),
                        raised_at=pc,
                    )
                return None
        return SymbolicException.symbolic(
            f"key_error_{pc}",
            KeyError,
            z3.Bool(f"key_missing_{pc}"),
            pc,
        )

    def analyze_attribute_access(
        self,
        obj: object,
        attr: str,
        pc: int,
    ) -> SymbolicException | None:
        """Model proven missing attribute access for supported object checks."""
        if obj is None:
            return SymbolicException.concrete(
                AttributeError,
                f"'NoneType' object has no attribute '{attr}'",
                raised_at=pc,
            )
        if _has_attribute_checker(obj):
            has_attr = obj.has_attribute(attr)
            if isinstance(has_attr, bool):
                if not has_attr:
                    type_name = type(obj).__name__
                    return SymbolicException.concrete(
                        AttributeError,
                        f"'{type_name}' object has no attribute '{attr}'",
                        raised_at=pc,
                    )
                return None
        return None

    def analyze_assertion(
        self,
        condition: object,
        message: str | None,
        pc: int,
    ) -> SymbolicException | None:
        """Model assertion failure from concrete or symbolic falsiness.

        Limitations:
            Unsupported truthiness values yield an unconstrained possible
            ``AssertionError``.
        """
        if isinstance(condition, bool):
            if not condition:
                return SymbolicException.concrete(
                    AssertionError,
                    message or "",
                    raised_at=pc,
                )
            return None
        if _has_could_be_falsy(condition):
            falsy_cond = condition.could_be_falsy()
            return SymbolicException.symbolic(
                f"assertion_{pc}",
                AssertionError,
                falsy_cond,
                pc,
            )
        return SymbolicException.symbolic(
            f"assertion_{pc}",
            AssertionError,
            z3.Bool(f"assert_fail_{pc}"),
            pc,
        )
