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

"""Evidence records for contract reasoning."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    import z3

    from pysymex._internal.contracts.enums import VerificationResult
    from pysymex._internal.contracts.ir.obligations import ObligationIR
    from pysymex.contracts import ContractKind, ContractSeverity


def _empty_counterexample() -> Mapping[str, object]:
    """Return an immutable empty counterexample mapping."""
    return MappingProxyType({})


def _empty_unsupported_reasons() -> tuple[UnsupportedReason, ...]:
    """Return an empty unsupported-reason tuple."""
    return ()


def _empty_theory_profile() -> tuple[TheoryFeature, ...]:
    """Return an empty theory-profile tuple."""
    return ()


class SolverStatus(Enum):
    """Solver status attached to contract evidence."""

    NOT_RUN = "not_run"
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class UnsupportedReason(Enum):
    """Classified reason a contract obligation could not be modeled."""

    ALIAS_IMPRECISION = "alias_imprecision"
    EFFECT_WRITE = "effect_write"
    PREDICATE_LOWERING = "predicate_lowering"
    PRECISION_LOSS = "precision_loss"
    SOLVER_FAILURE = "solver_failure"
    UNBOUNDED_QUANTIFIER = "unbounded_quantifier"
    UNSUPPORTED_DECLARATION = "unsupported_declaration"


class TheoryFeature(Enum):
    """SMT theory family used by a contract query."""

    ARRAY = "array"
    BIT_VECTOR = "bit_vector"
    BOOL = "bool"
    FLOATING_POINT = "floating_point"
    INTEGER = "integer"
    QUANTIFIER = "quantifier"
    REAL = "real"
    STRING = "string"
    UNINTERPRETED = "uninterpreted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    """Path-specific outcome for one contract obligation."""

    obligation: ObligationIR
    status: VerificationResult
    solver_status: SolverStatus
    message: str
    model: z3.ModelRef | None = None
    counterexample: Mapping[str, object] = field(default_factory=_empty_counterexample)
    unsupported_reasons: tuple[UnsupportedReason, ...] = field(
        default_factory=_empty_unsupported_reasons,
    )
    timeout_ms: int | None = None
    need_model: bool = False
    theory_profile: tuple[TheoryFeature, ...] = field(default_factory=_empty_theory_profile)

    @property
    def kind(self) -> ContractKind:
        """Return the contract kind for this evidence."""
        return self.obligation.clause.kind

    @property
    def severity(self) -> ContractSeverity:
        """Return the declared severity for this evidence."""
        return self.obligation.clause.severity

    @property
    def condition(self) -> str:
        """Return the original display condition."""
        return self.obligation.clause.condition

    @property
    def line_number(self) -> int | None:
        """Return the source line associated with the clause when known."""
        return self.obligation.clause.line_number

    @property
    def function_name(self) -> str:
        """Return the target function name."""
        return self.obligation.clause.target.name


def evidence_result(
    obligation: ObligationIR,
    status: VerificationResult,
    solver_status: SolverStatus,
    message: str,
    *,
    model: z3.ModelRef | None = None,
    unsupported_reasons: tuple[UnsupportedReason, ...] = (),
    timeout_ms: int | None = None,
    need_model: bool = False,
    theory_profile: tuple[TheoryFeature, ...] = (),
) -> EvidenceResult:
    """Create a normalized evidence result."""
    return EvidenceResult(
        obligation=obligation,
        status=status,
        solver_status=solver_status,
        message=message,
        model=model,
        unsupported_reasons=unsupported_reasons,
        timeout_ms=timeout_ms,
        need_model=need_model,
        theory_profile=theory_profile,
    )
