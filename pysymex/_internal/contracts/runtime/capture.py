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

"""Capture contract verification outcomes during symbolic execution.

Appends per-clause :class:`~pysymex._internal.contracts.enums.VerificationResult`
records to a :class:`contextvars.ContextVar` while
:func:`capture_runtime_contract_outcomes` is active. Runtime hooks build
detector issues separately and record them through this module.
Does not compile predicates or query the solver.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.contracts.enums import VerificationResult
    from pysymex._internal.contracts.ir.evidence import EvidenceResult
    from pysymex._internal.contracts.types import Contract
    from pysymex.contracts import ContractKind, ContractSeverity


@dataclass(frozen=True, slots=True)
class RuntimeContractOutcome:
    """Immutable record of one evaluated contract clause on the active path."""

    kind: ContractKind
    condition: str
    function_identity: int
    function_name: str
    line_number: int | None
    severity: ContractSeverity
    result: VerificationResult
    issue: Issue | None = None
    evidence: EvidenceResult | None = None

    @property
    def obligation_key(self) -> tuple[object, ...]:
        """Return a stable key for deduplicating obligation counters."""
        if self.evidence is not None:
            obligation_key = self.evidence.obligation.obligation_id
            return (
                self.kind,
                self.condition,
                self.function_identity,
                self.line_number,
                *obligation_key,
            )
        return (self.kind, self.condition, self.function_identity, self.line_number)

    @classmethod
    def record_outcome(
        cls,
        clause: Contract,
        func: Callable[..., object],
        result: VerificationResult,
        issue: Issue | None = None,
        evidence: EvidenceResult | None = None,
    ) -> None:
        """Record one evaluated clause outcome.

        Appends the outcome to the active capture context if
        :func:`capture_runtime_contract_outcomes` is currently active.
        """
        outcomes = _captured_outcomes.get()
        if outcomes is None:
            return
        outcomes.append(
            cls(
                kind=clause.kind,
                condition=clause.condition,
                function_identity=id(func),
                function_name=getattr(func, "__name__", "unknown"),
                line_number=clause.line_number,
                severity=clause.severity,
                result=result,
                issue=issue,
                evidence=evidence,
            ),
        )

    @classmethod
    def record_evidence(
        cls,
        clause: Contract,
        func: Callable[..., object],
        evidence: EvidenceResult,
        issue: Issue | None = None,
    ) -> None:
        """Record one evaluated clause directly from evidence."""
        cls.record_outcome(clause, func, evidence.status, issue, evidence=evidence)


_captured_outcomes: ContextVar[list[RuntimeContractOutcome] | None] = ContextVar(
    "contract_runtime_outcomes",
    default=None,
)


@contextmanager
def capture_runtime_contract_outcomes() -> Generator[list[RuntimeContractOutcome]]:
    """Capture dynamic outcomes produced during one verified execution.

    Yields:
        A list where all contract outcomes evaluated during the context lifecycle
        will be appended.

    Side Effects:
        Modifies the thread-local/async-local context variable ``_captured_outcomes``.

    """
    outcomes: list[RuntimeContractOutcome] = []
    token = _captured_outcomes.set(outcomes)
    try:
        yield outcomes
    finally:
        _captured_outcomes.reset(token)
