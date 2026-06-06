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

"""Owner outcomes for CEGIS-selected evidence actions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pysymex.core.solver.engine.results import SolverResult
from pysymex.execution.scheduling.cegis.bids import EvidenceAction, EvidenceActionKind

__all__ = [
    "EvidenceCertificate",
    "EvidenceCertificateKind",
    "EvidenceOutcome",
    "EvidenceOutcomeKind",
    "dominance_certificate_outcome",
    "solver_unsat_core_outcome",
]


class EvidenceOutcomeKind(Enum):
    """Typed outcomes emitted by the owner of a selected evidence action."""

    EXECUTED = "executed"
    SAT = "sat"
    EXACT_UNSAT = "exact_unsat"
    EXACT_DOMINATED = "exact_dominated"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"
    SOLVER_UNKNOWN = "solver_unknown"
    TIMEOUT = "timeout"


class EvidenceCertificateKind(Enum):
    """Exact proof certificate families accepted by phase-0 outcomes."""

    UNSAT_CORE = "unsat_core"
    DOMINANCE = "dominance"


@dataclass(frozen=True, slots=True)
class EvidenceCertificate:
    """Exact owner certificate describing which capsules a proof covers."""

    kind: EvidenceCertificateKind
    subject_capsule_id: str
    covered_capsule_ids: tuple[str, ...]
    core_indices: tuple[int, ...] = ()
    explanation: str = ""

    def covers(self, capsule_id: str) -> bool:
        """Return whether this certificate covers ``capsule_id``."""
        return capsule_id in self.covered_capsule_ids


@dataclass(frozen=True, slots=True)
class EvidenceOutcome:
    """Result returned by the subsystem that owns a CEGIS-selected action.

    CEGIS may rank and select actions, but only exact owner outcomes may remove
    work. Unknown, timeout, unsupported, and inconclusive outcomes remain
    visible as non-removing evidence.
    """

    action: EvidenceAction
    kind: EvidenceOutcomeKind
    removed_capsule_ids: tuple[str, ...] = ()
    explanation: str = ""
    certificate: EvidenceCertificate | None = None

    @property
    def is_exact_removal_evidence(self) -> bool:
        """Return whether this outcome is an exact owner proof for work removal."""
        return self.kind in {
            EvidenceOutcomeKind.EXACT_UNSAT,
            EvidenceOutcomeKind.EXACT_DOMINATED,
        }

    @property
    def valid_removed_capsule_ids(self) -> tuple[str, ...]:
        """Return removed capsules only when all no-false-prune gates are satisfied."""
        if (
            self.removed_capsule_ids
            and self.action.may_remove_work
            and self.action.requires_exact_evidence
            and self.is_exact_removal_evidence
        ):
            covered_capsule_ids = self._covered_capsule_ids()
            return tuple(
                capsule_id
                for capsule_id in self.removed_capsule_ids
                if capsule_id in covered_capsule_ids
            )
        return ()

    @property
    def has_invalid_removal_attempt(self) -> bool:
        """Return whether the outcome tried to remove work without exact evidence."""
        return self.valid_removed_capsule_ids != self.removed_capsule_ids

    def _covered_capsule_ids(self) -> frozenset[str]:
        """Return capsule IDs covered by exact owner evidence for this action."""
        certificate = self.certificate
        if certificate is None:
            return frozenset()
        if not self._certificate_matches_outcome(certificate):
            return frozenset()
        return frozenset(certificate.covered_capsule_ids)

    def _certificate_matches_outcome(self, certificate: EvidenceCertificate) -> bool:
        """Return whether ``certificate`` matches the action and exact outcome kind."""
        if certificate.subject_capsule_id != self.action.capsule_id:
            return False
        if certificate.kind is EvidenceCertificateKind.UNSAT_CORE:
            return (
                self.kind is EvidenceOutcomeKind.EXACT_UNSAT
                and self.action.kind is EvidenceActionKind.TRY_UNSAT_CORE
            )
        if certificate.kind is EvidenceCertificateKind.DOMINANCE:
            return (
                self.kind is EvidenceOutcomeKind.EXACT_DOMINATED
                and self.action.kind is EvidenceActionKind.CHECK_DOMINANCE
            )
        return False


def solver_unsat_core_outcome(
    action: EvidenceAction,
    solver_result: SolverResult,
    *,
    covered_capsule_ids: tuple[str, ...],
    core_indices: tuple[int, ...],
    timed_out: bool = False,
) -> EvidenceOutcome:
    """Build a CEGIS outcome from solver-owned UNSAT-core evidence.

    SAT, UNKNOWN, timeout, malformed action, and missing-core cases are
    explicitly non-removing. Only structured UNSAT with at least one core index
    can produce an ``UNSAT_CORE`` certificate.
    """
    if action.kind is not EvidenceActionKind.TRY_UNSAT_CORE:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action is not an UNSAT-core solver action",
        )
    if solver_result.is_sat:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.SAT,
            explanation="solver established SAT; no UNSAT removal certificate",
        )
    if solver_result.is_unknown:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.TIMEOUT if timed_out else EvidenceOutcomeKind.SOLVER_UNKNOWN,
            explanation="solver result is inconclusive",
        )
    if not solver_result.is_unsat:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="solver did not establish exact UNSAT",
        )
    if not core_indices:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="solver established UNSAT but no core certificate was supplied",
        )
    if action.capsule_id not in covered_capsule_ids:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="UNSAT-core certificate did not cover the selected capsule",
        )
    certificate = EvidenceCertificate(
        kind=EvidenceCertificateKind.UNSAT_CORE,
        subject_capsule_id=action.capsule_id,
        covered_capsule_ids=covered_capsule_ids,
        core_indices=core_indices,
        explanation="solver-owned UNSAT core evidence",
    )
    return EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=covered_capsule_ids,
        certificate=certificate,
        explanation="solver established exact UNSAT core coverage",
    )


def dominance_certificate_outcome(
    action: EvidenceAction,
    *,
    dominated_capsule_ids: tuple[str, ...],
) -> EvidenceOutcome:
    """Build a CEGIS outcome from frontier-owned exact dominance evidence.

    The current runtime owner uses this for checkpoint-validated structural
    duplicates only.
    Empty, self-dominating, or malformed actions remain non-removing.
    """
    if action.kind is not EvidenceActionKind.CHECK_DOMINANCE:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="action is not a dominance check",
        )
    if not dominated_capsule_ids:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="dominance check did not prove any dominated capsules",
        )
    if action.capsule_id in dominated_capsule_ids:
        return EvidenceOutcome(
            action=action,
            kind=EvidenceOutcomeKind.INCONCLUSIVE,
            explanation="dominance evidence cannot remove the selected capsule",
        )
    certificate = EvidenceCertificate(
        kind=EvidenceCertificateKind.DOMINANCE,
        subject_capsule_id=action.capsule_id,
        covered_capsule_ids=dominated_capsule_ids,
        explanation="frontier-owned exact checkpoint duplicate evidence",
    )
    return EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_DOMINATED,
        removed_capsule_ids=dominated_capsule_ids,
        certificate=certificate,
        explanation="frontier established exact checkpoint duplicate coverage",
    )
