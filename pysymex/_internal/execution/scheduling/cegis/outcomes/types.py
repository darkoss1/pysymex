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

"""Typed CEGIS owner outcomes and exact proof certificates."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
)


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
