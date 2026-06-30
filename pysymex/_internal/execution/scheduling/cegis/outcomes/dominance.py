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

"""Frontier-owned dominance outcomes for selected CEGIS actions."""

from __future__ import annotations

from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
)
from pysymex._internal.execution.scheduling.cegis.outcomes.types import (
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOutcome,
    EvidenceOutcomeKind,
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
