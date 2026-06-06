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

"""Contract intermediate records.

The IR package owns normalized contract clauses, path-local obligations, and
evidence records. Runtime hooks, verifier APIs, and report adapters should use
these records instead of deriving proof status from ad hoc booleans or issues.
"""

from __future__ import annotations

from pysymex.contracts.ir.clauses import ContractClauseIR, ContractTarget, target_for_source
from pysymex.contracts.ir.evidence import (
    EvidenceResult,
    SolverStatus,
    TheoryFeature,
    UnsupportedReason,
)
from pysymex.contracts.ir.obligations import ObligationHook, ObligationIR, QueryKind
from pysymex.contracts.ir.predicates import (
    PredicateIR,
    PredicateIRKind,
    QuantifierPredicateIR,
    QuantifierPredicateKind,
)

__all__ = [
    "ContractClauseIR",
    "ContractTarget",
    "EvidenceResult",
    "ObligationHook",
    "ObligationIR",
    "PredicateIR",
    "PredicateIRKind",
    "QueryKind",
    "QuantifierPredicateIR",
    "QuantifierPredicateKind",
    "SolverStatus",
    "TheoryFeature",
    "UnsupportedReason",
    "target_for_source",
]
