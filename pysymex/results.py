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

"""Public result, outcome, and summary helpers."""

from __future__ import annotations

from pysymex._internal.api.results import AnalysisOutcome
from pysymex._internal.api.results import ExecutionResult
from pysymex._internal.api.results import OutcomeEvidence
from pysymex._internal.api.results import OutcomeSubreason
from pysymex._internal.api.results import ScanResult
from pysymex._internal.api.results import TerminationProof
from pysymex._internal.api.results import TerminationStatus
from pysymex._internal.api.results import VerifiedExecutionResult
from pysymex._internal.api.results import clean
from pysymex._internal.api.results import count
from pysymex._internal.api.results import data
from pysymex._internal.api.results import degraded

__all__ = [
    "AnalysisOutcome",
    "ExecutionResult",
    "OutcomeEvidence",
    "OutcomeSubreason",
    "ScanResult",
    "TerminationProof",
    "TerminationStatus",
    "VerifiedExecutionResult",
    "clean",
    "count",
    "data",
    "degraded",
]
