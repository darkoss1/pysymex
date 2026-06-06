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

"""Loop analysis for symbolic execution.

Provides loop detection from bytecode, bound inference via Z3,
induction-variable recognition, invariant generation and proof,
loop summarisation for fast-path execution, and widening operators.
"""

from pysymex.analysis.static.loops.bounds import LoopBoundInference
from pysymex.analysis.static.loops.detector import LoopDetector
from pysymex.analysis.static.loops.induction import InductionVariableDetector
from pysymex.analysis.static.loops.invariant_generation import (
    LoopInvariantGenerator,
)
from pysymex.analysis.static.loops.summaries import LoopSummarizer
from pysymex.analysis.static.loops.widening import LoopWidening
from pysymex.analysis.static.loops.types import InductionVariable
from pysymex.analysis.static.loops.types import LoopBound
from pysymex.analysis.static.loops.types import LoopInfo
from pysymex.analysis.static.loops.types import LoopInvariantProof
from pysymex.analysis.static.loops.types import (
    LoopInvariantProofStatus,
)
from pysymex.analysis.static.loops.types import LoopSummary
from pysymex.analysis.static.loops.types import LoopType

__all__ = [
    "InductionVariable",
    "InductionVariableDetector",
    "LoopBound",
    "LoopBoundInference",
    "LoopDetector",
    "LoopInfo",
    "LoopInvariantGenerator",
    "LoopInvariantProof",
    "LoopInvariantProofStatus",
    "LoopSummarizer",
    "LoopSummary",
    "LoopType",
    "LoopWidening",
]
