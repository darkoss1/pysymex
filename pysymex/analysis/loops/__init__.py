# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Loop analysis for pysymex.
This module provides loop detection, bound inference, and invariant generation
for improving symbolic execution of loops.

Split into:
- loops_types: dataclasses, enums, type-only classes
- loops_core: logic classes
"""

from pysymex.analysis.loops.core import (
    InductionVariableDetector as InductionVariableDetector,
)
from pysymex.analysis.loops.core import LoopBoundInference as LoopBoundInference
from pysymex.analysis.loops.core import LoopDetector as LoopDetector
from pysymex.analysis.loops.core import (
    LoopInvariantGenerator as LoopInvariantGenerator,
)
from pysymex.analysis.loops.core import LoopSummarizer as LoopSummarizer
from pysymex.analysis.loops.core import LoopWidening as LoopWidening
from pysymex.analysis.loops.types import InductionVariable as InductionVariable
from pysymex.analysis.loops.types import LoopBound as LoopBound
from pysymex.analysis.loops.types import LoopInfo as LoopInfo
from pysymex.analysis.loops.types import LoopSummary as LoopSummary
from pysymex.analysis.loops.types import LoopType as LoopType

__all__ = [
    "InductionVariable",
    "InductionVariableDetector",
    "LoopBound",
    "LoopBoundInference",
    "LoopDetector",
    "LoopInfo",
    "LoopInvariantGenerator",
    "LoopSummarizer",
    "LoopSummary",
    "LoopType",
    "LoopWidening",
]
