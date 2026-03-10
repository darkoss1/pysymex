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
