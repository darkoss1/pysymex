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

"""Taint Analysis for PySyMex — slim hub with re-exports.

Extraction modules:
  - checker_types: enums, dataclasses, definitions (TaintKind, SinkKind, etc.)
  - checker_core: TaintAnalyzer, TaintFlowAnalysis, TaintChecker
"""

from pysymex.analysis.taint.checker_core import TaintAnalyzer as TaintAnalyzer
from pysymex.analysis.taint.checker_core import TaintChecker as TaintChecker
from pysymex.analysis.taint.checker_core import TaintFlowAnalysis as TaintFlowAnalysis
from pysymex.analysis.taint.checker_types import Sanitizer as Sanitizer
from pysymex.analysis.taint.checker_types import SinkKind as SinkKind
from pysymex.analysis.taint.checker_types import TaintDefinitions as TaintDefinitions
from pysymex.analysis.taint.checker_types import TaintedValue as TaintedValue
from pysymex.analysis.taint.checker_types import TaintKind as TaintKind
from pysymex.analysis.taint.checker_types import TaintLabel as TaintLabel
from pysymex.analysis.taint.checker_types import TaintSink as TaintSink
from pysymex.analysis.taint.checker_types import TaintSource as TaintSource
from pysymex.analysis.taint.checker_types import TaintState as TaintState
from pysymex.analysis.taint.checker_types import TaintViolation as TaintViolation

__all__ = [
    "Sanitizer",
    "SinkKind",
    "TaintAnalyzer",
    "TaintChecker",
    "TaintDefinitions",
    "TaintFlowAnalysis",
    "TaintKind",
    "TaintLabel",
    "TaintSink",
    "TaintSource",
    "TaintState",
    "TaintViolation",
    "TaintedValue",
]
