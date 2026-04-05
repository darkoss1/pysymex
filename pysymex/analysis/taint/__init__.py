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

"""Taint analysis package — taint tracking and taint-flow checking.

Submodules
----------
core      Taint sources/sinks, labels, flows, tracker, basic analyzer
checker   Flow-sensitive taint checker with CFG-based data-flow analysis
"""

from __future__ import annotations

from pysymex.analysis.taint.checker import (
    TaintChecker,
    TaintViolation,
)
from pysymex.analysis.taint.core import (
    TaintAnalyzer,
    TaintedValue,
    TaintFlow,
    TaintLabel,
    TaintPolicy,
    TaintSink,
    TaintSource,
    TaintTracker,
)

__all__ = [
    "TaintAnalyzer",
    "TaintChecker",
    "TaintFlow",
    "TaintLabel",
    "TaintPolicy",
    "TaintSink",
    "TaintSource",
    "TaintTracker",
    "TaintViolation",
    "TaintedValue",
]
