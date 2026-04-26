# pysymex: Python Symbolic Execution & Formal Verification
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

"""
Function Summaries for pysymex – re-export hub.
Phase 20: Inter-procedural analysis through function summaries.
"""

from pysymex.analysis.summaries.core import SUMMARY_REGISTRY as SUMMARY_REGISTRY
from pysymex.analysis.summaries.core import SummaryAnalyzer as SummaryAnalyzer
from pysymex.analysis.summaries.core import SummaryBuilder as SummaryBuilder
from pysymex.analysis.summaries.core import SummaryRegistry as SummaryRegistry
from pysymex.analysis.summaries.core import compose_summaries as compose_summaries
from pysymex.analysis.summaries.core import (
    create_builtin_summaries as create_builtin_summaries,
)
from pysymex.analysis.summaries.core import get_summary as get_summary
from pysymex.analysis.summaries.core import instantiate_summary as instantiate_summary
from pysymex.analysis.summaries.core import (
    register_builtin_summaries as register_builtin_summaries,
)
from pysymex.analysis.summaries.core import register_summary as register_summary
from pysymex.analysis.summaries.types import CallSite as CallSite
from pysymex.analysis.summaries.types import ExceptionInfo as ExceptionInfo
from pysymex.analysis.summaries.types import FunctionSummary as FunctionSummary
from pysymex.analysis.summaries.types import ModifiedVariable as ModifiedVariable
from pysymex.analysis.summaries.types import ParameterInfo as ParameterInfo
from pysymex.analysis.summaries.types import ReadVariable as ReadVariable

__all__ = [
    "SUMMARY_REGISTRY",
    "CallSite",
    "ExceptionInfo",
    "FunctionSummary",
    "ModifiedVariable",
    "ParameterInfo",
    "ReadVariable",
    "SummaryAnalyzer",
    "SummaryBuilder",
    "SummaryRegistry",
    "compose_summaries",
    "create_builtin_summaries",
    "get_summary",
    "instantiate_summary",
    "register_builtin_summaries",
    "register_summary",
]
