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

"""
Function Summaries for pysymex – re-export hub.
Phase 20: Inter-procedural analysis through function summaries.
"""

from pysymex.analysis.runtime.summaries.analyzer import SummaryAnalyzer
from pysymex.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex.analysis.runtime.summaries.builtins import (
    create_builtin_summaries,
)
from pysymex.analysis.runtime.summaries.builtins import (
    register_builtin_summaries,
)
from pysymex.analysis.runtime.summaries.composition import compose_summaries
from pysymex.analysis.runtime.summaries.instantiation import instantiate_summary
from pysymex.analysis.runtime.summaries.registry import SUMMARY_REGISTRY
from pysymex.analysis.runtime.summaries.registry import SummaryRegistry
from pysymex.analysis.runtime.summaries.registry import get_summary
from pysymex.analysis.runtime.summaries.registry import register_summary
from pysymex.analysis.runtime.summaries.types import CallSite
from pysymex.analysis.runtime.summaries.types import ExceptionInfo
from pysymex.analysis.runtime.summaries.types import FunctionSummary
from pysymex.analysis.runtime.summaries.types import ModifiedVariable
from pysymex.analysis.runtime.summaries.types import ParameterInfo
from pysymex.analysis.runtime.summaries.types import (
    PreconditionCheckResult,
)
from pysymex.analysis.runtime.summaries.types import (
    PreconditionCheckStatus,
)
from pysymex.analysis.runtime.summaries.types import ReadVariable

__all__ = [
    "SUMMARY_REGISTRY",
    "CallSite",
    "ExceptionInfo",
    "FunctionSummary",
    "ModifiedVariable",
    "ParameterInfo",
    "PreconditionCheckResult",
    "PreconditionCheckStatus",
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
