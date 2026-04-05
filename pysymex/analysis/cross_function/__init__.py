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

"""Cross-function analysis — slim hub with re-exports."""

from pysymex.analysis.cross_function.core import (
    PYTHON_TYPE_TO_PYTYPE as PYTHON_TYPE_TO_PYTYPE,
)
from pysymex.analysis.cross_function.core import CallGraph as CallGraph
from pysymex.analysis.cross_function.core import CallGraphBuilder as CallGraphBuilder
from pysymex.analysis.cross_function.core import (
    ContextSensitiveAnalyzer as ContextSensitiveAnalyzer,
)
from pysymex.analysis.cross_function.core import (
    CrossFunctionAnalyzer as CrossFunctionAnalyzer,
)
from pysymex.analysis.cross_function.core import EffectAnalyzer as EffectAnalyzer
from pysymex.analysis.cross_function.core import (
    FunctionSummaryCache as FunctionSummaryCache,
)
from pysymex.analysis.cross_function.core import (
    infer_return_type as infer_return_type,
)
from pysymex.analysis.cross_function.types import CallContext as CallContext
from pysymex.analysis.cross_function.types import CallGraphNode as CallGraphNode
from pysymex.analysis.cross_function.types import CallSiteInfo as CallSiteInfo
from pysymex.analysis.cross_function.types import (
    ContextSensitiveSummary as ContextSensitiveSummary,
)
from pysymex.analysis.cross_function.types import Effect as Effect
from pysymex.analysis.cross_function.types import EffectSummary as EffectSummary

_infer_return_type = infer_return_type

__all__ = [
    "PYTHON_TYPE_TO_PYTYPE",
    "CallContext",
    "CallGraph",
    "CallGraphBuilder",
    "CallGraphNode",
    "CallSiteInfo",
    "ContextSensitiveAnalyzer",
    "ContextSensitiveSummary",
    "CrossFunctionAnalyzer",
    "Effect",
    "EffectAnalyzer",
    "EffectSummary",
    "FunctionSummaryCache",
    "_infer_return_type",
    "infer_return_type",
]
