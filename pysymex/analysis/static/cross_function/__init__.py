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

"""Cross-function analysis: call-graph construction, context sensitivity, and call-site tracking."""

from pysymex.analysis.static.cross_function.analyzer import (
    CrossFunctionAnalyzer,
)
from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.analysis.static.cross_function.call_graph.builder import (
    CallGraphBuilder,
)
from pysymex.analysis.static.cross_function.context import (
    ContextSensitiveAnalyzer,
)
from pysymex.analysis.static.cross_function.effects import EffectAnalyzer
from pysymex.analysis.static.cross_function.return_types import (
    PYTHON_TYPE_TO_PYTYPE,
)
from pysymex.analysis.static.cross_function.return_types import infer_return_type
from pysymex.analysis.static.cross_function.summary_cache import (
    FunctionSummaryCache,
)
from pysymex.analysis.static.cross_function.types import CallContext
from pysymex.analysis.static.cross_function.types import CallGraphNode
from pysymex.analysis.static.cross_function.types import CallSiteInfo
from pysymex.analysis.static.cross_function.types import (
    ContextSensitiveSummary,
)
from pysymex.analysis.static.cross_function.types import Effect
from pysymex.analysis.static.cross_function.types import EffectSummary

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
    "infer_return_type",
]
