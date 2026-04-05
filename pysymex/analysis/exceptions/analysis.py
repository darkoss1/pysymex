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

"""
Exception Flow Analysis for PySyMex – re-export hub.

All public names are re-exported from the split sub-modules so that
existing ``from pysymex.analysis.exceptions.analysis import …`` imports
continue to work unchanged.
"""

from pysymex.analysis.exceptions.analysis_core import (
    ExceptionAnalyzer as ExceptionAnalyzer,
)
from pysymex.analysis.exceptions.analysis_core import (
    ExceptionASTAnalyzer as ExceptionASTAnalyzer,
)
from pysymex.analysis.exceptions.analysis_core import (
    ExceptionBytecodeAnalyzer as ExceptionBytecodeAnalyzer,
)
from pysymex.analysis.exceptions.analysis_core import (
    ExceptionChainAnalyzer as ExceptionChainAnalyzer,
)
from pysymex.analysis.exceptions.analysis_core import (
    UncaughtExceptionAnalyzer as UncaughtExceptionAnalyzer,
)
from pysymex.analysis.exceptions.analysis_core import (
    classify_handler_intent as classify_handler_intent,
)
from pysymex.analysis.exceptions.analysis_core import (
    infer_caught_at as infer_caught_at,
)
from pysymex.analysis.exceptions.analysis_core import (
    try_body_calls_crashy_api as try_body_calls_crashy_api,
)


_classify_handler_intent = classify_handler_intent
_try_body_calls_crashy_api = try_body_calls_crashy_api
from pysymex.analysis.exceptions.analysis_types import (
    KNOWN_CRASHY_APIS as KNOWN_CRASHY_APIS,
)
from pysymex.analysis.exceptions.analysis_types import (
    ExceptionHandler as ExceptionHandler,
)
from pysymex.analysis.exceptions.analysis_types import (
    ExceptionWarning as ExceptionWarning,
)
from pysymex.analysis.exceptions.analysis_types import (
    ExceptionWarningKind as ExceptionWarningKind,
)
from pysymex.analysis.exceptions.analysis_types import HandlerIntent as HandlerIntent
from pysymex.analysis.exceptions.analysis_types import TryBlock as TryBlock

__all__ = [
    "KNOWN_CRASHY_APIS",
    "ExceptionASTAnalyzer",
    "ExceptionAnalyzer",
    "ExceptionBytecodeAnalyzer",
    "ExceptionChainAnalyzer",
    "ExceptionHandler",
    "ExceptionWarning",
    "ExceptionWarningKind",
    "HandlerIntent",
    "TryBlock",
    "UncaughtExceptionAnalyzer",
    "_classify_handler_intent",
    "_try_body_calls_crashy_api",
    "classify_handler_intent",
    "infer_caught_at",
    "try_body_calls_crashy_api",
]
