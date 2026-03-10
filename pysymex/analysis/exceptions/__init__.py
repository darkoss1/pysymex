"""Exception analysis package — exception tracking and handler analysis.

Submodules
----------
analysis  Exception type inference and warning generation
handler   Exception handler detection and skip-issue logic
"""

from __future__ import annotations

from pysymex.analysis.exceptions.analysis import (
    ExceptionAnalyzer,
    ExceptionWarningKind,
)
from pysymex.analysis.exceptions.handler import (
    ExceptionHandlerAnalyzer,
    ExceptionHandlerInfo,
    ExceptionHandlerType,
    should_skip_issue_in_handler,
)

__all__ = [
    "ExceptionAnalyzer",
    "ExceptionHandlerAnalyzer",
    "ExceptionHandlerInfo",
    "ExceptionHandlerType",
    "ExceptionWarningKind",
    "should_skip_issue_in_handler",
]
