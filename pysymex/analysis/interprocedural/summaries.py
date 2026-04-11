# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

"""Interprocedural summary exports.

This module provides the blueprint path for function summary constructs used
by cross-function and context-sensitive analyses.
"""

from __future__ import annotations

from pysymex.analysis.interprocedural.cross_function import (
    CallSite,
    CallType,
    FunctionSummary,
)
from pysymex.analysis.summaries.core import (
    SummaryAnalyzer,
    SummaryBuilder,
    SummaryRegistry,
    compose_summaries,
    create_builtin_summaries,
    instantiate_summary,
)
from pysymex.analysis.summaries.types import ExceptionInfo, ModifiedVariable, ParameterInfo

__all__ = [
    "CallSite",
    "CallType",
    "ExceptionInfo",
    "FunctionSummary",
    "ModifiedVariable",
    "ParameterInfo",
    "SummaryAnalyzer",
    "SummaryBuilder",
    "SummaryRegistry",
    "compose_summaries",
    "create_builtin_summaries",
    "instantiate_summary",
]
