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

"""Execution trace analyzer module - exports pipeline, stream, and CLI facades."""

from __future__ import annotations

from pysymex.tracing.analyzer.cli import build_parser, main
from pysymex.tracing.analyzer.manual import AI_MANUAL, print_ai_manual
from pysymex.tracing.analyzer.pipeline import FilterFn, FilterPipeline, build_pipeline
from pysymex.tracing.analyzer.stream import (
    SummaryAccumulator,
    format_fields,
    format_pretty,
    run,
    stream_events,
)

__all__ = [
    "FilterPipeline",
    "build_pipeline",
    "FilterFn",
    "stream_events",
    "SummaryAccumulator",
    "run",
    "format_pretty",
    "format_fields",
    "print_ai_manual",
    "AI_MANUAL",
    "build_parser",
    "main",
]
