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

"""Execution tracer module - exports event dispatcher, solver proxy, and session managers."""

from __future__ import annotations

from pysymex.tracing.tracer.core import ExecutionTracer
from pysymex.tracing.tracer.factory import attach_tracer
from pysymex.tracing.tracer.helpers import (
    TraceWriter as _TraceWriter,
    normalise_config_snapshot as _normalise_config_snapshot,
    to_config_scalar as _to_config_scalar,
)
from pysymex.tracing.tracer.proxy import TracingSolverProxy

__all__ = [
    "ExecutionTracer",
    "TracingSolverProxy",
    "attach_tracer",
    "_TraceWriter",
    "_normalise_config_snapshot",
    "_to_config_scalar",
]
