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

"""``pysymex.tracing`` â€” LLM-optimised execution observability layer.

This package provides a completely decoupled tracing system for
:class:`~pysymex.execution.executors.core.SymbolicExecutor`.  It emits
structured JSONL trace files designed for consumption by LLM agents.

Quick start
-----------
.. code-block:: python

    from pysymex import SymbolicExecutor, ExecutionConfig
    from pysymex.tracing import ExecutionTracer, TracerConfig, VerbosityLevel

    config = ExecutionConfig(max_paths=200)
    executor = SymbolicExecutor(config=config)

    tracer_cfg = TracerConfig(verbosity=VerbosityLevel.DELTA_ONLY)
    tracer = ExecutionTracer(tracer_cfg)

    with tracer:
        tracer.start_session(
            func_name="my_func",
            signature_str="(x: int, y: int) -> int",
            initial_args={"x": "int", "y": "int"},
            source_file="/path/to/my_module.py",
        )
        tracer.install(executor)
        result = executor.execute_function(my_func, {"x": "int", "y": "int"})

    print(f"Trace written to: {tracer._trace_path}")

Alternatively, use the convenience factory::

    from pysymex.tracing import attach_tracer

    tracer, path = attach_tracer(executor, "my_func", initial_args={"x": "int"})
    result = executor.execute_function(my_func, {"x": "int"})
    tracer.end_session()

Public API
----------
"""

from __future__ import annotations

from pysymex.tracing.hooks import TracingHookPlugin
from pysymex.tracing.schemas import (
    ConstraintEntry,
    IssueEvent,
    KeyframeEvent,
    SolveEvent,
    StackDiff,
    StepDeltaEvent,
    SystemContextEvent,
    TraceEvent,
    TracerConfig,
    VarDiff,
    VerbosityLevel,
)
from pysymex.tracing.tracer import ExecutionTracer, TracingSolverProxy, attach_tracer
from pysymex.tracing.z3_utils import Z3SemanticRegistry, Z3Serializer

__all__ = [
    "ConstraintEntry",
    "ExecutionTracer",
    "IssueEvent",
    "KeyframeEvent",
    "SolveEvent",
    "StackDiff",
    "StepDeltaEvent",
    "SystemContextEvent",
    "TraceEvent",
    "TracerConfig",
    "TracingHookPlugin",
    "TracingSolverProxy",
    "VarDiff",
    "VerbosityLevel",
    "Z3SemanticRegistry",
    "Z3Serializer",
    "attach_tracer",
]
