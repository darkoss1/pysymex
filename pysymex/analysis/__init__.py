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

"""Analysis module for bug detection, path exploration, and program reasoning.

Owns higher-level analyses that sit above the VM execution layer:
bug detectors, scanner-integrated range checks, type inference, data-flow
analysis, complexity estimation, loop handling, resource
tracking, and function summaries. All public symbols are lazy-loaded on first
access via ``__getattr__``.

Subpackages:
    scan/        Scanner preparation: loading, preflight, complexity, records.
    static/      Static facts: CFG, dataflow, types, stubs, loops, interprocedural facts.
    runtime/     Runtime-facing support: caches and function summaries.
    domains/     Reusable domain facts: resources, concurrency, exceptions, ranges, strings.
    detectors/   Bug candidates, feasibility, confidence, and detector registries.
    utils/       Analysis utility functions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.analysis.runtime.cache import (
        AnalysisResult,
        AnalysisTask,
        CacheKey,
        CacheKeyType,
    )
    from pysymex.analysis.scan.complexity import (
        ComplexityMetrics,
        analyze_complexity,
        recommended_timeout_ms,
        tune_execution_config,
    )
    from pysymex.analysis.static.dead_code.analyzer import DeadCodeAnalyzer
    from pysymex.analysis.domains.exceptions.analyzer.bytecode import infer_caught_at
    from pysymex.analysis.domains.exceptions.analyzer.core import (
        ExceptionAnalyzer,
    )
    from pysymex.analysis.static.loops.detector import LoopDetector
    from pysymex.analysis.static.loops.widening import LoopWidening
    from pysymex.analysis.domains.resources.leak_detection import (
        ResourceLeakAnalyzer,
    )
    from pysymex.analysis.domains.resources.resource_analyzer import ResourceAnalyzer
    from pysymex.analysis.domains.resources.usage import ResourceKind
    from pysymex.analysis.domains.resources.types import StateTransition
    from pysymex.analysis.runtime.summaries.types import FunctionSummary

_EXPORTS: dict[str, tuple[str, str]] = {
    "AnalysisResult": ("pysymex.analysis.runtime.cache", "AnalysisResult"),
    "AnalysisTask": ("pysymex.analysis.runtime.cache", "AnalysisTask"),
    "CacheKey": ("pysymex.analysis.runtime.cache", "CacheKey"),
    "CacheKeyType": ("pysymex.analysis.runtime.cache", "CacheKeyType"),
    "ComplexityMetrics": ("pysymex.analysis.scan.complexity", "ComplexityMetrics"),
    "analyze_complexity": ("pysymex.analysis.scan.complexity", "analyze_complexity"),
    "recommended_timeout_ms": ("pysymex.analysis.scan.complexity", "recommended_timeout_ms"),
    "tune_execution_config": ("pysymex.analysis.scan.complexity", "tune_execution_config"),
    "DeadCodeAnalyzer": ("pysymex.analysis.static.dead_code.analyzer", "DeadCodeAnalyzer"),
    "ExceptionAnalyzer": ("pysymex.analysis.domains.exceptions.analyzer.core", "ExceptionAnalyzer"),
    "infer_caught_at": ("pysymex.analysis.domains.exceptions.analyzer.bytecode", "infer_caught_at"),
    "LoopDetector": ("pysymex.analysis.static.loops.detector", "LoopDetector"),
    "LoopWidening": ("pysymex.analysis.static.loops.widening", "LoopWidening"),
    "ResourceAnalyzer": (
        "pysymex.analysis.domains.resources.resource_analyzer",
        "ResourceAnalyzer",
    ),
    "ResourceKind": ("pysymex.analysis.domains.resources.usage", "ResourceKind"),
    "ResourceLeakAnalyzer": (
        "pysymex.analysis.domains.resources.leak_detection",
        "ResourceLeakAnalyzer",
    ),
    "StateTransition": ("pysymex.analysis.domains.resources.types", "StateTransition"),
    "FunctionSummary": ("pysymex.analysis.runtime.summaries.types", "FunctionSummary"),
}

__all__ = [
    "AnalysisResult",
    "AnalysisTask",
    "CacheKey",
    "CacheKeyType",
    "ComplexityMetrics",
    "DeadCodeAnalyzer",
    "ExceptionAnalyzer",
    "FunctionSummary",
    "LoopDetector",
    "LoopWidening",
    "ResourceAnalyzer",
    "ResourceKind",
    "ResourceLeakAnalyzer",
    "StateTransition",
    "analyze_complexity",
    "infer_caught_at",
    "recommended_timeout_ms",
    "tune_execution_config",
]


def __getattr__(name: str) -> object:
    """Lazy-load a module attribute or class from its defined location.

    Args:
        name (str): The name of the attribute or class to retrieve.

    Returns:
        object: The imported module attribute or class.

    Raises:
        AttributeError: If the name is not in the module's lazy exports.
    """
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Return the complete directory of names exposed by this module.

    Returns:
        list[str]: A list of all available attribute and class names in the module.
    """
    return lazy_dir(_EXPORTS, globals())
