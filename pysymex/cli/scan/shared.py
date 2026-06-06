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

"""Shared scan command helpers."""

from __future__ import annotations

import argparse
import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.scanner.types import ScanResult

_Namespace = argparse.Namespace
_SOLVER_SCAN_METRIC_EVENTS = {
    "queries": "SOLVER_QUERY",
    "sat_results": "SOLVER_SAT",
    "unsat_results": "SOLVER_UNSAT",
    "unknown_results": "SOLVER_UNKNOWN",
}


def typed_scan_results(results: Sequence[object]) -> list[ScanResult]:
    """Filter a sequence of generic results, returning only ScanResult instances.

    Args:
        results (Sequence[object]): Sequence of raw execution/scan results.

    Returns:
        list[ScanResult]: List containing only ScanResult instances.
    """
    from pysymex.scanner.types import ScanResult as _ScanResult

    return [result for result in results if isinstance(result, _ScanResult)]


@runtime_checkable
class IndexableObjectSequence(Protocol):
    """Protocol for indexable sequences of opaque objects."""

    def __len__(self) -> int:
        """Return sequence length."""
        ...

    def __getitem__(self, index: int) -> object:
        """Return sequence item by index."""
        ...


def call_with_supported_kwargs(
    func: Callable[..., object],
    *args: object,
    **kwargs: object,
) -> object:
    """Call *func* with only keyword args accepted by its runtime signature."""
    signature = inspect.signature(func)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return func(*args, **kwargs)
    filtered = {k: v for k, v in kwargs.items() if k in signature.parameters}
    return func(*args, **filtered)


def stop_stats_if_requested(args: _Namespace) -> None:
    """Stop stats before final report emission to avoid post-report metric lines."""
    if not getattr(args, "stats", False):
        return
    if getattr(args, "_stats_stopped", False):
        return
    from pysymex.stats import stop

    stop()
    setattr(args, "_stats_stopped", True)


def _scan_solver_metric_total(results: Sequence[ScanResult], key: str) -> int:
    """Return a non-negative integer solver metric total from scan results."""
    total = 0
    for result in results:
        value = result.solver_stats.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        total += max(0, value)
    return total


def _published_solver_metric(registry_metrics: Mapping[str, object], key: str) -> int:
    """Return a non-negative integer solver metric already visible in stats."""
    value = registry_metrics.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def publish_scan_stats_if_requested(args: _Namespace, results: Sequence[object]) -> None:
    """Publish parent-visible scan aggregates to the stats sink before final stop."""
    if not getattr(args, "stats", False):
        return
    scan_results = typed_scan_results(results)
    if not scan_results:
        return

    from pysymex.stats import EventType, emit, registry

    registry.flush()
    total_paths = float(sum(max(0, result.paths_explored) for result in scan_results))
    current_paths = registry.global_metrics.get("total_paths_explored", 0.0)
    if isinstance(current_paths, int | float) and total_paths > float(current_paths):
        emit(EventType.PATH_EXPLORED, total_paths - float(current_paths))

    scan_average_memory_samples = [
        result.avg_memory_mb for result in scan_results if getattr(result, "avg_memory_mb", 0) > 0
    ]
    if scan_average_memory_samples:
        emit(
            EventType.SCAN_AVG_MEMORY,
            sum(scan_average_memory_samples) / len(scan_average_memory_samples),
        )

    for result_key, event_name in _SOLVER_SCAN_METRIC_EVENTS.items():
        total = _scan_solver_metric_total(scan_results, result_key)
        current_key = "solver_queries" if result_key == "queries" else f"solver_{result_key[:-8]}"
        current = _published_solver_metric(registry.global_metrics, current_key)
        delta = total - current
        if delta > 0:
            emit(getattr(EventType, event_name), float(delta))
    registry.flush()


__all__ = [
    "IndexableObjectSequence",
    "call_with_supported_kwargs",
    "publish_scan_stats_if_requested",
    "stop_stats_if_requested",
    "typed_scan_results",
]
