"""Executor setup for runtime detector benchmark cases."""

from __future__ import annotations

import logging
from importlib import import_module
from types import ModuleType

from pysymex.analysis.detectors import DetectorRegistry, default_registry
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig

logging.getLogger("pysymex.execution.executors.core").setLevel(logging.CRITICAL)


def build_executor_for_detector(detector_name: str) -> SymbolicExecutor:
    """Create a single-detector executor for targeted benchmark runs."""
    detector = default_registry.get(detector_name)
    if detector is None:
        raise ValueError(f"Unknown detector name: {detector_name}")
    custom_registry = DetectorRegistry()
    custom_registry.register(type(detector))
    config = ExecutionConfig(
        max_paths=256,
        max_depth=128,
        max_iterations=16384,
        timeout_seconds=20.0,
        enable_cross_function=False,
        enable_type_inference=False,
        use_loop_analysis=False,
        enable_caching=False,
        enable_fp_filtering=False,
        enable_solver_cache=False,
        detect_overflow=True,
        verbose=False,
    )
    return SymbolicExecutor(config=config, detector_registry=custom_registry)


def load_runtime_corpus_module() -> ModuleType:
    """Import and return the runtime detector corpus module."""
    return import_module("tests.repro.detector_corpus_runtime")
