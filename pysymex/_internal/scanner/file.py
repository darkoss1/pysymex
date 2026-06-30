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

"""Single-file scanning pipeline orchestration.

This module coordinates a single source-file scan. It loads bytecode, gathers
scan candidates, delegates execution setup and symbolic passes to execution
owners, and stores normalized issue records in a :class:`ScanResult`.
"""

from __future__ import annotations

import ast
import time
from contextlib import ExitStack
from datetime import datetime
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.loading.globals import build_module_globals
from pysymex._internal.analysis.scan.loading.package.context import (
    detect_package_name,
    scoped_package_import_path,
)
from pysymex._internal.analysis.scan.loading.source.paths import SourceScanPaths
from pysymex._internal.analysis.scan.preflight.collector import find_scan_preflight
from pysymex._internal.analysis.scan.symbolic_inputs import TypeHintExtractor
from pysymex._internal.config.defaults import DEFAULT_TRACE_VERBOSITY
from pysymex._internal.config.environment import scanner_issue_dedup_enabled
from pysymex._internal.core.cache.control import process_caches_disabled
from pysymex._internal.core.outcome import OutcomePolicy
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.scan.setup import build_scan_execution_setup
from pysymex._internal.logging.root import get_logger
from pysymex._internal.pathing import normalize_input_path
from pysymex._internal.scanner.code import get_code_objects_with_context
from pysymex._internal.scanner.issues import ScannerIssueSink
from pysymex._internal.scanner.types import ScanResult

if TYPE_CHECKING:
    import types
    from pathlib import Path

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor
    from pysymex._internal.execution.scan.metrics import ExecutionMetrics
    from pysymex._internal.execution.scan.types import (
        CodeContext,
        ScanExecutionObserver,
        ScanExecutionSetup,
    )
    from pysymex._internal.scanner.protocols import ScanReporter
    from pysymex._internal.tracing.scan import ScanTracer

logger = get_logger(__name__)


def _read_scan_source(file_path: Path) -> str:
    """Return UTF-8 source text for a scan target."""
    return file_path.read_text(encoding="utf-8")


def _extract_source_type_hints(content: str) -> dict[tuple[str, str | None], dict[str, str]]:
    """Extract function parameter annotations without executing the module."""
    type_hint_extractor = TypeHintExtractor()
    type_hint_extractor.visit(ast.parse(content))
    return type_hint_extractor.hints


def _load_scan_code_object(content: str, file_path: Path, *, use_sandbox: bool) -> types.CodeType:
    """Compile or sandbox-extract the module code object."""
    if not use_sandbox:
        return compile(content, str(file_path), "exec")

    from pysymex._internal.sandbox.bridge.bytecode import extract_bytecode

    bytecode_blob = extract_bytecode(content.encode("utf-8"), str(file_path))
    return bytecode_blob.reconstruct()


def _selected_scan_code_contexts(
    code_obj: types.CodeType,
    content: str,
    file_path: Path,
    function_filter: str | None,
) -> tuple[list[CodeContext], list[CodeContext]]:
    """Return all code contexts plus the source-level contexts selected for scanning."""
    all_code_with_context = get_code_objects_with_context(code_obj)
    source_scan_paths = SourceScanPaths.collect(content, file_path)
    scan_code_with_context = [
        item for item in all_code_with_context if item[2] in source_scan_paths
    ]
    if function_filter:
        filter_name = function_filter.strip()
        if filter_name:
            scan_code_with_context = [
                item
                for item in scan_code_with_context
                if item[2] == filter_name or item[0].co_name == filter_name
            ]
    return all_code_with_context, scan_code_with_context


def _bind_init_type_hints(
    module_globals: dict[str, object],
    source_type_hints: dict[tuple[str, str | None], dict[str, str]],
) -> None:
    """Attach ``__init__`` annotation snapshots to built class objects."""
    for (func_name, class_name), hints in source_type_hints.items():
        if func_name != "__init__" or class_name is None:
            continue
        class_obj = module_globals.get(class_name)
        if isinstance(class_obj, SymbolicValue):
            class_obj.set_init_type_hints(dict(hints))


def _install_trace_session(
    *,
    trace_enabled: bool | None,
    trace_output_dir: str | None,
    trace_verbosity: str,
    file_path: Path,
    base_config: ExecutionConfig,
    executor: SymbolicExecutor,
) -> ScanTracer | None:
    """Install optional scan tracing while keeping tracing imports lazy."""
    if trace_enabled is False:
        return None

    from pysymex._internal.tracing.scan import install_scan_tracer

    return install_scan_tracer(
        trace_enabled=trace_enabled,
        trace_output_dir=trace_output_dir,
        trace_verbosity=trace_verbosity,
        file_path=file_path,
        config=base_config,
        executor=executor,
    )


def _close_trace_session(tracer: ScanTracer | None, file_path: Path) -> None:
    """Close a trace session without hiding the scan result."""
    if tracer is None:
        return
    try:
        tracer.end_session()
    except Exception:
        logger.debug("Failed to close trace session for %s", file_path, exc_info=True)


def _record_execution_metrics(result: ScanResult, metrics: ExecutionMetrics) -> None:
    """Copy execution pass metrics into the public scan result record."""
    result.paths_explored = metrics.paths_explored
    result.paths_pruned = metrics.paths_pruned
    result.error = metrics.error
    result.degraded_passes = metrics.degraded_passes
    result.outcome_evidence = metrics.outcome_evidence
    result.solver_stats = dict(metrics.solver_stats)
    result.avg_memory_mb = metrics.avg_memory_mb
    if result.error and "KeyboardInterrupt" in result.error:
        result.error = "KeyboardInterrupt"


def _confirm_replay_candidates(
    *,
    confirm_issues: bool,
    result: ScanResult,
    content: str,
    file_path: Path,
    replay_timeout: float,
) -> None:
    """Replay eligible counterexamples when the caller requested confirmation."""
    if not confirm_issues or not result.issues or result.error == "KeyboardInterrupt":
        return

    from pysymex._internal.scanner.replay import confirm_issue_replays

    confirm_issue_replays(
        content=content,
        file_path=file_path,
        issues=result.issues,
        timeout_seconds=replay_timeout,
    )


def _report_scan_error(
    reporter: ScanReporter | None,
    file_path: Path,
    error: str,
) -> None:
    """Forward an error to an optional reporter."""
    if reporter is not None:
        reporter.on_error(file_path, error)


def scan_file(
    file_path: str | Path,
    verbose: bool = False,
    max_paths: int | None = None,
    timeout: float | None = None,
    max_depth: int | None = None,
    auto_tune: bool = True,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    no_cache: bool = False,
    max_iterations: int | None = None,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
    enable_fp_filtering: bool = True,
    detect_overflow: bool = False,
    execution_observer: ScanExecutionObserver | None = None,
    confirm_issues: bool = False,
    replay_timeout: float = 2.0,
    function_filter: str | None = None,
    preloaded_content: str | None = None,
    preloaded_code_obj: types.CodeType | None = None,
    execution_setup: ScanExecutionSetup | None = None,
) -> ScanResult:
    """Scan a single Python file for potential bugs and type mismatch errors.

    Compiles the target file (using a subprocess sandbox if requested), identifies
    scannable functions and classes, extracts source type-hint annotations, and executes
    symbolic execution passes.
    """
    from pysymex._internal.execution.scan.passes import run_symbolic_execution_passes

    file_path = normalize_input_path(file_path)
    result = ScanResult(file_path=str(file_path), timestamp=datetime.now().isoformat())
    start_time = time.perf_counter()
    tracer: ScanTracer | None = None
    resources = ExitStack()
    try:
        resources.enter_context(process_caches_disabled(no_cache))
        content = preloaded_content if preloaded_content is not None else _read_scan_source(file_path)
        resources.enter_context(scoped_package_import_path(file_path))
        full_module_name, package_name = detect_package_name(file_path)
        source_type_hints = _extract_source_type_hints(content)
        code_obj = (
            preloaded_code_obj
            if preloaded_code_obj is not None
            else _load_scan_code_object(content, file_path, use_sandbox=use_sandbox)
        )
        all_code_with_context, scan_code_with_context = _selected_scan_code_contexts(
            code_obj,
            content,
            file_path,
            function_filter,
        )
        result.code_objects = len(scan_code_with_context)

        if execution_setup is None:
            execution_setup = build_scan_execution_setup(
                max_paths=max_paths,
                max_depth=max_depth,
                timeout=timeout,
                no_cache=no_cache,
                max_iterations=max_iterations,
                enable_fp_filtering=enable_fp_filtering,
                detect_overflow=detect_overflow,
                execution_observer=execution_observer,
            )
        elif execution_observer is not None:
            execution_observer.activate(execution_setup.executor)
        base_config = execution_setup.config
        executor = execution_setup.executor
        module_globals = build_module_globals(
            content=content,
            file_path=file_path,
            full_module_name=full_module_name,
            package_name=package_name,
            all_code_with_context=all_code_with_context,
        )
        _bind_init_type_hints(module_globals, source_type_hints)
        tracer = _install_trace_session(
            trace_enabled=trace_enabled,
            trace_output_dir=trace_output_dir,
            trace_verbosity=trace_verbosity,
            file_path=file_path,
            base_config=base_config,
            executor=executor,
        )

        issue_sink = ScannerIssueSink(
            result=result,
            blocked_resolution_sites=set(),
            dedup_enabled=scanner_issue_dedup_enabled(),
            reporter=reporter,
            verbose=verbose,
        )
        for issue in find_scan_preflight(content).issues:
            issue_sink.handle_issue(issue)

        metrics = run_symbolic_execution_passes(
            scan_code_with_context=scan_code_with_context,
            source_type_hints=source_type_hints,
            module_globals=module_globals,
            file_path=file_path,
            base_config=base_config,
            executor=executor,
            auto_tune=auto_tune,
            tracer=tracer,
            issue_sink=issue_sink,
            execution_observer=execution_observer,
        )
        _record_execution_metrics(result, metrics)
        _confirm_replay_candidates(
            confirm_issues=confirm_issues,
            result=result,
            content=content,
            file_path=file_path,
            replay_timeout=replay_timeout,
        )
        result.elapsed_time = time.perf_counter() - start_time
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        result.outcome_evidence.append(OutcomePolicy.evidence_from_exception(e, source="scanner"))
        _report_scan_error(reporter, file_path, result.error)
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        result.outcome_evidence.append(OutcomePolicy.evidence_from_exception(e, source="scanner"))
        _report_scan_error(reporter, file_path, result.error)
    except KeyboardInterrupt as e:
        result.error = "KeyboardInterrupt"
        result.outcome_evidence.append(OutcomePolicy.evidence_from_exception(e, source="scanner"))
        _report_scan_error(reporter, file_path, "KeyboardInterrupt")
    finally:
        _close_trace_session(tracer, file_path)
        resources.close()
    return result
