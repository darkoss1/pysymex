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

This module handles the execution of symbolic and abstract range analysis
passes on a single Python source file. It parses AST annotations, manages
sandboxed extraction, constructs execution configurations, and reports issues.
"""

from __future__ import annotations

import ast
import time
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.config.defaults import (
    DEFAULT_SCAN_RANDOM_SEED,
    DEFAULT_SCANNER_FILE_MAX_PATHS,
    DEFAULT_SCANNER_TIMEOUT_SECONDS,
    DEFAULT_TRACE_VERBOSITY,
)
from pysymex.config.environment import scanner_issue_dedup_enabled
from pysymex.core.cache.control import process_caches_disabled
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor
from pysymex.execution.opcodes import load_opcode_handlers
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path
from pysymex.scanner.execution.passes import (
    ScanExecutionObserver,
    run_symbolic_execution_passes,
)
from pysymex.scanner.issue_sink import ScannerIssueSink
from pysymex.analysis.static.code_objects import get_code_objects_with_context
from pysymex.analysis.scan.loading import (
    build_module_globals,
    collect_source_scan_paths,
    detect_package_name,
    scoped_package_import_path,
)
from pysymex.analysis.scan.preflight import (
    collect_bytearray_modulo_index_diagnostics,
    collect_equality_guarded_zero_division_diagnostics,
    collect_guarded_index_offset_diagnostics,
    collect_infeasible_branch_division_suppressions,
    collect_masked_zero_division_diagnostics,
    collect_self_canceling_zero_division_diagnostics,
)
from pysymex.scanner.session import session_var
from pysymex.scanner.symbolic_vars import (
    TypeHintExtractor,
    scanner_solver_timeout_ms,
)
from pysymex.scanner.trace_runtime import install_scanner_tracer
from pysymex.scanner.types import ScanResult
from pysymex.scanner.value_range_passes import emit_value_range_issues

logger = get_logger(__name__)

load_opcode_handlers()  # triggers opcode handler registration


def scan_file(
    file_path: str | Path,
    verbose: bool = False,
    max_paths: int = DEFAULT_SCANNER_FILE_MAX_PATHS,
    timeout: float = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = DEFAULT_SCAN_RANDOM_SEED,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = DEFAULT_TRACE_VERBOSITY,
    enable_fp_filtering: bool = True,
    execution_observer: ScanExecutionObserver | None = None,
) -> ScanResult:
    """Scan a single Python file for potential bugs and type mismatch errors.

    Compiles the target file (using a subprocess sandbox if requested), identifies
    scannable functions and classes, extracts source type-hint annotations, and executes
    symbolic execution and abstract range-check passes.

    Args:
        file_path: Target path of the Python source file.
        verbose: Print detailed scan execution steps and final issues status to console.
        max_paths: Maximum number of symbolic execution paths to explore per function.
        timeout: Hard timeout limit per file in seconds.
        auto_tune: Adjust symbolic execution parameters dynamically based on AST size.
        reporter: Callback listener hook notifying on scan status updates and issues.
        use_sandbox: Extract code objects using isolated AppContainer/namespace sub-processes.
        deterministic_mode: Run path solver heuristics with a fixed random seed.
        random_seed: Seed for deterministic path-exploration randomized steps.
        no_cache: Disable and clear process-local, executor-result, and solver caches
            for this file scan.

    Returns:
        A :class:`~pysymex.scanner.types.ScanResult` containing issues records, path counts,
        and elapsed execution time.

    Side Effects:
        - If a session is set, appends the result via :meth:`~pysymex.scanner.types.ScanSession.add_result`.
        - Installs trace hooks on :class:`~pysymex.execution.executors.core.SymbolicExecutor` instances.
        - Closes opened files and package environment paths on normal/abnormal exit.

    Limitations:
        - Files containing syntactically invalid Python source fail early with a syntax error.
        - Dynamic imports, dynamic reflection patterns, and native modules are approximated.
    """
    file_path = normalize_input_path(file_path)
    session = session_var.get()
    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )
    start_time = time.perf_counter()
    tracer = None
    resources = ExitStack()
    try:
        resources.enter_context(process_caches_disabled(no_cache))
        content = file_path.read_text(encoding="utf-8")
        resources.enter_context(scoped_package_import_path(file_path))
        full_module_name, package_name = detect_package_name(file_path)
        type_hint_extractor = TypeHintExtractor()
        type_hint_extractor.visit(ast.parse(content))
        source_type_hints = type_hint_extractor.hints

        if use_sandbox:
            from pysymex.sandbox.bridge.bytecode import extract_bytecode

            bytecode_blob = extract_bytecode(content.encode("utf-8"), str(file_path))
            code_obj = bytecode_blob.reconstruct()
        else:
            code_obj = compile(content, str(file_path), "exec")
        all_code_with_context = get_code_objects_with_context(code_obj)
        source_scan_paths = collect_source_scan_paths(content, file_path)
        scan_code_with_context = [
            item for item in all_code_with_context if item[2] in source_scan_paths
        ]
        result.code_objects = len(scan_code_with_context)
        config = ExecutionConfig(
            max_paths=max_paths,
            max_depth=1000,
            max_iterations=max_iterations if max_iterations > 0 else max(5000, max_paths * 100),
            timeout_seconds=timeout,
            solver_timeout_ms=scanner_solver_timeout_ms(timeout),
            enable_caching=not no_cache,
            enable_solver_cache=not no_cache,
            enable_cross_function=False,
            deterministic_mode=deterministic_mode,
            random_seed=random_seed,
            enable_fp_filtering=enable_fp_filtering,
        )
        base_config = config
        executor = SymbolicExecutor(config=config)
        if execution_observer is not None:
            execution_observer.activate(executor)

        module_globals = build_module_globals(
            content=content,
            file_path=file_path,
            full_module_name=full_module_name,
            package_name=package_name,
            all_code_with_context=all_code_with_context,
        )
        for (func_name, class_name), hints in source_type_hints.items():
            if func_name != "__init__" or class_name is None:
                continue
            class_obj = module_globals.get(class_name)
            if class_obj is not None:
                setattr(class_obj, "_pysymex_init_type_hints", dict(hints))

        tracer = None
        tracer = install_scanner_tracer(
            trace_enabled=trace_enabled,
            trace_output_dir=trace_output_dir,
            trace_verbosity=trace_verbosity,
            file_path=file_path,
            config=config,
            executor=executor,
        )

        bytearray_modulo_issues = collect_bytearray_modulo_index_diagnostics(content)
        equality_zero_issues = collect_equality_guarded_zero_division_diagnostics(content)
        guarded_index_issues = collect_guarded_index_offset_diagnostics(content)
        masked_zero_issues = collect_masked_zero_division_diagnostics(content)
        self_canceling_zero_issues = collect_self_canceling_zero_division_diagnostics(content)
        infeasible_branch_suppressions = collect_infeasible_branch_division_suppressions(content)
        issue_sink = ScannerIssueSink(
            result=result,
            blocked_resolution_sites=set(),
            dedup_enabled=scanner_issue_dedup_enabled(),
            reporter=reporter,
            verbose=verbose,
        )

        for bytearray_modulo_issue in bytearray_modulo_issues:
            issue_sink.handle_issue(bytearray_modulo_issue)
        for equality_zero_issue in equality_zero_issues:
            issue_sink.handle_issue(equality_zero_issue)
        for guarded_index_issue in guarded_index_issues:
            issue_sink.handle_issue(guarded_index_issue)
        for masked_zero_issue in masked_zero_issues:
            issue_sink.handle_issue(masked_zero_issue)
        for self_canceling_zero_issue in self_canceling_zero_issues:
            issue_sink.handle_issue(self_canceling_zero_issue)

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
        result.paths_explored = metrics.paths_explored
        result.error = metrics.error
        result.degraded_passes = metrics.degraded_passes
        result.solver_stats = dict(metrics.solver_stats)
        emit_value_range_issues(
            scan_code_with_context=scan_code_with_context,
            file_path=file_path,
            issue_sink=issue_sink,
            complete_coverage=metrics.complete_coverage,
            degraded_by_code=metrics.degraded_by_code,
            suppressed_issue_offsets_by_code=metrics.suppressed_issue_offsets_by_code,
            suppressed_lines=infeasible_branch_suppressions,
        )
        result.elapsed_time = time.perf_counter() - start_time
        result.avg_memory_mb = metrics.avg_memory_mb

        if verbose and not reporter:
            if result.error:
                print(f"[X] {file_path}: {result.error}")
            elif result.degraded_passes:
                print(f"[!] {file_path}: Analysis degraded: {', '.join(result.degraded_passes)}")
            else:
                status_msg = f"{len(result.issues)} issues found" if result.issues else "No issues"
                print(f"{'[!]' if result.issues else '[OK]'} {file_path}: {status_msg}")
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n[X] {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n[X] {result.error}")
    finally:
        if tracer is not None:
            try:
                tracer.end_session()
            except Exception:
                logger.debug("Failed to close trace session for %s", file_path, exc_info=True)
        resources.close()
    if session:
        session.add_result(result)
    return result
