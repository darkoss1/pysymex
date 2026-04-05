# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Core symbolic executor engine.

Provides :class:`SymbolicExecutor`, the main entry point for
symbolically executing Python bytecode.  The executor compiles a
function to CPython bytecode, sets up symbolic arguments, and
explores execution paths via Z3-backed constraint solving.

Key responsibilities:

* Bytecode dispatch via :class:`OpcodeDispatcher`.
* Path management (CHTD-native/adaptive-coverage).
* Bug detection via pluggable :class:`Detector` instances.
* Loop detection, widening, and state merging.
* Resource limit enforcement (paths, depth, time, memory).
* Optional analysis passes: taint tracking, abstract interpretation,
  cross-function analysis, and type inference.
"""

from __future__ import annotations

import dis
import inspect
import logging
import time
import types
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, TypeAlias, cast, get_type_hints

import z3

if TYPE_CHECKING:
    from pysymex._typing import SolverProtocol, StackValue
    from pysymex.core.treewidth import BranchInfo, TreeDecomposition
    from pysymex.plugins.base import PluginManager

import pysymex.core.solver as solver_mod
from pysymex._compat import get_starts_line
from pysymex.analysis.abstract.interpreter import AbstractAnalyzer
from pysymex.analysis.cache import LRUCache, hash_function
from pysymex.analysis.cross_function import CrossFunctionAnalyzer
from pysymex.analysis.detectors import (
    Detector,
    DetectorRegistry,
    Issue,
    IssueKind,
    default_registry,
)
from pysymex.analysis.false_positive_filter import deduplicate_issues, filter_issues
from pysymex.analysis.loops import LoopDetector, LoopWidening
from pysymex.analysis.path_manager import (
    AdaptivePathManager,
    PathManager,
    create_path_manager,
)
from pysymex.analysis.state_merger import MergePolicy, StateMerger
from pysymex.analysis.taint import TaintTracker
from pysymex.analysis.type_inference import TypeAnalyzer
from pysymex.core.addressing import next_address
from pysymex.core.copy_on_write import CowDict
from pysymex.core.floats import SymbolicFloat
from pysymex.core.solver import IncrementalSolver
from pysymex.core.state import VMState
from pysymex.core.treewidth import ConstraintInteractionGraph
from pysymex.core.types import (
    SymbolicString,
    SymbolicValue,
)
from pysymex.core.types_containers import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher, OpcodeHandler, OpcodeResult
from pysymex.execution.executor_types import (
    BRANCH_OPCODES,
    ExecutionConfig,
    ExecutionResult,
)
from pysymex.resources import LimitExceeded, ResourceLimits, ResourceTracker


class _GpuBagSolver(Protocol):
    """Minimal protocol for GPU CHTD solvers."""

    is_gpu_available: bool

    def propagate_all(self, td: TreeDecomposition, branch_info: dict[int, BranchInfo]) -> bool: ...


_CHTD_SOLVER_UNAVAILABLE = object()
_chtd_solvers: dict[bool, _GpuBagSolver | object] = {}


def _get_chtd_solver(*, use_gpu: bool) -> _GpuBagSolver | None:
    """Lazy-load the unified CHTD solver with backend preference.

    The solver implements the same CHTD algorithm in both modes:
    - ``use_gpu=True``: prefer GPU backend, CPU fallback inside solver when unavailable
    - ``use_gpu=False``: force CPU backend path
    """
    cached = _chtd_solvers.get(use_gpu)
    if cached is None:
        try:
            from pysymex.h_acceleration.chtd_solver import create_gpu_bag_solver

            loaded_solver = create_gpu_bag_solver(use_gpu=use_gpu)
            solver = cast("_GpuBagSolver", loaded_solver)
            _chtd_solvers[use_gpu] = solver
            logger.info(
                "CHTD solver initialized: use_gpu=%s gpu_available=%s",
                use_gpu,
                solver.is_gpu_available,
            )
            return solver
        except ImportError:
            _chtd_solvers[use_gpu] = _CHTD_SOLVER_UNAVAILABLE
            return None

    if cached is _CHTD_SOLVER_UNAVAILABLE:
        return None
    return cast("_GpuBagSolver", cached)


logger = logging.getLogger(__name__)

_CHTD_MAX_BRANCH_INFOS = 256
_CHTD_CHECK_INTERVAL = 64
_CHTD_GPU_MIN_BRANCH_INFOS = 32

__all__ = ["SymbolicExecutor"]

SymbolicCreatedValue: TypeAlias = (
    SymbolicValue | SymbolicString | SymbolicList | SymbolicDict | SymbolicObject | SymbolicFloat
)


class SymbolicExecutor:
    """Main symbolic execution engine.

    Symbolically executes Python functions by interpreting CPython bytecode
    with Z3-backed symbolic values.  Each conditional branch forks the
    execution state; infeasible paths are pruned by the solver.

    Typical usage::

        executor = SymbolicExecutor(ExecutionConfig(max_paths=500))
        result = executor.execute_function(my_func, {"x": "int"})
        for issue in result.issues:
            print(issue.format())

    The executor is **reusable**: calling :meth:`execute_function` or
    :meth:`execute_code` resets internal state while preserving the
    solver, dispatcher, and detector infrastructure.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
        **config_overrides: object,
    ) -> None:
        import pysymex.execution.opcodes as _opcodes  # type: ignore[reportUnusedImport]  # noqa: F401

        if config is None:
            config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
            self.config = config_ctor(**config_overrides)
        elif config_overrides:
            from dataclasses import replace as _dc_replace

            self.config = _dc_replace(config, **config_overrides)
        else:
            self.config = config
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.solver: SolverProtocol = IncrementalSolver(
            timeout_ms=self.config.solver_timeout_ms,
            use_cache=self.config.enable_solver_cache,
        )
        self._instructions: list[dis.Instruction] = []
        self._pc_to_line: dict[int, int] = {}
        self._worklist: PathManager[VMState] | None = None
        self._issues: list[Issue] = []
        self._abstract_hints: list[tuple[str, int, int]] = []
        self._coverage: set[int] = set()
        self._visited_states: set[tuple[int, ...]] = set()
        self._paths_explored: int = 0
        self._paths_completed: int = 0
        self._paths_pruned: int = 0
        self._iterations: int = 0
        self._loop_detector: LoopDetector | None = None
        self._loop_widening: LoopWidening | None = None
        self._taint_tracker: TaintTracker | None = None
        self._result_cache: LRUCache[str, ExecutionResult] | None = None
        self._state_merger: StateMerger | None = None
        self._resource_tracker: ResourceTracker | None = None
        self._cross_function: CrossFunctionAnalyzer | None = None
        self._type_analyzer: TypeAnalyzer | None = None
        self._abstract_analyzer: AbstractAnalyzer | None = None
        self._effect_summaries: dict[str, object] = {}
        self._degraded_passes: list[str] = []
        self._reported_hacc_fallback: bool = False
        self._prev_loop_states: dict[int, VMState] = {}
        self._interaction_graph = ConstraintInteractionGraph(self.solver.constraint_optimizer())
        self._current_chtd_interval: int = max(1, self.config.chtd_check_interval)
        self._next_chtd_check_iteration: int = 0
        self._last_chtd_branch_count: int = 0
        self._chtd_runs: int = 0
        self._chtd_unsat_hits: int = 0
        self._chtd_unsat_validations: int = 0
        self._chtd_unsat_mismatches: int = 0
        self._chtd_solver_unavailable: int = 0
        self._chtd_skipped_unstable: int = 0
        self._chtd_skipped_size: int = 0
        self._chtd_skipped_treewidth: int = 0
        self._chtd_total_time_seconds: float = 0.0
        self._phase_timers_seconds: dict[str, float] = {
            "execute_step": 0.0,
            "process_execution_result": 0.0,
            "path_feasibility": 0.0,
            "chtd_decomposition": 0.0,
            "chtd_propagation": 0.0,
        }
        self._phase_counts: dict[str, int] = {
            "execute_step": 0,
            "process_execution_result": 0,
            "path_feasibility": 0,
            "chtd_decomposition": 0,
            "chtd_propagation": 0,
        }
        if self.config.enable_taint_tracking:
            self._taint_tracker = TaintTracker()
        if self.config.enable_caching:
            self._result_cache = LRUCache[str, ExecutionResult](maxsize=500)
        if self.config.enable_state_merging:
            policy_map = {
                "conservative": MergePolicy.CONSERVATIVE,
                "moderate": MergePolicy.MODERATE,
                "aggressive": MergePolicy.AGGRESSIVE,
            }
            self._state_merger = StateMerger(
                policy=policy_map.get(self.config.merge_policy, MergePolicy.MODERATE)
            )
        if self.config.enable_cross_function:
            self._cross_function = CrossFunctionAnalyzer()
            self.dispatcher.cross_function = self._cross_function

        if self.config.enable_type_inference:
            pass

        if self.config.enable_abstract_interpretation:
            try:
                self._abstract_analyzer = AbstractAnalyzer()
            except (ImportError, RuntimeError, TypeError):
                logger.warning("Failed to initialize abstract analyzer", exc_info=True)
                self._degraded_passes.append("abstract_interpretation")
        limits = ResourceLimits(
            max_paths=self.config.max_paths,
            max_depth=self.config.max_depth,
            max_iterations=self.config.max_iterations,
            timeout_seconds=self.config.timeout_seconds,
        )
        self._resource_tracker = ResourceTracker(limits=limits)

        self._active_detectors: list[Detector] = self._build_active_detectors()

        self._plugin_manager: PluginManager | None = None
        self._hooks: dict[str, list[Callable[..., object]]] = {}

    def add_detector(self, detector: Detector) -> None:
        """Add a detector dynamically (used by plugins)."""
        self._active_detectors.append(detector)

    def _get_instructions(self, code: types.CodeType) -> tuple[dis.Instruction, ...]:
        """Get instructions for a code object, with caching.

        Delegates to the shared instruction cache so other components
        (CFG builder, loop detector, abstract interpreter) also benefit.
        """
        from pysymex.core.instruction_cache import get_instructions

        return get_instructions(code)

    def register_handler(self, opcode: str, handler: OpcodeHandler) -> None:
        """Register an opcode handler dynamically (used by plugins)."""
        self.dispatcher.register_handler(opcode, handler)

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None:
        """Register a hook handler (used by plugins)."""
        self._hooks.setdefault(hook_name, []).append(handler)

    def load_plugins(self, plugin_manager: PluginManager) -> None:
        """Activate all plugins from the given plugin manager."""
        self._plugin_manager = plugin_manager
        plugin_manager.activate(self)

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """Symbolically execute a Python function.

        Compiles *func* to bytecode, creates symbolic arguments, and
        explores all feasible execution paths up to the configured
        resource limits.

        Args:
            func: The Python function to analyse.
            symbolic_args: Mapping of parameter names to type hints
                (e.g. ``{"x": "int", "s": "str"}``).  Parameters
                not listed default to ``"int"``.

        Returns:
            An :class:`ExecutionResult` summarising detected issues,
            path statistics, and bytecode coverage.

        **Execution Algorithm:**
        1. **Reset**: Clears caches and resets solvers for a clean slate.
        2. **Compile**: Retrieves cached bytecode instructions.
        3. **Initialize**: Creates a `VMState` with symbolic arguments based on hints.
        4. **Explore**: Enters the worklist-driven exploration loop until path limits or
           time budget is exhausted.
        5. **Finalize**: Reconciles abstract hints with symbolic findings to produce
           the final issue report.
        """
        import time

        cache_key = None
        if self.config.enable_caching and self._result_cache is not None:
            code = func.__code__
            cache_key = hash_function(func.__name__, code, str(symbolic_args))
            cached = self._result_cache.get(cache_key)
            if cached is not None:
                return cached
        start_time = time.time()
        self._reset()
        code = func.__code__
        self._instructions = list(self._get_instructions(code))
        self.dispatcher.set_instructions(self._instructions)
        try:
            bytecode_obj = dis.Bytecode(func)
            entries = getattr(bytecode_obj, "exception_entries", ())
            self.dispatcher.set_exception_entries(list(entries))
        except (AttributeError, TypeError):
            self.dispatcher.set_exception_entries([])
        self._build_line_mapping(code)
        initial_state = self._create_initial_state(func, symbolic_args or {}, initial_values)

        try:
            closure = getattr(func, "__closure__", None)
            freevars = list(getattr(code, "co_freevars", ()))
            if closure and freevars:
                for fv_name, cell in zip(freevars, closure, strict=False):
                    try:
                        initial_state.local_vars[fv_name] = cell.cell_contents
                    except ValueError:
                        continue
        except (AttributeError, TypeError):
            pass

        try:
            module_funcs: dict[str, StackValue] = {}
            for g_name, g_val in func.__globals__.items():
                if inspect.isfunction(g_val) and getattr(g_val, "__module__", None) == getattr(
                    func, "__module__", None
                ):
                    module_funcs[g_name] = cast("StackValue", g_val)
            if module_funcs:
                initial_state.global_vars = CowDict(module_funcs)
        except (AttributeError, TypeError):
            pass
        if self._taint_tracker is not None:
            initial_state.taint_tracker = self._taint_tracker
        self._worklist = create_path_manager(
            self.config.strategy,
            deterministic=self.config.deterministic_mode,
            random_seed=self.config.random_seed,
        )
        self._worklist.add_state(initial_state)
        if self.config.use_loop_analysis:
            self._loop_detector = LoopDetector()
            self._loop_detector.analyze_cfg(self._instructions)
            self._loop_widening = LoopWidening(widening_threshold=self.config.max_loop_iterations)
        if self._state_merger is not None:
            self._state_merger.detect_join_points(self._instructions, code=func.__code__)

        if self._abstract_analyzer is not None:
            self._run_abstract_interpretation(code)

        if self._cross_function is not None:
            try:
                self._cross_function.analyze_module(code)
                self._effect_summaries = getattr(self._cross_function, "effect_summaries", {})
            except (AttributeError, TypeError, RuntimeError, RecursionError):
                logger.warning("Cross-function analysis failed", exc_info=True)
                self._degraded_passes.append("cross_function")
                self._cross_function = None
        if self.config.enable_type_inference:
            try:
                self._type_analyzer = TypeAnalyzer()
                analyze_fn = getattr(self._type_analyzer, "analyze", None)
                if analyze_fn is not None:
                    analyze_fn(code)
            except (ImportError, AttributeError, TypeError, RuntimeError):
                logger.warning("Type analyzer initialization failed", exc_info=True)
                self._degraded_passes.append("type_inference")
                self._type_analyzer = None
        self._execute_loop()
        self._promote_abstract_hints()
        end_time = time.time()
        logger.debug("Executor issues count: %d", len(self._issues))
        final_issues = self._issues
        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)
                final_issues = deduplicate_issues(final_issues)
            except (TypeError, ValueError, KeyError, AttributeError):
                logger.warning("FP filtering/deduplication failed, using raw issues", exc_info=True)
                self._degraded_passes.append("fp_filtering")
                final_issues = self._issues
        result = ExecutionResult(
            issues=final_issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=end_time - start_time,
            function_name=func.__name__,
            source_file=code.co_filename,
            final_globals=getattr(self, "_last_globals", {}),
            final_locals=getattr(self, "_last_locals", {}),
            branches=getattr(self, "_last_branches", []),
            treewidth_stats=self._interaction_graph.get_stats(),
            solver_stats={
                **self.solver.get_stats(),
                "chtd": self._collect_chtd_stats(),
                "state_merger": self._collect_state_merger_stats(),
            },
            degraded_passes=self._degraded_passes,
        )
        if cache_key is not None and self._result_cache is not None:
            self._result_cache.put(cache_key, result)
        return result

    def _create_code_initial_state(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, StackValue] | None = None,
    ) -> VMState:
        initial_state = VMState()
        if initial_globals:
            initial_state.global_vars = CowDict(initial_globals.copy())
        if self._taint_tracker is not None:
            initial_state.taint_tracker = self._taint_tracker
        symbolic_vars = dict(symbolic_vars or {})

        argcount = code.co_argcount + code.co_kwonlyargcount
        varargs_name = None
        varkw_name = None
        if code.co_flags & 0x04:
            varargs_name = code.co_varnames[argcount]
            argcount += 1
        if code.co_flags & 0x08:
            varkw_name = code.co_varnames[argcount]
            argcount += 1

        for param in code.co_varnames[:argcount]:
            if param not in symbolic_vars:
                if param == varargs_name:
                    symbolic_vars[param] = "tuple"
                elif param == varkw_name:
                    symbolic_vars[param] = "dict"
                else:
                    symbolic_vars[param] = "any"

        for name, type_hint in symbolic_vars.items():
            sym_val, constraint = self._create_symbolic_for_type(name, type_hint)
            initial_state.local_vars[name] = sym_val
            initial_state = initial_state.add_constraint(constraint)
        return initial_state

    def execute_code(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """
        Symbolically execute a code object.
        Args:
            code: The code object to analyze
            symbolic_vars: Mapping of variable names to types
        Returns:
            ExecutionResult with issues and statistics
        """
        import time

        start_time = time.time()
        self._reset()
        self._instructions = list(self._get_instructions(code))
        self.dispatcher.set_instructions(self._instructions)
        try:
            bytecode_obj = dis.Bytecode(code)
            entries = getattr(bytecode_obj, "exception_entries", ())
            self.dispatcher.set_exception_entries(list(entries))
        except (AttributeError, TypeError):
            self.dispatcher.set_exception_entries([])
        self._build_line_mapping(code)

        initial_state = self._create_code_initial_state(
            code,
            symbolic_vars,
            cast("dict[str, StackValue] | None", initial_globals),
        )
        self._worklist = create_path_manager(
            self.config.strategy,
            deterministic=self.config.deterministic_mode,
            random_seed=self.config.random_seed,
        )
        self._worklist.add_state(initial_state)
        if self.config.use_loop_analysis:
            self._loop_detector = LoopDetector()
            self._loop_detector.analyze_cfg(self._instructions)
            self._loop_widening = LoopWidening(widening_threshold=self.config.max_loop_iterations)
        if self._state_merger is not None:
            try:
                self._state_merger.detect_join_points(self._instructions, code=code)
            except (AttributeError, TypeError, IndexError, ValueError):
                logger.warning("State merger join-point detection failed", exc_info=True)
                self._degraded_passes.append("state_merger")

        if self._abstract_analyzer is not None:
            self._run_abstract_interpretation(code)

        self._execute_loop()
        self._promote_abstract_hints()
        end_time = time.time()
        final_issues = self._issues
        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)
                final_issues = deduplicate_issues(final_issues)
            except (TypeError, ValueError, KeyError, AttributeError):
                logger.warning("FP filtering/deduplication failed, using raw issues", exc_info=True)
                self._degraded_passes.append("fp_filtering")
                final_issues = self._issues
        return ExecutionResult(
            issues=final_issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=end_time - start_time,
            function_name=code.co_name,
            source_file=code.co_filename,
            final_globals=getattr(self, "_last_globals", {}),
            final_locals=getattr(self, "_last_locals", {}),
            branches=getattr(self, "_last_branches", []),
            treewidth_stats=self._interaction_graph.get_stats(),
            solver_stats={
                **self.solver.get_stats(),
                "chtd": self._collect_chtd_stats(),
                "state_merger": self._collect_state_merger_stats(),
            },
            degraded_passes=self._degraded_passes,
        )

    def _reset(self) -> None:
        """Reset execution state for a new code object.

        Keeps the executor infrastructure (solver, dispatcher, detectors,
        instruction cache) alive to avoid re-initialization overhead.
        Only resets per-execution state.
        """
        self._instructions = []
        self._pc_to_line = {}
        self._issues = []
        self._abstract_hints = []
        self._coverage = set()
        self._visited_states = set()
        self._paths_explored = 1
        self._paths_completed = 0
        self._paths_pruned = 0
        self._iterations = 0
        self._current_chtd_interval = max(1, self.config.chtd_check_interval)
        self._next_chtd_check_iteration = 0
        self._last_chtd_branch_count = 0
        self._chtd_runs = 0
        self._chtd_unsat_hits = 0
        self._chtd_unsat_validations = 0
        self._chtd_unsat_mismatches = 0
        self._chtd_solver_unavailable = 0
        self._chtd_skipped_unstable = 0
        self._chtd_skipped_size = 0
        self._chtd_skipped_treewidth = 0
        self._chtd_total_time_seconds = 0.0
        self._phase_timers_seconds = {
            "execute_step": 0.0,
            "process_execution_result": 0.0,
            "path_feasibility": 0.0,
            "chtd_decomposition": 0.0,
            "chtd_propagation": 0.0,
        }
        self._phase_counts = {
            "execute_step": 0,
            "process_execution_result": 0,
            "path_feasibility": 0,
            "chtd_decomposition": 0,
            "chtd_propagation": 0,
        }
        self._last_branches = []
        self._degraded_passes: list[str] = []
        self._loop_detector = None
        self._loop_widening = None
        self._prev_loop_states = {}
        if self._taint_tracker is not None:
            self._taint_tracker.clear()
        if self._state_merger is not None:
            self._state_merger.reset()

        if self._resource_tracker is not None:
            self._resource_tracker.reset()

        self.solver.reset()
        self._interaction_graph.reset()

        from pysymex.core.types import FROM_CONST_CACHE, SYMBOLIC_CACHE

        SYMBOLIC_CACHE.clear()
        FROM_CONST_CACHE.clear()

        from pysymex.core.instruction_cache import clear_cache as _clear_icache

        _clear_icache()

    def _build_line_mapping(self, code: types.CodeType) -> None:
        """Build mapping from PC to source line numbers."""
        last_line = None
        for i, instr in enumerate(self._instructions):
            if hasattr(instr, "positions") and instr.positions:
                line = instr.positions.lineno
                if line:
                    self._pc_to_line[i] = line
                    last_line = line
                elif last_line:
                    self._pc_to_line[i] = last_line
            elif (line := get_starts_line(instr)) is not None:
                self._pc_to_line[i] = line
                last_line = line
            elif last_line:
                self._pc_to_line[i] = last_line

    def _run_abstract_interpretation(self, code: types.CodeType) -> None:
        """Run fast abstract interpretation pass.

        Stores warnings as hints rather than immediately creating Issues.
        Hints are later reconciled by ``_promote_abstract_hints`` after
        symbolic execution — only those corroborated by a real symbolic
        finding (matching IssueKind) are promoted to full Issues.
        """
        try:
            assert self._abstract_analyzer is not None
            warnings = self._abstract_analyzer.analyze_function(code)
            for warning in warnings:
                confidence = getattr(warning, "confidence", "possible")
                if confidence == "definite":
                    line = getattr(warning, "line", 0)
                    pc = getattr(warning, "pc", 0)
                    msg = getattr(warning, "message", str(warning))
                    self._abstract_hints.append((msg, line, pc))
                    logger.debug("Abstract interpreter hint: %s at %s:%s", msg, code.co_name, line)
        except (AttributeError, TypeError, RuntimeError, RecursionError):
            logger.debug("Abstract interpretation failed for %s", code.co_name, exc_info=True)

    def _promote_abstract_hints(self) -> None:
        """Promote abstract interpreter hints to Issues when corroborated.

        An abstract hint is promoted only if symbolic execution independently
        found at least one issue with the same ``IssueKind``.  This prevents
        false positives from unreachable branches that the abstract interpreter
        cannot rule out but the symbolic executor can.
        """
        if not self._abstract_hints:
            return

        confirmed_kinds: set[IssueKind] = {issue.kind for issue in self._issues}

        for msg, line, pc in self._abstract_hints:
            kind = self._infer_issue_kind(msg)
            if kind is IssueKind.UNKNOWN:
                continue
            if kind in confirmed_kinds:
                self._issues.append(
                    Issue(
                        kind=kind,
                        message=f"[Abstract Interpreter] {msg}",
                        pc=pc,
                        line_number=line,
                    )
                )

    @staticmethod
    def _infer_issue_kind(msg: str) -> IssueKind:
        """Infer IssueKind from an abstract interpreter warning message."""
        lower = msg.lower()
        if "division" in lower or "zero" in lower:
            return IssueKind.DIVISION_BY_ZERO
        if "index" in lower or "bounds" in lower:
            return IssueKind.INDEX_ERROR
        if "assert" in lower:
            return IssueKind.ASSERTION_ERROR
        if "type" in lower:
            return IssueKind.TYPE_ERROR
        if "key" in lower:
            return IssueKind.KEY_ERROR
        if "attribute" in lower:
            return IssueKind.ATTRIBUTE_ERROR

        return IssueKind.UNKNOWN

    def _create_initial_state(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str],
        initial_values: dict[str, object] | None = None,
    ) -> VMState:
        """Create initial VM state with symbolic arguments."""
        state = VMState()
        parameters: dict[str, inspect.Parameter] = {}
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            parameters = dict(sig.parameters)
        except (ValueError, TypeError):
            params = list(func.__code__.co_varnames[: func.__code__.co_argcount])
        inferred_types: dict[str, str] = {}
        if self.config and self.config.use_type_hints:
            try:
                hints = get_type_hints(func)
                for param, hint in hints.items():
                    if param in params:
                        inferred_types[param] = self._hint_to_type_str(hint)
            except (TypeError, NameError, AttributeError, ValueError):
                logger.debug("Type hint extraction failed for %s", func.__name__, exc_info=True)
        for name in params:
            param = parameters.get(name)
            param_kind = (
                param.kind if param is not None else inspect.Parameter.POSITIONAL_OR_KEYWORD
            )
            if param_kind == inspect.Parameter.VAR_POSITIONAL:
                type_hint = "list"
            elif param_kind == inspect.Parameter.VAR_KEYWORD:
                type_hint = "dict"
            else:
                type_hint = symbolic_args.get(name) or inferred_types.get(name, "int")

            sym_val, constraint = self._create_symbolic_for_type(name, type_hint)
            if self.config and self.config.enable_taint_tracking:
                with_taint = getattr(sym_val, "with_taint", None)
                if callable(with_taint):
                    try:
                        tainted = with_taint("user_input")
                        if isinstance(
                            tainted,
                            (
                                SymbolicValue,
                                SymbolicString,
                                SymbolicList,
                                SymbolicDict,
                                SymbolicObject,
                                SymbolicFloat,
                            ),
                        ):
                            sym_val = tainted
                    except (AttributeError, TypeError):
                        pass
            state.local_vars[name] = sym_val
            state = state.add_constraint(constraint)

            if self._taint_tracker is not None:
                try:
                    from pysymex.analysis.taint import TaintSource

                    self._taint_tracker.mark_tainted(
                        sym_val,
                        TaintSource.USER_INPUT,
                        origin=name,
                        line=0,
                    )
                except (ImportError, AttributeError, TypeError):
                    pass

            if self.config and self.config.heuristic_assume_non_null_self:
                ln_name = name.lower()
                if ln_name in ("self", "cls") or ln_name.startswith(("self_", "cls_")):
                    import z3

                    maybe_none_expr = getattr(sym_val, "is_none", None)
                    if isinstance(maybe_none_expr, z3.BoolRef):
                        state = state.add_constraint(z3.Not(maybe_none_expr))
                    else:
                        maybe_addr_expr = getattr(sym_val, "z3_addr", None)
                        if isinstance(maybe_addr_expr, z3.ExprRef):
                            state = state.add_constraint(maybe_addr_expr != 0)

            if initial_values and name in initial_values:
                val = initial_values[name]
                if isinstance(sym_val, SymbolicValue):
                    if isinstance(val, int) and not isinstance(val, bool):
                        state = state.add_constraint(sym_val.z3_int == val)
                    elif isinstance(val, bool):
                        state = state.add_constraint(sym_val.z3_bool == val)
        return state

    def _hint_to_type_str(self, hint: type) -> str:
        """Convert a type hint to a type string for symbolic creation."""
        hint_str = str(hint).lower()
        if hint is int or "int" in hint_str:
            return "int"
        elif hint is float or "float" in hint_str:
            return "float"
        elif hint is str or "str" in hint_str:
            return "str"
        elif hint is bool or "bool" in hint_str:
            return "bool"
        elif hint is list or "list" in hint_str:
            return "list"
        elif hint is dict or "dict" in hint_str:
            return "dict"
        elif "path" in hint_str:
            return "path"
        return "int"

    def _create_symbolic_for_type(
        self, name: str, type_hint: str
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value and its type constraint."""
        type_hint = type_hint.lower()

        if name == "self" and type_hint == "any":
            type_hint = "object"

        if type_hint in ("int", "integer"):
            value_int, constraint_int = SymbolicValue.symbolic_int(name)
            return cast("SymbolicCreatedValue", value_int), constraint_int
        elif type_hint in ("float", "real"):
            sf = SymbolicFloat(name)
            return sf, z3.BoolVal(True)
        elif type_hint in ("str", "string"):
            value_str, constraint_str = SymbolicString.symbolic(name)
            return cast("SymbolicCreatedValue", value_str), constraint_str
        elif type_hint in ("list", "array", "tuple"):
            value_list, constraint_list = SymbolicList.symbolic(name)
            return cast("SymbolicCreatedValue", value_list), constraint_list
        elif type_hint in ("bool", "boolean"):
            value_bool, constraint_bool = SymbolicValue.symbolic_bool(name)
            return cast("SymbolicCreatedValue", value_bool), constraint_bool
        elif type_hint in ("path", "pathlib.path"):
            value_path, constraint_path = SymbolicValue.symbolic_path(name)
            return cast("SymbolicCreatedValue", value_path), constraint_path
        elif type_hint in ("dict", "mapping", "kwargs"):
            value_dict, constraint_dict = SymbolicDict.symbolic(name)
            return cast("SymbolicCreatedValue", value_dict), constraint_dict
        elif type_hint == "object":
            id_suffix = next_address()
            z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
            sym_val = SymbolicObject(
                _name=name, address=id_suffix, z3_addr=z3_addr, potential_addresses={id_suffix}
            )
            return sym_val, z3_addr != 0
        else:
            sym_val, constraint = SymbolicValue.symbolic(name)
            import z3 as _z3

            return cast("SymbolicCreatedValue", sym_val), _z3.And(
                constraint, _z3.Not(sym_val.is_none)
            )

    def _execute_loop(self) -> None:
        """Main execution engine heartbeat.

        **Orchestration Logic:**
        Uses a `PathManager` (Worklist) to manage the exploration queue. In each
        iteration, it pops a `VMState`, checks resource bounds, and executes
        exactly one bytecode instruction via `_execute_step`.

        If an instruction (like a conditional jump) result in multiple states
        (forking), they are re-added to the worklist provided they are satisfiable
        and haven't exceeded the depth limit.

        The loop terminates when:
        - The worklist is empty (all paths explored).
        - A global limit (time, path count, iterations) is hit.
        """
        if self._worklist is None:
            return
        if self._resource_tracker is not None:
            self._resource_tracker.start()

        solver_mod.active_incremental_solver.set(self.solver)
        try:
            while not self._worklist.is_empty():
                self._iterations += 1
                try:
                    if self._resource_tracker is not None:
                        self._resource_tracker.check_all_limits()
                        self._resource_tracker.record_iteration()
                except LimitExceeded:
                    break
                state = self._worklist.get_next_state()
                if state is None:
                    break

                coverage_before = len(self._coverage)
                issues_before = len(self._issues)

                step_start = time.perf_counter()
                self._execute_step(state)
                self._phase_timers_seconds["execute_step"] += time.perf_counter() - step_start
                self._phase_counts["execute_step"] += 1

                if isinstance(self._worklist, AdaptivePathManager):
                    new_coverage = len(self._coverage) - coverage_before
                    new_issues = len(self._issues) - issues_before
                    reward = 0.0
                    if new_issues > 0:
                        reward += 10.0 * new_issues
                    if new_coverage > 0:
                        reward += 3.0 * new_coverage
                    elif new_coverage == 0 and new_issues == 0:
                        reward -= 0.5
                    self._worklist.record_reward(reward)

                try:
                    if self._resource_tracker is not None:
                        self._resource_tracker.check_time_limit()
                except LimitExceeded:
                    break
        finally:
            solver_mod.active_incremental_solver.set(None)

    def _check_resource_limits(self, state: VMState) -> bool:
        """Check if resource limits are exceeded."""
        try:
            if self._resource_tracker is not None:
                self._resource_tracker.check_depth_limit()
            return True
        except LimitExceeded:
            self._paths_pruned += 1
            for _hook in self._hooks.get("on_prune", ()):
                try:
                    _hook(self, state, "resource_limit")
                except Exception:
                    logger.exception("Plugin hook execution failed")
            return False

    def _fetch_instruction(
        self, state: VMState
    ) -> tuple[dis.Instruction | None, list[dis.Instruction]]:
        """Determine active instruction list and fetch current instruction."""
        current = state.current_instructions
        if current is not None:
            if not current or isinstance(current[0], dis.Instruction):
                active_instructions = cast("list[dis.Instruction]", current)
            else:
                active_instructions = self._instructions
        else:
            active_instructions = self._instructions
        if state.pc >= len(active_instructions):
            return None, active_instructions
        return active_instructions[state.pc], active_instructions

    def _check_path_feasibility(self, state: VMState) -> bool:
        """Check if the current path is feasible with Z3.

        Optimization: skip the solver call if no new constraints have been added
        since the last successful feasibility check.
        """
        if state.pending_constraint_count <= 0:
            return True

        start = time.perf_counter()
        self._phase_counts["path_feasibility"] += 1
        try:
            known_prefix_len = max(0, len(state.path_constraints) - state.pending_constraint_count)
            if not self.solver.is_sat(
                state.path_constraints, known_sat_prefix_len=known_prefix_len
            ):
                self._paths_pruned += 1
                for _hook in self._hooks.get("on_prune", ()):
                    try:
                        _hook(self, state, "infeasible")
                    except Exception:
                        logger.exception("Plugin hook execution failed")
                return False

            state.pending_constraint_count = 0
            return True
        finally:
            self._phase_timers_seconds["path_feasibility"] += time.perf_counter() - start

    def _handle_loop_logic(
        self, state: VMState, active_instructions: list[dis.Instruction]
    ) -> bool:
        """
        Handle loop detection, widening, and iteration limiting.
        Returns True if execution should continue on this path, False otherwise.
        """
        if self._loop_detector is None or state.pc >= len(active_instructions):
            return True

        instr_offset = active_instructions[state.pc].offset
        loop = self._loop_detector.get_loop_at(instr_offset)

        if loop is None or not loop.is_header(instr_offset):
            return True

        pc_key = loop.header_pc
        state.loop_iterations[pc_key] = state.loop_iterations.get(pc_key, 0) + 1

        if state.loop_iterations[pc_key] > self.config.max_loop_iterations:
            if self._loop_widening is not None:
                if self._loop_widening.should_widen(loop, state.loop_iterations[pc_key]):
                    prev_state = state.prev_loop_states.get(pc_key)
                    if prev_state is not None:
                        widened = self._loop_widening.widen_state(prev_state, state, loop)
                        if loop.exit_pcs:
                            exit_idx: int | None = None

                            max_body_offset = (
                                max(loop.body_pcs) if loop.body_pcs else loop.header_pc
                            )
                            for idx, ai in enumerate(active_instructions):
                                if ai.offset > max_body_offset:
                                    exit_idx = idx
                                    break

                            if exit_idx is None:
                                for ep in sorted(loop.exit_pcs):
                                    for idx, ai in enumerate(active_instructions):
                                        if ai.offset == ep:
                                            exit_idx = idx
                                            break
                                    if exit_idx is not None:
                                        break

                            if exit_idx is not None:
                                widened = widened.set_pc(exit_idx)
                            else:
                                widened = widened.set_pc(len(active_instructions))

                            while widened.block_stack:
                                top_block = widened.block_stack[-1]
                                if (
                                    top_block.start_pc >= loop.header_pc
                                    and top_block.end_pc <= max_body_offset + 1
                                ):
                                    widened.exit_block()
                                else:
                                    break
                            if self._worklist:
                                self._worklist.add_state(widened)
                            self._paths_explored += 1
                            if self.config.verbose:
                                logger.debug("Loop at PC %s: widened and jumped to exit", pc_key)
                            return False

            if self.config.verbose:
                logger.debug("Loop at PC %s exceeded max iterations", pc_key)
            self._paths_pruned += 1
            return False

        if not hasattr(state, "prev_loop_states"):
            state.prev_loop_states = {}
        state.prev_loop_states[pc_key] = state.fork()
        return True

    def _process_execution_result(
        self, result: OpcodeResult, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Process the result of an opcode execution."""
        process_start = time.perf_counter()
        self._phase_counts["process_execution_result"] += 1
        try:
            if result.issues:
                for issue in result.issues:
                    line_no = self._get_line_number(issue.pc, active_instructions)
                    if line_no != issue.line_number:
                        from dataclasses import replace as _dc_replace

                        issue = _dc_replace(issue, line_number=line_no)
                    self._issues.append(issue)
                    for _hook in self._hooks.get("on_issue", ()):
                        try:
                            _hook(self, state, issue)
                        except Exception:
                            logger.exception("Plugin hook execution failed")

            if result.terminal:
                self._paths_completed += 1
                self._last_branches = state.branch_trace.to_list()
                self._last_globals = state.global_vars
                self._last_locals = state.local_vars
                return

            sat = True

            if len(result.new_states) >= 2 and self.config.enable_chtd:
                for ns in result.new_states:
                    if ns.path_constraints:
                        last_constraint = ns.path_constraints.newest()
                        if last_constraint is None:
                            continue
                        try:
                            self._interaction_graph.add_branch(ns.pc, last_constraint)
                        except Exception:
                            import traceback

                            traceback.print_exc()

                should_run_chtd = self._should_run_chtd()
                if should_run_chtd:
                    start = time.perf_counter()
                    try:
                        td_start = time.perf_counter()
                        td = self._interaction_graph.compute_tree_decomposition()
                        self._phase_timers_seconds["chtd_decomposition"] += (
                            time.perf_counter() - td_start
                        )
                        self._phase_counts["chtd_decomposition"] += 1
                        if td.width > 0 and td.bags:
                            branch_info = self._interaction_graph.branch_info

                            use_gpu_for_chtd = (
                                self.config.enable_h_acceleration
                                and len(branch_info) >= _CHTD_GPU_MIN_BRANCH_INFOS
                            )
                            solver = _get_chtd_solver(use_gpu=use_gpu_for_chtd)
                            if solver is None:
                                self._chtd_solver_unavailable += 1
                            else:
                                if (
                                    use_gpu_for_chtd
                                    and not solver.is_gpu_available
                                    and not getattr(self, "_reported_hacc_fallback", False)
                                ):
                                    logger.info(
                                        "CHTD using CPU backend (GPU unavailable); algorithm remains identical"
                                    )
                                    self._reported_hacc_fallback = True
                                propagate_start = time.perf_counter()
                                sat = solver.propagate_all(td, branch_info)
                                self._phase_timers_seconds["chtd_propagation"] += (
                                    time.perf_counter() - propagate_start
                                )
                                self._phase_counts["chtd_propagation"] += 1
                                self._chtd_runs += 1
                                if not sat:
                                    self._chtd_unsat_hits += 1
                    except Exception:
                        import traceback

                        traceback.print_exc()
                        logger.debug("CHTD DP block raised unexpectedly", exc_info=True)
                    finally:
                        self._chtd_total_time_seconds += time.perf_counter() - start
                        self._reschedule_chtd_check()

            if not sat and result.new_states:
                if not self._validate_chtd_unsat(
                    parent_state=state, forked_states=result.new_states
                ):
                    sat = True

            if not sat:
                self._paths_pruned += len(result.new_states)
            elif result.new_states:
                first_state = result.new_states[0]
                if self._check_path_feasibility(first_state):
                    first_state.depth = state.depth + 1
                    if self._worklist:
                        self._worklist.add_state(first_state)

                for new_state in result.new_states[1:]:
                    can_add = True
                    if self._resource_tracker is not None:
                        try:
                            self._resource_tracker.record_path()
                        except LimitExceeded:
                            self._paths_pruned += 1
                            can_add = False

                    if can_add:
                        if self._check_path_feasibility(new_state):
                            new_state.depth = state.depth + 1
                            if self._worklist:
                                self._worklist.add_state(new_state)
                            self._paths_explored += 1

            if len(result.new_states) >= 2:
                for _hook in self._hooks.get("on_fork", ()):
                    try:
                        _hook(self, state, list(result.new_states))
                    except Exception:
                        logger.exception("Plugin hook execution failed")
        finally:
            self._phase_timers_seconds["process_execution_result"] += (
                time.perf_counter() - process_start
            )

    def _should_run_chtd(self) -> bool:
        if not self._interaction_graph.is_stabilized():
            self._chtd_skipped_unstable += 1
            return False

        if self._worklist is not None and self._worklist.size() < 50:
            return False

        if getattr(self._interaction_graph, "estimated_treewidth", 0) > 25:
            self._chtd_skipped_treewidth += 1
            return False

        if len(self._interaction_graph.branch_info) > self.config.chtd_max_branch_infos:
            self._chtd_skipped_size += 1
            return False
        return self._iterations >= self._next_chtd_check_iteration

    def _reschedule_chtd_check(self) -> None:
        branch_count = len(self._interaction_graph.branch_info)
        branch_growth = branch_count - self._last_chtd_branch_count
        self._last_chtd_branch_count = branch_count

        if self.config.chtd_adaptive_interval:
            min_interval = max(1, self.config.chtd_min_check_interval)
            max_interval = max(min_interval, self.config.chtd_max_check_interval)
            if branch_growth >= self.config.chtd_growth_trigger:
                self._current_chtd_interval = max(min_interval, self._current_chtd_interval // 2)
            elif branch_growth <= 0:
                self._current_chtd_interval = min(max_interval, self._current_chtd_interval * 2)

        self._next_chtd_check_iteration = self._iterations + self._current_chtd_interval

    def _collect_chtd_stats(self) -> dict[str, object]:
        return {
            "runs": self._chtd_runs,
            "unsat_hits": self._chtd_unsat_hits,
            "unsat_validations": self._chtd_unsat_validations,
            "unsat_mismatches": self._chtd_unsat_mismatches,
            "solver_unavailable": self._chtd_solver_unavailable,
            "skipped_unstable": self._chtd_skipped_unstable,
            "skipped_size": self._chtd_skipped_size,
            "skipped_treewidth": self._chtd_skipped_treewidth,
            "total_time_seconds": self._chtd_total_time_seconds,
            "current_interval": self._current_chtd_interval,
            "next_check_iteration": self._next_chtd_check_iteration,
            "phase_timers_seconds": dict(self._phase_timers_seconds),
            "phase_counts": dict(self._phase_counts),
        }

    def _validate_chtd_unsat(self, *, parent_state: VMState, forked_states: list[VMState]) -> bool:
        """Confirm CHTD UNSAT decisions with incremental Z3 before pruning.

        This guards soundness if a backend/integration bug reports false UNSAT.
        """
        self._chtd_unsat_validations += 1
        parent_prefix_len = len(parent_state.path_constraints)
        for candidate in forked_states:
            constraints = candidate.path_constraints
            known_prefix_len = min(parent_prefix_len, len(candidate.path_constraints))
            if self.solver.is_sat(
                constraints,
                known_sat_prefix_len=known_prefix_len if known_prefix_len > 0 else None,
            ):
                self._chtd_unsat_mismatches += 1
                logger.warning(
                    "CHTD reported UNSAT but incremental solver found SAT; skipping CHTD prune"
                )
                return False
        return True

    def _collect_state_merger_stats(self) -> dict[str, object]:
        if self._state_merger is None:
            return {
                "enabled": False,
                "states_before_merge": 0,
                "states_after_merge": 0,
                "merge_operations": 0,
                "subsumption_hits": 0,
                "reduction_ratio": 0.0,
            }
        stats = self._state_merger.stats
        return {
            "enabled": True,
            "states_before_merge": stats.states_before_merge,
            "states_after_merge": stats.states_after_merge,
            "merge_operations": stats.merge_operations,
            "subsumption_hits": stats.subsumption_hits,
            "reduction_ratio": stats.reduction_ratio,
        }

    def _execute_step(self, state: VMState) -> None:
        """Execute a single step (one instruction).

        **Lazy Evaluation Logic:**
        Uses lazy constraint evaluation to minimize solver overhead. It only
        queries Z3 for path feasibility when:
        1. A conditional branch opcode (controlled by `BRANCH_OPCODES`) is reached.
        2. The cumulative pending constraint count exceeds `lazy_eval_threshold`.
        3. A detector needs to verify a security or correctness property.
        """
        for hook in self._hooks.get("pre_step", ()):
            hook(self, state)

        instr, active_instructions = self._fetch_instruction(state)

        if instr is None:
            self._paths_completed += 1
            self._last_globals = state.global_vars
            self._last_locals = state.local_vars
            self._last_branches = state.branch_trace.to_list()
            return

        if not self._check_resource_limits(state):
            return

        if self._state_merger is not None and self._state_merger.should_merge(state):
            merged = self._state_merger.add_state_for_merge(state)
            if merged is None:
                self._paths_pruned += 1
                return
            if merged is not state:
                state = merged

        if not self._handle_loop_logic(state, active_instructions):
            return

        is_jump_or_branch = instr.opname in BRANCH_OPCODES or "JUMP" in instr.opname
        if is_jump_or_branch:
            state_key = self._state_key(state)
            if state_key in self._visited_states:
                self._paths_pruned += 1
                for _hook in self._hooks.get("on_prune", ()):
                    try:
                        _hook(self, state, "duplicate_state")
                    except Exception:
                        logger.exception("Plugin hook execution failed")
                return
            self._visited_states.add(state_key)

        self._coverage.add(state.pc)
        state.visited_pcs.add(state.pc)

        needs_check = instr.opname in BRANCH_OPCODES or (
            state.pending_constraint_count >= self.config.lazy_eval_threshold
            and state.pending_constraint_count > 0
        )
        if needs_check:
            if not self._check_path_feasibility(state):
                return
            state.pending_constraint_count = 0
        self._run_detectors(state, instr, active_instructions)

        try:
            result = self.dispatcher.dispatch(instr, state)

            states_to_hook = result.new_states or [state]
            for next_state in states_to_hook:
                for _hook in self._hooks.get("post_step", ()):
                    try:
                        _hook(self, next_state, instr)
                    except Exception:
                        logger.exception("Plugin hook execution failed")
            self._process_execution_result(result, state, active_instructions)
        except (
            RuntimeError,
            TypeError,
            ValueError,
            KeyError,
            AttributeError,
            IndexError,
            z3.Z3Exception,
        ) as e:
            if self.config.verbose:
                logger.debug("Execution error at PC %d: %s", state.pc, e)
            self._paths_pruned += 1
            return

    def _get_line_number(self, pc: int, active_instructions: list[dis.Instruction]) -> int | None:
        """Get line number."""
        if active_instructions is self._instructions:
            return self._pc_to_line.get(pc)
        for i in range(min(pc, len(active_instructions) - 1), -1, -1):
            instr = active_instructions[i]
            if (pos := getattr(instr, "positions", None)) is not None and pos.lineno:
                return pos.lineno
            if getattr(instr, "starts_line", None) is not None:
                return instr.starts_line
        return None

    def _build_active_detectors(self) -> list[Detector]:
        """Build the list of active detectors once at init time."""
        disabled_names: set[str] = set()
        if not self.config.detect_division_by_zero:
            disabled_names.add("division-by-zero")
        if not self.config.detect_assertion_errors:
            disabled_names.add("assertion-error")
        if not self.config.detect_index_errors:
            disabled_names.add("index-error")
        if not self.config.detect_type_errors:
            disabled_names.add("type-error")
        if not self.config.detect_overflow:
            disabled_names.add("overflow")
            disabled_names.add("bounded-overflow")
        if not self.config.detect_value_errors:
            disabled_names.add("value-error")
        active = [
            d
            for d in self.detector_registry.get_all()
            if d is not None and d.name not in disabled_names
        ]

        self._detector_dispatch: dict[str, list[Detector]] = {}
        self._universal_detectors: list[Detector] = []
        for d in active:
            opcodes = d.relevant_opcodes
            if not opcodes:
                self._universal_detectors.append(d)
            else:
                for op in opcodes:
                    self._detector_dispatch.setdefault(op, []).append(d)

        return active

    def _run_detectors(
        self, state: VMState, instr: dis.Instruction, active_instructions: list[dis.Instruction]
    ) -> None:
        """Run enabled detectors on current state.

        Uses opcode→detector dispatch table to avoid calling detectors
        that don't care about the current instruction.
        """
        opname = instr.opname

        prefix_len = len(state.path_constraints)

        def detector_is_sat(c: list[z3.BoolRef]) -> bool:
            return self.solver.is_sat(
                c, known_sat_prefix_len=prefix_len if len(c) > prefix_len else 0
            )

        for detector in self._universal_detectors:
            issue = detector.check(state, instr, detector_is_sat)
            if issue:
                line_no = self._get_line_number(state.pc, active_instructions)
                if line_no != issue.line_number:
                    from dataclasses import replace as _dc_replace

                    issue = _dc_replace(issue, line_number=line_no)
                self._issues.append(issue)
                for _hook in self._hooks.get("on_issue", ()):
                    try:
                        _hook(self, state, issue)
                    except Exception:
                        logger.exception("Plugin hook execution failed")

        specific = self._detector_dispatch.get(opname)
        if specific:
            for detector in specific:
                issue = detector.check(state, instr, detector_is_sat)
                if issue:
                    line_no = self._get_line_number(state.pc, active_instructions)
                    if line_no != issue.line_number:
                        from dataclasses import replace as _dc_replace

                        issue = _dc_replace(issue, line_number=line_no)
                    self._issues.append(issue)
                    for _hook in self._hooks.get("on_issue", ()):
                        try:
                            _hook(self, state, issue)
                        except Exception:
                            logger.exception("Plugin hook execution failed")

    def _hash_state(self, state: VMState) -> int:
        """Create a hash of the state to detect truly redundant paths.
        Delegates to VMState.hash_value() for content-based hashing.
        """
        return state.hash_value()

    def _state_key(self, state: VMState) -> tuple[int, ...]:
        """Composite state key to avoid hash-only collisions."""
        return (
            state.hash_value(),
            state.pc,
            len(state.path_constraints),
            len(state.stack),
            len(state.call_stack),
            len(state.block_stack),
        )
