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
* Optional analysis passes: abstract interpretation,
  cross-function analysis, and type inference.
"""

from __future__ import annotations

import dis
import inspect
import logging
import time
import types
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias, cast, get_type_hints

import z3

if TYPE_CHECKING:
    from pysymex._typing import SolverProtocol, StackValue
    from pysymex.plugins.base import PluginManager

import pysymex.core.solver.engine as solver_mod
from pysymex._compat import get_starts_line
from pysymex.analysis.exceptions.analyzer import infer_caught_at
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
from pysymex.analysis.detectors.filter import deduplicate_issues, filter_issues
from pysymex.stats.registry import StatsRegistry
from pysymex.stats.types import EventType, Metadata
from pysymex.analysis.loops import LoopDetector, LoopWidening
from pysymex.execution.strategies.manager import (
    AdaptivePathManager,
    PathManager,
    create_path_manager,
)

from pysymex.execution.strategies.merger import MergePolicy, StateMerger
from pysymex.analysis.type_inference import TypeAnalyzer
from pysymex.core.builtins import get_all_builtins
from pysymex.core.memory.addressing import next_address
from pysymex.core.memory.cow import CowDict
from pysymex.core.types.floats import AdvancedSymbolicFloat
from pysymex.core.solver.engine import IncrementalSolver
from pysymex.core.solver.constraints import ConstraintHasher, structural_hash
from pysymex.core.state import VMState, VMStateError
from pysymex.core.graph.treewidth import ConstraintInteractionGraph
from pysymex.core.types import (
    SymbolicString,
    SymbolicValue,
)
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher, OpcodeHandler, OpcodeResult
from pysymex.execution.types import (
    BRANCH_OPCODES,
    ExecutionConfig,
    ExecutionResult,
)
from pysymex.resources import LimitExceeded, ResourceLimits, ResourceTracker

logger = logging.getLogger(__name__)
_stats_registry = StatsRegistry()


def _emit_event(
    event_type: EventType,
    value: float = 0.0,
    metadata: Metadata | None = None,
) -> None:
    """Emit a stats event through the shared stats registry."""
    _stats_registry.emit(event_type, value, metadata)


_CHTD_SAT_MIN_BRANCH_INFOS = 4
_DETECTOR_QUERY_CACHE_MAX_ENTRIES = 4096

SymbolicCreatedValue: TypeAlias = (
    SymbolicValue
    | SymbolicString
    | SymbolicList
    | SymbolicDict
    | SymbolicObject
    | AdvancedSymbolicFloat
)


@dataclass(frozen=True, slots=True)
class _DetectorQueryCacheEntry:
    constraints: tuple[z3.BoolRef, ...]
    result: bool


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
        if config is None:
            config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
            self.config = config_ctor(**config_overrides)
        elif config_overrides:
            from dataclasses import replace as _dc_replace

            self.config = _dc_replace(config, **config_overrides)
        else:
            self.config = config
        from pysymex.execution.opcodes import load_opcode_handlers

        load_opcode_handlers()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        setattr(self.dispatcher, "config", self.config)
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
        from pysymex.core.solver.independence import ConstraintIndependenceOptimizer

        self._independence_optimizer = ConstraintIndependenceOptimizer()
        self._interaction_graph = ConstraintInteractionGraph(self._independence_optimizer)
        self._detector_constraint_hasher = ConstraintHasher()
        self._detector_query_cache: OrderedDict[int, list[_DetectorQueryCacheEntry]] = OrderedDict()
        self._detector_query_cache_hits: int = 0
        self._detector_query_cache_misses: int = 0
        self._reported_detector_sites: set[tuple[int, int, IssueKind]] = set()

        try:
            from pysymex.core.memory.unsat_core_registry import SparseCoreRegistry
            from pysymex.core.solver.learner import (
                ConflictLearner,
                ConflictWorker,
            )

            self.conflict_learner = ConflictLearner(timeout_ms=self.config.solver_timeout_ms)
            self.conflict_worker = ConflictWorker(self.conflict_learner)
            self.core_registry = SparseCoreRegistry()
        except ImportError:
            pass
        self._current_chtd_interval: int = max(1, self.config.chtd_check_interval)
        self._next_chtd_check_iteration: int = 0
        self._last_chtd_branch_count: int = 0
        self._chtd_runs: int = 0
        self._chtd_unsat_hits: int = 0
        self._chtd_unsat_validations: int = 0
        self._chtd_unsat_mismatches: int = 0
        self._chtd_solver_unavailable: int = 0
        self._chtd_skipped_unstable: int = 0
        self._chtd_skipped_no_fork: int = 0
        self._chtd_skipped_size: int = 0
        self._chtd_skipped_treewidth: int = 0
        self._chtd_total_time_seconds: float = 0.0
        self._chtd_runtime_failures: int = 0
        self._chtd_runtime_disabled: bool = False
        self._last_should_run_chtd: bool | None = None
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
        from pysymex.core.cache import get_instructions

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

    def _execute_with_post_analysis(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
        issue_collector: Callable[[], list[Issue]] | None = None,
    ) -> ExecutionResult:
        """Template method for subclasses to execute with post-analysis issue collection.

        Subclasses should override this to call their specific execute_function
        and then extend the result with collected issues.
        """
        result = self.execute_function(func, symbolic_args, initial_values)
        if issue_collector:
            issues = issue_collector()
            result.issues.extend(issues)
        return result

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
        cache_key = None
        if self.config.enable_caching and self._result_cache is not None:
            code = func.__code__
            cache_key = hash_function(func.__name__, code, str(symbolic_args))
            cached = self._result_cache.get(cache_key)
            if cached is not None:
                return cached
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
                        initial_state = initial_state.set_local(fv_name, cell.cell_contents)
                    except ValueError:
                        continue
        except (AttributeError, TypeError):
            pass

        try:
            module_vars: dict[str, StackValue] = {}
            target_module = getattr(func, "__module__", None)
            for g_name, g_val in func.__globals__.items():
                if (inspect.isfunction(g_val) or inspect.isclass(g_val)) and getattr(
                    g_val, "__module__", None
                ) == target_module:
                    module_vars[g_name] = cast("StackValue", g_val)
            if module_vars:
                for g_name, g_val in module_vars.items():
                    initial_state.global_vars[g_name] = g_val
        except (AttributeError, TypeError):
            pass
        self._worklist = create_path_manager(
            self.config.strategy,
            deterministic=self.config.deterministic_mode,
            random_seed=self.config.random_seed,
            cig=self._interaction_graph,
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
        if self._resource_tracker is None:
            raise RuntimeError("Resource tracker is unavailable")
        snap = self._resource_tracker.snapshot()
        result = ExecutionResult(
            issues=final_issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=snap.elapsed_time,
            avg_memory_mb=snap.avg_memory_mb,
            function_name=func.__name__,
            source_file=code.co_filename,
            final_globals=getattr(self, "_last_globals", {}),
            final_locals=getattr(self, "_last_locals", {}),
            final_stack=getattr(self, "_last_stack", []),
            final_exception=getattr(self, "_last_exception", None),
            branches=getattr(self, "_last_branches", []),
            treewidth_stats={
                "num_vertices": self._interaction_graph.num_vertices,
                "num_edges": self._interaction_graph.num_edges,
            },
            solver_stats={
                **self.solver.get_stats(),
                "detector_queries": self._collect_detector_query_stats(),
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
            initial_state = initial_state.set_local(name, sym_val)
            initial_state = initial_state.add_constraint(constraint)

        # Populate initial memory from temp storage (used for collections)
        temp_mem = getattr(self, "_temp_memory_init", None)
        if temp_mem:
            for k, v in temp_mem.items():
                initial_state = initial_state.store_heap(k, v)
            self._temp_memory_init = {}

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
            cig=self._interaction_graph,
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
        final_issues = self._issues
        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)
                final_issues = deduplicate_issues(final_issues)
            except (TypeError, ValueError, KeyError, AttributeError):
                logger.warning("FP filtering/deduplication failed, using raw issues", exc_info=True)
                self._degraded_passes.append("fp_filtering")
                final_issues = self._issues
        if self._resource_tracker is None:
            raise RuntimeError("Resource tracker is unavailable")
        snap = self._resource_tracker.snapshot()
        return ExecutionResult(
            issues=final_issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=snap.elapsed_time,
            avg_memory_mb=snap.avg_memory_mb,
            function_name=code.co_name,
            source_file=code.co_filename,
            final_globals=getattr(self, "_last_globals", {}),
            final_locals=getattr(self, "_last_locals", {}),
            branches=getattr(self, "_last_branches", []),
            treewidth_stats={
                "num_vertices": self._interaction_graph.num_vertices,
                "num_edges": self._interaction_graph.num_edges,
            },
            solver_stats={
                **self.solver.get_stats(),
                "detector_queries": self._collect_detector_query_stats(),
                "chtd": self._collect_chtd_stats(),
                "state_merger": self._collect_state_merger_stats(),
            },
            degraded_passes=self._degraded_passes,
        )

    def _reset(self) -> None:
        """Reset execution state for a new code object.

        Keeps the executor infrastructure alive to avoid re-initialization overhead.
        Only resets per-execution state.
        """
        self.solver.reset()
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
        self._chtd_skipped_no_fork = 0
        self._chtd_skipped_size = 0
        self._chtd_skipped_treewidth = 0
        self._chtd_total_time_seconds = 0.0
        self._last_should_run_chtd = None
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
        self._last_stack = []
        self._last_exception = None
        self._degraded_passes = []
        self._loop_detector = None
        self._loop_widening = None
        self._prev_loop_states = {}
        self._detector_query_cache.clear()
        self._detector_constraint_hasher.clear()
        self._detector_query_cache_hits = 0
        self._detector_query_cache_misses = 0
        self._reported_detector_sites = set()
        if self._state_merger is not None:
            self._state_merger.reset()

        if self._resource_tracker is not None:
            self._resource_tracker.reset()

        self.solver.reset()
        self._interaction_graph.clear()

        from pysymex.core.types.scalars import FROM_CONST_CACHE, SYMBOLIC_CACHE, STRING_CONST_CACHE

        SYMBOLIC_CACHE.clear()
        FROM_CONST_CACHE.clear()
        STRING_CONST_CACHE.clear()
        try:
            from pysymex.core.objects.oop import enhanced_class_registry

            enhanced_class_registry.clear()
        except ImportError:
            logger.debug("Enhanced class registry unavailable during executor reset")

        from pysymex.core.cache import clear_cache as _clear_icache

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
        symbolic execution â€” only those corroborated by a real symbolic
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
        """Abstract hints are advisory only and not promoted to runtime issues."""
        return

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
        builtin_globals = get_all_builtins()
        for name, value in builtin_globals.items():
            state.global_vars[name] = value
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
                type_hint = symbolic_args.get(name) or inferred_types.get(name, "any")

            sym_val, constraint = self._create_symbolic_for_type(name, type_hint)
            state = state.set_local(name, sym_val)
            state = state.add_constraint(constraint)

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

        if self.config and getattr(self.config, "enable_contract_verification", False):
            from pysymex.contracts.injector import inject_preconditions_initial

            state = inject_preconditions_initial(state, func)
            state.contract_frames.append(func)

        temp_mem = getattr(self, "_temp_memory_init", None)
        if temp_mem:
            for k, v in temp_mem.items():
                state = state.store_heap(k, v)
            self._temp_memory_init = {}

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

        if type_hint.startswith(("int", "integer")):
            value_int, constraint_int = SymbolicValue.symbolic_int(name)
            return cast("SymbolicCreatedValue", value_int), constraint_int
        elif type_hint.startswith(("float", "real")):
            sf = AdvancedSymbolicFloat(name)
            return sf, z3.BoolVal(True)
        elif type_hint.startswith(("str", "string")):
            value_str, constraint_str = SymbolicString.symbolic(name)
            return cast("SymbolicCreatedValue", value_str), constraint_str
        elif type_hint.startswith(("list", "array", "tuple")):
            value_list, constraint_list = SymbolicList.symbolic(name)
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, z3.IntVal(addr), {addr})
            state_initial_memory = getattr(self, "_temp_memory_init", {})
            state_initial_memory[addr] = value_list
            self._temp_memory_init = state_initial_memory
            return cast("SymbolicCreatedValue", sym_obj), constraint_list
        elif type_hint.startswith(("bool", "boolean")):
            value_bool, constraint_bool = SymbolicValue.symbolic_bool(name)
            return cast("SymbolicCreatedValue", value_bool), constraint_bool
        elif type_hint.startswith(("path", "pathlib.path")):
            value_path, constraint_path = SymbolicValue.symbolic_path(name)
            return cast("SymbolicCreatedValue", value_path), constraint_path
        if type_hint.startswith(("dict", "mapping", "kwargs")):
            value_dict, constraint_dict = SymbolicDict.symbolic(name)
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, z3.IntVal(addr), {addr})
            state_initial_memory = getattr(self, "_temp_memory_init", {})
            state_initial_memory[addr] = value_dict
            self._temp_memory_init = state_initial_memory
            return cast("SymbolicCreatedValue", sym_obj), constraint_dict

        elif type_hint == "object":
            id_suffix = next_address()
            z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
            sym_val = SymbolicObject(
                _name=name, address=id_suffix, z3_addr=z3_addr, potential_addresses={id_suffix}
            )
            return sym_val, z3_addr != 0
        elif type_hint in {"any", "nullable", "optional"}:
            sym_val, constraint = SymbolicValue.symbolic(name)
            return cast("SymbolicCreatedValue", sym_val), constraint
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

        set_deadline = getattr(self.solver, "set_deadline", None)
        if callable(set_deadline):
            set_deadline(time.perf_counter() + self.config.timeout_seconds)

        active_solver_token = solver_mod.active_incremental_solver.set(self.solver)
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
            if callable(set_deadline):
                set_deadline(None)
            solver_mod.active_incremental_solver.reset(active_solver_token)

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

        Implements tiered feasibility checking:
        a. Registry containment check (cached UNSAT cores).
        b. CHTD bag-local UNSAT check (if enabled).
        c. Full incremental SMT fallback.
        """
        # a. core registry containment check
        if getattr(self, "core_registry", None):
            path_indices: set[int] = {c.hash() for c in state.path_constraints}
            if not self.core_registry.is_feasible(path_indices):
                self._paths_pruned += 1
                for _hook in self._hooks.get("on_prune", ()):
                    try:
                        _hook(self, state, "chtd_pruned")
                    except Exception as exc:
                        logger.debug("Plugin hook execution failed: %s", exc)
                return False

        # c. CHTD bag-local UNSAT check
        if self.config.enable_chtd and self.config.chtd_max_branch_infos > 0:
            core_info = self._check_chtd_unsat(state)
            if core_info:
                core_indices, decisions = core_info
                self._chtd_unsat_hits += 1
                exprs_list = list(state.path_constraints)
                core = frozenset(exprs_list[i].hash() for i in core_indices)
                frontier_pruned = 0
                if self.core_registry.add_core(core):
                    if isinstance(self._worklist, AdaptivePathManager):
                        frontier_pruned = self._worklist.prune_states_containing_core(core)
                        self._paths_pruned += frontier_pruned

                if isinstance(self._worklist, AdaptivePathManager):
                    # Local UNSAT is found synchronously here
                    self._worklist.feedback_unsat_core(
                        core_indices,
                        paths_pruned=frontier_pruned,
                        decisions=decisions,
                    )

                self._paths_pruned += 1
                for _hook in self._hooks.get("on_prune", ()):
                    try:
                        _hook(self, state, "chtd_unsat")
                    except Exception:
                        logger.exception("Plugin hook execution failed")
                return False

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

            # Persist newly verified constraints to the solver
            new_constraints = list(state.path_constraints)[known_prefix_len:]
            extend_path_fn = getattr(self.solver, "extend_path", None)
            if callable(extend_path_fn):
                extend_path_fn(new_constraints)
            else:
                for c in new_constraints:
                    self.solver.add(c)

            state.pending_constraint_count = 0
            return True
        finally:
            self._phase_timers_seconds["path_feasibility"] += time.perf_counter() - start

    def _check_chtd_unsat(self, state: VMState) -> tuple[list[int], dict[str, str]] | None:
        """Perform bag-local UNSAT checking. Returns (core_indices, decisions) if UNSAT.

        Implements hierarchical scheduling for:
        - decomposition policy
        - bag/subtree target policy
        - solver-budget policy
        """
        if not self.config.enable_chtd or self._interaction_graph.num_branches < 2:
            return None

        # 0. Sample hierarchical arms
        if not isinstance(self._worklist, AdaptivePathManager):
            return None

        decomposition_arm = self._worklist.scheduler.decomposition.sample()
        target_arm = self._worklist.scheduler.target.sample()
        budget_arm = self._worklist.scheduler.budget.sample()

        decisions = {"decomposition": decomposition_arm, "target": target_arm, "budget": budget_arm}

        # 1. Get/Compute tree decomposition using chosen policy
        start_tw = time.perf_counter()
        self._phase_counts["chtd_decomposition"] += 1
        try:
            # Simplified: we use min-fill if decomposition_arm says so, else default
            # (In a real impl, we'd pass the policy to compute_tree_decomposition)
            td = self._interaction_graph.compute_tree_decomposition()
        except Exception:
            self._record_degraded_passes(["chtd_decomposition_failed"])
            return None
        finally:
            self._phase_timers_seconds["chtd_decomposition"] += time.perf_counter() - start_tw

        # 2. Identify the target bag using chosen policy
        active_bag_id = None
        if target_arm == "smallest active bag":
            # Find smallest bag containing state.pc
            best_size = float("inf")
            for bid, pcs in td.bags.items():
                if state.pc in pcs and len(pcs) < best_size:
                    best_size = len(pcs)
                    active_bag_id = bid
        else:
            # Default: first bag containing state.pc
            for bid, pcs in td.bags.items():
                if state.pc in pcs:
                    active_bag_id = bid
                    break

        if active_bag_id is None:
            return None

        bag_pcs = td.bags[active_bag_id]
        path_exprs = list(state.path_constraints)

        # 3. Collect active constraints whose full scope is covered by the bag.
        pc_to_cond = {
            pc: info.condition
            for pc, info in self._interaction_graph.branch_info.items()
            if info.condition is not None
        }
        cond_hash_to_pc = {
            structural_hash([cond], self._detector_constraint_hasher): pc
            for pc, cond in pc_to_cond.items()
        }

        bag_constraints: list[z3.BoolRef] = []
        bag_indices: list[int] = []
        for i, expr in enumerate(path_exprs):
            expr_hash = structural_hash([expr], self._detector_constraint_hasher)
            if expr_hash in cond_hash_to_pc:
                pc = cond_hash_to_pc[expr_hash]
                if pc in bag_pcs:
                    bag_constraints.append(expr)
                    bag_indices.append(i)

        if not bag_constraints:
            return None

        # 4. Check the bag formula with chosen budget
        check_start = time.perf_counter()
        self._phase_counts["chtd_propagation"] += 1
        try:
            # We use the conflict learner to extract a certified core from the bag
            # Budget policy could control minimization effort
            core_indices = self.conflict_learner.extract_conflict_sync(bag_constraints)
            if core_indices:
                return [bag_indices[i] for i in core_indices], decisions
        except Exception:
            self._record_degraded_passes(["chtd_bag_solve_failed"])
        finally:
            self._phase_timers_seconds["chtd_propagation"] += time.perf_counter() - check_start

        return None

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
        iteration_count = state.increment_loop_iteration(pc_key)

        if iteration_count > self.config.max_loop_iterations:
            if self._loop_widening is not None:
                if self._loop_widening.should_widen(loop, iteration_count):
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
                            _emit_event(EventType.PATH_EXPLORED, 1.0)
                            if self.config.verbose:
                                logger.debug("Loop at PC %s: widened and jumped to exit", pc_key)
                            self._paths_pruned += 1
                            return False

            if self.config.verbose:
                logger.debug("Loop at PC %s exceeded max iterations", pc_key)
            self._paths_pruned += 1
            return False

        state.prev_loop_states[pc_key] = state.fork()
        return True

    def _process_execution_result(
        self, result: OpcodeResult, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Process the result of an opcode execution."""
        process_start = time.perf_counter()
        self._phase_counts["process_execution_result"] += 1
        try:
            self._record_degraded_passes(result.degraded_passes)
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
                self._last_stack = list(state.stack)
                self._last_exception = result.issues[0] if result.issues else None
                return

            sat = True

            if result.new_states and self.config.enable_chtd:
                if len(result.new_states) < 2:
                    self._chtd_skipped_no_fork += 1
                for ns in result.new_states:
                    if ns.path_constraints:
                        last_constraint = ns.path_constraints.newest()
                        if last_constraint is None:
                            continue
                        try:
                            self._interaction_graph.add_branch(ns.pc, last_constraint)
                        except Exception:
                            logger.debug("CHTD interaction-graph update failed", exc_info=True)

                should_run_chtd = self._should_run_chtd(len(state.path_constraints))
                if (
                    should_run_chtd
                    and self._last_should_run_chtd is False
                    and isinstance(self._worklist, AdaptivePathManager)
                ):
                    self._worklist.reheat_arm(AdaptivePathManager.ARM_STRUCTURAL, strength=0.35)
                if not should_run_chtd and isinstance(self._worklist, AdaptivePathManager):
                    self._worklist.record_reward(0.5)
                self._last_should_run_chtd = should_run_chtd
                if should_run_chtd:
                    start = time.perf_counter()
                    try:

                        def _unsat_core_callback(core_indices: list[int] | None) -> None:
                            if core_indices:
                                self._chtd_unsat_hits += 1
                                frontier_pruned = 0
                                if getattr(self, "core_registry", None):
                                    exprs_list = list(state.path_constraints)
                                    core = frozenset(exprs_list[i].hash() for i in core_indices)
                                    if self.core_registry.add_core(core):
                                        if isinstance(self._worklist, AdaptivePathManager):
                                            frontier_pruned = (
                                                self._worklist.prune_states_containing_core(core)
                                            )
                                            self._paths_pruned += frontier_pruned
                                if isinstance(self._worklist, AdaptivePathManager):
                                    elapsed_ms = (time.perf_counter() - start) * 1000
                                    self._worklist.feedback_unsat_core(
                                        core_indices,
                                        paths_pruned=frontier_pruned,
                                        elapsed_ms=elapsed_ms,
                                    )

                        if getattr(self, "conflict_worker", None):
                            exprs = list(state.path_constraints)
                            self.conflict_worker.dispatch(
                                exprs,
                                _unsat_core_callback,
                                current_depth=state.depth,
                                max_depth=self.config.max_depth,
                            )
                            self._chtd_runs += 1
                    except Exception:
                        self._chtd_runtime_failures += 1
                        self._chtd_runtime_disabled = True
                        logger.debug("CHTD DP block raised unexpectedly", exc_info=True)
                    finally:
                        self._chtd_total_time_seconds += time.perf_counter() - start
                        self._reschedule_chtd_check()

            states_to_process = list(result.new_states)
            if not sat and result.new_states:
                unsat_states, sat_states = self._partition_chtd_unsat(
                    parent_state=state,
                    forked_states=result.new_states,
                )
                if unsat_states:
                    self._paths_pruned += len(unsat_states)
                states_to_process = sat_states

            if states_to_process:
                first_state = states_to_process[0]
                first_state.depth = state.depth + 1
                if self._worklist:
                    self._worklist.add_state(first_state)

                for new_state in states_to_process[1:]:
                    can_add = True
                    if self._resource_tracker is not None:
                        try:
                            self._resource_tracker.record_path()
                        except LimitExceeded:
                            self._paths_pruned += 1
                            can_add = False

                    if can_add:
                        new_state.depth = state.depth + 1
                        if self._worklist:
                            self._worklist.add_state(new_state)
                        self._paths_explored += 1
                        _emit_event(EventType.PATH_EXPLORED, 1.0)

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

    def _record_degraded_passes(self, degraded_passes: list[str]) -> None:
        """Add degraded-pass markers without duplicating existing entries."""
        for degraded_pass in degraded_passes:
            if degraded_pass not in self._degraded_passes:
                self._degraded_passes.append(degraded_pass)

    def _should_run_chtd(self, path_constraint_count: int) -> bool:
        if self._chtd_runtime_disabled:
            return False

        if path_constraint_count < _CHTD_SAT_MIN_BRANCH_INFOS:
            self._chtd_skipped_unstable += 1
            return False

        if (
            self.config.chtd_max_branch_infos
            and self._interaction_graph.num_vertices > self.config.chtd_max_branch_infos
        ):
            self._chtd_skipped_size += 1
            return False

        if (
            self._worklist is not None
            and self._worklist.size() < self.config.chtd_min_frontier_size
        ):
            self._chtd_skipped_size += 1
            return False

        return self._iterations >= self._next_chtd_check_iteration

    def _reschedule_chtd_check(self) -> None:
        branch_count = self._interaction_graph.num_vertices
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

    def _collect_detector_query_stats(self) -> dict[str, object]:
        return {
            "cache_hits": self._detector_query_cache_hits,
            "cache_misses": self._detector_query_cache_misses,
            "cache_size": len(self._detector_query_cache),
            "cache_capacity": _DETECTOR_QUERY_CACHE_MAX_ENTRIES,
        }

    def _detector_query_cache_key(self, constraints: list[z3.BoolRef]) -> int:
        return structural_hash(constraints, self._detector_constraint_hasher)

    def _same_detector_query_constraints(
        self,
        left: tuple[z3.BoolRef, ...],
        right: list[z3.BoolRef],
    ) -> bool:
        if len(left) != len(right):
            return False
        for left_constraint, right_constraint in zip(left, right, strict=True):
            if self._detector_constraint_hasher.hash_expr(
                left_constraint
            ) != self._detector_constraint_hasher.hash_expr(right_constraint):
                return False
            if not z3.eq(left_constraint, right_constraint):
                return False
        return True

    def _detector_is_sat(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None,
    ) -> bool:
        if not constraints:
            return True

        cache_key = self._detector_query_cache_key(constraints)
        cached_entries = self._detector_query_cache.get(cache_key)
        if cached_entries is not None:
            for cached_entry in cached_entries:
                if self._same_detector_query_constraints(cached_entry.constraints, constraints):
                    self._detector_query_cache_hits += 1
                    self._detector_query_cache.move_to_end(cache_key)
                    return cached_entry.result

        self._detector_query_cache_misses += 1
        result = self.solver.check_sat_result(
            constraints,
            known_sat_prefix_len=None,
        )
        if result.is_unknown:
            self._record_degraded_passes(["solver_unknown_detector_query"])
        is_sat = result.is_sat
        entry = _DetectorQueryCacheEntry(tuple(constraints), is_sat)
        if cached_entries is None:
            self._detector_query_cache[cache_key] = [entry]
        else:
            cached_entries.append(entry)
            self._detector_query_cache.move_to_end(cache_key)
        if len(self._detector_query_cache) > _DETECTOR_QUERY_CACHE_MAX_ENTRIES:
            self._detector_query_cache.popitem(last=False)
        return is_sat

    def _collect_chtd_stats(self) -> dict[str, object]:
        return {
            "runs": self._chtd_runs,
            "unsat_hits": self._chtd_unsat_hits,
            "unsat_validations": self._chtd_unsat_validations,
            "unsat_mismatches": self._chtd_unsat_mismatches,
            "solver_unavailable": self._chtd_solver_unavailable,
            "skipped_unstable": self._chtd_skipped_unstable,
            "skipped_no_fork": self._chtd_skipped_no_fork,
            "skipped_size": self._chtd_skipped_size,
            "skipped_treewidth": self._chtd_skipped_treewidth,
            "runtime_failures": self._chtd_runtime_failures,
            "runtime_disabled": self._chtd_runtime_disabled,
            "total_time_seconds": self._chtd_total_time_seconds,
            "current_interval": self._current_chtd_interval,
            "next_check_iteration": self._next_chtd_check_iteration,
            "phase_timers_seconds": dict(self._phase_timers_seconds),
            "phase_counts": dict(self._phase_counts),
        }

    def _partition_chtd_unsat(
        self,
        *,
        parent_state: VMState,
        forked_states: list[VMState],
    ) -> tuple[list[VMState], list[VMState]]:
        """Validate CHTD UNSAT decisions per candidate path.

        Returns:
            (unsat_states, sat_states)
        """
        _ = parent_state
        self._chtd_unsat_validations += len(forked_states)
        unsat_states: list[VMState] = []
        sat_states: list[VMState] = []
        for candidate in forked_states:
            constraints = candidate.path_constraints
            if self.solver.is_sat(constraints):
                self._chtd_unsat_mismatches += 1
                newest = constraints.newest()
                logger.warning(
                    "CHTD reported UNSAT but full solver found SAT; skipping "
                    "CHTD prune for candidate at pc=%s newest=%s",
                    candidate.pc,
                    newest,
                )
                sat_states.append(candidate)
            else:
                unsat_states.append(candidate)
        return unsat_states, sat_states

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

        # The dispatcher is shared across queued states, while states may be
        # paused in different caller/callee instruction streams.
        self.dispatcher.set_instructions(active_instructions)
        state.current_instructions = cast("list[object]", active_instructions)

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
        state.mark_visited()

        needs_check = (
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

            if state.call_stack:
                self._last_locals = state.call_stack[-1].local_vars
            else:
                self._last_locals = state.local_vars

            self._last_globals = state.global_vars
            self._last_stack = list(state.stack)

            states_to_hook = result.new_states or [state]
            for next_state in states_to_hook:
                for _hook in self._hooks.get("post_step", ()):
                    try:
                        _hook(self, next_state, instr)
                    except Exception:
                        logger.exception("Plugin hook execution failed")
            self._process_execution_result(result, state, active_instructions)
        except VMStateError as e:
            logger.warning("Unsupported VM state at PC %d: %s", state.pc, e)
            line_no = self._get_line_number(state.pc, active_instructions)
            issue = Issue(
                kind=IssueKind.UNKNOWN,
                message=f"Unsupported VM state: {e}",
                constraints=list(state.path_constraints),
                pc=state.pc,
                line_number=line_no,
            )
            self._issues.append(issue)
            self._last_exception = issue
            self._paths_pruned += 1
            self._record_degraded_passes(["unsupported_vm_state"])
            return
        except Exception as e:
            logger.error("Engine failure at PC %d: %s", state.pc, e, exc_info=True)
            raise e

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

        def detector_is_sat(c: list[z3.BoolRef]) -> bool:
            return self._detector_is_sat(c, None)

        for detector in self._universal_detectors:
            site_key = (id(active_instructions), state.pc, detector.issue_kind)
            if site_key in self._reported_detector_sites:
                continue
            issue = detector.check(state, instr, detector_is_sat)
            if issue:
                if self._issue_is_caught_by_exception_handler(issue, instr):
                    continue
                self._reported_detector_sites.add(site_key)
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
                site_key = (id(active_instructions), state.pc, detector.issue_kind)
                if site_key in self._reported_detector_sites:
                    continue
                issue = detector.check(state, instr, detector_is_sat)
                if issue:
                    if self._issue_is_caught_by_exception_handler(issue, instr):
                        continue
                    self._reported_detector_sites.add(site_key)
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

    def _issue_is_caught_by_exception_handler(
        self,
        issue: Issue,
        instr: dis.Instruction,
    ) -> bool:
        exception_name = self._exception_name_for_issue(issue)
        if exception_name is None:
            return False
        return self._exception_handler_catches(instr.offset, exception_name)

    @staticmethod
    def _exception_name_for_issue(issue: Issue) -> str | None:
        if issue.kind == IssueKind.DIVISION_BY_ZERO:
            return "ZeroDivisionError"
        if issue.kind == IssueKind.TYPE_ERROR:
            return "TypeError"
        if issue.kind == IssueKind.VALUE_ERROR:
            return "ValueError"
        if issue.kind == IssueKind.ATTRIBUTE_ERROR:
            return "AttributeError"
        if issue.kind == IssueKind.INDEX_ERROR:
            return "IndexError"
        if issue.kind == IssueKind.KEY_ERROR:
            return "KeyError"
        if issue.kind != IssueKind.UNHANDLED_EXCEPTION:
            return None

        if ": " in issue.message:
            candidate = issue.message.rsplit(": ", 1)[-1].strip()
            if candidate:
                return candidate.split("(", 1)[0].split("[", 1)[0].strip()
        if "] " in issue.message:
            tail = issue.message.split("] ", 1)[1]
            candidate = tail.split(":", 1)[0].strip()
            if candidate:
                return candidate
        return None

    def _exception_handler_catches(self, offset: int, exception_name: str) -> bool:
        handler_index = self.dispatcher.find_exception_handler(offset)
        if handler_index is None:
            return False
        handler_offset = self.dispatcher.instructions[handler_index].offset
        caught_names = infer_caught_at(self.dispatcher.instructions, handler_offset)
        return self._exception_name_is_caught(exception_name, caught_names)

    @staticmethod
    def _exception_name_is_caught(exception_name: str, caught_names: set[str]) -> bool:
        if exception_name in caught_names:
            return True
        if exception_name == "ZeroDivisionError":
            return any(
                name in {"ArithmeticError", "Exception", "BaseException"} for name in caught_names
            )
        return any(name in {"Exception", "BaseException"} for name in caught_names)

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
