"""Core symbolic executor engine.

Provides :class:`SymbolicExecutor`, the main entry point for
symbolically executing Python bytecode.  The executor compiles a
function to CPython bytecode, sets up symbolic arguments, and
explores execution paths via Z3-backed constraint solving.

Key responsibilities:

* Bytecode dispatch via :class:`OpcodeDispatcher`.
* Path management (DFS/BFS/coverage-guided).
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
import types
from collections.abc import Callable
from typing import get_type_hints

import z3

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
    PathManager,
    create_path_manager,
)
from pysymex.analysis.state_merger import MergePolicy, StateMerger
from pysymex.analysis.taint import TaintTracker
from pysymex.analysis.type_inference import TypeAnalyzer
from pysymex.core.addressing import next_address
from pysymex.core.copy_on_write import CowDict
from pysymex.core.solver import IncrementalSolver
from pysymex.core.state import VMState
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicString,
    SymbolicValue,
    SymbolicObject,
)
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.executor_types import (
    BRANCH_OPCODES,
    ExecutionConfig,
    ExecutionResult,
)
from pysymex.resources import LimitExceeded, ResourceLimits, ResourceTracker

logger = logging.getLogger(__name__)

__all__ = ["SymbolicExecutor"]


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
    ):
        """Initialise the symbolic executor.

        Args:
            config: Execution configuration.  Uses sensible defaults
                when ``None``.
            detector_registry: Registry of bug detectors to run.
                Falls back to the built-in default registry.
        """
        self.config = config or ExecutionConfig()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.solver = IncrementalSolver(
            timeout_ms=self.config.solver_timeout_ms,
            use_cache=self.config.enable_solver_cache,
        )
        self._instructions: list[dis.Instruction] = []
        self._pc_to_line: dict[int, int] = {}
        self._worklist: PathManager | None = None
        self._issues: list[Issue] = []
        self._abstract_hints: list[tuple[str, int, int]] = []
        self._coverage: set[int] = set()
        self._visited_states: set[int] = set()
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
        self._prev_loop_states: dict[int, VMState] = {}
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
                logger.debug("Failed to initialize abstract analyzer", exc_info=True)
        limits = ResourceLimits(
            max_paths=self.config.max_paths,
            max_depth=self.config.max_depth,
            max_iterations=self.config.max_iterations,
            timeout_seconds=self.config.timeout_seconds,
        )
        self._resource_tracker = ResourceTracker(limits=limits)

        self._active_detectors: list[Detector] = self._build_active_detectors()

        self._plugin_manager = None
        self._hooks: dict[str, list[object]] = {}

    def add_detector(self, detector: object) -> None:
        """Add a detector dynamically (used by plugins)."""
        self._active_detectors.append(detector)

    def _get_instructions(self, code: types.CodeType) -> tuple[dis.Instruction, ...]:
        """Get instructions for a code object, with caching.

        Delegates to the shared instruction cache so other components
        (CFG builder, loop detector, abstract interpreter) also benefit.
        """
        from pysymex.core.instruction_cache import get_instructions

        return get_instructions(code)

    def register_handler(self, opcode: str, handler: object) -> None:
        """Register an opcode handler dynamically (used by plugins)."""
        self.dispatcher.register_handler(opcode, handler)

    def register_hook(self, hook_name: str, handler: object) -> None:
        """Register a hook handler (used by plugins)."""
        self._hooks.setdefault(hook_name, []).append(handler)

    def load_plugins(self, plugin_manager: object) -> None:
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
        """
        import time

        cache_key = None
        if self.config.enable_caching and self._result_cache is not None:
            code = func.__code__
            cache_key = hash_function(func.__name__, code.co_code, str(symbolic_args))
            cached = self._result_cache.get(cache_key)
            if cached is not None:
                return cached
        start_time = time.time()
        self._reset()
        code = func.__code__
        self._instructions = list(self._get_instructions(code))
        self.dispatcher.set_instructions(self._instructions)
        self._build_line_mapping(code)
        initial_state = self._create_initial_state(func, symbolic_args or {}, initial_values)
        if self._taint_tracker is not None:
            initial_state.taint_tracker = self._taint_tracker
        self._worklist = create_path_manager(self.config.strategy)
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
                logger.debug("Cross-function analysis failed", exc_info=True)
                self._cross_function = None
        if self.config.enable_type_inference:
            try:
                self._type_analyzer = TypeAnalyzer()
                analyze_fn = getattr(self._type_analyzer, "analyze", None)
                if analyze_fn is not None:
                    analyze_fn(code)
            except (ImportError, AttributeError, TypeError, RuntimeError):
                logger.debug("Type analyzer initialization failed", exc_info=True)
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
                logger.debug("FP filtering/deduplication failed, using raw issues", exc_info=True)
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
        )
        if cache_key is not None and self._result_cache is not None:
            self._result_cache.put(cache_key, result)
        return result

    def _create_code_initial_state(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, object] | None = None,
    ) -> VMState:
        """Create code initial state."""
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
        self._build_line_mapping(code)

        initial_state = self._create_code_initial_state(code, symbolic_vars, initial_globals)
        self._worklist = create_path_manager(self.config.strategy)
        self._worklist.add_state(initial_state)
        if self.config.use_loop_analysis:
            self._loop_detector = LoopDetector()
            self._loop_detector.analyze_cfg(self._instructions)
            self._loop_widening = LoopWidening(widening_threshold=self.config.max_loop_iterations)
        if self._state_merger is not None:
            try:
                self._state_merger.detect_join_points(self._instructions, code=code)
            except (AttributeError, TypeError, IndexError, ValueError):
                logger.debug("State merger join-point detection failed", exc_info=True)

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
                logger.debug("FP filtering/deduplication failed, using raw issues", exc_info=True)
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
        self._last_branches = []
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

    def _run_abstract_interpretation(self, code: object) -> None:
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

        return IssueKind.DIVISION_BY_ZERO

    def _create_initial_state(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str],
        initial_values: dict[str, object] | None = None,
    ) -> VMState:
        """Create initial VM state with symbolic arguments."""
        state = VMState()
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
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
        for name, param in sig.parameters.items():
            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                type_hint = "list"
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                type_hint = "dict"
            else:
                type_hint = symbolic_args.get(name) or inferred_types.get(name, "int")

            sym_val, constraint = self._create_symbolic_for_type(name, type_hint)
            state.local_vars[name] = sym_val
            state = state.add_constraint(constraint)
            
            # Apply Noise Reduction Heuristic: Assume 'self'/'cls' is non-None
            if self.config and self.config.heuristic_assume_non_null_self:
                ln_name = name.lower()
                if ln_name == "self" or ln_name.startswith("self_") or \
                   ln_name == "cls" or ln_name.startswith("cls_"):
                    import z3
                    if hasattr(sym_val, "is_none"):
                        state = state.add_constraint(z3.Not(sym_val.is_none))
                    elif hasattr(sym_val, "z3_addr"):
                        state = state.add_constraint(sym_val.z3_addr != 0)

            if initial_values and name in initial_values:
                val = initial_values[name]
                from pysymex.core.types import SymbolicValue
                if isinstance(sym_val, SymbolicValue):
                    if isinstance(val, int) and not isinstance(val, bool):
                        state = state.add_constraint(sym_val.z3_int == val)
                    elif isinstance(val, bool):
                        state = state.add_constraint(sym_val.z3_bool == val)
        return state

    def _hint_to_type_str(self, hint: object) -> str:
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

    def _create_symbolic_for_type(self, name: str, type_hint: str) -> tuple[object, z3.BoolRef]:
        """Create a symbolic value and its type constraint."""
        type_hint = type_hint.lower()

        if name == "self" and type_hint == "any":
            type_hint = "object"

        if type_hint in ("int", "integer"):
            return SymbolicValue.symbolic_int(name)
        elif type_hint in ("float", "real"):
            from pysymex.core.floats import SymbolicFloat

            sf = SymbolicFloat(name)
            return sf, z3.BoolVal(True)
        elif type_hint in ("str", "string"):
            return SymbolicString.symbolic(name)
        elif type_hint in ("list", "array", "tuple"):
            return SymbolicList.symbolic(name)
        elif type_hint in ("bool", "boolean"):
            return SymbolicValue.symbolic_bool(name)
        elif type_hint in ("path", "pathlib.path"):
            return SymbolicValue.symbolic_path(name)
        elif type_hint in ("dict", "mapping", "kwargs"):
            return SymbolicDict.symbolic(name)
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

            return sym_val, _z3.And(constraint, _z3.Not(sym_val.is_none))

    def _execute_loop(self) -> None:
        """Main execution loop."""
        if self._worklist is None:
            return
        if self._resource_tracker is not None:
            self._resource_tracker.start()

        solver_mod.active_incremental_solver.set(self.solver)
        try:
            while not self._worklist.is_empty():
                try:
                    if self._resource_tracker is not None:
                        self._resource_tracker.check_all_limits()
                        self._resource_tracker.record_iteration()
                except LimitExceeded:
                    break
                state = self._worklist.get_next_state()
                if state is None:
                    break
                self._execute_step(state)
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
        active_instructions = state.current_instructions or self._instructions
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

        if not self.solver.is_sat(list(state.path_constraints)):
            self._paths_pruned += 1
            for _hook in self._hooks.get("on_prune", ()):
                try:
                    _hook(self, state, "infeasible")
                except Exception:
                    logger.exception("Plugin hook execution failed")
            return False

        # Reset the pending counter after a confirmed SAT result
        state.pending_constraint_count = 0
        return True

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
        self, result: object, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Process the result of an opcode execution."""
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

        if result.new_states:
            # The first state is always a continuation of the current path
            first_state = result.new_states[0]
            if self._check_path_feasibility(first_state):
                first_state.depth = state.depth + 1
                if self._worklist:
                    self._worklist.add_state(first_state)
            
            # Additional states are new paths, check limits before adding
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

    def _execute_step(self, state: VMState) -> None:
        """Execute a single step (one instruction).

        Uses lazy constraint evaluation: skips the expensive Z3 feasibility
        check on straight-line code and only checks when:
        1. A conditional branch opcode is reached.
        2. The pending constraint count exceeds the lazy_eval_threshold.
        3. Detectors need to verify a property.
        """
        # Optimization: removed redundant _check_path_feasibility call here.
        # Feasibility is already checked when states are added to the worklist
        # or at the end of constraints-modifying opcodes.
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

        state_hash = self._hash_state(state)
        if state_hash in self._visited_states:
            self._paths_pruned += 1
            for _hook in self._hooks.get("on_prune", ()):
                try:
                    _hook(self, state, "duplicate_state")
                except Exception:
                    logger.exception("Plugin hook execution failed")
            return
        self._visited_states.add(state_hash)

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
            # Call post_step on each resulting state (or the original if terminal/unmodified)
            states_to_hook = result.new_states if result.new_states else [state]
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

        for detector in self._universal_detectors:
            issue = detector.check(state, instr, self.solver.is_sat)
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
                issue = detector.check(state, instr, self.solver.is_sat)
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
