"""Core symbolic executor engine."""

from __future__ import annotations


import dis

import inspect

import logging

import types

from collections.abc import Callable

from typing import Any


import z3


import pysymex.execution.opcodes

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

from pysymex.core.copy_on_write import CowDict

from pysymex.core.solver import ShadowSolver

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue

from pysymex.execution.dispatcher import OpcodeDispatcher

from pysymex.execution.executor_types import (
    ExecutionConfig,
    ExecutionResult,
    BRANCH_OPCODES,
)

from pysymex.resources import LimitExceeded, ResourceLimits, ResourceTracker

logger = logging.getLogger(__name__)


__all__ = ["SymbolicExecutor"]


class SymbolicExecutor:
    """Main symbolic execution engine."""

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ):
        self.config = config or ExecutionConfig()

        self.detector_registry = detector_registry or default_registry

        self.dispatcher = OpcodeDispatcher()

        self.solver = ShadowSolver(timeout_ms=self.config.solver_timeout_ms)

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

        self._loop_iterations: dict[int, int] = {}

        self._taint_tracker: TaintTracker | None = None

        self._result_cache: LRUCache[str, ExecutionResult] | None = None

        self._state_merger: StateMerger | None = None

        self._resource_tracker: ResourceTracker | None = None

        self._cross_function: CrossFunctionAnalyzer | None = None

        self._type_analyzer: TypeAnalyzer | None = None

        self._abstract_analyzer: AbstractAnalyzer | None = None

        self._effect_summaries: dict[str, Any] = {}

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

            except Exception:
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

        self._hooks: dict[str, list[Any]] = {}

    def add_detector(self, detector: Any) -> None:
        """Add a detector dynamically (used by plugins)."""

        self._active_detectors.append(detector)

    def _get_instructions(self, code: types.CodeType) -> list[dis.Instruction]:
        """Get instructions for a code object, with caching.

        Delegates to the shared instruction cache so other components
        (CFG builder, loop detector, abstract interpreter) also benefit.
        """

        from pysymex.core.instruction_cache import get_instructions

        return get_instructions(code)

    def register_handler(self, opcode: str, handler: Any) -> None:
        """Register an opcode handler dynamically (used by plugins)."""

        self.dispatcher._handlers[opcode] = handler

    def register_hook(self, hook_name: str, handler: Any) -> None:
        """Register a hook handler (used by plugins)."""

        self._hooks.setdefault(hook_name, []).append(handler)

    def load_plugins(self, plugin_manager: Any) -> None:
        """Activate all plugins from the given plugin manager."""

        self._plugin_manager = plugin_manager

        plugin_manager.activate(self)

    def execute_function(
        self,
        func: Callable[..., Any],
        symbolic_args: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Symbolically execute a Python function."""

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

        self._instructions = self._get_instructions(code)

        self.dispatcher.set_instructions(self._instructions)

        self._build_line_mapping(code)

        initial_state = self._create_initial_state(func, symbolic_args or {})

        if self._taint_tracker is not None:
            initial_state.taint_tracker = self._taint_tracker

        self._worklist = create_path_manager(self.config.strategy)

        self._worklist.add_state(initial_state)

        if self.config.use_loop_analysis:
            self._loop_detector = LoopDetector()

            self._loop_detector.analyze_cfg(self._instructions)

            self._loop_widening = LoopWidening(widening_threshold=self.config.max_loop_iterations)

        if self._state_merger is not None:
            self._state_merger.detect_join_points(self._instructions)

        if self._abstract_analyzer is not None:
            self._run_abstract_interpretation(code)

        if self._cross_function is not None:
            try:
                self._cross_function.analyze_module(code)

                self._effect_summaries = getattr(self._cross_function, "effect_summaries", {})

            except Exception:
                logger.debug("Cross-function analysis failed", exc_info=True)

                self._cross_function = None

        if self.config.enable_type_inference:
            try:
                self._type_analyzer = TypeAnalyzer()

                self._type_analyzer.analyze(code)

            except Exception:
                logger.debug("Type analyzer initialization failed", exc_info=True)

                self._type_analyzer = None

        self._execute_loop()

        self._promote_abstract_hints()

        end_time = time.time()

        final_issues = self._issues

        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)

                final_issues = deduplicate_issues(final_issues)

            except Exception:
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
        )

        if cache_key is not None and self._result_cache is not None:
            self._result_cache.put(cache_key, result)

        return result

    def _create_code_initial_state(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, Any] | None = None,
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

            initial_state.add_constraint(constraint)

        return initial_state

    def execute_code(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, Any] | None = None,
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

        self._instructions = self._get_instructions(code)

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
                self._state_merger.detect_join_points(self._instructions)

            except Exception:
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

            except Exception:
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

        self._paths_explored = 0

        self._paths_completed = 0

        self._paths_pruned = 0

        self._iterations = 0

        self._loop_detector = None

        self._loop_widening = None

        self._loop_iterations = {}

        if self._taint_tracker is not None:
            self._taint_tracker.clear()

        if self._state_merger is not None:
            self._state_merger.reset()

        if self._resource_tracker is not None:
            self._resource_tracker.reset()

        self.solver.reset()

        from pysymex.core.types import SYMBOLIC_CACHE, FROM_CONST_CACHE

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

    def _run_abstract_interpretation(self, code: Any) -> None:
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

        except Exception:
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
        func: Callable[..., Any],
        symbolic_args: dict[str, str],
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
                from typing import get_type_hints

                hints = get_type_hints(func)

                for param, hint in hints.items():
                    if param in params:
                        inferred_types[param] = self._hint_to_type_str(hint)

            except Exception:
                logger.debug("Type hint extraction failed for %s", func.__name__, exc_info=True)

        for param in params:
            type_hint = symbolic_args.get(param) or inferred_types.get(param, "int")

            sym_val, constraint = self._create_symbolic_for_type(param, type_hint)

            state.local_vars[param] = sym_val

            state.add_constraint(constraint)

        return state

    def _hint_to_type_str(self, hint: Any) -> str:
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

    def _create_symbolic_for_type(self, name: str, type_hint: str) -> tuple[Any, z3.BoolRef]:
        """Create a symbolic value and its type constraint."""

        type_hint = type_hint.lower()

        if type_hint in ("int", "integer"):
            return SymbolicValue.symbolic(name)

        elif type_hint in ("float", "real"):
            from pysymex.core.floats import SymbolicFloat

            sf = SymbolicFloat(name)

            return sf, z3.BoolVal(True)

        elif type_hint in ("str", "string"):
            return SymbolicString.symbolic(name)

        elif type_hint in ("list", "array", "tuple"):
            return SymbolicList.symbolic(name)

        elif type_hint in ("bool", "boolean"):
            return SymbolicValue.symbolic(name)

        elif type_hint in ("path", "pathlib.path"):
            return SymbolicValue.symbolic_path(name)

        elif type_hint in ("dict", "mapping", "kwargs"):
            from pysymex.core.types import SymbolicDict

            return SymbolicDict.symbolic(name)

        else:
            return SymbolicValue.symbolic(name)

    def _execute_loop(self) -> None:
        """Main execution loop."""

        if self._worklist is None:
            return

        if self._resource_tracker is not None:
            self._resource_tracker.start()

        import pysymex.core.solver as _solver_mod

        _solver_mod.active_incremental_solver = self.solver

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

        finally:
            _solver_mod.active_incremental_solver = None

    def _check_resource_limits(self, state: VMState) -> bool:
        """Check if resource limits are exceeded."""

        try:
            if self._resource_tracker is not None:
                self._resource_tracker.check_depth_limit()

            return True

        except LimitExceeded:
            self._paths_pruned += 1

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
        """Check if the current path is feasible with Z3."""

        if not self.solver.is_sat(list(state.path_constraints)):
            self._paths_pruned += 1

            return False

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

        self._loop_iterations[pc_key] = self._loop_iterations.get(pc_key, 0) + 1

        if self._loop_iterations[pc_key] > self.config.max_loop_iterations:
            if self._loop_widening is not None:
                self._loop_widening.record_iteration(loop)

                if self._loop_widening.should_widen(loop):
                    prev_state = getattr(self, "_prev_loop_states", {}).get(pc_key)

                    if prev_state is not None:
                        widened = self._loop_widening.widen_state(prev_state, state, loop)

                        if loop.exit_pcs:
                            widened.pc = min(loop.exit_pcs)

                            if self._worklist:
                                self._worklist.add_state(widened)

                            self._paths_explored += 1

                            if self.config.verbose:
                                print(f"Loop at PC {pc_key}: widened and jumped to exit")

                            return False

            if self.config.verbose:
                print(f"Loop at PC {pc_key} exceeded max iterations")

            self._paths_pruned += 1

            return False

        if not hasattr(self, "_prev_loop_states"):
            self._prev_loop_states = {}

        self._prev_loop_states[pc_key] = state.fork()

        return True

    def _process_execution_result(
        self, result: Any, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Process the result of an opcode execution."""

        if result.issues:
            for issue in result.issues:
                issue.line_number = self._get_line_number(issue.pc, active_instructions)

                self._issues.append(issue)

        if result.terminal:
            self._paths_completed += 1

            return

        for new_state in result.new_states:
            new_state.depth = state.depth + 1

            if self._worklist:
                self._worklist.add_state(new_state)

            if self._resource_tracker is not None:
                self._resource_tracker.record_path()

            self._paths_explored += 1

    def _execute_step(self, state: VMState) -> None:
        """Execute a single step (one instruction).

        Uses lazy constraint evaluation: skips the expensive Z3 feasibility
        check on straight-line code and only checks when:
        1. A conditional branch opcode is reached.
        2. The pending constraint count exceeds the lazy_eval_threshold.
        3. Detectors need to verify a property.
        """

        instr, active_instructions = self._fetch_instruction(state)

        if instr is None:
            self._paths_completed += 1

            self._last_globals = state.global_vars

            self._last_locals = state.local_vars

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

            return

        self._visited_states.add(state_hash)

        self._coverage.add(state.pc)

        state.visited_pcs.add(state.pc)

        needs_check = (
            instr.opname in BRANCH_OPCODES
            or state.pending_constraint_count >= self.config.lazy_eval_threshold
        )

        if needs_check:
            if not self._check_path_feasibility(state):
                return

            state.pending_constraint_count = 0

        self._run_detectors(state, instr, active_instructions)

        try:
            result = self.dispatcher.dispatch(instr, state)

            self._process_execution_result(result, state, active_instructions)

        except Exception as e:
            if self.config.verbose:
                print(f"Execution error at PC {state.pc}: {e}")

            self._paths_pruned += 1

            return

    def _get_line_number(self, pc: int, active_instructions: list[dis.Instruction]) -> int | None:
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

        if not self.config.detect_value_errors:
            disabled_names.add("value-error")

        active = [
            d
            for d in self.detector_registry.get_all()
            if d is not None and d.name not in disabled_names
        ]

        _DETECTOR_OPCODES: dict[str, frozenset[str]] = {
            "division-by-zero": frozenset(
                {
                    "BINARY_OP",
                    "BINARY_TRUE_DIVIDE",
                    "BINARY_FLOOR_DIVIDE",
                    "BINARY_MODULO",
                }
            ),
            "assertion-error": frozenset({"RAISE_VARARGS"}),
            "index-error": frozenset({"BINARY_SUBSCR"}),
            "enhanced-index-error": frozenset({"BINARY_SUBSCR"}),
            "key-error": frozenset({"BINARY_SUBSCR"}),
            "type-error": frozenset({"BINARY_OP"}),
            "enhanced-type-error": frozenset({"BINARY_SUBSCR", "BINARY_OP"}),
            "overflow": frozenset({"BINARY_OP"}),
            "none-dereference": frozenset({"LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR"}),
            "format-string": frozenset({"CALL", "CALL_FUNCTION", "FORMAT_VALUE"}),
            "value-error": frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD"}),
            "unbound-variable": frozenset({"LOAD_FAST", "LOAD_FAST_CHECK"}),
            "attribute-error": frozenset({"__NEVER__"}),
            "resource-leak": frozenset({"__NEVER__"}),
        }

        self._detector_dispatch: dict[str, list[Detector]] = {}

        self._universal_detectors: list[Detector] = []

        for d in active:
            opcodes = _DETECTOR_OPCODES.get(d.name, frozenset())

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
                issue.line_number = self._get_line_number(state.pc, active_instructions)

                self._issues.append(issue)

        specific = self._detector_dispatch.get(opname)

        if specific:
            for detector in specific:
                issue = detector.check(state, instr, self.solver.is_sat)

                if issue:
                    issue.line_number = self._get_line_number(state.pc, active_instructions)

                    self._issues.append(issue)

    def _hash_state(self, state: VMState) -> int:
        """Create a hash of the state to detect truly redundant paths.

        For soundness, this must include all variables and the stack.

        **CPU-cache-friendly implementation**: Uses a rolling polynomial hash
        directly over state fields — no tuple allocation, no generators, no
        sorted() — producing zero garbage per invocation.  The hash quality
        is comparable to the previous tuple-based approach (positions are
        preserved for the stack via multiplicative accumulation).

        KNOWN BUG: Uses ``len(state.path_constraints)`` instead of hashing
        the constraint *content*.  Two states at the same PC with the same
        stack, locals, call-depth, and number of constraints — but *different*
        constraint expressions — will collide and the second will be pruned.
        This can cause the executor to miss feasible paths.

        Attempts to fix this by comparing constraint identity (``id()`` or
        ``sexpr()``) as a secondary filter exposed 3 pre-existing false-
        positive detections in tests that relied on the imprecise dedup to
        mask them (``test_object_merge``, ``test_path_explosion_simplest``,
        ``test_path_explosion_resistance``).  A proper fix requires both:
          1. More precise dedup (constraint content in the hash), AND
          2. Improved SimpleNamespace / attribute-merge tracking so that
             the newly-explored paths do not produce false positives.
        Until (2) is addressed, the len-based hash is retained for
        compatibility.
        """

        h = state.pc * 2654435761

        h ^= len(state.path_constraints) * 999999937

        h ^= state.call_depth() * 1000000007

        for v in state.stack:
            try:
                h = (h * 31) ^ hash(v)

            except TypeError:
                h = (h * 31) ^ id(v)

        for k, v in state.local_vars.items():
            try:
                h ^= hash(k) * 1000000007 ^ hash(v)

            except TypeError:
                h ^= hash(k) * 1000000007 ^ id(v)

        return h
