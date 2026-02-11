"""Main symbolic executor for PySpectre."""

from __future__ import annotations

import dis
import inspect
import types
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import z3

from pyspectre.analysis.cache import LRUCache, hash_function
from pyspectre.analysis.abstract_interpreter import AbstractAnalyzer
from pyspectre.analysis.cross_function import CrossFunctionAnalyzer
from pyspectre.analysis.detectors import DetectorRegistry, Issue, IssueKind, default_registry
from pyspectre.analysis.fp_filter import deduplicate_issues, filter_issues
from pyspectre.analysis.loops import LoopDetector, LoopWidening
from pyspectre.analysis.path_manager import (
    ExplorationStrategy,
    PathManager,
    create_path_manager,
)
from pyspectre.analysis.state_merger import MergePolicy, StateMerger
from pyspectre.analysis.taint import TaintTracker
from pyspectre.analysis.type_inference import TypeAnalyzer
from pyspectre.core.solver import ShadowSolver
from pyspectre.core.state import VMState
from pyspectre.core.types import SymbolicList, SymbolicString, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeDispatcher
from pyspectre.resources import LimitExceeded, ResourceLimits, ResourceTracker
import pyspectre.execution.opcodes  # noqa: F401 — side-effect import for handler registration


@dataclass
class ExecutionConfig:
    """Configuration for symbolic execution."""

    max_paths: int = 10000
    max_depth: int = 1000
    max_iterations: int = 100000
    timeout_seconds: float = 300.0
    strategy: ExplorationStrategy = ExplorationStrategy.DFS
    max_loop_iterations: int = 100
    unroll_loops: bool = True
    solver_timeout_ms: int = 10000
    use_incremental_solving: bool = True
    detect_division_by_zero: bool = True
    detect_assertion_errors: bool = True
    detect_index_errors: bool = True
    detect_type_errors: bool = True
    detect_overflow: bool = False
    detect_value_errors: bool = True
    verbose: bool = False
    collect_coverage: bool = True
    use_loop_analysis: bool = False
    enable_taint_tracking: bool = True
    enable_caching: bool = True
    use_type_hints: bool = True
    enable_state_merging: bool = True
    merge_policy: str = "moderate"
    enable_fp_filtering: bool = True
    enable_cross_function: bool = True
    enable_type_inference: bool = True
    enable_abstract_interpretation: bool = True
    symbolic_args: dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of symbolic execution."""

    issues: list[Issue] = field(default_factory=list)
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    coverage: set[int] = field(default_factory=set)
    total_time_seconds: float = 0.0
    solver_time_seconds: float = 0.0
    function_name: str = ""
    source_file: str = ""
    final_globals: dict[str, Any] = field(default_factory=dict)
    final_locals: dict[str, Any] = field(default_factory=dict)

    def has_issues(self) -> bool:
        """Check if any issues were found."""
        return len(self.issues) > 0

    def get_issues_by_kind(self, kind: IssueKind) -> list[Issue]:
        """Get issues of a specific kind."""
        return [i for i in self.issues if i.kind == kind]

    def format_summary(self) -> str:
        """Format a summary of results."""
        lines = [
            "=== PySpectre Execution Results ===",
            f"Function: {self.function_name}",
            f"Paths explored: {self.paths_explored}",
            f"Paths completed: {self.paths_completed}",
            f"Coverage: {len(self.coverage)} bytecode instructions",
            f"Total time: {self.total_time_seconds:.2f}s",
            "",
        ]
        if self.issues:
            lines.append(f"Issues found: {len(self.issues)}")
            for issue in self.issues:
                lines.append("")
                lines.append(issue.format())
        else:
            lines.append("No issues found!")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "function_name": self.function_name,
            "source_file": self.source_file,
            "paths_explored": self.paths_explored,
            "paths_completed": self.paths_completed,
            "paths_pruned": self.paths_pruned,
            "coverage_size": len(self.coverage),
            "total_time_seconds": self.total_time_seconds,
            "issues": [i.to_dict() for i in self.issues],
        }

    def to_sarif(self, output_path: str | None = None) -> dict[str, Any]:
        """Convert to SARIF v2.1.0 format for IDE/CI integration.

        Uses the existing SARIFGenerator from pyspectre.reporting.sarif.

        Args:
            output_path: If provided, write the SARIF JSON to this file.

        Returns:
            SARIF log as a dictionary.
        """
        from pyspectre.reporting.sarif import SARIFGenerator

        generator = SARIFGenerator(
            tool_name="PySpectre",
            tool_version="0.3.0-alpha",
        )
        issue_dicts = []
        for issue in self.issues:
            issue_dict = {
                "type": issue.kind.name.lower(),
                "message": issue.message,
                "line": issue.line_number or 0,
                "file": issue.filename or self.source_file or "",
            }
            counterexample = issue.get_counterexample()
            if counterexample:
                issue_dict["triggering_input"] = counterexample
            issue_dicts.append(issue_dict)

        sarif_log = generator.generate(
            issues=issue_dicts,
            analyzed_files=[self.source_file] if self.source_file else [],
        )
        sarif_dict = sarif_log.to_dict()

        if sarif_dict.get("runs"):
            run = sarif_dict["runs"][0]
            if run.get("invocations"):
                run["invocations"][0]["properties"] = {
                    "pathsExplored": self.paths_explored,
                    "pathsCompleted": self.paths_completed,
                    "pathsPruned": self.paths_pruned,
                    "coverageInstructions": len(self.coverage),
                    "totalTimeSeconds": round(self.total_time_seconds, 3),
                }

        if output_path:
            import json

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_dict, f, indent=2, default=str)

        return sarif_dict


class SymbolicExecutor:
    """Main symbolic execution engine."""

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ):
        self.config = config or ExecutionConfig()
        if self.config is None:
            self.config = ExecutionConfig()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.solver = ShadowSolver(timeout_ms=self.config.solver_timeout_ms)
        self._instructions: list[dis.Instruction] = []
        self._pc_to_line: dict[int, int] = {}
        self._worklist: PathManager | None = None
        self._issues: list[Issue] = []
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
        self._result_cache: LRUCache | None = None
        self._state_merger: StateMerger | None = None
        self._resource_tracker: ResourceTracker | None = None
        self._cross_function: CrossFunctionAnalyzer | None = None
        self._type_analyzer: TypeAnalyzer | None = None
        self._abstract_analyzer: AbstractAnalyzer | None = None
        self._effect_summaries: dict[str, Any] = {}
        if self.config.enable_taint_tracking:
            self._taint_tracker = TaintTracker()
        if self.config.enable_caching:
            self._result_cache = LRUCache(maxsize=500)
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
            try:
                self._cross_function = CrossFunctionAnalyzer()
            except Exception:
                pass

        if self.config.enable_type_inference:
            try:
                self._type_analyzer = TypeAnalyzer()
            except Exception:
                pass

        if self.config.enable_abstract_interpretation:
            try:
                self._abstract_analyzer = AbstractAnalyzer()
            except Exception:
                pass
        limits = ResourceLimits(
            max_paths=self.config.max_paths,
            max_depth=self.config.max_depth,
            max_iterations=self.config.max_iterations,
            timeout_seconds=self.config.timeout_seconds,
        )
        self._resource_tracker = ResourceTracker(limits=limits)

    def execute_function(
        self,
        func: Callable,
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
        self._instructions = list(dis.get_instructions(code))
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
                self._cross_function.analyze(code)
                self._effect_summaries = getattr(self._cross_function, "effect_summaries", {})
            except Exception:
                self._cross_function = None
        if self.config.enable_type_inference:
            try:
                self._type_analyzer = TypeAnalyzer()
                self._type_analyzer.analyze(code)
            except Exception:
                self._type_analyzer = None
        self._execute_loop()
        end_time = time.time()
        final_issues = self._issues
        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)
                final_issues = deduplicate_issues(final_issues)
            except Exception:
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
        self._instructions = list(dis.get_instructions(code))
        self.dispatcher.set_instructions(self._instructions)
        self._build_line_mapping(code)
        initial_state = VMState()
        if initial_globals:
            initial_state.global_vars = initial_globals.copy()
        if self._taint_tracker is not None:
            initial_state.taint_tracker = self._taint_tracker
        for name, type_hint in (symbolic_vars or {}).items():
            sym_val, constraint = self._create_symbolic_for_type(name, type_hint)
            initial_state.local_vars[name] = sym_val
            initial_state.add_constraint(constraint)
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
                pass

        if self._abstract_analyzer is not None:
            self._run_abstract_interpretation(code)

        self._execute_loop()
        end_time = time.time()
        final_issues = self._issues
        if self.config.enable_fp_filtering:
            try:
                final_issues = filter_issues(final_issues)
                final_issues = deduplicate_issues(final_issues)
            except Exception:
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
        """Reset execution state."""
        self._instructions = []
        self._pc_to_line = {}
        self._issues = []
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
            elif instr.starts_line and isinstance(instr.starts_line, int):
                self._pc_to_line[i] = instr.starts_line
                last_line = instr.starts_line
            elif last_line:
                self._pc_to_line[i] = last_line

    def _run_abstract_interpretation(self, code: Any) -> None:
        """Run fast abstract interpretation pass."""
        try:
            warnings = self._abstract_analyzer.analyze_function(code)
            for warning in warnings:
                confidence = getattr(warning, "confidence", "possible")
                if confidence == "definite":
                    line = getattr(warning, "line", 0)
                    pc = getattr(warning, "pc", 0)
                    msg = getattr(warning, "message", str(warning))

                    issue = Issue(
                        kind=IssueKind.DIVISION_BY_ZERO,
                        message=f"[Abstract Interpreter] {msg}",
                        line_number=line,
                        pc=pc,
                        function_name=code.co_name,
                    )
                    self._issues.append(issue)
                    self._issues.append(issue)
        except Exception:
            pass

    def _create_initial_state(
        self,
        func: Callable,
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
                pass
        for param in params:
            type_hint = symbolic_args.get(param) or inferred_types.get(param, "int")
            sym_val, constraint = self._create_symbolic_for_type(param, type_hint)
            state.local_vars[param] = sym_val
            state.add_constraint(constraint)
        return state

    def _hint_to_type_str(self, hint) -> str:
        """Convert a type hint to a type string for symbolic creation."""
        hint_str = str(hint).lower()
        if hint is int or "int" in hint_str:
            return "int"
        elif hint is str or "str" in hint_str:
            return "str"
        elif hint is bool or "bool" in hint_str:
            return "bool"
        elif hint is list or "list" in hint_str:
            return "list"
        elif "path" in hint_str:
            return "path"
        return "int"

    def _create_symbolic_for_type(self, name: str, type_hint: str) -> tuple[Any, z3.BoolRef]:
        """Create a symbolic value and its type constraint."""
        type_hint = type_hint.lower()
        if type_hint in ("int", "integer"):
            return SymbolicValue.symbolic(name)
        elif type_hint in ("str", "string"):
            return SymbolicString.symbolic(name)
        elif type_hint in ("list", "array"):
            return SymbolicList.symbolic(name)
        elif type_hint in ("bool", "boolean"):
            return SymbolicValue.symbolic(name)
        elif type_hint in ("path", "pathlib.path"):
            return SymbolicValue.symbolic_path(name)
        else:
            return SymbolicValue.symbolic(name)

    def _execute_loop(self) -> None:
        """Main execution loop."""
        if self._worklist is None:
            return
        if self._resource_tracker is not None:
            self._resource_tracker.start()
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

    def _process_execution_result(self, result: Any, state: VMState) -> None:
        """Process the result of an opcode execution."""
        if result.issues:
            for issue in result.issues:
                issue.line_number = self._pc_to_line.get(state.pc)
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
        """Execute a single step (one instruction)."""
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
        else:
            self._visited_states.add(state_hash)

        self._coverage.add(state.pc)
        state.visited_pcs.add(state.pc)

        if not self._check_path_feasibility(state):
            return

        self._run_detectors(state, instr)

        try:
            result = self.dispatcher.dispatch(instr, state)
            self._process_execution_result(result, state)
        except Exception as e:
            if self.config.verbose:
                print(f"Execution error at PC {state.pc}: {e}")
            self._paths_pruned += 1
            return

    def _run_detectors(self, state: VMState, instr: dis.Instruction) -> None:
        """Run enabled detectors on current state."""
        if self.detector_registry is None:
            return
        for detector in self.detector_registry.get_all():
            if detector is None:
                continue
            if detector.name == "division-by-zero" and not self.config.detect_division_by_zero:
                continue
            if detector.name == "assertion-error" and not self.config.detect_assertion_errors:
                continue
            if detector.name == "index-error" and not self.config.detect_index_errors:
                continue
            if detector.name == "type-error" and not self.config.detect_type_errors:
                continue
            if detector.name == "overflow" and not self.config.detect_overflow:
                continue
            if detector.name == "value-error" and not self.config.detect_value_errors:
                continue
            issue = detector.check(state, instr, self.solver.is_sat)
            if issue:
                issue.line_number = self._pc_to_line.get(state.pc)
                self._issues.append(issue)

    def _hash_state(self, state: VMState) -> int:
        """Create a hash of the state to detect truly redundant paths.
        For soundness, this must include all variables and the stack.
        """
        stack_vals = tuple(str(v) for v in state.stack)
        local_vals = tuple(sorted((k, str(v)) for k, v in state.local_vars.items()))
        return hash(
            (
                state.pc,
                len(state.path_constraints),
                stack_vals,
                local_vals,
                state.call_depth(),
            )
        )


def analyze(
    func: Callable,
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs,
) -> ExecutionResult:
    """
    Analyze a function for potential issues.
    Args:
        func: Function to analyze
        symbolic_args: Mapping of parameter names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    Example:
        >>> def divide(x, y):
        ...     return x / y
        >>> result = analyze(divide, {"x": "int", "y": "int"})
        >>> print(result.issues)  # Division by zero issue
    """
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)


def analyze_code(
    code: str | types.CodeType,
    symbolic_vars: dict[str, str] | None = None,
    **config_kwargs,
) -> ExecutionResult:
    """
    Analyze code for potential issues.
    Args:
        code: Source code string or code object
        symbolic_vars: Mapping of variable names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    """
    if isinstance(code, str):
        compiled = compile(code, "<string>", "exec")
        code = compiled
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(code, symbolic_vars)


def quick_check(func: Callable) -> list[Issue]:
    """
    Quick check a function for common issues.
    Args:
        func: Function to check
    Returns:
        List of issues found
    Example:
        >>> issues = quick_check(lambda x: 1/x)
        >>> print(issues[0].kind)  # IssueKind.DIVISION_BY_ZERO
    """
    result = analyze(func, max_paths=100, max_iterations=1000)
    return result.issues
