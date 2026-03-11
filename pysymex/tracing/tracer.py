"""Core execution tracer: event dispatcher, solver proxy, and session manager.

Architecture
~~~~~~~~~~~~
The tracer is built around three collaborating objects:

* :class:`TracingSolverProxy` — A transparent proxy that wraps
  :class:`~pysymex.core.solver.IncrementalSolver`.  It intercepts ``is_sat``
  and ``check`` calls to capture SMT telemetry (latency, cache hit, result)
  without modifying any logic in the solver itself.

* :class:`ExecutionTracer` — The main session manager and event dispatcher.
  It owns the JSONL file handle, the monotonic sequence counter, and the
  Keyframe + Delta buffering strategy.  Its hook methods (``pre_step``,
  ``post_step``, ``on_fork``, ``on_prune``, ``on_solve``, ``on_issue``) are
  registered with the executor and called by the executor's lifecycle
  methods.

* :func:`attach_tracer` — A convenience factory that creates a fully
  configured tracer, starts its session, installs it into an executor, and
  optionally returns a context manager for structured cleanup.

Buffering strategy
~~~~~~~~~~~~~~~~~~
* ``step`` events are written to an in-memory ``_delta_buffer`` (list of raw
  JSONL strings) and flushed when ``len(buffer) >= delta_batch_size``.
* ``solve`` events are added to the same buffer (they are frequent but small).
* ``keyframe`` and ``issue`` events are written immediately and trigger a
  **force-flush** of the entire buffer to disk, then an OS-level
  ``file.flush()``.  This guarantees that critical events are always on disk
  even if the process subsequently crashes.
* The ``system_context`` event is force-flushed the moment the session starts.

Thread safety
~~~~~~~~~~~~~
:class:`ExecutionTracer` uses a ``threading.Lock`` to serialise all writes
to the JSONL file and the sequence counter.  The solver proxy must therefore
only be used from the same thread as the executor (the analysis loop is
single-threaded by default in pysymex).
"""

from __future__ import annotations

import dis
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from pysymex.tracing.schemas import (
    ConstraintEntry,
    IssueEvent,
    KeyframeEvent,
    SolveEvent,
    StackDiff,
    StepDeltaEvent,
    SystemContextEvent,
    TracerConfig,
    VarDiff,
    VerbosityLevel,
)
from pysymex.tracing.z3_utils import Z3SemanticRegistry, Z3Serializer

if TYPE_CHECKING:
    from pysymex.analysis.detectors.base import Issue
    from pysymex.core.solver import IncrementalSolver
    from pysymex.core.state import VMState
    from pysymex.execution.executor_core import SymbolicExecutor


def _to_config_scalar(value: Any) -> str | int | float | bool | None:
    """Coerce arbitrary config values into schema-safe scalar values.

    ``SystemContextEvent.tracer_config`` accepts only scalar values. Nested
    structures (e.g. dict/list) and enums are serialised to stable JSON strings.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except Exception:
        return str(value)


def _normalise_config_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, str | int | float | bool | None]:
    """Convert a raw config snapshot to ``SystemContextEvent`` scalar schema."""
    return {str(key): _to_config_scalar(value) for key, value in snapshot.items()}


class TracingSolverProxy:
    """Transparent proxy around :class:`~pysymex.core.solver.IncrementalSolver`.

    Intercepts ``is_sat`` and ``check`` method calls to measure solver latency
    and detect cache hits, then fires :meth:`ExecutionTracer.on_solve`.  Every
    other attribute access is delegated to the wrapped instance unchanged.

    Args:
        inner:        The real :class:`~pysymex.core.solver.IncrementalSolver`.
        tracer:       The :class:`ExecutionTracer` that receives ``on_solve``
                      notifications.
        state_getter: Zero-argument callable that returns the *current*
                      :class:`~pysymex.core.state.VMState`, used to embed
                      ``path_id`` and ``pc`` in solver events without the
                      proxy needing a direct reference to a mutable state.

    Safety contract
    ~~~~~~~~~~~~~~~
    * Any exception raised inside the proxy's interception logic is caught and
      written to ``stderr``.  The actual solver result is **always** returned
      to the caller unchanged — the proxy never interferes with correctness.
    * The proxy does not store or copy constraint objects beyond the duration
      of the call, preventing memory leaks on long analyses.
    """

    def __init__(
        self,
        inner: IncrementalSolver,
        tracer: ExecutionTracer,
        state_getter: Any,
    ) -> None:

        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_tracer", tracer)
        object.__setattr__(self, "_state_getter", state_getter)

    def is_sat(self, constraints: list[Any]) -> bool:
        """Intercept is_sat, record telemetry, then delegate."""
        inner: IncrementalSolver = object.__getattribute__(self, "_inner")
        tracer: ExecutionTracer = object.__getattribute__(self, "_tracer")
        state_getter = object.__getattribute__(self, "_state_getter")

        cache_hits_before: int = getattr(inner, "_cache_hits", 0)
        t0 = time.perf_counter()
        result: bool = inner.is_sat(constraints)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        cache_hits_after: int = getattr(inner, "_cache_hits", 0)
        cache_hit = cache_hits_after > cache_hits_before

        try:
            state: VMState | None = state_getter()
            path_id = getattr(state, "path_id", 0) if state is not None else 0
            pc = getattr(state, "pc", 0) if state is not None else 0
            result_str = "sat" if result else "unsat"
            tracer.on_solve(
                constraints=constraints,
                result_str=result_str,
                latency_ms=latency_ms,
                cache_hit=cache_hit,
                model=None,
                path_id=path_id,
                pc=pc,
            )
        except Exception as exc:
            print(
                f"[pysymex.tracing] TracingSolverProxy.is_sat telemetry error: {exc}",
                file=sys.stderr,
            )
        return result

    def check(self, *assumptions: Any) -> Any:
        """Intercept check (used by several internal callers), record telemetry."""
        inner: IncrementalSolver = object.__getattribute__(self, "_inner")
        tracer: ExecutionTracer = object.__getattribute__(self, "_tracer")
        state_getter = object.__getattribute__(self, "_state_getter")

        cache_hits_before: int = getattr(inner, "_cache_hits", 0)
        t0 = time.perf_counter()

        result = inner.check(*assumptions) if assumptions else inner.check()
        latency_ms = (time.perf_counter() - t0) * 1000.0
        cache_hits_after: int = getattr(inner, "_cache_hits", 0)
        cache_hit = cache_hits_after > cache_hits_before

        try:
            state: VMState | None = state_getter()
            path_id = getattr(state, "path_id", 0) if state is not None else 0
            pc = getattr(state, "pc", 0) if state is not None else 0
            is_sat_flag = getattr(result, "is_sat", None)
            if is_sat_flag is True:
                result_str = "sat"
            elif getattr(result, "is_unsat", None) is True:
                result_str = "unsat"
            else:
                result_str = "unknown"
            model = getattr(result, "model", None)
            tracer.on_solve(
                constraints=list(assumptions),
                result_str=result_str,
                latency_ms=latency_ms,
                cache_hit=cache_hit,
                model=model,
                path_id=path_id,
                pc=pc,
            )
        except Exception as exc:
            print(
                f"[pysymex.tracing] TracingSolverProxy.check telemetry error: {exc}",
                file=sys.stderr,
            )
        return result

    def __getattr__(self, name: str) -> Any:
        """Delegate every other attribute look-up to the inner solver."""
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Delegate attribute writes to the inner solver."""
        setattr(object.__getattribute__(self, "_inner"), name, value)


class ExecutionTracer:
    """LLM-optimised observability layer for :class:`~pysymex.execution.executor_core.SymbolicExecutor`.

    Session lifecycle
    ~~~~~~~~~~~~~~~~~
    1. Construct the tracer with a :class:`~pysymex.tracing.schemas.TracerConfig`.
    2. Call :meth:`start_session` (or use as a context manager).
    3. Call :meth:`install` on a :class:`~pysymex.execution.executor_core.SymbolicExecutor`
       **before** ``execute_function`` / ``execute_code`` is called.
    4. Let the executor run.
    5. Call :meth:`end_session` (or exit the context manager) to flush and
       close the JSONL file.  The returned :class:`~pathlib.Path` points to
       the completed trace file.

    Keyframe + Delta strategy
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    * **Deltas** (``step`` events) capture only *what changed* per instruction:
      stack diff, variable diff, memory diff, and (optionally) a new
      constraint.  They are cheap to write and cheap to replay.
    * **Keyframes** (``keyframe`` events) capture the *full symbolic state*
      at structurally important moments (fork, prune, issue).  They let an
      LLM re-anchor its understanding without replaying all prior deltas.

    Args:
        config: Tracer configuration.  Defaults to :class:`TracerConfig`.
    """

    def __init__(self, config: TracerConfig | None = None) -> None:

        self._config: TracerConfig = config if config is not None else TracerConfig.from_env()
        self._registry: Z3SemanticRegistry = Z3SemanticRegistry()
        self._serializer: Z3Serializer = Z3Serializer(self._registry)

        self._lock: Lock = Lock()
        self._file: Any = None
        self._trace_path: Path | None = None
        self._seq: int = 0
        self._delta_buffer: list[str] = []

        self._path_tree: dict[int, int | None] = {}

        self._pre_step_snapshot: (
            tuple[list[Any], dict[str, Any], dict[str, Any], dict[Any, Any]] | None
        ) = None

        self._current_state: VMState | None = None

    @property
    def registry(self) -> Z3SemanticRegistry:
        """The semantic name registry.  Accessible for external pre-registration."""
        return self._registry

    def start_session(
        self,
        func_name: str,
        signature_str: str,
        initial_args: dict[str, str],
        config_snapshot: dict[str, Any] | None = None,
        source_file: str = "<unknown>",
    ) -> Path:
        """Open a new trace file and write the ``system_context`` header.

        Args:
            func_name:       Qualified name of the function under analysis.
            signature_str:   String representation of the function signature.
            initial_args:    ``{parameter_name: type_string}`` mapping.
            config_snapshot: Serialised :class:`~pysymex.execution.executor_types.ExecutionConfig`
                             as a plain dict, or ``None``.
            source_file:     Absolute path to the source file.

        Returns:
            The :class:`~pathlib.Path` where events will be written.

        Raises:
            RuntimeError: If a session is already active.
        """
        if self._file is not None:
            raise RuntimeError("A tracing session is already active.  Call end_session() first.")
        if not self._config.enabled:
            return Path(self._config.output_dir)

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        safe_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in func_name)
        filename = f"trace_{ts}_{safe_name}.jsonl.gz"
        out_dir = Path(self._config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        self._trace_path = out_dir / filename

        import gzip
        self._file = gzip.open(
            self._trace_path,
            "wt",
            encoding="utf-8",
            compresslevel=self._config.compression_level,
        )

        z3_version = "unavailable"
        try:
            import z3 as _z3

            z3_version = _z3.get_version_string()
        except Exception:
            pass

        pysymex_version = "unknown"
        try:
            from importlib.metadata import version

            pysymex_version = version("pysymex")
        except Exception:
            try:
                import pysymex as _px

                pysymex_version = getattr(_px, "__version__", "unknown")
            except Exception:
                pass

        raw_config = config_snapshot if config_snapshot is not None else self._config.model_dump()

        header = SystemContextEvent(
            timestamp_iso=datetime.now(UTC).isoformat(),
            pysymex_version=pysymex_version,
            z3_version=z3_version,
            function_name=func_name,
            function_signature=signature_str,
            source_file=source_file,
            initial_symbolic_args=initial_args,
            tracer_config=_normalise_config_snapshot(raw_config),
        )
        self._write_event(header, force_flush=True)
        return self._trace_path

    def end_session(self) -> Path | None:
        """Flush all buffered events and close the trace file.

        Returns:
            The :class:`~pathlib.Path` to the completed trace file, or
            ``None`` if the tracer is disabled or no session was active.
        """
        if not self._config.enabled or self._file is None:
            return self._trace_path
        with self._lock:
            self._flush_buffer_locked()
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            finally:
                self._file = None
        return self._trace_path

    def __enter__(self) -> ExecutionTracer:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:

            try:
                self.end_session()
            except Exception:
                pass
        else:
            self.end_session()

    def install(self, executor: SymbolicExecutor) -> None:
        """Register all tracer hooks with *executor* and wrap its solver.

        This must be called **before** ``execute_function`` / ``execute_code``,
        but **after** ``start_session``.

        Args:
            executor: The :class:`~pysymex.execution.executor_core.SymbolicExecutor`
                      whose execution will be traced.
        """
        if not self._config.enabled:
            return

        executor.register_hook("pre_step", self.pre_step)
        executor.register_hook("post_step", self.post_step)
        executor.register_hook("on_fork", self.on_fork)
        executor.register_hook("on_prune", self.on_prune)
        executor.register_hook("on_issue", self.on_issue)

        state_getter = lambda: self._current_state
        executor.solver = TracingSolverProxy(executor.solver, self, state_getter)

    def pre_step(self, executor: SymbolicExecutor, state: VMState) -> None:
        """Capture a lightweight snapshot *before* the instruction dispatches.

        The snapshot records the current lengths/contents of stack, locals,
        globals, and memory so that ``post_step`` can compute diffs cheaply.

        Args:
            executor: The running executor (for config access).
            state:    Current VM state.
        """
        if not self._config.enabled:
            return
        self._current_state = state
        try:
            stack_copy = list(state.stack)
            locals_copy = dict(state.local_vars) if state.local_vars is not None else {}
            globals_copy = dict(state.global_vars) if state.global_vars is not None else {}
            memory_copy = dict(state.memory) if state.memory is not None else {}
            self._pre_step_snapshot = (stack_copy, locals_copy, globals_copy, memory_copy)
        except Exception:
            self._pre_step_snapshot = None

    def post_step(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        instr: dis.Instruction,
    ) -> None:
        """Emit a :class:`~pysymex.tracing.schemas.StepDeltaEvent` after dispatch.

        Computes the diff between the pre-step snapshot and the current state,
        then appends the delta to the buffer.

        Args:
            executor: The running executor.
            state:    VM state **after** the instruction was dispatched.
            instr:    The instruction that was just executed.
        """
        if not self._config.enabled:
            return
        if self._config.verbosity == VerbosityLevel.QUIET:
            return

        snap = self._pre_step_snapshot
        stack_diff = StackDiff()
        var_diff = VarDiff()
        mem_diff: dict[str, str] = {}
        constraint_added: ConstraintEntry | None = None

        try:
            current_stack = list(state.stack) if state.stack is not None else []
            current_locals = dict(state.local_vars) if state.local_vars is not None else {}
            current_memory = dict(state.memory) if state.memory is not None else {}

            if snap is not None:
                prev_stack, prev_locals, _prev_globals, prev_memory = snap

                prev_len = len(prev_stack)
                curr_len = len(current_stack)
                if curr_len < prev_len:
                    stack_diff = StackDiff(popped=prev_len - curr_len, pushed=[])
                elif curr_len > prev_len:
                    pushed_vals = [
                        self._serializer.serialize_stack_value(v) for v in current_stack[prev_len:]
                    ]
                    stack_diff = StackDiff(popped=0, pushed=pushed_vals)
                elif current_stack != prev_stack:

                    n_changed = sum(1 for a, b in zip(prev_stack, current_stack) if a is not b)
                    if n_changed:
                        stack_diff = StackDiff(
                            popped=n_changed,
                            pushed=[
                                self._serializer.serialize_stack_value(v)
                                for v in current_stack[-n_changed:]
                            ],
                        )

                for k, v in current_locals.items():
                    if k not in prev_locals:
                        var_diff = VarDiff(
                            modified=var_diff.modified,
                            added={**var_diff.added, k: self._serializer.serialize_stack_value(v)},
                            removed=var_diff.removed,
                        )
                    elif prev_locals[k] is not v:
                        var_diff = VarDiff(
                            modified={
                                **var_diff.modified,
                                k: self._serializer.serialize_stack_value(v),
                            },
                            added=var_diff.added,
                            removed=var_diff.removed,
                        )
                removed = [k for k in prev_locals if k not in current_locals]
                if removed:
                    var_diff = VarDiff(
                        modified=var_diff.modified,
                        added=var_diff.added,
                        removed=removed,
                    )

                if self._config.verbosity == VerbosityLevel.FULL:
                    for addr, val in current_memory.items():
                        if addr not in prev_memory or prev_memory[addr] is not val:
                            mem_diff[str(addr)] = self._serializer.serialize_stack_value(val)

            try:
                prev_constraint_count = getattr(state, "_pre_step_constraint_count", None)
                current_constraints = state.path_constraints
                current_count = len(current_constraints) if current_constraints is not None else 0
                if prev_constraint_count is not None and current_count > prev_constraint_count:

                    if (
                        current_constraints is not None
                        and current_constraints.constraint is not None
                    ):
                        newest = current_constraints.constraint
                        causality = f"{instr.opname} at PC={state.pc}"
                        constraint_added = ConstraintEntry(
                            smtlib=self._serializer.safe_sexpr(newest),
                            causality=causality,
                        )
            except Exception:
                pass

        except Exception:
            pass

        source_line: int | None = None
        try:
            pos = getattr(instr, "positions", None)
            if pos is not None and getattr(pos, "lineno", None) is not None:
                source_line = pos.lineno
            elif getattr(instr, "starts_line", None) is not None:
                source_line = instr.starts_line
        except Exception:
            pass

        event = StepDeltaEvent(
            seq=self._next_seq(),
            path_id=getattr(state, "path_id", 0),
            pc=getattr(state, "pc", 0),
            offset=getattr(instr, "offset", 0),
            opcode=getattr(instr, "opname", "UNKNOWN"),
            source_line=source_line,
            stack_diff=stack_diff,
            var_diff=var_diff,
            mem_diff=mem_diff,
            constraint_added=constraint_added,
        )
        self._write_event(event, force_flush=False)

    def on_fork(
        self,
        executor: SymbolicExecutor,
        parent_state: VMState,
        child_states: list[VMState],
    ) -> None:
        """Emit a keyframe snapshot when a path forks.

        Args:
            executor:      The running executor.
            parent_state:  The state from which the fork originates.
            child_states:  The new child states that were added to the worklist.
        """
        if not self._config.enabled:
            return
        if not self._config.keyframe_on_fork:
            return

        parent_id = getattr(parent_state, "path_id", 0)
        child_ids = [getattr(c, "path_id", 0) for c in child_states]

        for cid in child_ids:
            self._path_tree[cid] = parent_id

        event = self._build_keyframe(
            state=parent_state,
            trigger="fork",
            child_path_ids=child_ids,
            prune_reason=None,
        )
        self._write_event(event, force_flush=True)

    def on_prune(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        reason: str,
    ) -> None:
        """Emit a keyframe snapshot when a path is pruned.

        Args:
            executor: The running executor.
            state:    The pruned state.
            reason:   Short string identifying the prune cause
                      (e.g. ``"infeasible"``, ``"resource_limit"``,
                      ``"duplicate_state"``).
        """
        if not self._config.enabled:
            return
        if not self._config.keyframe_on_prune:
            return

        event = self._build_keyframe(
            state=state,
            trigger="prune",
            child_path_ids=None,
            prune_reason=reason,
        )
        self._write_event(event, force_flush=True)

    def on_solve(
        self,
        constraints: list[Any],
        result_str: str,
        latency_ms: float,
        cache_hit: bool,
        model: Any,
        path_id: int = 0,
        pc: int = 0,
    ) -> None:
        """Emit an SMT solver telemetry event.

        Args:
            constraints:  The constraint list that was checked.
            result_str:   ``"sat"``, ``"unsat"``, or ``"unknown"``.
            latency_ms:   Wall-clock query time in milliseconds.
            cache_hit:    Whether the result was found in the LRU cache.
            model:        The Z3 model (satisfying assignment), or ``None``.
            path_id:      Execution path for context.
            pc:           Program counter for context.
        """
        if not self._config.enabled:
            return

        model_excerpt: dict[str, str] | None = None
        if result_str == "sat" and model is not None:
            try:
                model_excerpt = self._serializer.serialize_model(model, max_vars=30)
            except Exception:
                pass

        result_val: Any = result_str if result_str in ("sat", "unsat", "unknown") else "unknown"

        event = SolveEvent(
            seq=self._next_seq(),
            path_id=path_id,
            pc=pc,
            num_constraints=len(constraints) if constraints else 0,
            result=result_val,
            solver_latency_ms=round(latency_ms, 3),
            cache_hit=cache_hit,
            model_excerpt=model_excerpt,
        )
        self._write_event(event, force_flush=False)

    def on_issue(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        issue: Issue,
    ) -> None:
        """Emit a keyframe + issue event when a bug is detected.

        Args:
            executor: The running executor.
            state:    The VM state at detection time.
            issue:    The :class:`~pysymex.analysis.detectors.base.Issue` object.
        """
        if not self._config.enabled:
            return

        if self._config.keyframe_on_issue:
            kf = self._build_keyframe(
                state=state, trigger="issue", child_path_ids=None, prune_reason=None
            )
            self._write_event(kf, force_flush=False)

        z3_model: dict[str, str] | None = None
        issue_model = getattr(issue, "model", None)
        if issue_model is not None:
            try:
                z3_model = self._serializer.serialize_model(issue_model, max_vars=30)
            except Exception:
                pass
        if z3_model is None:
            ce = getattr(issue, "counterexample", None)
            if ce:
                z3_model = {str(k): str(v) for k, v in ce.items()}

        constraints_at_issue: list[ConstraintEntry] = []
        try:
            pc_val = getattr(state, "pc", 0)
            causality_base = f"path constraint at PC={pc_val}"
            issue_constraints = getattr(issue, "constraints", None) or []
            raw_dicts = self._serializer.constraints_to_smtlib(issue_constraints, causality_base)
            constraints_at_issue = [
                ConstraintEntry(smtlib=d["smtlib"], causality=d["causality"])
                for d in raw_dicts[: self._config.max_constraint_display]
            ]
        except Exception:
            pass

        severity = "HIGH"
        try:
            sev_attr = getattr(issue, "severity", None)
            if sev_attr is not None:
                severity = str(sev_attr.name) if hasattr(sev_attr, "name") else str(sev_attr)
        except Exception:
            pass

        issue_kind = "UNKNOWN"
        try:
            kind_attr = getattr(issue, "kind", None)
            if kind_attr is not None:
                issue_kind = kind_attr.name if hasattr(kind_attr, "name") else str(kind_attr)
        except Exception:
            pass

        detector_name = issue_kind.lower().replace("_", "-")
        try:
            fn = getattr(issue, "function_name", None)
            if fn:
                detector_name = fn
        except Exception:
            pass

        source_line: int | None = getattr(issue, "line_number", None)

        event = IssueEvent(
            seq=self._next_seq(),
            path_id=getattr(state, "path_id", 0),
            pc=getattr(issue, "pc", getattr(state, "pc", 0)),
            source_line=source_line,
            severity=severity,
            detector_name=detector_name,
            issue_kind=issue_kind,
            message=str(getattr(issue, "message", "")),
            constraints_at_issue=constraints_at_issue,
            z3_model=z3_model,
        )
        self._write_event(event, force_flush=True)

    def _next_seq(self) -> int:
        """Return and post-increment the global sequence counter."""
        with self._lock:
            seq = self._seq
            self._seq += 1
        return seq

    def _build_keyframe(
        self,
        state: VMState,
        trigger: str,
        child_path_ids: list[int] | None,
        prune_reason: str | None,
    ) -> KeyframeEvent:
        """Construct a :class:`~pysymex.tracing.schemas.KeyframeEvent` from *state*."""
        path_id = getattr(state, "path_id", 0)
        parent_path_id = self._path_tree.get(path_id)

        stack_strs: list[str] = []
        try:
            for v in state.stack or []:
                stack_strs.append(self._serializer.serialize_stack_value(v))
        except Exception:
            pass

        local_strs = self._serializer.serialize_namespace(state.local_vars)
        global_strs: dict[str, str] = {}
        if self._config.verbosity != VerbosityLevel.QUIET:
            global_strs = self._serializer.serialize_namespace(state.global_vars)

        constraint_entries: list[ConstraintEntry] = []
        try:
            pc_val = getattr(state, "pc", 0)
            depth_val = getattr(state, "depth", 0)
            causality = f"path constraint at PC={pc_val}, depth={depth_val}"
            constraints_raw = list(state.path_constraints or [])
            bounded = constraints_raw[: self._config.max_constraint_display]
            raw_dicts = self._serializer.constraints_to_smtlib(bounded, causality)
            constraint_entries = [
                ConstraintEntry(smtlib=d["smtlib"], causality=d["causality"]) for d in raw_dicts
            ]
        except Exception:
            pass

        trigger_val: Any = trigger if trigger in ("fork", "prune", "issue") else "prune"

        return KeyframeEvent(
            seq=self._next_seq(),
            trigger=trigger_val,
            path_id=path_id,
            parent_path_id=parent_path_id,
            child_path_ids=child_path_ids,
            pc=getattr(state, "pc", 0),
            depth=getattr(state, "depth", 0),
            stack=stack_strs,
            local_vars=local_strs,
            global_vars=global_strs,
            path_constraints=constraint_entries,
            prune_reason=prune_reason,
        )

    def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
        """Serialise *event* to JSONL and manage the write buffer.

        Force-flush behaviour:
        * ``force_flush=True`` → append the line, then flush the entire
          buffer to disk and call ``file.flush()`` for OS-level durability.
        * ``force_flush=False`` → append to buffer; only flush if buffer
          reaches ``delta_batch_size``.

        Args:
            event:       A Pydantic model instance.
            force_flush: Whether to synchronously flush to disk.
        """
        if self._file is None:
            return
        try:
            line = event.model_dump_json()
        except Exception:
            return

        with self._lock:
            self._delta_buffer.append(line)
            if force_flush or len(self._delta_buffer) >= self._config.delta_batch_size:
                self._flush_buffer_locked()

    def _flush_buffer_locked(self) -> None:
        """Write all buffered lines to file.  Must be called under ``_lock``."""
        if self._file is None or not self._delta_buffer:
            return
        try:
            self._file.write("\n".join(self._delta_buffer) + "\n")
            self._file.flush()
            self._delta_buffer.clear()
        except Exception:
            self._delta_buffer.clear()


def attach_tracer(
    executor: SymbolicExecutor,
    func_name: str,
    signature_str: str = "",
    initial_args: dict[str, str] | None = None,
    config: TracerConfig | None = None,
    source_file: str = "<unknown>",
) -> tuple[ExecutionTracer, Path | None]:
    """Create, start, and install a tracer onto *executor* in one call.

    This is the recommended entry point for most use cases.  The caller is
    responsible for calling :meth:`ExecutionTracer.end_session` after the
    analysis completes (or using the tracer as a context manager).

    Args:
        executor:       The executor to trace.
        func_name:      Qualified name of the function under analysis.
        signature_str:  Human-readable signature string.
        initial_args:   ``{param_name: type_string}`` mapping.
        config:         Tracer configuration.  Defaults to :class:`TracerConfig`.
        source_file:    Path to the source file.

    Returns:
        ``(tracer, trace_path)`` tuple.  ``trace_path`` is ``None`` if the
        tracer is disabled.
    """
    tracer = ExecutionTracer(config=config)
    trace_path = tracer.start_session(
        func_name=func_name,
        signature_str=signature_str,
        initial_args=initial_args or {},
        source_file=source_file,
    )
    tracer.install(executor)
    return tracer, trace_path
