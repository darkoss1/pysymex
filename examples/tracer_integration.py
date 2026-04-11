"""Example: integrating ExecutionTracer with SymbolicExecutor.

This script demonstrates every major capability of the tracing module:

1.  Manual tracer creation and session management.
2.  Auto-registration of symbolic argument names in the Z3 registry.
3.  Direct installation via ``tracer.install(executor)``.
4.  Using the ``attach_tracer`` convenience factory.
5.  Reading back the generated trace and validating its structure.

Run from the repo root ::

    python pysymex_release/examples/tracer_integration.py

The script writes a ``trace_*.jsonl`` file under ``.pysymex/traces/`` in
the current working directory and prints a summary to stdout.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Target functions under analysis
# ---------------------------------------------------------------------------


def divide(x: int, y: int) -> int:
    """Trivial function that exercises division-by-zero detection."""
    return x // y


def binary_search(arr: list[int], target: int) -> int:
    """Classic binary search â€” exercises branching and path explosion."""
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def nested_branches(a: int, b: int, c: int) -> int:
    """Deeply nested branches â€” good for observing fork/keyframe events."""
    if a > 0:
        if b > a:
            if c > b:
                return a + b + c
            else:
                return a + b - c
        else:
            return b - a
    else:
        return -a


# ---------------------------------------------------------------------------
# Helper: pretty-print event stats from a trace file
# ---------------------------------------------------------------------------


def summarise_trace(path: Path) -> None:
    """Read a JSONL trace and print aggregate statistics."""
    counts: dict[str, int] = {}
    issues: list[dict] = []
    keyframes: list[dict] = []
    solves: list[dict] = []

    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"  [WARN] Line {line_no}: JSON parse error â€” {exc}", file=sys.stderr)
                continue
            etype = event.get("event_type", "<unknown>")
            counts[etype] = counts.get(etype, 0) + 1
            if etype == "issue":
                issues.append(event)
            elif etype == "keyframe":
                keyframes.append(event)
            elif etype == "solve":
                solves.append(event)

    print(f"\n  Trace: {path.name}")
    print(f"  {'Event type':<20} {'Count':>8}")
    print(f"  {'-'*20} {'-'*8}")
    for etype, cnt in sorted(counts.items()):
        print(f"  {etype:<20} {cnt:>8}")

    if solves:
        latencies = [s.get("solver_latency_ms", 0.0) for s in solves]
        cache_hits = sum(1 for s in solves if s.get("cache_hit"))
        avg_lat = sum(latencies) / len(latencies)
        print(f"\n  SMT:  avg latency={avg_lat:.2f}ms  cache_hit_rate={cache_hits}/{len(solves)}")

    prune_keyframes = [k for k in keyframes if k.get("trigger") == "prune"]
    fork_keyframes = [k for k in keyframes if k.get("trigger") == "fork"]
    print(f"  Keyframes: {len(fork_keyframes)} fork, {len(prune_keyframes)} prune, "
          f"{len([k for k in keyframes if k.get('trigger') == 'issue'])} issue")

    if issues:
        print(f"\n  Issues detected: {len(issues)}")
        for iss in issues:
            print(f"    [{iss.get('severity', '?')}] {iss.get('issue_kind', '?')} â€” "
                  f"{iss.get('message', '')[:80]}")
            if iss.get("z3_model"):
                print(f"      model: {iss['z3_model']}")


# ---------------------------------------------------------------------------
# Example 1: Manual session lifecycle using tracer.install()
# ---------------------------------------------------------------------------


def example_manual(func=divide) -> None:
    """Trace ``divide`` with full manual session control."""
    print("\n=== Example 1: manual session ===")

    # Late import so the example can stand alone if pysymex is on PYTHONPATH
    from pysymex.execution.executors.facade import SymbolicExecutor, ExecutionConfig
    from pysymex.tracing import ExecutionTracer, TracerConfig, VerbosityLevel

    config = ExecutionConfig(
        max_paths=50,
        max_depth=20,
        solver_timeout_ms=5000,
        detect_division_by_zero=True,
    )
    executor = SymbolicExecutor(config=config)

    tracer_cfg = TracerConfig(
        output_dir=".pysymex/traces",
        verbosity=VerbosityLevel.DELTA_ONLY,
        delta_batch_size=20,
        keyframe_on_fork=True,
        keyframe_on_prune=True,
        keyframe_on_issue=True,
    )
    tracer = ExecutionTracer(tracer_cfg)

    # Auto-register symbolic arg names so the Z3 registry can rename k!N â†’ x / y
    try:
        from pysymex.core.types import SymbolicValue
        sym_x = SymbolicValue.symbolic("x")
        sym_y = SymbolicValue.symbolic("y")
        tracer.registry.auto_register(sym_x, "x")
        tracer.registry.auto_register(sym_y, "y")
    except Exception as exc:
        print(f"  [NOTE] SymbolicValue pre-registration skipped: {exc}")

    # Optional manual overrides â€” highest priority
    tracer.registry.update({"k!0": "x", "k!1": "y"})

    sig = str(inspect.signature(func))
    source_file = inspect.getfile(func) if hasattr(func, "__code__") else "<unknown>"

    trace_path = tracer.start_session(
        func_name=func.__qualname__,
        signature_str=sig,
        initial_args={"x": "int", "y": "int"},
        source_file=source_file,
    )
    print(f"  Writing trace â†’ {trace_path}")

    # Install the tracer (registers hooks + wraps solver)
    tracer.install(executor)

    try:
        result = executor.execute_function(func, {"x": "int", "y": "int"})
        print(f"  Execution complete: {result.paths_explored} paths, "
              f"{result.paths_pruned} pruned, {len(result.issues)} issues")
    finally:
        tracer.end_session()

    summarise_trace(trace_path)


# ---------------------------------------------------------------------------
# Example 2: attach_tracer convenience factory + context manager
# ---------------------------------------------------------------------------


def example_convenience(func=nested_branches) -> None:
    """Trace ``nested_branches`` with the convenience factory."""
    print("\n=== Example 2: attach_tracer factory ===")

    from pysymex.execution.executors.facade import SymbolicExecutor, ExecutionConfig
    from pysymex.tracing import TracerConfig, VerbosityLevel, attach_tracer

    config = ExecutionConfig(max_paths=100, max_depth=30, solver_timeout_ms=5000)
    executor = SymbolicExecutor(config=config)

    tracer_cfg = TracerConfig(
        verbosity=VerbosityLevel.FULL,
        delta_batch_size=50,
    )
    sig = str(inspect.signature(func))
    source_file = inspect.getfile(func) if hasattr(func, "__code__") else "<unknown>"

    # attach_tracer starts session + installs in one call
    tracer, trace_path = attach_tracer(
        executor,
        func_name=func.__qualname__,
        signature_str=sig,
        initial_args={"a": "int", "b": "int", "c": "int"},
        config=tracer_cfg,
        source_file=source_file,
    )

    print(f"  Writing trace â†’ {trace_path}")

    # Use the tracer as a context manager for automatic end_session
    with tracer:
        result = executor.execute_function(func, {"a": "int", "b": "int", "c": "int"})
        print(f"  Execution complete: {result.paths_explored} paths, "
              f"{result.paths_pruned} pruned, {len(result.issues)} issues")

    if trace_path:
        summarise_trace(trace_path)


# ---------------------------------------------------------------------------
# Example 3: Plugin-adapter installation path
# ---------------------------------------------------------------------------


def example_plugin_adapter(func=divide) -> None:
    """Install tracing via the HookPlugin adapter (plugin-manager path)."""
    print("\n=== Example 3: TracingHookPlugin adapter ===")

    from pysymex.execution.executors.facade import SymbolicExecutor, ExecutionConfig
    from pysymex.tracing import ExecutionTracer, TracerConfig, VerbosityLevel
    from pysymex.tracing.hooks import TracingHookPlugin

    config = ExecutionConfig(max_paths=30, detect_division_by_zero=True)
    executor = SymbolicExecutor(config=config)

    tracer_cfg = TracerConfig(verbosity=VerbosityLevel.QUIET)
    tracer = ExecutionTracer(tracer_cfg)

    sig = str(inspect.signature(func))
    source_file = inspect.getfile(func) if hasattr(func, "__code__") else "<unknown>"
    trace_path = tracer.start_session(
        func_name=func.__qualname__,
        signature_str=sig,
        initial_args={"x": "int", "y": "int"},
        source_file=source_file,
    )
    print(f"  Writing trace â†’ {trace_path}")

    # Install via plugin adapter instead of direct tracer.install()
    plugin = TracingHookPlugin(tracer)
    plugin.activate(executor)   # registers hooks + wraps solver

    try:
        result = executor.execute_function(func, {"x": "int", "y": "int"})
        print(f"  Execution complete: {result.paths_explored} paths, "
              f"{len(result.issues)} issues")
    finally:
        tracer.end_session()

    if trace_path:
        summarise_trace(trace_path)


# ---------------------------------------------------------------------------
# Example 4: Validate JSONL integrity and read back with TypeAdapter
# ---------------------------------------------------------------------------


def example_validate(func=divide) -> None:
    """Run example_manual and then validate the JSONL with Pydantic TypeAdapter."""
    print("\n=== Example 4: JSONL validation with TypeAdapter ===")

    from pydantic import TypeAdapter

    from pysymex.execution.executors.facade import SymbolicExecutor, ExecutionConfig
    from pysymex.tracing import ExecutionTracer, TracerConfig, TraceEvent
    from pysymex.tracing import VerbosityLevel

    config = ExecutionConfig(max_paths=20, detect_division_by_zero=True)
    executor = SymbolicExecutor(config=config)

    tracer = ExecutionTracer(TracerConfig(verbosity=VerbosityLevel.DELTA_ONLY))
    sig = str(inspect.signature(func))
    source_file = inspect.getfile(func) if hasattr(func, "__code__") else "<unknown>"
    trace_path = tracer.start_session(
        func_name=func.__qualname__,
        signature_str=sig,
        initial_args={"x": "int", "y": "int"},
        source_file=source_file,
    )
    tracer.install(executor)

    try:
        executor.execute_function(func, {"x": "int", "y": "int"})
    finally:
        tracer.end_session()

    # Read back and validate every event
    adapter = TypeAdapter(TraceEvent)
    events = []
    errors = 0
    with open(trace_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = adapter.validate_json(line)
                events.append(event)
            except Exception as exc:
                errors += 1
                print(f"  [ERROR] Line {lineno}: {exc}", file=sys.stderr)

    print(f"  Validated {len(events)} events, {errors} errors.")
    assert errors == 0, f"{errors} JSONL validation errors in {trace_path}"

    # Structural check: first event must be system_context
    from pysymex.tracing.schemas import SystemContextEvent
    assert isinstance(events[0], SystemContextEvent), (
        f"First event must be system_context, got {type(events[0]).__name__}"
    )
    print(f"  âœ“ First event is system_context: func={events[0].function_name!r}")
    print(f"  âœ“ All {len(events)} events parse cleanly.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import os
    os.makedirs(".pysymex/traces", exist_ok=True)

    example_manual()
    example_convenience()
    example_plugin_adapter()
    example_validate()

    print("\nAll examples completed successfully.")


