"""pysymex-trace-analyze — Streaming Omni-Filter CLI for pysymex JSONL trace logs.

Usage
-----
::

    # Basic: stream all events from a trace file
    pysymex-trace-analyze trace.jsonl

    # Filter: only fork keyframes at depth >= 50 (path-explosion probe)
    pysymex-trace-analyze trace.jsonl --event-type keyframe --trigger fork --depth-min 50

    # Print the LLM / AI diagnostic manual and exit
    pysymex-trace-analyze --ai-manual

Architecture
------------
The CLI processes the JSONL file in a **line-by-line streaming fashion** using a
generator so that only one parsed JSON object is held in memory at a time.  Even
Gigabyte-scale traces consume O(1) memory (with the single exception of
``--tail N``, which buffers the last *N* lines in a fixed-size
:class:`collections.deque`).

Composable Filter Pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~
Each CLI flag appends one :class:`FilterFn` to a :class:`FilterPipeline`.  A
parsed event dict is passed to the output only when
``pipeline.matches(event) is True`` — i.e. every active filter returns
``True``.  Filters are short-circuit evaluated (``all()``), so the cheapest /
most selective filters should come first; the ordering is determined by the
argument evaluation sequence.

Stdout is always raw JSONL (one JSON object per line) unless ``--format`` is
overridden to ``pretty`` or ``summary``.

Entry point
~~~~~~~~~~~
The ``main()`` function is registered as the ``pysymex-trace-analyze`` console
script in ``pyproject.toml``.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Callable, Generator, Iterator
from typing import Any

FilterFn = Callable[[dict[str, Any]], bool]
"""A predicate that accepts a parsed event dict and returns True to keep it."""


class FilterPipeline:
    """Composable, ordered chain of :data:`FilterFn` predicates.

    Filters are appended via :meth:`add` and evaluated lazily in insertion
    order by :meth:`matches`.  Because ``all()`` short-circuits on the first
    falsy result, cheap structural checks (e.g. ``event_type`` equality)
    should be added before expensive deep-search predicates.

    Example::

        pipeline = FilterPipeline()
        pipeline.add(lambda e: e.get("event_type") == "step")
        pipeline.add(lambda e: e.get("opcode") == "LOAD_ATTR")
        assert pipeline.matches({"event_type": "step", "opcode": "LOAD_ATTR"})
    """

    __slots__ = ("_filters",)

    def __init__(self) -> None:
        """Init."""
        """Initialize the class instance."""
        self._filters: list[FilterFn] = []

    def add(self, fn: FilterFn) -> None:
        """Append *fn* to the filter chain."""
        self._filters.append(fn)

    def matches(self, event: dict[str, Any]) -> bool:
        """Return ``True`` iff all registered filters accept *event*."""
        return all(f(event) for f in self._filters)

    def __len__(self) -> int:
        """Len."""
        """Return the number of elements in the container."""
        return len(self._filters)


def stream_events(
    path: str,
) -> Generator[tuple[str, dict[str, Any]], None, None]:
    """Yield ``(raw_line, parsed_event)`` tuples from a JSONL trace file.

    The file is read one line at a time, ensuring O(1) heap allocation
    regardless of trace file size.  Blank lines are silently skipped.
    Lines that are not valid JSON emit a warning to *stderr* and are
    **skipped** — the stream never terminates on corrupt input.

    Args:
        path: Filesystem path to the ``.jsonl`` trace file, or ``"-"``
              to read from ``sys.stdin``.

    Yields:
        ``(raw_line, parsed_event)`` where *raw_line* is the untransformed
        UTF-8 string (used when ``--format jsonl`` re-emits the line
        unchanged) and *parsed_event* is the decoded JSON dict.
    """
    handle: Iterator[str]
    is_gz = str(path).endswith(".gz")

    if path == "-":
        handle = sys.stdin
    elif is_gz:
        import gzip
        # Open in 'rt' mode translates gzip bytes to unicode strings automatically
        handle = gzip.open(path, "rt", encoding="utf-8")
    else:
        handle = open(path, encoding="utf-8")

    try:
        for raw in handle:
            raw = raw.rstrip("\n\r")
            if not raw:
                continue
            try:
                event: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(
                    f"[pysymex-trace-analyze] WARNING: skipping malformed line: {exc}",
                    file=sys.stderr,
                )
                continue
            yield raw, event
    finally:
        if path != "-":

            try:
                handle.close()
            except Exception:
                pass


def _str_contains(text: str | None, substring: str) -> bool:
    """Return True if *text* is a non-None string containing *substring*."""
    return text is not None and substring in text


def _any_value_contains(mapping: dict[str, Any] | None, substring: str) -> bool:
    """Return True if any value in *mapping* (as string) contains *substring*."""
    if not mapping:
        return False
    return any(substring in str(v) for v in mapping.values())


def _list_contains(lst: list[Any] | None, substring: str) -> bool:
    """Return True if any element in *lst* (as string) contains *substring*."""
    if not lst:
        return False
    return any(substring in str(item) for item in lst)


def _constraints_contain(constraints: list[dict[str, Any]] | None, substring: str) -> bool:
    """Return True if any constraint's ``smtlib`` field contains *substring*."""
    if not constraints:
        return False
    return any(substring in c.get("smtlib", "") for c in constraints)


def build_pipeline(args: argparse.Namespace) -> FilterPipeline:
    """Derive a :class:`FilterPipeline` from parsed CLI arguments.

    Each ``if args.<flag>:`` block appends exactly one :data:`FilterFn`
    closure.  The closures capture their argument value at build time so
    they are stateless and safe to call repeatedly.

    Args:
        args: The result of :func:`argparse.ArgumentParser.parse_args`.

    Returns:
        A :class:`FilterPipeline` ready for streaming evaluation.
    """
    p = FilterPipeline()

    if args.event_type:
        allowed: frozenset[str] = frozenset(args.event_type)
        p.add(lambda e, a=allowed: e.get("event_type") in a)

    if args.seq is not None:
        target_seq: int = args.seq
        p.add(lambda e, s=target_seq: e.get("seq") == s)

    if args.seq_range:
        lo, hi = args.seq_range
        p.add(lambda e, lo=lo, hi=hi: e.get("seq") is not None and lo <= e["seq"] <= hi)

    if args.path_id is not None:
        target_pid: int = args.path_id
        p.add(lambda e, pid=target_pid: e.get("path_id") == pid)

    if args.path_id_list:
        allowed_pids: frozenset[int] = frozenset(args.path_id_list)
        p.add(lambda e, ps=allowed_pids: e.get("path_id") in ps)

    if args.pc is not None:
        target_pc: int = args.pc
        p.add(lambda e, pc=target_pc: e.get("pc") == pc)

    if args.pc_range:
        pc_lo, pc_hi = args.pc_range
        p.add(lambda e, lo=pc_lo, hi=pc_hi: e.get("pc") is not None and lo <= e["pc"] <= hi)

    if args.opcode:
        oc: str = args.opcode.upper()
        p.add(lambda e, o=oc: e.get("opcode", "").upper() == o)

    if args.source_line is not None:
        sl: int = args.source_line
        p.add(lambda e, s=sl: e.get("source_line") == s)

    if args.has_stack_push:
        p.add(lambda e: bool((e.get("stack_diff") or {}).get("pushed")))

    if args.has_stack_pop:
        p.add(lambda e: (e.get("stack_diff") or {}).get("popped", 0) > 0)

    if args.has_var_modified:
        p.add(lambda e: bool((e.get("var_diff") or {}).get("modified")))

    if args.var_modified_name:
        vmn: str = args.var_modified_name
        p.add(lambda e, k=vmn: k in (e.get("var_diff") or {}).get("modified", {}))

    if args.has_var_added:
        p.add(lambda e: bool((e.get("var_diff") or {}).get("added")))

    if args.var_added_name:
        van: str = args.var_added_name
        p.add(lambda e, k=van: k in (e.get("var_diff") or {}).get("added", {}))

    if args.has_var_removed:
        p.add(lambda e: bool((e.get("var_diff") or {}).get("removed")))

    if args.var_removed_name:
        vrn: str = args.var_removed_name
        p.add(lambda e, k=vrn: k in (e.get("var_diff") or {}).get("removed", []))

    if args.has_mem_write:
        p.add(lambda e: bool(e.get("mem_diff")))

    if args.has_constraint_added:
        p.add(lambda e: e.get("constraint_added") is not None)

    if args.constraint_causality_contains:
        ccc: str = args.constraint_causality_contains
        p.add(lambda e, s=ccc: _str_contains((e.get("constraint_added") or {}).get("causality"), s))

    if args.trigger:
        trg: str = args.trigger
        p.add(lambda e, t=trg: e.get("trigger") == t)

    if args.depth is not None:
        d_exact: int = args.depth
        p.add(lambda e, d=d_exact: e.get("depth") == d)

    if args.depth_min is not None:
        d_min: int = args.depth_min
        p.add(lambda e, d=d_min: e.get("depth") is not None and e["depth"] >= d)

    if args.depth_max is not None:
        d_max: int = args.depth_max
        p.add(lambda e, d=d_max: e.get("depth") is not None and e["depth"] <= d)

    if args.parent_path_id is not None:
        ppid: int = args.parent_path_id
        p.add(lambda e, pp=ppid: e.get("parent_path_id") == pp)

    if args.has_child_fork:
        p.add(lambda e: bool(e.get("child_path_ids")))

    if args.prune_reason:
        pr: str = args.prune_reason
        p.add(lambda e, s=pr: _str_contains(e.get("prune_reason"), s))

    if args.stack_contains:
        sc: str = args.stack_contains
        p.add(lambda e, s=sc: _list_contains(e.get("stack"), s))

    if args.local_var_name:
        lvn: str = args.local_var_name
        p.add(lambda e, k=lvn: k in (e.get("local_vars") or {}))

    if args.global_var_name:
        gvn: str = args.global_var_name
        p.add(lambda e, k=gvn: k in (e.get("global_vars") or {}))

    if args.constraint_smtlib_contains:
        csc: str = args.constraint_smtlib_contains
        p.add(lambda e, s=csc: _constraints_contain(e.get("path_constraints"), s))

    if args.num_path_constraints_min is not None:
        npcmin: int = args.num_path_constraints_min
        p.add(lambda e, n=npcmin: len(e.get("path_constraints") or []) >= n)

    if args.num_path_constraints_max is not None:
        npcmax: int = args.num_path_constraints_max
        p.add(
            lambda e, n=npcmax: e.get("path_constraints") is not None
            and len(e["path_constraints"]) <= n
        )

    if args.solve_result:
        sr: str = args.solve_result
        p.add(lambda e, r=sr: e.get("result") == r)

    if args.cache_hit:
        p.add(lambda e: e.get("cache_hit") is True)

    if args.cache_miss:
        p.add(lambda e: e.get("cache_hit") is False)

    if args.solver_latency_min is not None:
        slmin: float = args.solver_latency_min
        p.add(
            lambda e, ms=slmin: e.get("solver_latency_ms") is not None
            and e["solver_latency_ms"] >= ms
        )

    if args.solver_latency_max is not None:
        slmax: float = args.solver_latency_max
        p.add(
            lambda e, ms=slmax: e.get("solver_latency_ms") is not None
            and e["solver_latency_ms"] <= ms
        )

    if args.num_constraints_min is not None:
        ncmin: int = args.num_constraints_min
        p.add(lambda e, n=ncmin: e.get("num_constraints") is not None and e["num_constraints"] >= n)

    if args.num_constraints_max is not None:
        ncmax: int = args.num_constraints_max
        p.add(lambda e, n=ncmax: e.get("num_constraints") is not None and e["num_constraints"] <= n)

    if args.has_model_excerpt:
        p.add(lambda e: e.get("model_excerpt") is not None)

    if args.model_var_name:
        mvn: str = args.model_var_name
        p.add(lambda e, k=mvn: k in (e.get("model_excerpt") or {}))

    if args.severity:
        sevs: frozenset[str] = frozenset(s.upper() for s in args.severity)
        p.add(lambda e, ss=sevs: (e.get("severity") or "").upper() in ss)

    if args.detector:
        det: str = args.detector
        p.add(lambda e, s=det: _str_contains(e.get("detector_name"), s))

    if args.issue_kind:
        ik: str = args.issue_kind
        p.add(lambda e, s=ik: _str_contains(e.get("issue_kind"), s))

    if args.message_contains:
        mc: str = args.message_contains
        p.add(lambda e, s=mc: _str_contains(e.get("message"), s))

    if args.has_z3_model:
        p.add(lambda e: e.get("z3_model") is not None)

    if args.z3_model_var:
        zmv: str = args.z3_model_var
        p.add(lambda e, k=zmv: k in (e.get("z3_model") or {}))

    if args.issue_source_line is not None:
        isl: int = args.issue_source_line
        p.add(lambda e, s=isl: e.get("source_line") == s)

    if args.confidence:
        conf_lo, conf_hi = args.confidence
        p.add(
            lambda e, lo=conf_lo, hi=conf_hi: e.get("confidence") is not None
            and lo <= float(e["confidence"]) <= hi
        )

    if args.constraint_at_issue_contains:
        caic: str = args.constraint_at_issue_contains
        p.add(lambda e, s=caic: _constraints_contain(e.get("constraints_at_issue"), s))

    if args.function_name:
        fn_sub: str = args.function_name
        p.add(lambda e, s=fn_sub: _str_contains(e.get("function_name"), s))

    if args.source_file:
        sf_sub: str = args.source_file
        p.add(lambda e, s=sf_sub: _str_contains(e.get("source_file"), s))

    if args.pysymex_version:
        pv: str = args.pysymex_version
        p.add(lambda e, v=pv: e.get("pysymex_version") == v)

    if args.z3_version:
        zv: str = args.z3_version
        p.add(lambda e, v=zv: e.get("z3_version") == v)

    if args.touches_var:
        tv: str = args.touches_var

        def _touches_var(e: dict[str, Any], needle: str = tv) -> bool:
            """Touches var."""

            for item in e.get("stack") or []:
                if needle in str(item):
                    return True
            for mapping_key in (
                "local_vars",
                "global_vars",
                "mem_diff",
                "model_excerpt",
                "z3_model",
                "initial_symbolic_args",
            ):
                mapping = e.get(mapping_key) or {}
                for k, v in mapping.items():
                    if needle in str(k) or needle in str(v):
                        return True
            return False

        p.add(_touches_var)

    if args.constraint_contains:
        cc: str = args.constraint_contains

        def _any_constraint(e: dict[str, Any], needle: str = cc) -> bool:
            """Any constraint."""

            ca = e.get("constraint_added")
            if ca and needle in ca.get("smtlib", ""):
                return True

            if _constraints_contain(e.get("path_constraints"), needle):
                return True

            if _constraints_contain(e.get("constraints_at_issue"), needle):
                return True
            return False

        p.add(_any_constraint)

    if args.any_field_contains:
        afc: str = args.any_field_contains

        pass

    return p


def _format_pretty(event: dict[str, Any]) -> str:
    """Two-space-indented JSON, suitable for human reading."""
    return json.dumps(event, indent=2, ensure_ascii=False)


def _format_fields(event: dict[str, Any], fields: list[str]) -> str:
    """Emit only the requested top-level *fields* as a JSONL object."""
    subset = {f: event[f] for f in fields if f in event}
    return json.dumps(subset, ensure_ascii=False)


class SummaryAccumulator:
    """Accumulate lightweight statistics across matched events.

    Used by ``--format summary`` to produce an LLM-friendly preamble
    without materialising the full event stream.
    """

    def __init__(self) -> None:
        """Init."""
        """Initialize the class instance."""
        self.total: int = 0
        self.by_type: dict[str, int] = collections.defaultdict(int)
        self.first_seq: dict[str, int] = {}
        self.last_seq: dict[str, int] = {}

    def record(self, event: dict[str, Any]) -> None:
        """Record."""
        et: str = event.get("event_type", "unknown")
        seq: int = event.get("seq", -1)
        self.total += 1
        self.by_type[et] += 1
        if et not in self.first_seq:
            self.first_seq[et] = seq
        self.last_seq[et] = seq

    def render(self) -> str:
        """Render."""
        lines = [
            "# pysymex Trace Summary",
            f"Total matched events: {self.total}",
            "",
            "| event_type      | count | first_seq | last_seq |",
            "|-----------------|-------|-----------|----------|",
        ]
        for et in sorted(self.by_type):
            cnt = self.by_type[et]
            fs = self.first_seq.get(et, -1)
            ls = self.last_seq.get(et, -1)
            lines.append(f"| {et:<15} | {cnt:>5} | {fs:>9} | {ls:>8} |")
        return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    """Execute the streaming filter loop.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Unix exit code (0 = success, 1 = error).
    """
    pipeline = build_pipeline(args)
    any_field_needle: str | None = getattr(args, "any_field_contains", None)

    output_format: str = args.format
    fields: list[str] | None = (
        [f.strip() for f in args.fields.split(",") if f.strip()]
        if getattr(args, "fields", None)
        else None
    )
    head_limit: int | None = getattr(args, "head", None)
    tail_n: int | None = getattr(args, "tail", None)
    count_only: bool = getattr(args, "count", False)

    tail_buf: collections.deque[str] | None = (
        collections.deque(maxlen=tail_n) if tail_n is not None else None
    )

    summary = SummaryAccumulator() if output_format == "summary" else None
    matched = 0

    try:
        for raw_line, event in stream_events(args.input):

            if any_field_needle is not None and any_field_needle not in raw_line:
                continue

            if not pipeline.matches(event):
                continue

            if output_format == "pretty":
                rendered = _format_pretty(event)
            elif fields is not None:
                rendered = _format_fields(event, fields)
            else:
                rendered = raw_line

            matched += 1

            if summary is not None:
                summary.record(event)
            elif count_only:
                pass
            elif tail_buf is not None:
                tail_buf.append(rendered)
            else:

                print(rendered)
                if head_limit is not None and matched >= head_limit:
                    break

    except BrokenPipeError:

        pass
    except FileNotFoundError as exc:
        print(f"[pysymex-trace-analyze] ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass

    if tail_buf is not None and not count_only and summary is None:
        for line in tail_buf:
            print(line)

    if count_only:
        print(matched)
    elif summary is not None:
        print(summary.render())

    return 0


_AI_MANUAL = """
# pysymex Trace Analyzer — AI / LLM Diagnostic Manual

> **For Gemini, GPT-4o, Claude, and other LLM agents.**
> This document is the *authoritative* reference for `pysymex-trace-analyze`.
> Read it once; then compose CLI invocations to extract diagnostic signal from
> a symbolic-execution trace file without loading the entire Gigabyte into RAM.

---

## 1. Trace Format Overview

pysymex writes a **JSONL** file (one JSON object per line). Each line is one
**TraceEvent** from a discriminated union keyed on `event_type`:

| `event_type`     | Frequency       | Purpose |
|------------------|-----------------|---------|
| `system_context` | Once (first)    | Static analysis-session metadata (pysymex version, Z3 version, function name, initial symbolic arguments, TracerConfig). |
| `step`           | Per instruction | Incremental diff: what changed on the stack, in locals, in memory, whether a new path constraint was added, and the **original source text**. |
| `keyframe`       | Fork/prune/issue | Full symbolic-state snapshot. Re-anchors understanding without replaying prior deltas. |
| `solve`          | Per SMT call    | SMT solver telemetry: latency (ms), cache hit/miss, satisfying model excerpt, number of constraints. |
| `issue`          | Per bug found   | Bug report: severity, **confidence (0-1)**, source_text, Z3 model of the triggering input. |

All events carry a **monotonically increasing `seq` integer** — use it to
establish temporal ordering across mixed event types.

**Keyframe + Delta strategy:**
- *Deltas* (`step` events) record only what changed — cheap to write, cheap to scan.
- *Keyframes* (`keyframe` events) record the complete symbolic state (stack, locals, globals, all path constraints) at structurally important moments (fork, prune, detected issue). They let you understand a path without replaying all prior deltas.

---

## 2. Filter Reference Table

Every CLI flag is listed below. Columns: flag name, which `event_type` it
targets, what field it tests, when to use it.

### 2.1 Event Routing (universal — works on all event types)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--event-type TYPE` | `event_type` | Keep only events of this type. Repeatable. Values: `step`, `keyframe`, `solve`, `issue`, `system_context`. |
| `--seq N` | `seq` | Keep exactly the event with sequence number N. |
| `--seq-range START:END` | `seq` | Keep events whose seq is in [START, END] inclusive. |
| `--path-id N` | `path_id` | Keep events belonging to execution path N. |
| `--path-id-list N,N,...` | `path_id` | Keep events for any of the listed path IDs. |
| `--pc N` | `pc` | Keep events at program counter N. |
| `--pc-range START:END` | `pc` | Keep events at PC in [START, END]. |

### 2.2 StepDeltaEvent Filters (`event_type = step`)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--opcode NAME` | `opcode` | Keep step events for a specific Python opcode (e.g. `LOAD_ATTR`, `BINARY_OP`, `CALL`). Case-insensitive. |
| `--source-line N` | `source_line` | Keep steps that originated at source line N. |
| `--has-stack-push` | `stack_diff.pushed` | Keep steps that pushed at least one value onto the symbolic stack. |
| `--has-stack-pop` | `stack_diff.popped` | Keep steps that popped at least one value off the symbolic stack. |
| `--has-var-modified` | `var_diff.modified` | Keep steps that modified at least one existing local variable. |
| `--var-modified-name NAME` | `var_diff.modified` | Keep steps that modified the specific local variable NAME. |
| `--has-var-added` | `var_diff.added` | Keep steps that introduced a new local variable. |
| `--var-added-name NAME` | `var_diff.added` | Keep steps that introduced the specific local variable NAME. |
| `--has-var-removed` | `var_diff.removed` | Keep steps that deleted a local variable (e.g. `del`). |
| `--var-removed-name NAME` | `var_diff.removed` | Keep steps that deleted the specific local variable NAME. |
| `--has-mem-write` | `mem_diff` | Keep steps that wrote to the symbolic memory model (only populated in FULL verbosity mode). |
| `--has-constraint-added` | `constraint_added` | Keep steps that added a new path constraint (branch taken). |
| `--constraint-causality-contains TEXT` | `constraint_added.causality` | Keep steps where the causality annotation of the newly added constraint contains TEXT (e.g. a specific opcode like `POP_JUMP_IF_FALSE`). |

### 2.3 KeyframeEvent Filters (`event_type = keyframe`)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--trigger {fork,prune,issue}` | `trigger` | Keep keyframes triggered by a specific event: `fork` (path split), `prune` (path terminated), or `issue` (bug found). |
| `--depth N` | `depth` | Keep keyframes at exactly call/loop depth N. |
| `--depth-min N` | `depth` | Keep keyframes at depth >= N. |
| `--depth-max N` | `depth` | Keep keyframes at depth <= N. |
| `--parent-path-id N` | `parent_path_id` | Keep keyframes whose parent execution path is N. Useful for tracing a fork tree. |
| `--has-child-fork` | `child_path_ids` | Keep fork keyframes that produced at least one child path. |
| `--prune-reason TEXT` | `prune_reason` | Keep prune keyframes whose reason string contains TEXT (e.g. `infeasible`, `duplicate_state`, `resource_limit`). |
| `--stack-contains TEXT` | `stack` | Keep keyframes where at least one stack value's string representation contains TEXT. |
| `--local-var-name NAME` | `local_vars` | Keep keyframes where the local variable NAME is in scope. |
| `--global-var-name NAME` | `global_vars` | Keep keyframes where the global variable NAME is in scope. |
| `--constraint-smtlib-contains TEXT` | `path_constraints[*].smtlib` | Keep keyframes where at least one path constraint SMT-LIB string contains TEXT. |
| `--num-path-constraints-min N` | `path_constraints` | Keep keyframes with at least N accumulated path constraints. |
| `--num-path-constraints-max N` | `path_constraints` | Keep keyframes with at most N accumulated path constraints. |

### 2.4 SolveEvent Filters (`event_type = solve`)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--solve-result {sat,unsat,unknown}` | `result` | Keep solver calls with the specified result. |
| `--cache-hit` | `cache_hit` | Keep solver calls that were served from the LRU cache (fast, no Z3 invocation). |
| `--cache-miss` | `cache_hit` | Keep solver calls that were NOT cached (real Z3 invocations). Mutually exclusive with `--cache-hit`. |
| `--solver-latency-min MS` | `solver_latency_ms` | Keep solver calls taking at least MS milliseconds. |
| `--solver-latency-max MS` | `solver_latency_ms` | Keep solver calls taking at most MS milliseconds. |
| `--num-constraints-min N` | `num_constraints` | Keep solver calls with at least N constraints in the query. |
| `--num-constraints-max N` | `num_constraints` | Keep solver calls with at most N constraints in the query. |
| `--has-model-excerpt` | `model_excerpt` | Keep SAT solver calls that produced a partial model (satisfying variable assignment). |
| `--model-var-name NAME` | `model_excerpt` | Keep SAT results where the model contains variable NAME (exact key match). |

### 2.5 IssueEvent Filters (`event_type = issue`)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--severity LEVEL` | `severity` | Keep issues at the given severity. Repeatable. Values: `HIGH`, `MEDIUM`, `LOW`, `CRITICAL`. |
| `--detector NAME` | `detector_name` | Keep issues from detectors whose name contains NAME (substring). |
| `--issue-kind KIND` | `issue_kind` | Keep issues whose kind contains KIND (substring). |
| `--message-contains TEXT` | `message` | Keep issues whose human-readable message contains TEXT. |
| `--has-z3-model` | `z3_model` | Keep issues that have a concrete Z3 counterexample model. |
| `--z3-model-var NAME` | `z3_model` | Keep issues whose Z3 model contains variable NAME. |
| `--issue-source-line N` | `source_text` | Keep issues detected at source line N. |
| `--constraint-at-issue-contains TEXT` | `constraints_at_issue[*].smtlib` | Keep issues where at least one constraint in the path-at-detection-time contains TEXT. |
| `--confidence MIN:MAX` | `confidence` | Keep issues whose confidence is in [MIN, MAX]. |
| `--source-text TEXT` | `source_text` | Keep issues whose source_text contains TEXT. |

### 2.6 SystemContextEvent Filters (`event_type = system_context`)

| Flag | Field tested | Description |
|------|-------------|-------------|
| `--function-name NAME` | `function_name` | Keep system_context events whose analyzed function name contains NAME. Useful when trace files from multiple analyses are concatenated. |
| `--source-file PATH` | `source_file` | Keep system_context events for a specific source file (substring match). |
| `--pysymex-version VER` | `pysymex_version` | Keep system_context events for an exact pysymex version string. |
| `--z3-version VER` | `z3_version` | Keep system_context events for an exact Z3 version string. |

### 2.7 Deep / Semantic Cross-Event Filters

| Flag | Description |
|------|-------------|
| `--touches-var NAME` | Recursively searches `stack`, `local_vars`, `global_vars`, `mem_diff`, `model_excerpt`, `z3_model`, and `initial_symbolic_args` for any string containing NAME. Works across all event types. Use this to track a specific symbolic variable through its entire lifetime. |
| `--constraint-contains TEXT` | Searches all constraint-bearing fields: `constraint_added.smtlib` (step), `path_constraints[*].smtlib` (keyframe), `constraints_at_issue[*].smtlib` (issue). Use this to find where a specific expression enters the constraint set. |
| `--any-field-contains TEXT` | Raw substring scan of the complete JSON line before parsing. This is the fastest full-text search option. Use it when you don't know which field contains the value. |

---

## 3. Diagnostic Recipes

These are ready-to-run command combinations for specific bug classes in the
pysymex symbolic execution engine.

---

### Recipe 1: Path Explosion Diagnostics

**Symptom:** The executor spawns hundreds of thousands of paths; analysis never
terminates or exhausts memory.

**Goal:** Find where the fork tree becomes exponentially deep and wide.

```bash
# Show all fork keyframes at depth >= 50, sorted naturally by seq
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --trigger fork --depth-min 50

# Count how many forks there are at each depth band
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --trigger fork --depth-min 30 --depth-max 50 --count

# Trace a specific subtree: all events under path 42
pysymex-trace-analyze trace.jsonl --path-id 42 --format pretty | head -200
```

**What to look for:** Forks where `child_path_ids` has > 2 entries (multi-way
branch), or forks where depth grows > 2x between consecutive `seq` numbers.

---

### Recipe 2: Solver Bottleneck Diagnostics

**Symptom:** Each analysis step is slow; profiling shows Z3 consuming > 90% of
wall time.

**Goal:** Identify the constraint queries that take the most time.

```bash
# All slow solver calls (> 500 ms)
pysymex-trace-analyze trace.jsonl \\
    --event-type solve --solver-latency-min 500

# Cache miss rate summary: count misses vs hits
pysymex-trace-analyze trace.jsonl --event-type solve --cache-miss --count
pysymex-trace-analyze trace.jsonl --event-type solve --cache-hit --count

# Find the specific path where the slowest queries occur
pysymex-trace-analyze trace.jsonl \\
    --event-type solve --solver-latency-min 1000 --format pretty | head -50
```

**What to look for:** Queries with high `num_constraints` and `cache_hit=false`.
The `model_excerpt` on SAT results tells you what concrete values triggered the
slow path.

---

### Recipe 3: Infeasible Path Over-Pruning

**Symptom:** The engine prunes paths that a human analysis shows should be
feasible; important bug paths are missed.

**Goal:** Find prune events that are backed by large / complex constraint sets
(which may contain an over-approximation error).

```bash
# Prune events classified as infeasible with >= 20 accumulated constraints
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --trigger prune \\
    --prune-reason infeasible \\
    --num-path-constraints-min 20 \\
    --format pretty

# Find the predecessor fork (parent path) of a suspicious prune on path 99
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --path-id 99 --trigger prune --format pretty
```

**What to look for:** `path_constraints` entries whose `smtlib` field contains
quantifiers (`forall`, `exists`) or non-linear arithmetic — both are common
sources of false-unsat in Z3.

---

### Recipe 4: Duplicate State / Hash Collision Diagnostics

**Symptom:** The loop/recursion bounding should prevent revisiting states, but
the engine keeps processing what appears to be the same state.

**Goal:** Find all prune-with-reason=`duplicate_state` events and inspect the
symbolic state that was considered a duplicate.

```bash
# All duplicate-state prunes
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --trigger prune --prune-reason duplicate_state

# Check if the "duplicate" had the same path constraints as another path
pysymex-trace-analyze trace.jsonl \\
    --event-type keyframe --trigger prune --prune-reason duplicate_state \\
    --num-path-constraints-min 1 --format pretty | head -100
```

**What to look for:** Two keyframes with identical `local_vars` and
`path_constraints` but different `path_id` — that's a true hash collision.
If the constraints differ, the deduplication logic may be over-aggressive.

---

### Recipe 5: Tracking a Symbolic Variable Through Its Lifetime

**Symptom:** A symbolic variable `user_input` appears in a bug report but you
want to trace every step where it was read, written, or constrained.

**Goal:** Full lifecycle trace of a single variable across all event types.

```bash
# Every event that mentions 'user_input' in any container
pysymex-trace-analyze trace.jsonl --touches-var user_input

# Narrow to a specific path
pysymex-trace-analyze trace.jsonl --touches-var user_input --path-id 7

# See only the steps where user_input was introduced or modified
pysymex-trace-analyze trace.jsonl \\
    --event-type step \\
    --var-added-name user_input

pysymex-trace-analyze trace.jsonl \\
    --event-type step \\
    --var-modified-name user_input --format pretty
```

---

### Recipe 6: Constraint Explosion / Over-Approximation Investigation

**Symptom:** A specific execution path accumulates hundreds of constraints;
analysis slows to a crawl on that path.

**Goal:** Find the exact instructions that add new constraints on a suspect path.

```bash
# Every step on path 12 that added a constraint
pysymex-trace-analyze trace.jsonl \\
    --event-type step --path-id 12 --has-constraint-added

# Check if a specific expression (e.g. 'x + y') is in any constraint
pysymex-trace-analyze trace.jsonl --constraint-contains "x + y"

# Find which opcode generates the most constraints
pysymex-trace-analyze trace.jsonl \\
    --event-type step --has-constraint-added --opcode POP_JUMP_IF_FALSE --count
```

---

### Recipe 7: Cache Miss Storm Diagnostics

**Symptom:** Repeated Z3 invocations for logically equivalent queries; the LRU
cache appears ineffective.

**Goal:** Find all cache misses with non-trivial latency to understand why the
cache key design is failing.

```bash
# Real Z3 invocations (cache misses) slower than 100 ms
pysymex-trace-analyze trace.jsonl \\
    --event-type solve --cache-miss --solver-latency-min 100

# Isolate to a specific path where you know caching should work
pysymex-trace-analyze trace.jsonl \\
    --event-type solve --cache-miss --path-id 5 --format pretty

# Compare: how many constraints did cache-miss queries have vs cache-hits?
pysymex-trace-analyze trace.jsonl \\
    --event-type solve --cache-miss --num-constraints-min 30 --count
```

---

### Recipe 8: Full Issue Deep-Dive

**Symptom:** A reported bug is a false positive (or you want to understand the
exact constraint path that led to it).

**Goal:** See the complete symbolic context at bug-detection time.

```bash
# All issues of any severity
pysymex-trace-analyze trace.jsonl --event-type issue --format pretty

# Issues from a specific detector
pysymex-trace-analyze trace.jsonl --detector null-deref --format pretty

# Issues AND the keyframe immediately before them (full context)
pysymex-trace-analyze trace.jsonl \\
    --event-type issue,keyframe --path-id 42 --format pretty

# Find which input triggered the bug via the Z3 model
pysymex-trace-analyze trace.jsonl --event-type issue --has-z3-model --format pretty
```

---

## 4. Feeding Output to an LLM

Gigabyte trace files cannot be fed directly to any LLM. Use these strategies:

### Strategy A: Summary Preamble
```bash
# Get counts by event type first — tiny, always fits in context
pysymex-trace-analyze trace.jsonl --format summary
```

Include the summary table in your LLM prompt as context before asking
diagnostic questions.

### Strategy B: Head + Tail Sampling
```bash
# First 50 events (analysis startup context)
pysymex-trace-analyze trace.jsonl --head 50 --format pretty

# Last 50 events (analysis ending context — often where bugs appear)
pysymex-trace-analyze trace.jsonl --tail 50 --format pretty
```

### Strategy C: Targeted Filter Chains
Compose 2–4 filters to isolate precisely the events relevant to your question:
```bash
# "Which SAT results mentioned variable 'idx' on slow queries?"
pysymex-trace-analyze trace.jsonl \\
    --event-type solve \\
    --solve-result sat \\
    --solver-latency-min 200 \\
    --any-field-contains idx \\
    --format pretty | head -30
```

### Strategy D: Count First, Then Retrieve
Always count before rendering pretty-printing:
```bash
pysymex-trace-analyze trace.jsonl --event-type issue --count
# → 847
# Now retrieve only first 10 for inspection:
pysymex-trace-analyze trace.jsonl --event-type issue --head 10 --format pretty
```

### Strategy E: Issue-Specific Context
- **Isolate a bug**: `pysymex-trace-analyze trace.jsonl --event-type issue --fields seq,path_id,message,source_text,confidence`
- **Reconstruct logic around a bug**: Find sequence N for an `issue`. Then run `pysymex-trace-analyze trace.jsonl --seq-range (N-20):N --format pretty` to see the instructions that led to it.

---

## 5. Architecture Notes for LLM Reasoning

**seq monotonicity:** `seq` is a global, monotonically increasing integer
incremented under a lock. You can sort any mixed-type subset of events by
`seq` to recover chronological order.

**Keyframe + Delta composition:**
To reconstruct full symbolic state at any `step` event:
1. Find the most recent `keyframe` event with `seq < target_step.seq` and the
   same `path_id`.
2. Replay all `step` events from `keyframe.seq + 1` to `target_step.seq` where
   `path_id` matches, applying each `stack_diff`, `var_diff`, and `mem_diff`.


**Path tree reconstruction:**
Each `keyframe` with `trigger=fork` contains `parent_path_id` and
`child_path_ids`. Collecting all fork keyframes reconstructs the complete
execution tree topology.

**Thread safety note:**
The tracer uses a single `threading.Lock` for all writes. The JSONL file is
always consistent — a line is either fully written or not present. You will
never see a partial line.

**QUIET verbosity:**
When `TracerConfig.verbosity=QUIET`, `step` events are suppressed entirely.
Only `keyframe`, `solve`, and `issue` events are emitted. Use
`--event-type keyframe,solve,issue` to avoid filtering out everything when
analyzing a QUIET-mode trace.

**Zero-overhead guarantee:**
When `TracerConfig.enabled=False` (the default), the tracer performs zero
work. No Z3 serialization, no Pydantic validation, no file I/O. Every hook
method short-circuits immediately on the `enabled` check. Set
`PY_SYMEX_TRACE=1` in the environment (or pass `TracerConfig(enabled=True)`)
to activate tracing.

---

*End of AI Manual. Generated by `pysymex-trace-analyze --ai-manual`.*
""".strip()


def print_ai_manual() -> None:
    """Print the AI/LLM diagnostic manual to stdout and return."""

    sys.stdout.buffer.write((_AI_MANUAL + "\n").encode("utf-8"))


def _parse_seq_range(value: str) -> tuple[int, int]:
    """Parse seq range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("seq-range must be in the form START:END (e.g. 100:500)")
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"seq-range values must be integers: {exc}") from exc


def _parse_pc_range(value: str) -> tuple[int, int]:
    """Parse pc range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("pc-range must be in the form START:END (e.g. 0:200)")
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"pc-range values must be integers: {exc}") from exc


def _parse_path_id_list(value: str) -> list[int]:
    """Parse path id list."""
    try:
        return [int(x.strip()) for x in value.split(",") if x.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"path-id-list must be comma-separated integers: {exc}"
        ) from exc


def _parse_confidence_range(value: str) -> tuple[float, float]:
    """Parse confidence range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("confidence must be in the form MIN:MAX (e.g. 0.8:1.0)")
    try:
        return float(parts[0]), float(parts[1])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"confidence values must be floats: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the fully-configured CLI :class:`ArgumentParser`.

    Every argument includes a `help` string written for both human and LLM
    consumers, explaining *which event type* the flag targets, *what field*
    it tests, and *when* to use it for engine diagnostics.
    """
    parser = argparse.ArgumentParser(
        prog="pysymex-trace-analyze",
        description=(
            "Streaming Omni-Filter CLI for pysymex JSONL execution trace files.\n\n"
            "Processes the trace file line-by-line (O(1) memory for all modes except "
            "--tail N) and applies a composable filter pipeline. Only lines matching "
            "ALL active filters are emitted to stdout.\n\n"
            "Run --ai-manual to print a full Markdown reference for LLM agents."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        metavar="TRACE_FILE",
        help=(
            "Path to the .jsonl trace file produced by pysymex ExecutionTracer, "
            "or '-' (default) to read from stdin. The file is processed one line "
            "at a time so files of any size are supported."
        ),
    )

    parser.add_argument(
        "--ai-manual",
        action="store_true",
        default=False,
        help=(
            "Print a richly formatted Markdown document designed as a "
            "Prompt/Context for LLM agents (Gemini, GPT-4o, Claude, etc.). "
            "Includes a complete filter reference table and 8 Diagnostic Recipes "
            "for common pysymex engine bug classes. "
            "Bypasses all other flags and exits immediately after printing."
        ),
    )

    routing = parser.add_argument_group(
        "Event Routing",
        "Filters that match on fields common to all event types.",
    )
    routing.add_argument(
        "--event-type",
        "-e",
        dest="event_type",
        action="append",
        metavar="TYPE",
        choices=["step", "keyframe", "solve", "issue", "system_context"],
        help=(
            "Keep only events of TYPE. Repeatable: "
            "`-e step -e solve` keeps both step and solve events. "
            "Values: step, keyframe, solve, issue, system_context. "
            "Use `--event-type keyframe` to focus on fork/prune/issue snapshots "
            "without the high-volume delta noise."
        ),
    )
    routing.add_argument(
        "--seq",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep the single event whose seq == N. Useful for pinpointing an "
            "exact event from a seq number seen in a summary or issue report."
        ),
    )
    routing.add_argument(
        "--seq-range",
        type=_parse_seq_range,
        default=None,
        metavar="START:END",
        help=(
            "Keep events with seq in the inclusive range [START, END]. "
            "Use this to isolate a time window around a known bad event "
            "(e.g. --seq-range 1000:1050 to see the 50 events around seq 1025)."
        ),
    )
    routing.add_argument(
        "--path-id",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep only events belonging to execution path N.  "
            "path_id is assigned at fork time and is stable for the lifetime of "
            "the path.  Use this to replay the full history of a single path."
        ),
    )
    routing.add_argument(
        "--path-id-list",
        type=_parse_path_id_list,
        default=None,
        metavar="N,N,...",
        help=(
            "Keep events for any of the comma-separated path IDs.  "
            "Use this when you want to compare two sibling paths produced by a fork."
        ),
    )
    routing.add_argument(
        "--pc",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep only events at program counter N.  "
            "pc is the bytecode offset of the instruction being executed.  "
            "Use this to find all events associated with a specific bytecode instruction."
        ),
    )
    routing.add_argument(
        "--pc-range",
        type=_parse_pc_range,
        default=None,
        metavar="START:END",
        help=(
            "Keep events at PC in the inclusive range [START, END].  "
            "Use to focus on a specific function body or loop."
        ),
    )

    step_grp = parser.add_argument_group(
        "StepDeltaEvent Filters (event_type=step)",
        "Filters on incremental instruction-level diff events.",
    )
    step_grp.add_argument(
        "--opcode",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events for a specific Python bytecode opcode name "
            "(e.g. LOAD_ATTR, BINARY_OP, CALL, POP_JUMP_IF_FALSE).  "
            "Case-insensitive.  Use this to count how many times a given "
            "instruction executes on a path, or to find where attribute "
            "accesses on a symbolic object start diverging."
        ),
    )
    step_grp.add_argument(
        "--source-line",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep step events that map to source line N.  "
            "Requires FULL or DELTA_ONLY verbosity (source_line is None in QUIET mode).  "
            "Use to correlate a bytecode offset back to the Python source."
        ),
    )
    step_grp.add_argument(
        "--has-stack-push",
        action="store_true",
        default=False,
        help=(
            "Keep step events where at least one symbolic value was pushed "
            "onto the stack (stack_diff.pushed is non-empty).  "
            "Use to trace where new symbolic expressions are introduced."
        ),
    )
    step_grp.add_argument(
        "--has-stack-pop",
        action="store_true",
        default=False,
        help=(
            "Keep step events where at least one value was popped from the stack "
            "(stack_diff.popped > 0).  Useful for spotting unbalanced stack operations."
        ),
    )
    step_grp.add_argument(
        "--has-var-modified",
        action="store_true",
        default=False,
        help=(
            "Keep step events that modified at least one existing local variable "
            "(var_diff.modified is non-empty).  "
            "Use to find where a known variable's symbolic value changes."
        ),
    )
    step_grp.add_argument(
        "--var-modified-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events that modified the local variable NAME "
            "(exact key match in var_diff.modified).  "
            "Use to trace the full mutation history of a specific variable."
        ),
    )
    step_grp.add_argument(
        "--has-var-added",
        action="store_true",
        default=False,
        help=(
            "Keep step events that introduced a new local variable "
            "(var_diff.added is non-empty)."
        ),
    )
    step_grp.add_argument(
        "--var-added-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events where the specific local variable NAME was "
            "first introduced (key in var_diff.added).  "
            "Use to find where a symbolic variable enters scope."
        ),
    )
    step_grp.add_argument(
        "--has-var-removed",
        action="store_true",
        default=False,
        help=(
            "Keep step events that deleted a local variable "
            "(var_diff.removed is non-empty, e.g. from a `del` statement)."
        ),
    )
    step_grp.add_argument(
        "--var-removed-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events that deleted the specific local variable NAME "
            "(exact match in var_diff.removed list)."
        ),
    )
    step_grp.add_argument(
        "--has-mem-write",
        action="store_true",
        default=False,
        help=(
            "Keep step events that wrote to the symbolic memory model "
            "(mem_diff is non-empty).  "
            "NOTE: mem_diff is only populated when TracerConfig.verbosity=FULL.  "
            "Use to detect unexpected writes to symbolic addresses."
        ),
    )
    step_grp.add_argument(
        "--has-constraint-added",
        action="store_true",
        default=False,
        help=(
            "Keep step events where a new path constraint was added "
            "(constraint_added is not null).  "
            "A new constraint means a conditional branch was taken.  "
            "Use to measure constraint accumulation rate on a path."
        ),
    )
    step_grp.add_argument(
        "--constraint-causality-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep step events where the causality annotation of the newly added "
            "constraint contains TEXT.  "
            "causality encodes 'OPCODE at PC=N' — e.g. use "
            "'POP_JUMP_IF_FALSE' to find all taken conditional branches."
        ),
    )

    kf_grp = parser.add_argument_group(
        "KeyframeEvent Filters (event_type=keyframe)",
        "Filters on full-state snapshot events emitted at fork, prune, and issue time.",
    )
    kf_grp.add_argument(
        "--trigger",
        type=str,
        default=None,
        choices=["fork", "prune", "issue"],
        help=(
            "Keep keyframes triggered by a specific engine event.  "
            "fork: path split (state space branching).  "
            "prune: path terminated (infeasible, resource limit, duplicate).  "
            "issue: bug detected.  "
            "Use --trigger fork to study path explosion; "
            "--trigger prune to audit path termination decisions."
        ),
    )
    kf_grp.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at exactly call/loop depth N.  "
            "depth tracks nesting level of the current execution frame.  "
            "Use for targeted depth-budget analysis."
        ),
    )
    kf_grp.add_argument(
        "--depth-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at depth >= N.  "
            "Use --depth-min 50 to find deep paths which are the primary "
            "driver of path explosion in recursive or loop-heavy functions."
        ),
    )
    kf_grp.add_argument(
        "--depth-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at depth <= N.  "
            "Use to restrict analysis to a shallow portion of the call stack, "
            "e.g. to test whether top-level branches are being explored."
        ),
    )
    kf_grp.add_argument(
        "--parent-path-id",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes whose parent execution path ID is N.  "
            "Use to find all children of a specific fork and reconstruct "
            "the local fork tree topology."
        ),
    )
    kf_grp.add_argument(
        "--has-child-fork",
        action="store_true",
        default=False,
        help=(
            "Keep fork keyframes that produced at least one child path "
            "(child_path_ids is non-empty).  This always should be true for "
            "trigger=fork, but can be used to verify the tree is well-formed."
        ),
    )
    kf_grp.add_argument(
        "--prune-reason",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep prune keyframes whose prune_reason string contains TEXT.  "
            "Known reasons: 'infeasible', 'duplicate_state', 'resource_limit', "
            "'depth_limit', 'loop_bound'.  "
            "Use --prune-reason infeasible to audit false-unsat decisions."
        ),
    )
    kf_grp.add_argument(
        "--stack-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep keyframes where at least one element of the symbolic stack "
            "(as a string) contains TEXT.  "
            "Use to find states where a specific symbolic expression is on the "
            "top of the stack, e.g. a function return value."
        ),
    )
    kf_grp.add_argument(
        "--local-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep keyframes where the local variable NAME is present in "
            "local_vars.  Use to find all states where a variable is in scope."
        ),
    )
    kf_grp.add_argument(
        "--global-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep keyframes where the global variable NAME is present in "
            "global_vars.  Only populated in FULL and DELTA_ONLY verbosity modes."
        ),
    )
    kf_grp.add_argument(
        "--constraint-smtlib-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep keyframes where at least one path constraint's SMT-LIB "
            "string contains TEXT.  "
            "Use to find states where a specific sub-expression has been "
            "constrained, e.g. --constraint-smtlib-contains 'bvslt' to find "
            "states with signed integer comparison constraints."
        ),
    )
    kf_grp.add_argument(
        "--num-path-constraints-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes with at least N accumulated path constraints.  "
            "Use with --trigger prune to find infeasible paths that had very "
            "complex constraint sets — candidates for over-approximation bugs."
        ),
    )
    kf_grp.add_argument(
        "--num-path-constraints-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes with at most N accumulated path constraints.  "
            "Use to study early-path behavior before constraints accumulate."
        ),
    )

    solve_grp = parser.add_argument_group(
        "SolveEvent Filters (event_type=solve)",
        "Filters on SMT solver invocation telemetry events.",
    )
    solve_grp.add_argument(
        "--solve-result",
        type=str,
        default=None,
        choices=["sat", "unsat", "unknown"],
        metavar="RESULT",
        help=(
            "Keep solver events with the given result.  "
            "sat: constraints are satisfiable (feasible path / concrete witness found).  "
            "unsat: constraints are unsatisfiable (path is infeasible).  "
            "unknown: Z3 timed out or could not decide.  "
            "Use --solve-result unknown to find Z3 timeout hotspots."
        ),
    )

    cache_group = solve_grp.add_mutually_exclusive_group()
    cache_group.add_argument(
        "--cache-hit",
        action="store_true",
        default=False,
        help=(
            "Keep solver invocations that were served from the LRU cache "
            "(cache_hit=True).  "
            "A high cache hit rate means the engine is avoiding redundant Z3 "
            "queries.  Use --cache-hit to confirm caching is working."
        ),
    )
    cache_group.add_argument(
        "--cache-miss",
        action="store_true",
        default=False,
        help=(
            "Keep solver invocations that required a real Z3 call "
            "(cache_hit=False).  "
            "Mutually exclusive with --cache-hit.  "
            "Use --cache-miss --solver-latency-min 200 to find expensive "
            "uncached queries that are bottlenecking the engine."
        ),
    )
    solve_grp.add_argument(
        "--solver-latency-min",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep solver events where solver_latency_ms >= MS.  "
            "Use --solver-latency-min 500 to find individual queries that "
            "take more than half a second — these are the primary bottleneck "
            "candidates."
        ),
    )
    solve_grp.add_argument(
        "--solver-latency-max",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep solver events where solver_latency_ms <= MS.  "
            "Useful when combined with --cache-miss to find fast cache misses "
            "(possibly a cache key mis-match bug)."
        ),
    )
    solve_grp.add_argument(
        "--num-constraints-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep solver events with at least N constraints in the query.  "
            "Constraint count is a proxy for path depth.  "
            "Use to find the deepest queries."
        ),
    )
    solve_grp.add_argument(
        "--num-constraints-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep solver events with at most N constraints in the query.  "
            "Use to study early-path solver behavior."
        ),
    )
    solve_grp.add_argument(
        "--has-model-excerpt",
        action="store_true",
        default=False,
        help=(
            "Keep SAT solver events that include a model_excerpt "
            "(a partial satisfying variable assignment).  "
            "The model excerpt tells you which concrete input values were "
            "inferred by Z3 for a satisfiable path.  "
            "Use this to find the first concrete witness for a bug path."
        ),
    )
    solve_grp.add_argument(
        "--model-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep SAT solver events where the model_excerpt dict contains "
            "key NAME.  "
            "Use to find solver calls that inferred a specific concrete value "
            "for a named symbolic variable."
        ),
    )

    issue_grp = parser.add_argument_group(
        "IssueEvent Filters (event_type=issue)",
        "Filters on detected-bug events emitted by analysis detectors.",
    )
    issue_grp.add_argument(
        "--severity",
        action="append",
        metavar="LEVEL",
        help=(
            "Keep issues at the given severity level.  "
            "Repeatable: --severity HIGH --severity CRITICAL.  "
            "Values: HIGH, MEDIUM, LOW, CRITICAL (case-insensitive).  "
            "Use --severity CRITICAL to focus on the most impactful findings."
        ),
    )
    issue_grp.add_argument(
        "--detector",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep issues from detectors whose detector_name contains NAME "
            "(case-sensitive substring match).  "
            "Example: --detector null-deref to see all null-dereference findings."
        ),
    )
    issue_grp.add_argument(
        "--issue-kind",
        type=str,
        default=None,
        metavar="KIND",
        help=(
            "Keep issues whose issue_kind field contains KIND (substring).  "
            "issue_kind is the canonical enum string (e.g. NULL_DEREF, "
            "INTEGER_OVERFLOW, DIVISION_BY_ZERO).  "
            "Use --issue-kind OVERFLOW to find all overflow variants."
        ),
    )
    issue_grp.add_argument(
        "--message-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep issues whose human-readable message contains TEXT.  "
            "The message is written for human review; use this for quick "
            "keyword filtering without knowing the exact detector name."
        ),
    )
    issue_grp.add_argument(
        "--has-z3-model",
        action="store_true",
        default=False,
        help=(
            "Keep issues that have a concrete Z3 counterexample model (z3_model "
            "is not null).  A present z3_model means there is a definite "
            "exploitable input — these are the highest-confidence findings."
        ),
    )
    issue_grp.add_argument(
        "--z3-model-var",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep issues whose z3_model dict contains key NAME.  "
            "Use to find all bugs where a specific input variable (e.g. 'n', "
            "'user_id') appears in the triggering counterexample."
        ),
    )
    issue_grp.add_argument(
        "--confidence",
        type=_parse_confidence_range,
        default=None,
        metavar="MIN:MAX",
        help=(
            "Keep issues whose confidence score is in [MIN, MAX].  "
            "Higher confidence (0.8-1.0) means the engine is highly certain "
            "it found a real bug.  Low confidence (0.1-0.5) usually indicates "
            "theoretical edge cases involving unconstrained parameters.  "
            "Use --confidence 0.8:1.0 to see only the most reliable findings."
        ),
    )
    issue_grp.add_argument(
        "--issue-source-line",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep issues detected at source line N (source_line field).  "
            "Use to find all detectors that fired at a particular location."
        ),
    )
    issue_grp.add_argument(
        "--constraint-at-issue-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep issues where at least one constraint in constraints_at_issue "
            "has a SMT-LIB string containing TEXT.  "
            "Use to find bugs whose path-at-detection includes a specific "
            "expression, e.g. a known unsafe comparison."
        ),
    )

    ctx_grp = parser.add_argument_group(
        "SystemContextEvent Filters (event_type=system_context)",
        "Filters on the static analysis-session metadata event (first line of every trace).",
    )
    ctx_grp.add_argument(
        "--function-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep system_context events whose function_name contains NAME.  "
            "Useful when querying a concatenated multi-analysis trace file."
        ),
    )
    ctx_grp.add_argument(
        "--source-file",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Keep system_context events for a specific source file "
            "(substring match on source_file).  "
            "Use to filter a multi-trace log to a specific module."
        ),
    )
    ctx_grp.add_argument(
        "--pysymex-version",
        type=str,
        default=None,
        metavar="VER",
        help=(
            "Keep system_context events for an exact pysymex version string.  "
            "Use to separate traces from different versions of the engine in "
            "a benchmark or regression run."
        ),
    )
    ctx_grp.add_argument(
        "--z3-version",
        type=str,
        default=None,
        metavar="VER",
        help=(
            "Keep system_context events for an exact Z3 version string.  "
            "Use to isolate version-specific solver behavior in benchmarks."
        ),
    )

    deep_grp = parser.add_argument_group(
        "Deep / Semantic Filters (cross-event)",
        (
            "Slower recursive searches across multiple fields.  Add these "
            "after cheap routing filters to minimize work per line."
        ),
    )
    deep_grp.add_argument(
        "--touches-var",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep any event where the string NAME appears in ANY of: "
            "stack elements, local_vars keys/values, global_vars keys/values, "
            "mem_diff keys/values, model_excerpt keys/values, z3_model "
            "keys/values, initial_symbolic_args keys/values.  "
            "This is the most powerful filter for tracking a symbolic variable "
            "through its entire lifetime across all event types.  "
            "Tip: combine with --path-id to restrict the search to one path."
        ),
    )
    deep_grp.add_argument(
        "--constraint-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep any event where TEXT appears in ANY constraint SMT-LIB string: "
            "constraint_added.smtlib (step), path_constraints[*].smtlib (keyframe), "
            "or constraints_at_issue[*].smtlib (issue).  "
            "Use to find where a specific sub-expression first enters the "
            "constraint set and where it drives infeasibility or bug detection."
        ),
    )
    deep_grp.add_argument(
        "--any-field-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep any event whose raw JSON line string contains TEXT.  "
            "This is the fastest full-text search option because it operates "
            "on the raw string before JSON parsing.  "
            "Use when you don't know which field a value might appear in.  "
            "Tip: quote values containing spaces: --any-field-contains '\"x\"'."
        ),
    )

    out_grp = parser.add_argument_group("Output Control")
    out_grp.add_argument(
        "--format",
        choices=["jsonl", "pretty", "summary"],
        default="jsonl",
        help=(
            "Output format for matched events.  "
            "jsonl (default): one JSON object per line, identical to input — "
            "suitable for piping to other tools.  "
            "pretty: two-space-indented JSON for human reading.  "
            "summary: print a Markdown table of per-event-type counts and "
            "first/last seq — ideal as an LLM context preamble (tiny output)."
        ),
    )
    out_grp.add_argument(
        "--head",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Stop after emitting the first N matched events.  "
            "O(1) memory — the stream is terminated early.  "
            "Use for fast sampling of the beginning of a trace."
        ),
    )
    out_grp.add_argument(
        "--tail",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Emit only the last N matched events after consuming the full stream.  "
            "NOTE: this buffers up to N rendered lines in memory (O(N)).  "
            "Use for sampling the end of a trace (where bugs often appear).  "
            "Mutually exclusive with streaming use cases: the full file must "
            "be consumed before output is emitted."
        ),
    )
    out_grp.add_argument(
        "--count",
        action="store_true",
        default=False,
        help=(
            "Print only the integer count of matched events, then exit.  "
            "No events are emitted.  Use for fast quantification before "
            "deciding which filter combination to use for full retrieval."
        ),
    )
    out_grp.add_argument(
        "--fields",
        type=str,
        default=None,
        metavar="F1,F2,...",
        help=(
            "Emit only the specified comma-separated top-level field names "
            "for each matched event.  "
            "Use to slim down output for LLM context windows: "
            "--fields event_type,seq,path_id,severity,message  "
            "Fields not present in a particular event type are silently omitted."
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point.  Registered as ``pysymex-trace-analyze`` console script.

    Args:
        argv: Argument vector.  ``None`` means ``sys.argv[1:]``.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ai_manual:
        print_ai_manual()
        sys.exit(0)

    sys.exit(run(args))


if __name__ == "__main__":
    main()
