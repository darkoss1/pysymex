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

"""Introductory text sections for the trace analyzer AI manual.

Exposes the introductory section of the AI manual detailing trace formats,
event types, filter tables, and diagnostic guidelines.
"""

from __future__ import annotations

"""Introductory AI manual sections."""

AI_MANUAL_INTRO = """
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
| `step`           | Per instruction | Incremental diff: dispatch latency, what changed on the stack, in locals, in memory, whether a new path constraint was added, and the **original source text**. |
| `keyframe`       | Fork/prune/issue | Full symbolic-state snapshot. Re-anchors understanding without replaying prior deltas. |
| `solve`          | Per SMT call    | SMT solver telemetry: latency (ms), cache hit/miss, satisfying model excerpt, number of constraints. |
| `detector_query` | Per detector SAT query | Detector feasibility decision, cache/witness use, inconclusive-prefix context, and a bounded query-constraint excerpt. |
| `path_feasibility` | Per pending path check | Path feasibility policy decision, solver use, hard-theory skips, policy latency, and a bounded query-constraint excerpt. |
| `scheduler`      | Per frontier enqueue/select | Worklist scheduling decision, frontier size, priority, branch pressure, detector obligations, and resident-size estimates. |
| `fallback`       | Per degraded decision | Unsupported, inconclusive, precision-loss, or resource-limit diagnostics. |
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
| `--event-type TYPE` | `event_type` | Keep only events of this type. Repeatable. Values: `step`, `keyframe`, `solve`, `detector_query`, `path_feasibility`, `scheduler`, `fallback`, `issue`, `system_context`. |
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
| `--step-latency-min MS` | `step_latency_ms` | Keep steps whose instruction dispatch latency is at least MS milliseconds. |
| `--step-latency-max MS` | `step_latency_ms` | Keep steps whose instruction dispatch latency is at most MS milliseconds. |
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
| `--constraint-contains TEXT` | Searches all constraint-bearing fields: `constraint_added.smtlib` (step), `path_constraints[*].smtlib` (keyframe), `constraint_excerpt[*].smtlib` (detector_query), `query_constraint_excerpt[*].smtlib` (path_feasibility), and `constraints_at_issue[*].smtlib` (issue). Use this to find where a specific expression enters the constraint set. |
| `--any-field-contains TEXT` | Raw substring scan of the complete JSON line before parsing. This is the fastest full-text search option. Use it when you don't know which field contains the value. |

---
""".strip()

__all__ = ["AI_MANUAL_INTRO"]
