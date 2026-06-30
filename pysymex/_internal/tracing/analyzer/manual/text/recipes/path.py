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

"""Path, solver, infeasible-prune, and duplicate-state recipe text.

Exposes the path recipes section of the AI manual detailing diagnostics for
path explosions, solver bottlenecks, infeasible path over-pruning, and duplicate
states.
"""

from __future__ import annotations

"""Path, solver, infeasible-prune, and duplicate-state recipe text."""

AI_MANUAL_PATH_RECIPES = """
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
pysymex trace-analyze trace.jsonl \
    --event-type keyframe --trigger fork --depth-min 50

# Count how many forks there are at each depth band
pysymex trace-analyze trace.jsonl \
    --event-type keyframe --trigger fork --depth-min 30 --depth-max 50 --count

# Trace a specific subtree: all events under path 42
pysymex trace-analyze trace.jsonl --path-id 42 --format pretty | head -200
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
pysymex trace-analyze trace.jsonl \
    --event-type solve --solver-latency-min 500

# Cache miss rate summary: count misses vs hits
pysymex trace-analyze trace.jsonl --event-type solve --cache-miss --count
pysymex trace-analyze trace.jsonl --event-type solve --cache-hit --count

# Find the specific path where the slowest queries occur
pysymex trace-analyze trace.jsonl \
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
pysymex trace-analyze trace.jsonl \
    --event-type keyframe --trigger prune \
    --prune-reason infeasible \
    --num-path-constraints-min 20 \
    --format pretty

# Find the predecessor fork (parent path) of a suspicious prune on path 99
pysymex trace-analyze trace.jsonl \
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
pysymex trace-analyze trace.jsonl \
    --event-type keyframe --trigger prune --prune-reason duplicate_state

# Check if the "duplicate" had the same path constraints as another path
pysymex trace-analyze trace.jsonl \
    --event-type keyframe --trigger prune --prune-reason duplicate_state \
    --num-path-constraints-min 1 --format pretty | head -100
```

**What to look for:** Two keyframes with identical `local_vars` and
`path_constraints` but different `path_id` — that's a true hash collision.
If the constraints differ, the deduplication logic may be over-aggressive.
""".strip()
