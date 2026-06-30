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

"""Variable, constraint, cache, and issue deep-dive recipe text.

Exposes the investigation recipes section of the AI manual detailing how to
track variables, investigate constraint explosions, diagnose cache misses, and
perform deep-dive issue analysis.
"""

from __future__ import annotations

"""Variable, constraint, cache, and issue deep-dive recipe text."""

AI_MANUAL_INVESTIGATION_RECIPES = """
---

### Recipe 5: Tracking a Symbolic Variable Through Its Lifetime

**Symptom:** A symbolic variable `user_input` appears in a bug report but you
want to trace every step where it was read, written, or constrained.

**Goal:** Full lifecycle trace of a single variable across all event types.

```bash
# Every event that mentions 'user_input' in any container
pysymex trace-analyze trace.jsonl --touches-var user_input

# Narrow to a specific path
pysymex trace-analyze trace.jsonl --touches-var user_input --path-id 7

# See only the steps where user_input was introduced or modified
pysymex trace-analyze trace.jsonl \
    --event-type step \
    --var-added-name user_input

pysymex trace-analyze trace.jsonl \
    --event-type step \
    --var-modified-name user_input --format pretty
```

---

### Recipe 6: Constraint Explosion / Over-Approximation Investigation

**Symptom:** A specific execution path accumulates hundreds of constraints;
analysis slows to a crawl on that path.

**Goal:** Find the exact instructions that add new constraints on a suspect path.

```bash
# Every step on path 12 that added a constraint
pysymex trace-analyze trace.jsonl \
    --event-type step --path-id 12 --has-constraint-added

# Check if a specific expression (e.g. 'x + y') is in any constraint
pysymex trace-analyze trace.jsonl --constraint-contains "x + y"

# Find which opcode generates the most constraints
pysymex trace-analyze trace.jsonl \
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
pysymex trace-analyze trace.jsonl \
    --event-type solve --cache-miss --solver-latency-min 100

# Isolate to a specific path where you know caching should work
pysymex trace-analyze trace.jsonl \
    --event-type solve --cache-miss --path-id 5 --format pretty

# Compare: how many constraints did cache-miss queries have vs cache-hits?
pysymex trace-analyze trace.jsonl \
    --event-type solve --cache-miss --num-constraints-min 30 --count
```

---

### Recipe 8: Full Issue Deep-Dive

**Symptom:** A reported bug is a false positive (or you want to understand the
exact constraint path that led to it).

**Goal:** See the complete symbolic context at bug-detection time.

```bash
# All issues of any severity
pysymex trace-analyze trace.jsonl --event-type issue --format pretty

# Issues from a specific detector
pysymex trace-analyze trace.jsonl --detector null-deref --format pretty

# Issues AND the keyframe immediately before them (full context)
pysymex trace-analyze trace.jsonl \
    --event-type issue,keyframe --path-id 42 --format pretty

# Find which input triggered the bug via the Z3 model
pysymex trace-analyze trace.jsonl --event-type issue --has-z3-model --format pretty
```

---
""".strip()
