"""Performance optimization utilities for pysymex.
This module provides:
- Constraint caching for faster satisfiability checks
- State merging to reduce path explosion
- Lazy symbolic value evaluation
- Memory-efficient state representation
"""

from __future__ import annotations

import logging
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
)

import z3

from pysymex.core.solver import create_solver

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pysymex.core.state import VMState


@dataclass
class CacheStats:
    """Statistics for constraint cache performance."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_time_saved_ms: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Return cache hit rate as a percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        return (
            f"CacheStats(hits={self.hits}, misses={self.misses}, "
            f"hit_rate={self.hit_rate:.1f}%, time_saved={self.total_time_saved_ms:.1f}ms)"
        )


class ConstraintCache:
    """LRU cache for constraint satisfiability results.
    Caches the results of Z3 satisfiability checks to avoid
    redundant solver invocations. Uses constraint normalization
    and hashing for efficient lookup.
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._cache: OrderedDict[
            tuple[int, tuple[int, ...]], tuple[bool, z3.ModelRef | None, float]
        ] = OrderedDict()
        self._cache_index: dict[int, set[tuple[int, ...]]] = {}
        self.stats = CacheStats()

    def _hash_constraints(self, constraints: list[z3.ExprRef] | list[z3.BoolRef]) -> int:
        """Generate a hash for a list of constraints using structural hashing."""
        from pysymex.core.constraint_hash import structural_hash_sorted

        return structural_hash_sorted(constraints)

    @staticmethod
    def _constraints_discriminator(
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
    ) -> tuple[int, ...]:
        """Secondary discriminator for cache collision detection."""
        if not constraints:
            return ()
        return tuple(sorted(c.hash() for c in constraints))

    def get(
        self,
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
    ) -> tuple[bool, z3.ModelRef | None] | None:
        """Look up cached result for constraints."""
        key = self._hash_constraints(constraints)
        discriminator = self._constraints_discriminator(constraints)
        bucket = self._cache_index.get(key)
        if bucket is None:
            self.stats.misses += 1
            return None
        if discriminator not in bucket:
            logger.debug("SAT cache collision detected")
            self.stats.misses += 1
            return None
        cache_key = (key, discriminator)
        cached = self._cache.get(cache_key)
        if cached is None:
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        sat, model, time_taken = cached
        self.stats.total_time_saved_ms += time_taken
        self._cache.move_to_end(cache_key)
        return (sat, model)

    def put(
        self,
        constraints: list[z3.ExprRef] | list[z3.BoolRef],
        satisfiable: bool,
        model: z3.ModelRef | None,
        time_taken_ms: float,
    ) -> None:
        """Store result in cache."""
        key = self._hash_constraints(constraints)
        discriminator = self._constraints_discriminator(constraints)
        cache_key = (key, discriminator)
        if cache_key in self._cache:
            self._cache[cache_key] = (satisfiable, model, time_taken_ms)
            self._cache.move_to_end(cache_key)
            self._cache_index.setdefault(key, set()).add(discriminator)
            return
        while len(self._cache) >= self.max_size:
            old_key, _ = self._cache.popitem(last=False)
            old_primary, old_discriminator = old_key
            bucket = self._cache_index.get(old_primary)
            if bucket is not None:
                bucket.discard(old_discriminator)
                if not bucket:
                    del self._cache_index[old_primary]
            self.stats.evictions += 1
        self._cache[cache_key] = (satisfiable, model, time_taken_ms)
        self._cache_index.setdefault(key, set()).add(discriminator)

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        self._cache_index.clear()

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        return len(self._cache)


_global_cache: ConstraintCache | None = None
_global_cache_lock = threading.Lock()


def get_constraint_cache(max_size: int = 10000) -> ConstraintCache:
    """Get the global constraint cache, creating if needed.

    Thread-safe via double-checked locking.
    """
    global _global_cache
    if _global_cache is not None:
        return _global_cache
    with _global_cache_lock:
        if _global_cache is None:
            _global_cache = ConstraintCache(max_size)
        return _global_cache


def cached_is_satisfiable(
    constraints: list[z3.ExprRef] | list[z3.BoolRef],
    cache: ConstraintCache | None = None,
) -> bool:
    """Check satisfiability with caching."""
    if cache is None:
        cache = get_constraint_cache()
    cached_result = cache.get(constraints)
    if cached_result is not None:
        return cached_result[0]
    start_time = time.perf_counter()
    solver = create_solver()
    solver.add(constraints)
    result = solver.check() == z3.sat
    model = solver.model() if result else None
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    cache.put(constraints, result, model, elapsed_ms)
    return result


@dataclass
class MergeStats:
    """Statistics for state merging."""

    merges_attempted: int = 0
    merges_successful: int = 0
    states_reduced: int = 0


class StateMerger:
    """Merges similar VM states to reduce path explosion.
    Uses abstract interpretation techniques to identify and merge
    states that are "similar enough" to be combined.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.8,
        max_pending_states: int = 100,
    ):
        self.similarity_threshold = similarity_threshold
        self.max_pending_states = max_pending_states
        self.stats = MergeStats()

    def compute_state_signature(self, state: VMState) -> tuple[int, int, tuple[str, ...], int]:
        """Compute a signature for state similarity comparison."""
        return (
            state.pc,
            len(state.stack),
            tuple(sorted(str(k) for k in state.locals.keys())),
            len(state.path_constraints),
        )

    def states_are_similar(
        self,
        state1: VMState,
        state2: VMState,
    ) -> bool:
        """Check if two states are similar enough to merge."""
        sig1 = self.compute_state_signature(state1)
        sig2 = self.compute_state_signature(state2)
        if sig1[0] != sig2[0] or sig1[1] != sig2[1]:
            return False
        vars1 = set(sig1[2])
        vars2 = set(sig2[2])
        if not vars1 or not vars2:
            return True
        overlap = len(vars1 & vars2) / len(vars1 | vars2)
        return overlap >= self.similarity_threshold

    def merge_states(
        self,
        state1: VMState,
        state2: VMState,
    ) -> VMState | None:
        """Attempt to merge two states into one.

        Uses implication-guarded constraints to preserve KLEE-style
        constraint independence.  Each branch's unique constraints are
        wrapped with ``z3.Implies(branch_cond, c)`` so the solver can
        still partition queries by variable independence.
        """
        self.stats.merges_attempted += 1
        if not self.states_are_similar(state1, state2):
            return None
        merged = state1.copy()
        if state1.path_constraints and state2.path_constraints:
            from pysymex.core.copy_on_write import ConstraintChain

            constraints_list1 = state1.path_constraints.to_list()
            constraints_list2 = state2.path_constraints.to_list()
            common_len = 0
            min_len = min(len(constraints_list1), len(constraints_list2))
            while common_len < min_len:
                try:
                    if z3.eq(constraints_list1[common_len], constraints_list2[common_len]):
                        common_len += 1
                    else:
                        break
                except Exception:
                    break

            merged.path_constraints = ConstraintChain.from_list(constraints_list1[:common_len])

            extra1 = constraints_list1[common_len:]
            extra2 = constraints_list2[common_len:]
            if extra1 and extra2:
                branch_cond = extra1[0]
                for c in extra1:
                    merged.path_constraints = merged.path_constraints.append(
                        z3.Implies(branch_cond, c)
                    )
                for c in extra2:
                    merged.path_constraints = merged.path_constraints.append(
                        z3.Implies(z3.Not(branch_cond), c)
                    )
            elif extra1:
                for c in extra1:
                    merged.path_constraints = merged.path_constraints.append(c)
            elif extra2:
                for c in extra2:
                    merged.path_constraints = merged.path_constraints.append(c)

        for name, value2 in state2.locals.items():
            if name not in merged.locals:
                merged.locals[name] = value2
            elif str(merged.locals[name]) != str(value2):
                from pysymex.core.types import SymbolicValue

                s1: object = merged.locals[name]
                s2: object = value2
                if hasattr(s1, "conditional_merge"):
                    merged.locals[name] = s1.conditional_merge(s2, z3.BoolVal(True))
                else:
                    merged.locals[name] = SymbolicValue.from_const(0)
        self.stats.merges_successful += 1
        self.stats.states_reduced += 1
        return merged

    def reduce_state_set(
        self,
        states: list[VMState],
    ) -> list[VMState]:
        """Reduce a set of states by merging similar ones."""
        if len(states) <= 1:
            return states
        groups: dict[tuple[int, int, tuple[str, ...], int], list[VMState]] = {}
        for state in states:
            sig = self.compute_state_signature(state)
            if sig not in groups:
                groups[sig] = []
            groups[sig].append(state)
        result: list[VMState] = []
        for group_states in groups.values():
            if len(group_states) == 1:
                result.append(group_states[0])
            else:
                merged = group_states[0]
                for state in group_states[1:]:
                    merged_attempt = self.merge_states(merged, state)
                    if merged_attempt is not None:
                        merged = merged_attempt
                    else:
                        result.append(state)
                result.append(merged)
        return result


class LazySymbolicValue:
    """A symbolic value that delays constraint generation.
    Useful for reducing solver overhead when values may not
    actually be used.
    """

    def __init__(
        self,
        name: str,
        value_factory: Callable[[], object],
    ):
        self.name = name
        self._factory = value_factory
        self._value: object | None = None
        self._evaluated = False

    @property
    def value(self) -> object:
        """Get the actual value, evaluating lazily if needed."""
        if not self._evaluated:
            self._value = self._factory()
            self._evaluated = True
        return self._value

    def is_evaluated(self) -> bool:
        """Check if the value has been evaluated."""
        return self._evaluated


class CompactState:
    """Memory-efficient representation of VM state.
    Uses structural sharing and immutable data structures
    to reduce memory overhead when storing many states.
    """

    __slots__ = ("__weakref__", "_constraints", "_locals", "_parent", "_pc", "_stack")

    def __init__(
        self,
        pc: int = 0,
        stack: tuple[object, ...] | None = None,
        locals_: frozenset[tuple[str, object]] | None = None,
        constraints: tuple[object, ...] | None = None,
        parent: CompactState | None = None,
    ):
        self._pc = pc
        self._stack: tuple[object, ...] = stack or ()
        self._locals = locals_ or frozenset()
        self._constraints: tuple[object, ...] = constraints or ()
        self._parent = weakref.ref(parent) if parent else None

    @property
    def pc(self) -> int:
        """Property returning the pc."""
        return self._pc

    @property
    def stack(self) -> tuple[object, ...]:
        """Property returning the stack."""
        return self._stack

    @property
    def locals(self) -> dict[str, object]:
        """Property returning the locals."""
        return dict(self._locals)

    @property
    def constraints(self) -> tuple[object, ...]:
        """Property returning the constraints."""
        return self._constraints

    def with_pc(self, pc: int) -> CompactState:
        """Return new state with updated PC."""
        return CompactState(
            pc=pc,
            stack=self._stack,
            locals_=self._locals,
            constraints=self._constraints,
            parent=self,
        )

    def with_push(self, value: object) -> CompactState:
        """Return new state with value pushed to stack."""
        return CompactState(
            pc=self._pc,
            stack=self._stack + (value,),
            locals_=self._locals,
            constraints=self._constraints,
            parent=self,
        )

    def with_pop(self) -> tuple[CompactState, object]:
        """Return new state with top popped and the popped value."""
        if not self._stack:
            raise IndexError("Stack is empty")
        value = self._stack[-1]
        new_state = CompactState(
            pc=self._pc,
            stack=self._stack[:-1],
            locals_=self._locals,
            constraints=self._constraints,
            parent=self,
        )
        return new_state, value

    def with_local(self, name: str, value: object) -> CompactState:
        """Return new state with local variable set."""
        new_locals = frozenset((n, v) for n, v in self._locals if n != name) | {(name, value)}
        return CompactState(
            pc=self._pc,
            stack=self._stack,
            locals_=new_locals,
            constraints=self._constraints,
            parent=self,
        )

    def with_constraint(self, constraint: z3.ExprRef) -> CompactState:
        """Return new state with added constraint."""
        return CompactState(
            pc=self._pc,
            stack=self._stack,
            locals_=self._locals,
            constraints=self._constraints + (constraint,),
            parent=self,
        )


@dataclass
class ProfileData:
    """Profiling data for symbolic execution."""

    total_time_seconds: float = 0.0
    solver_time_seconds: float = 0.0
    opcode_times: dict[str, float] = field(default_factory=lambda: dict[str, float]())
    opcode_counts: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    states_created: int = 0
    states_explored: int = 0
    paths_explored: int = 0
    max_stack_depth: int = 0
    max_constraint_count: int = 0

    def format_report(self) -> str:
        """Format profiling data as a report."""
        total_time = self.total_time_seconds
        if total_time < 0.001:
            total_time = 0.001
        lines = [
            "=" * 60,
            "pysymex Performance Report",
            "=" * 60,
            f"Total execution time: {self.total_time_seconds:.3f}s",
            f"Solver time: {self.solver_time_seconds:.3f}s ({self.solver_time_seconds / total_time * 100:.1f}%)",
            f"States created: {self.states_created}",
            f"States explored: {self.states_explored}",
            f"Paths explored: {self.paths_explored}",
            f"Max stack depth: {self.max_stack_depth}",
            f"Max constraints: {self.max_constraint_count}",
            "",
            "Top 10 Opcodes by Time:",
            "-" * 40,
        ]
        sorted_opcodes = sorted(
            self.opcode_times.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        for opcode, time_taken in sorted_opcodes:
            count = self.opcode_counts.get(opcode, 0)
            avg_time = (time_taken / count * 1000) if count > 0 else 0
            lines.append(f"  {opcode:30} {time_taken:.4f}s ({count:5} calls, {avg_time:.3f}ms avg)")
        lines.append("=" * 60)
        return "\n".join(lines)


class ExecutionProfiler:
    """Profiler for symbolic execution."""

    def __init__(self):
        self.data = ProfileData()
        self._start_time: float | None = None
        self._opcode_start: float | None = None
        self._current_opcode: str | None = None

    def start(self) -> None:
        """Start profiling."""
        self._start_time = time.perf_counter()

    def stop(self) -> None:
        """Stop profiling and calculate total time."""
        if self._start_time is not None:
            self.data.total_time_seconds = time.perf_counter() - self._start_time

    def start_opcode(self, opcode: str) -> None:
        """Start timing an opcode."""
        self._current_opcode = opcode
        self._opcode_start = time.perf_counter()

    def stop_opcode(self) -> None:
        """Stop timing current opcode."""
        if self._opcode_start is not None and self._current_opcode is not None:
            elapsed = time.perf_counter() - self._opcode_start
            opcode = self._current_opcode
            self.data.opcode_times[opcode] = self.data.opcode_times.get(opcode, 0) + elapsed
            self.data.opcode_counts[opcode] = self.data.opcode_counts.get(opcode, 0) + 1

    def record_solver_time(self, seconds: float) -> None:
        """Record time spent in solver."""
        self.data.solver_time_seconds += seconds

    def record_state(self, state: VMState) -> None:
        """Record state metrics."""
        self.data.states_created += 1
        self.data.max_stack_depth = max(self.data.max_stack_depth, len(state.stack))
        self.data.max_constraint_count = max(
            self.data.max_constraint_count,
            len(state.path_constraints),
        )

    def get_report(self) -> str:
        """Get formatted profiling report."""
        return self.data.format_report()


__all__ = [
    "CacheStats",
    "CompactState",
    "ConstraintCache",
    "ExecutionProfiler",
    "LazySymbolicValue",
    "MergeStats",
    "ProfileData",
    "StateMerger",
    "cached_is_satisfiable",
    "get_constraint_cache",
]
