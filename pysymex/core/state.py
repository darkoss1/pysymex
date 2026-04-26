# pysymex: Python Symbolic Execution & Formal Verification
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

"""VM State management for pysymex.

This module defines the execution state of the symbolic virtual machine,
including the operand stack, local/global variables, path constraints,
and state forking for branch exploration.

Copy-on-write fork for O(1) state branching.
- CowDict for local/global vars and memory (shared until mutation)
- CowSet for visited PCs
- Atomic path counter (thread-safe)
- Structural constraint hashing

Fluent VMState API (Functional Core / Imperative Shell).
- Mutation helpers (push, pop, set_local, â€¦) return ``self`` so callers
  can write ``state = state.push(val)`` (preferred) or plain ``state.push(val)``.
- New convenience helpers: ``advance_pc()``, ``set_pc()``, ``_replace(**kw)``.
- ``fork()`` / ``replace()`` remain the way to create independent states
  for branching.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypeGuard, TypeVar

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.objects import ObjectState
    from pysymex.core.objects.oop import EnhancedClassRegistry

import z3

from pysymex.core.memory.cow import BranchChain, BranchRecord, ConstraintChain, CowDict, CowSet

_path_id_counter = itertools.count()


class _UnboundType:
    """Sentinel type to indicate an unbound local variable.

    Using a class rather than `object()` allows Pyright to properly
    narrow types in `if value is UNBOUND:` checks.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNBOUND"


UNBOUND: _UnboundType = _UnboundType()

if TYPE_CHECKING:

    def is_bound(value: StackValue | _UnboundType) -> TypeGuard[StackValue]:
        """TypeGuard that checks if a value is NOT the UNBOUND sentinel."""
        ...
else:

    def is_bound(value: object) -> bool:
        """Check if a value is NOT the UNBOUND sentinel."""
        return value is not UNBOUND


class HashableValue(Protocol):
    def hash_value(self) -> int: ...


def _is_hashable_value(value: object) -> TypeGuard[HashableValue]:
    return hasattr(value, "hash_value") and callable(getattr(value, "hash_value", None))


K = TypeVar("K")
T = TypeVar("T")


def wrap_cow_dict(val: dict[K, T] | CowDict[K, T] | None) -> CowDict[K, T]:
    """Wrap a dict in CowDict if it isn't already."""
    if isinstance(val, CowDict):
        return val
    return CowDict(val) if val else CowDict()


def wrap_cow_set(val: set[int] | CowSet | None) -> CowSet:
    """Wrap a set in CowSet if it isn't already."""
    if isinstance(val, CowSet):
        return val
    return CowSet(val) if val else CowSet()


def _copy_summary_builder(builder: object) -> object:
    """Create an independent copy of a SummaryBuilder.

    When CallFrames are forked, the summary_builder must NOT be shared
    by reference â€” mutations in one branch would contaminate the other.
    We use copy.copy (shallow) because the builder's mutable state
    (summary with its lists) needs independence but the Z3 expressions
    inside those lists are immutable and safe to share.
    """
    try:
        new = copy.copy(builder)

        if hasattr(builder, "summary"):
            setattr(new, "summary", copy.copy(getattr(builder, "summary")))
            for attr in (
                "parameters",
                "preconditions",
                "postconditions",
                "modified",
                "reads",
                "calls",
                "may_raise",
            ):
                summary = getattr(new, "summary")
                if hasattr(summary, attr):
                    setattr(summary, attr, list(getattr(summary, attr)))
        return new
    except (TypeError, AttributeError, RecursionError):
        return builder


@dataclass(frozen=True, slots=True)
class BlockInfo:
    """Metadata for a control-flow block (loop, try/except, with, etc.).

    Attributes:
        block_type: Kind of block (``"loop"``, ``"try"``, ``"finally"``, etc.).
        start_pc: Bytecode index where the block starts.
        end_pc: Bytecode index where the block ends.
        handler_pc: Target PC for exception handlers (``None`` if N/A).
    """

    block_type: str
    start_pc: int
    end_pc: int
    handler_pc: int | None = None

    def hash_value(self) -> int:
        """Stable hash of the block metadata."""
        return hash((self.block_type, self.start_pc, self.end_pc, self.handler_pc))


@dataclass(frozen=True, slots=True)
class CallFrame:
    """Saved state for a function call during inter-procedural analysis.

    Attributes:
        function_name: Qualified name of the called function.
        return_pc: PC to resume at after the call returns.
        local_vars: Caller's local variables (snapshot or CowDict).
        stack_depth: Operand-stack depth at the call site.
        caller_instructions: Instruction list of the caller (for returns).
        summary_builder: Optional function-summary builder being populated.
    """

    function_name: str
    return_pc: int
    local_vars: CowDict[str, StackValue]
    stack_depth: int
    caller_instructions: list[object] | None = None
    summary_builder: object | None = None

    def hash_value(self) -> int:
        """Stable content-aware hash of the call frame.

        Calculates a hash using the function name, rejoin point (return_pc),
        current operand-stack level, and a structural hash of the caller's
        local variables. Used for inter-procedural path deduplication.
        """
        return (
            hash((self.function_name, self.return_pc, self.stack_depth))
            ^ self.local_vars.hash_value()
        )


class VMState:
    """Symbolic Virtual Machine execution state for pysymex.

    Coordinates the complete architectural state of a single execution path,
    providing a fluent interface for bytecode emulation and an optimized
    Copy-on-Write (CoW) mechanism for path branching.

    **Architectural Components:**
    - **Operand Stack**: Last-in-first-out storage for symbolic values.
    - **Variable Stores**: `local_vars` and `global_vars` using `CowDict` for
      state isolation with O(1) forking.
    - **Control Flow Control**: `block_stack` (loops/exceptions) and `call_stack`
      (inter-procedural analysis).
    - **Path Constraints**: A `ConstraintChain` of Z3 boolean expressions
      defining the reachability conditions for this specific state.
    - **Memory Model**: A `CowDict` mapping symbolic addresses to values.

    **Evolution Patterns:**
    1. **Single-Path Mutation**: Fluent helpers like `push()`, `pop()`, and
       `set_local()` modify the current state and return `self` for chaining.
    2. **Branching (State Splitting)**: The `fork()` method creates a new,
       independent `VMState` that shares underlying immutable data structures
       until a mutation occurs (CoW).

    **State Hashing & Deduplication:**
    The `hash_value()` method provides a stable, content-based hash used for
    detecting path convergence and mitigating infinite loop depth.
    """

    __slots__ = (
        "_building_class",
        "_class_registry",
        "_object_state",
        "block_stack",
        "branch_trace",
        "call_stack",
        "contract_frames",
        "current_instructions",
        "depth",
        "global_vars",
        "local_vars",
        "loop_iterations",
        "memory",
        "path_constraints",
        "path_id",
        "pc",
        "pending_constraint_count",
        "pending_kw_names",
        "prev_loop_states",
        "stack",
        "visited_pcs",
    )

    def __init__(
        self,
        stack: list[StackValue] | None = None,
        local_vars: dict[str, StackValue] | CowDict[str, StackValue] | None = None,
        global_vars: dict[str, StackValue] | CowDict[str, StackValue] | None = None,
        path_constraints: list[z3.BoolRef] | ConstraintChain | None = None,
        pc: int = 0,
        block_stack: list[BlockInfo] | None = None,
        call_stack: list[CallFrame] | None = None,
        contract_frames: list[object] | None = None,
        visited_pcs: set[int] | CowSet | None = None,
        memory: dict[int, StackValue] | CowDict[int, StackValue] | None = None,
        object_state: ObjectState | None = None,
        path_id: int = 0,
        depth: int = 0,
        current_instructions: list[object] | None = None,
        pending_constraint_count: int = 0,
        loop_iterations: dict[int, int] | None = None,
        prev_loop_states: dict[int, VMState] | None = None,
        branch_trace: BranchChain | None = None,
        _path_counter: int = 0,
    ) -> None:
        """Initialize a fresh VM state.

        Args:
            stack: Initial operand stack.
            local_vars: Initial local variables (wrapped in CowDict for efficiency).
            global_vars: Initial global variables (wrapped in CowDict).
            path_constraints: Sequence of Z3 reachability constraints.
            pc: Initial program counter.
            block_stack: Saved control flow blocks (loops/tries).
            call_stack: Return-path saved states for function calls.
            visited_pcs: Set of bytecode offsets already explored in this path.
            memory: Symbolic memory store.
            path_id: Unique identifier for this execution path.
            depth: Number of symbolic steps taken from the root.
            current_instructions: List of bytecode instructions for the current scope.
            pending_constraint_count: Count of constraints added since the last Z3 check.
            loop_iterations: Tracks iteration counts for loop-bounding.
            prev_loop_states: Snapshots of prior loop entry points for state merging.
            branch_trace: A historical log of branch decisions (O(1) chain).
        """
        self.stack = stack if stack is not None else []
        self.local_vars = wrap_cow_dict(local_vars)
        self.global_vars = wrap_cow_dict(global_vars)
        if isinstance(path_constraints, ConstraintChain):
            self.path_constraints = path_constraints
        elif path_constraints is not None:
            self.path_constraints = ConstraintChain.from_list(path_constraints)
        else:
            self.path_constraints = ConstraintChain.empty()
        self.pc = pc
        self.block_stack = block_stack if block_stack is not None else []
        self.call_stack = call_stack if call_stack is not None else []
        self.contract_frames = contract_frames if contract_frames is not None else []
        self.visited_pcs = wrap_cow_set(visited_pcs)
        self.memory = wrap_cow_dict(memory)

        self._object_state = object_state

        self.path_id = path_id
        self.depth = depth
        self.current_instructions = current_instructions
        self.pending_constraint_count = pending_constraint_count
        self.loop_iterations = dict(loop_iterations) if loop_iterations is not None else {}
        self.prev_loop_states = dict(prev_loop_states) if prev_loop_states is not None else {}
        self.branch_trace = branch_trace if branch_trace is not None else BranchChain.empty()
        self.pending_kw_names: tuple[str, ...] | None = None
        self._building_class: bool = False
        self._class_registry: dict[str, object] | EnhancedClassRegistry = {}

    @property
    def building_class(self) -> bool:
        return self._building_class

    @building_class.setter
    def building_class(self, value: bool) -> None:
        self._building_class = value

    @property
    def class_registry(self) -> dict[str, object] | EnhancedClassRegistry:
        return self._class_registry

    @class_registry.setter
    def class_registry(self, value: dict[str, object] | EnhancedClassRegistry) -> None:
        self._class_registry = value

    @property
    def object_state(self) -> ObjectState:
        """Lazily materialize object-model state only when needed."""
        if self._object_state is None:
            from pysymex.core.objects import ObjectState

            self._object_state = ObjectState()
        return self._object_state

    @object_state.setter
    def object_state(self, value: ObjectState) -> None:
        self._object_state = value

    def _replace(self, **changes: object) -> VMState:
        """Create a CoW **fork** with specific fields altered.

        Use this when you need a *new* independent state (e.g. branching).
        For single-path mutation, use the fluent helpers instead.
        """
        child = self.fork()
        for attr, value in changes.items():
            object.__setattr__(child, attr, value)
        return child

    def push(self, value: StackValue) -> VMState:
        """Push *value* onto the operand stack.  Returns ``self``."""
        self.stack.append(value)
        return self

    def pop(self) -> StackValue:
        """Pop a value from the operand stack."""
        if not self.stack:
            raise RuntimeError("Stack underflow")
        return self.stack.pop()

    def peek(self, n: int = 0) -> StackValue:
        """Peek at the n-th value from the top of the stack (read-only)."""
        if len(self.stack) <= n:
            raise RuntimeError(f"Stack underflow: cannot peek at position {n}")
        return self.stack[-(n + 1)]

    def advance_pc(self, delta: int = 1) -> VMState:
        """Increment ``pc`` by *delta*.  Returns ``self``."""
        self.pc += delta
        return self

    def set_pc(self, target: int) -> VMState:
        """Set ``pc`` to *target*.  Returns ``self``."""
        self.pc = target
        return self

    def set_local(self, name: str, value: StackValue | _UnboundType) -> VMState:
        """Set local variable *name* to *value*.  Returns ``self``.

        Setting to UNBOUND marks the variable as unbound/cleared.
        """
        if value is UNBOUND:
            if name in self.local_vars:
                del self.local_vars[name]
            return self
        self.local_vars[name] = value  # type: ignore[index]  # StackValue is the expected type
        return self

    def set_global(self, name: str, value: StackValue) -> VMState:
        """Set global variable *name* to *value*.  Returns ``self``."""
        self.global_vars[name] = value
        return self

    def add_constraint(self, constraint: z3.BoolRef) -> VMState:
        """Append *constraint* to path constraints.  Returns ``self``."""
        self.path_constraints = self.path_constraints.append(constraint)
        import z3

        if not (z3.is_true(constraint) or z3.is_false(constraint)):
            self.pending_constraint_count += 1
        return self

    def record_branch(self, condition: z3.BoolRef, taken: bool, pc: int) -> VMState:
        """Record a branch decision. Returns ``self``."""
        record = BranchRecord(pc=pc, condition=condition, taken=taken)
        self.branch_trace = self.branch_trace.append(record)
        return self

    def mark_visited(self) -> bool:
        """Record the current ``pc`` in the path's visitation log.

        Uses the internal `CowSet` to efficiently track whether this program
        counter has been reached before on the current path. Essential for
        detecting infinite loops during symbolic exploration.

        Returns:
            ``True`` if the current ``pc`` was already present in `visited_pcs`.
        """
        if self.pc in self.visited_pcs:
            return True
        self.visited_pcs.add(self.pc)
        return False

    def enter_block(self, block: BlockInfo) -> VMState:
        """Push *block* onto the block stack.  Returns ``self``."""
        self.block_stack.append(block)
        return self

    def exit_block(self) -> BlockInfo | None:
        """Pop the innermost block from the block stack.

        Returns the popped ``BlockInfo``, or ``None`` if the stack is empty.
        """
        if self.block_stack:
            return self.block_stack.pop()
        return None

    def push_call(self, frame: CallFrame) -> VMState:
        """Push *frame* onto the call stack.  Returns ``self``."""
        self.call_stack.append(frame)
        return self

    def pop_call(self) -> CallFrame | None:
        """Pop the top call frame.

        Returns the popped ``CallFrame``, or ``None`` if the stack is empty.
        """
        if self.call_stack:
            return self.call_stack.pop()
        return None

    def get_local(self, name: str) -> StackValue | _UnboundType:
        """Get a local variable, or UNBOUND if not found or cleared."""
        if name in self.local_vars:
            return self.local_vars[name]
        return UNBOUND

    def get_global(self, name: str) -> StackValue | None:
        """Get a global variable, or None if not found."""
        return self.global_vars.get(name)

    @property
    def locals(self) -> CowDict[str, StackValue]:
        """Alias for local_vars (used by some callers)."""
        return self.local_vars

    def current_block(self) -> BlockInfo | None:
        """Get the current control flow block."""
        return self.block_stack[-1] if self.block_stack else None

    def call_depth(self) -> int:
        """Get the current call stack depth."""
        return len(self.call_stack)

    def copy_constraints(self) -> list[z3.BoolRef]:
        """Get a copy of the current path constraints."""
        return self.path_constraints.to_list()

    def constraint_hash(self) -> int:
        """Compute a hash of the current path constraints for loop detection."""
        return self.path_constraints.hash_value()

    def hash_value(self) -> int:
        """Compute a stable hash of the entire VM state.

        Essential for path deduplication and loop detection (FLAW 4 fix).
        Uses stable content-based hashing instead of object identity.
        """
        h = self.pc * 2654435761
        h ^= self.constraint_hash() * 999999937

        for frame in self.call_stack:
            h = (h * 1000003) ^ frame.hash_value()

        for block in self.block_stack:
            h = (h * 1000003) ^ block.hash_value()

        h ^= self.local_vars.hash_value() * 31
        h ^= self.global_vars.hash_value() * 1000003
        h ^= self.memory.hash_value() * 82520
        h ^= self.visited_pcs.hash_value() * 12345

        for v in self.stack:
            if _is_hashable_value(v):
                h = (h * 31) ^ v.hash_value()
            else:
                try:
                    h = (h * 31) ^ hash(v)
                except TypeError:
                    h = (h * 31) ^ 0

        return h & 0xFFFFFFFFFFFFFFFF

    def fork(self) -> VMState:
        """Create a copy-on-write fork of this state for branching.

        O(1) for dicts and sets (shared until mutation).
        Stack and constraints are shallow-copied (small and immutable refs).

        Returns:
            A new VMState sharing data with original until either mutates.
        """
        new_path_id = next(_path_id_counter)

        needs_deep_copy = any(f.summary_builder is not None for f in self.call_stack)

        if not needs_deep_copy:
            new_call_stack = list(self.call_stack)
        else:
            new_call_stack = [
                CallFrame(
                    function_name=f.function_name,
                    return_pc=f.return_pc,
                    local_vars=f.local_vars.cow_fork(),
                    stack_depth=f.stack_depth,
                    caller_instructions=f.caller_instructions,
                    summary_builder=(
                        _copy_summary_builder(f.summary_builder)
                        if f.summary_builder is not None
                        else None
                    ),
                )
                for f in self.call_stack
            ]

        child = VMState(
            stack=list(self.stack),
            local_vars=self.local_vars.cow_fork(),
            global_vars=self.global_vars.cow_fork(),
            path_constraints=self.path_constraints,
            pc=self.pc,
            block_stack=list(self.block_stack),
            call_stack=new_call_stack,
            contract_frames=list(self.contract_frames),
            visited_pcs=self.visited_pcs.cow_fork(),
            memory=self.memory.cow_fork(),
            object_state=(
                self._object_state.clone()
                if self._object_state is not None
                and hasattr(self._object_state, "clone")
                and callable(getattr(self._object_state, "clone", None))
                else copy.copy(self.object_state)
                if self._object_state is not None
                else None
            ),
            path_id=new_path_id,
            depth=self.depth,
            current_instructions=self.current_instructions,
            pending_constraint_count=self.pending_constraint_count,
            loop_iterations=dict(self.loop_iterations),
            prev_loop_states=dict(self.prev_loop_states),
            branch_trace=self.branch_trace,
        )

        child.building_class = self.building_class
        child.class_registry = (
            dict(self.class_registry)
            if isinstance(self.class_registry, dict)
            else self.class_registry
        )
        child.pending_kw_names = getattr(self, "pending_kw_names", None)
        return child

    def copy(self) -> VMState:
        """Create a copy of this state (alias for fork)."""
        return self.fork()

    def replace(self, **changes: object) -> VMState:
        """Fork this state and apply attribute changes to the child.

        Usage::

            new_state = state.replace(pc=target_pc, depth=state.depth + 1)

        Returns:
            A new VMState (fork) with the specified attributes overwritten.
        """
        return self._replace(**changes)

    def __repr__(self) -> str:
        return (
            f"VMState(path={self.path_id}, pc={self.pc}, "
            f"stack_depth={len(self.stack)}, "
            f"constraints={len(self.path_constraints)})"
        )


def create_initial_state(
    local_vars: dict[str, StackValue] | None = None,
    global_vars: dict[str, StackValue] | None = None,
    constraints: list[z3.BoolRef] | None = None,
) -> VMState:
    """Create an initial VM state for symbolic execution.

    Args:
        local_vars: Initial local variables.
        global_vars: Initial global variables.
        constraints: Initial path constraints.

    Returns:
        A fresh VMState ready for execution.
    """
    gvars = global_vars or {}
    if "__name__" not in gvars:
        gvars["__name__"] = "__main__"

    return VMState(
        stack=[],
        local_vars=local_vars or {},
        global_vars=gvars,
        path_constraints=constraints or [],
        pc=0,
    )
