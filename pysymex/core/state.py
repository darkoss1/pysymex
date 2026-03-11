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
- Mutation helpers (push, pop, set_local, …) return ``self`` so callers
  can write ``state = state.push(val)`` (preferred) or plain ``state.push(val)``.
- New convenience helpers: ``advance_pc()``, ``set_pc()``, ``_replace(**kw)``.
- ``fork()`` / ``replace()`` remain the way to create independent states
  for branching.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.oop_support import EnhancedClassRegistry

import z3

from pysymex.core.copy_on_write import ConstraintChain, CowDict, CowSet

_path_id_counter = itertools.count()

_EMPTY_TAINT: frozenset[str] = frozenset()
UNBOUND = object()


def wrap_cow_dict(val: dict[Any, Any] | CowDict[Any, Any] | None) -> CowDict[Any, Any]:
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
    by reference — mutations in one branch would contaminate the other.
    We use copy.copy (shallow) because the builder's mutable state
    (summary with its lists) needs independence but the Z3 expressions
    inside those lists are immutable and safe to share.
    """
    try:
        new: Any = copy.copy(builder)

        builder_any: Any = builder
        if hasattr(builder_any, "summary"):
            new.summary = copy.copy(builder_any.summary)
            for attr in (
                "parameters",
                "preconditions",
                "postconditions",
                "modified",
                "reads",
                "calls",
                "may_raise",
            ):
                if hasattr(new.summary, attr):
                    setattr(new.summary, attr, list(getattr(new.summary, attr)))
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


class VMState:
    """Virtual Machine execution state for symbolic execution.

    **Fluent API** — mutation helpers (``push``, ``set_local``, …) mutate
    *self* and return *self* so callers can write either style:

    - ``state.push(val)``   — traditional fire-and-forget
    - ``state = state.push(val)`` — explicit reassignment (preferred)

    For *branching* (two+ successors), use ``fork()`` or ``replace()``
    which always create a new, independent ``VMState``.

    Uses copy-on-write data structures for efficient forking:
    - CowDict for local_vars, global_vars, memory (O(1) fork, copy on mutation)
    - CowSet for visited_pcs (O(1) fork)
    """

    __slots__ = (
        "_building_class",
        "_class_registry",
        "_pending_taint_issues",
        "block_stack",
        "call_stack",
        "control_taint",
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
        "taint_tracker",
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
        visited_pcs: set[int] | CowSet | None = None,
        memory: dict[int, StackValue] | CowDict[int, StackValue] | None = None,
        path_id: int = 0,
        depth: int = 0,
        taint_tracker: object | None = None,
        current_instructions: list[object] | None = None,
        control_taint: frozenset[str] | None = None,
        pending_constraint_count: int = 0,
        loop_iterations: dict[int, int] | None = None,
        prev_loop_states: dict[int, VMState] | None = None,
        _path_counter: int = 0,
    ) -> None:
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
        self.visited_pcs = wrap_cow_set(visited_pcs)
        self.memory = wrap_cow_dict(memory)

        self.path_id = path_id
        self.depth = depth
        self.taint_tracker = taint_tracker
        self.current_instructions = current_instructions
        self.control_taint = control_taint if control_taint is not None else _EMPTY_TAINT
        self.pending_constraint_count = pending_constraint_count
        self.loop_iterations = dict(loop_iterations) if loop_iterations is not None else {}
        self.prev_loop_states = dict(prev_loop_states) if prev_loop_states is not None else {}
        self.pending_kw_names: tuple[str, ...] | None = None
        self._pending_taint_issues: list[object] = []
        self._building_class: bool = False
        self._class_registry: dict[str, object] | EnhancedClassRegistry = {}

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

    def set_local(self, name: str, value: StackValue) -> VMState:
        """Set local variable *name* to *value*.  Returns ``self``."""
        self.local_vars[name] = value
        return self

    def set_global(self, name: str, value: StackValue) -> VMState:
        """Set global variable *name* to *value*.  Returns ``self``."""
        self.global_vars[name] = value
        return self

    def add_constraint(self, constraint: z3.BoolRef) -> VMState:
        """Append *constraint* to path constraints.  Returns ``self``."""
        self.path_constraints = self.path_constraints.append(constraint)
        self.pending_constraint_count += 1
        return self

    def mark_visited(self) -> bool:
        """Mark current ``pc`` as visited.

        Returns:
            ``True`` if the PC was *already* visited (loop detected).
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

    def get_local(self, name: str) -> StackValue | object:
        """Get a local variable, or UNBOUND if not found or cleared."""
        return self.local_vars.get(name, UNBOUND)

    def get_global(self, name: str) -> StackValue | None:
        """Get a global variable, or None if not found."""
        return self.global_vars.get(name)

    @property
    def locals(self) -> CowDict[Any, Any]:
        """Alias for local_vars (used by some callers)."""
        return self.local_vars  # type: ignore[return-value]

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
        h ^= len(self.call_stack) * 1000000007

        h ^= self.local_vars.hash_value() * 31
        h ^= self.global_vars.hash_value() * 1000003
        h ^= self.memory.hash_value() * 82520
        h ^= self.visited_pcs.hash_value() * 12345

        for v in self.stack:
            v_any: Any = v
            if hasattr(v_any, "hash_value") and callable(v_any.hash_value):
                h = (h * 31) ^ cast("int", v_any.hash_value())
            else:
                try:
                    h = (h * 31) ^ hash(v)
                except TypeError:
                    h = (h * 31) ^ 0

        return h

    def fork(self) -> VMState:
        """Create a copy-on-write fork of this state for branching.

        O(1) for dicts and sets (shared until mutation).
        Stack and constraints are shallow-copied (small and immutable refs).

        Returns:
            A new VMState sharing data with original until either mutates.
        """
        new_path_id = next(_path_id_counter)
        child = VMState(
            stack=list(self.stack),
            local_vars=self.local_vars.cow_fork(),
            global_vars=self.global_vars.cow_fork(),
            path_constraints=self.path_constraints,
            pc=self.pc,
            block_stack=list(self.block_stack),
            call_stack=[
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
            ],
            visited_pcs=self.visited_pcs.cow_fork(),
            memory=self.memory.cow_fork(),
            path_id=new_path_id,
            depth=self.depth,
            taint_tracker=(
                cast("Any", self.taint_tracker).fork() if self.taint_tracker is not None else None
            ),
            current_instructions=self.current_instructions,
            control_taint=self.control_taint,
            pending_constraint_count=self.pending_constraint_count,  # BUG-012 fix: inherit, not reset to 0
            loop_iterations=dict(self.loop_iterations),
            prev_loop_states=dict(self.prev_loop_states),
        )

        child._pending_taint_issues = list(getattr(self, "_pending_taint_issues", []))
        child._building_class = getattr(self, "_building_class", False)
        child._class_registry = (
            dict(self._class_registry)
            if hasattr(self, "_class_registry") and isinstance(self._class_registry, dict)
            else getattr(self, "_class_registry", {})
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
    local_vars: dict[str, object] | None = None,
    global_vars: dict[str, object] | None = None,
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
    return VMState(
        stack=[],
        local_vars=local_vars or {},
        global_vars=global_vars or {},
        path_constraints=constraints or [],
        pc=0,
    )
