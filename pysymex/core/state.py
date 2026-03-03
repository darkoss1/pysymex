"""VM State management for pysymex.

This module defines the execution state of the symbolic virtual machine,
including the operand stack, local/global variables, path constraints,
and state forking for branch exploration.

v0.4.0: Copy-on-write fork for O(1) state branching.
- CowDict for local/global vars and memory (shared until mutation)
- CowSet for visited PCs
- Atomic path counter (thread-safe)
- Structural constraint hashing
"""

from __future__ import annotations


import copy

import itertools

from dataclasses import dataclass

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from pysymex.core.oop_support import EnhancedClassRegistry

import z3


from pysymex.core.copy_on_write import CowDict, CowSet

_path_id_counter = itertools.count()


_EMPTY_TAINT: frozenset[Any] = frozenset()


def _wrap_cow_dict(val: dict[str, Any] | dict[int, Any] | CowDict | None) -> CowDict:
    """Wrap a dict in CowDict if it isn't already."""

    if isinstance(val, CowDict):
        return val

    return CowDict(cast(dict[str, Any], val)) if val else CowDict()


def _wrap_cow_set(val: set[int] | CowSet | None) -> CowSet:
    """Wrap a set in CowSet if it isn't already."""

    if isinstance(val, CowSet):
        return val

    return CowSet(val) if val else CowSet()


def _copy_summary_builder(builder: Any) -> Any:
    """Create an independent copy of a SummaryBuilder.

    When CallFrames are forked, the summary_builder must NOT be shared
    by reference — mutations in one branch would contaminate the other.
    We use copy.copy (shallow) because the builder's mutable state
    (summary with its lists) needs independence but the Z3 expressions
    inside those lists are immutable and safe to share.
    """

    try:
        new = copy.copy(builder)

        if hasattr(builder, "summary"):
            new.summary = copy.copy(builder.summary)

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

    except Exception:
        return builder


@dataclass(slots=True)
class BlockInfo:
    """Information about a control flow block (loop, try/except, etc.)."""

    block_type: str

    start_pc: int

    end_pc: int

    handler_pc: int | None = None


@dataclass(slots=True)
class CallFrame:
    """Represents a function call frame for inter-procedural analysis."""

    function_name: str

    return_pc: int

    local_vars: dict[str, Any] | CowDict

    stack_depth: int

    caller_instructions: list[Any] | None = None

    summary_builder: Any | None = None


class VMState:
    """Virtual Machine execution state for symbolic execution.

    Uses copy-on-write data structures for efficient forking:
    - CowDict for local_vars, global_vars, memory (O(1) fork, copy on mutation)
    - CowSet for visited_pcs (O(1) fork)
    - Shared path_constraints list (Z3 exprs are immutable pointers)

    Attributes:
        stack: Operand stack holding symbolic values.
        local_vars: Local variable storage (CowDict, dict-compatible).
        global_vars: Global variable storage (CowDict, dict-compatible).
        path_constraints: Z3 constraints that must hold on this path.
        pc: Program counter (instruction index).
        block_stack: Stack of control flow blocks.
        call_stack: Stack of function call frames.
        visited_pcs: Set of PCs visited on this path (CowSet).
        memory: Heap memory model for objects (CowDict).
        path_id: Unique identifier for this execution path.
        depth: Execution depth for loop/recursion limiting.
        taint_tracker: Optional taint tracker for security analysis.
        pending_constraint_count: Steps since last feasibility check (lazy eval).
    """

    __slots__ = (
        "stack",
        "local_vars",
        "global_vars",
        "path_constraints",
        "pc",
        "block_stack",
        "call_stack",
        "visited_pcs",
        "memory",
        "path_id",
        "depth",
        "taint_tracker",
        "current_instructions",
        "control_taint",
        "pending_constraint_count",
        "pending_kw_names",
        "_pending_taint_issues",
        "_building_class",
        "_class_registry",
    )

    def __init__(
        self,
        stack: list[Any] | None = None,
        local_vars: dict[str, Any] | CowDict | None = None,
        global_vars: dict[str, Any] | CowDict | None = None,
        path_constraints: list[z3.BoolRef] | None = None,
        pc: int = 0,
        block_stack: list[BlockInfo] | None = None,
        call_stack: list[CallFrame] | None = None,
        visited_pcs: set[int] | CowSet | None = None,
        memory: dict[int, Any] | CowDict | None = None,
        path_id: int = 0,
        depth: int = 0,
        taint_tracker: Any | None = None,
        current_instructions: list[Any] | None = None,
        control_taint: frozenset[Any] | None = None,
        pending_constraint_count: int = 0,
        _path_counter: int = 0,
    ) -> None:
        self.stack = stack if stack is not None else []

        self.local_vars = _wrap_cow_dict(local_vars)

        self.global_vars = _wrap_cow_dict(global_vars)

        self.path_constraints = path_constraints if path_constraints is not None else []

        self.pc = pc

        self.block_stack = block_stack if block_stack is not None else []

        self.call_stack = call_stack if call_stack is not None else []

        self.visited_pcs = _wrap_cow_set(visited_pcs)

        self.memory = _wrap_cow_dict(memory)

        self.path_id = path_id

        self.depth = depth

        self.taint_tracker = taint_tracker

        self.current_instructions = current_instructions

        self.control_taint = control_taint if control_taint is not None else _EMPTY_TAINT

        self.pending_constraint_count = pending_constraint_count

        self.pending_kw_names: tuple[str, ...] | None = None

        self._pending_taint_issues: list[Any] = []

        self._building_class: bool = False

        self._class_registry: dict[str, Any] | EnhancedClassRegistry = {}

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
            path_constraints=list(self.path_constraints),
            pc=self.pc,
            block_stack=list(self.block_stack),
            call_stack=[
                CallFrame(
                    function_name=f.function_name,
                    return_pc=f.return_pc,
                    local_vars=(
                        f.local_vars.cow_fork()
                        if isinstance(f.local_vars, CowDict)
                        else dict(f.local_vars)
                    ),
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
            taint_tracker=(self.taint_tracker.fork() if self.taint_tracker is not None else None),
            current_instructions=self.current_instructions,
            control_taint=self.control_taint,
            pending_constraint_count=0,
        )

        child._pending_taint_issues = list(self._pending_taint_issues)

        child._building_class = self._building_class

        child._class_registry = (
            dict(self._class_registry)
            if isinstance(self._class_registry, dict)
            else self._class_registry
        )

        child.pending_kw_names = self.pending_kw_names

        return child

    @property
    def locals(self) -> CowDict:
        """Alias for local_vars (used by some callers)."""

        return self.local_vars

    def copy(self) -> VMState:
        """Create a copy of this state (alias for fork)."""

        return self.fork()

    def add_constraint(self, constraint: z3.BoolRef) -> None:
        """Add a path constraint."""

        self.path_constraints.append(constraint)

        self.pending_constraint_count += 1

    def push(self, value: Any) -> None:
        """Push a value onto the operand stack."""

        self.stack.append(value)

    def pop(self) -> Any:
        """Pop a value from the operand stack."""

        if not self.stack:
            raise RuntimeError("Stack underflow")

        return self.stack.pop()

    def peek(self, n: int = 0) -> Any:
        """Peek at the n-th value from the top of the stack."""

        if len(self.stack) <= n:
            raise RuntimeError(f"Stack underflow: cannot peek at position {n}")

        return self.stack[-(n + 1)]

    def get_local(self, name: str) -> Any | None:
        """Get a local variable, or None if not found."""

        return self.local_vars.get(name)

    def set_local(self, name: str, value: Any) -> None:
        """Set a local variable."""

        self.local_vars[name] = value

    def get_global(self, name: str) -> Any | None:
        """Get a global variable, or None if not found."""

        return self.global_vars.get(name)

    def set_global(self, name: str, value: Any) -> None:
        """Set a global variable."""

        self.global_vars[name] = value

    def constraint_hash(self) -> int:
        """Compute a hash of the current path constraints for loop detection."""

        from pysymex.core.constraint_hash import structural_hash

        return structural_hash(self.path_constraints)

    def mark_visited(self) -> bool:
        """Mark the current PC as visited.

        Returns:
            True if this PC was already visited on this path (loop detected).
        """

        if self.pc in self.visited_pcs:
            return True

        self.visited_pcs.add(self.pc)

        return False

    def enter_block(self, block: BlockInfo) -> None:
        """Enter a control flow block."""

        self.block_stack.append(block)

    def exit_block(self) -> BlockInfo | None:
        """Exit the current control flow block."""

        if self.block_stack:
            return self.block_stack.pop()

        return None

    def current_block(self) -> BlockInfo | None:
        """Get the current control flow block."""

        return self.block_stack[-1] if self.block_stack else None

    def push_call(self, frame: CallFrame) -> None:
        """Push a call frame for function entry."""

        self.call_stack.append(frame)

    def pop_call(self) -> CallFrame | None:
        """Pop a call frame for function return."""

        if self.call_stack:
            return self.call_stack.pop()

        return None

    def call_depth(self) -> int:
        """Get the current call stack depth."""

        return len(self.call_stack)

    def copy_constraints(self) -> list[z3.BoolRef]:
        """Get a copy of the current path constraints."""

        return list(self.path_constraints)

    def __repr__(self) -> str:
        return (
            f"VMState(path={self.path_id}, pc={self.pc}, "
            f"stack_depth={len(self.stack)}, "
            f"constraints={len(self.path_constraints)})"
        )


def create_initial_state(
    local_vars: dict[str, Any] | None = None,
    global_vars: dict[str, Any] | None = None,
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
