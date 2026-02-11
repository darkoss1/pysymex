"""VM State management for PySpectre.
This module defines the execution state of the symbolic virtual machine,
including the operand stack, local/global variables, path constraints,
and state forking for branch exploration.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import z3


@dataclass
class BlockInfo:
    """Information about a control flow block (loop, try/except, etc.)."""

    block_type: str
    start_pc: int
    end_pc: int
    handler_pc: int | None = None


@dataclass
class CallFrame:
    """Represents a function call frame for inter-procedural analysis."""

    function_name: str
    return_pc: int
    local_vars: dict[str, Any]
    stack_depth: int
    caller_instructions: list[Any] | None = None


@dataclass
class VMState:
    """Virtual Machine execution state for symbolic execution.
    This class represents a single execution state in the symbolic VM.
    States can be forked at branch points to explore different paths.
    Attributes:
        stack: Operand stack holding symbolic values.
        local_vars: Local variable storage.
        global_vars: Global variable storage.
        path_constraints: Z3 constraints that must hold on this path.
        pc: Program counter (instruction index).
        block_stack: Stack of control flow blocks.
        call_stack: Stack of function call frames.
        visited_pcs: Set of PCs visited on this path.
        memory: Heap memory model for objects.
        path_id: Unique identifier for this execution path.
        depth: Execution depth for loop/recursion limiting.
        taint_tracker: Optional taint tracker for security analysis.
    """

    stack: list[Any] = field(default_factory=list)
    local_vars: dict[str, Any] = field(default_factory=dict)
    global_vars: dict[str, Any] = field(default_factory=dict)
    path_constraints: list[z3.BoolRef] = field(default_factory=list)
    pc: int = 0
    block_stack: list[BlockInfo] = field(default_factory=list)
    call_stack: list[CallFrame] = field(default_factory=list)
    visited_pcs: set[int] = field(default_factory=set)
    memory: dict[int, Any] = field(default_factory=dict)
    path_id: int = 0
    depth: int = 0
    _path_counter: int = field(default=0, repr=False)
    taint_tracker: Any | None = None
    current_instructions: list[Any] | None = None
    control_taint: frozenset[Any] = field(default_factory=frozenset)

    def fork(self) -> VMState:
        """Create a deep copy of this state for branching.
        Returns:
            A new VMState with copied stack, variables, and constraints.
            Z3 expressions are immutable, so shallow copy is sufficient.
        """
        VMState._path_counter += 1
        return VMState(
            stack=list(self.stack),
            local_vars=dict(self.local_vars),
            global_vars=dict(self.global_vars),
            path_constraints=list(self.path_constraints),
            pc=self.pc,
            block_stack=list(self.block_stack),
            call_stack=[
                CallFrame(
                    function_name=f.function_name,
                    return_pc=f.return_pc,
                    local_vars=dict(f.local_vars),
                    stack_depth=f.stack_depth,
                    caller_instructions=f.caller_instructions,
                )
                for f in self.call_stack
            ],
            visited_pcs=set(self.visited_pcs),
            memory={addr: dict(attrs) for addr, attrs in self.memory.items()},
            path_id=VMState._path_counter,
            depth=self.depth,
            taint_tracker=self.taint_tracker,
            current_instructions=self.current_instructions,
            control_taint=self.control_taint,
        )

    def add_constraint(self, constraint: z3.BoolRef) -> None:
        """Add a path constraint."""
        self.path_constraints.append(constraint)

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
        return hash(tuple(str(c) for c in self.path_constraints))

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
