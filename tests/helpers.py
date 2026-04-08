"""Shared test helpers for pysymex test suite.

Provides factory functions for VMState, dis.Instruction, symbolic values,
and Z3 SAT/validity helpers.
"""

from __future__ import annotations

import dis
import inspect
from typing import Any

import z3

from pysymex.core.copy_on_write import CowDict
from pysymex.core.state import VMState, create_initial_state
from pysymex.core.solver import is_satisfiable as _solver_is_satisfiable
from pysymex.core.types import SymbolicValue, SymbolicString, Z3_TRUE, Z3_FALSE, Z3_ZERO
from pysymex.execution.dispatcher import OpcodeDispatcher, OpcodeResult

# Patch VMState with is_satisfiable if missing (some handlers call state.is_satisfiable())
if not hasattr(VMState, "is_satisfiable"):
    def _state_is_satisfiable(self, extra_constraint=None):
        constraints = list(self.path_constraints)
        if extra_constraint is not None:
            constraints.append(extra_constraint)
        return _solver_is_satisfiable(constraints)
    VMState.is_satisfiable = _state_is_satisfiable

# Ensure all opcode handlers are registered
import pysymex.execution.opcodes.arithmetic  # noqa: F401
import pysymex.execution.opcodes.compare  # noqa: F401
import pysymex.execution.opcodes.locals  # noqa: F401
import pysymex.execution.opcodes.stack  # noqa: F401
import pysymex.execution.opcodes.async_ops  # noqa: F401
import pysymex.execution.opcodes.collections  # noqa: F401
import pysymex.execution.opcodes.control  # noqa: F401
import pysymex.execution.opcodes.exceptions  # noqa: F401
import pysymex.execution.opcodes.functions  # noqa: F401


def make_instruction(
    opname: str,
    argval: Any = 0,
    arg: int = 0,
    argrepr: str = "",
    offset: int = 0,
) -> dis.Instruction:
    """Build a dis.Instruction namedtuple with sensible defaults."""
    params = set(inspect.signature(dis.Instruction).parameters)
    kwargs: dict[str, Any] = {
        "opname": opname,
        "opcode": dis.opmap.get(opname, 0),
        "arg": arg,
        "argval": argval,
        "argrepr": argrepr or str(argval),
        "offset": offset,
    }
    if "start_offset" in params:
        kwargs["start_offset"] = offset
    if "starts_line" in params:
        kwargs["starts_line"] = True if "line_number" in params else 1
    if "line_number" in params:
        kwargs["line_number"] = 1
    if "is_jump_target" in params:
        kwargs["is_jump_target"] = False
    if "label" in params:
        kwargs["label"] = None
    if "baseopname" in params:
        kwargs["baseopname"] = opname
    if "baseopcode" in params:
        kwargs["baseopcode"] = dis.opmap.get(opname, 0)
    if "positions" in params:
        kwargs["positions"] = None
    if "cache_info" in params:
        kwargs["cache_info"] = None
    return dis.Instruction(**kwargs)


def make_state(
    stack: list | None = None,
    locals_: dict[str, Any] | None = None,
    globals_: dict[str, Any] | None = None,
    constraints: list[z3.BoolRef] | None = None,
    pc: int = 0,
    n_instrs: int = 20,
) -> VMState:
    """Build a VMState with defaults suitable for opcode handler tests.

    Populates current_instructions with dummy NOP instructions so advance_pc()
    works without crashing.
    """
    state = VMState(
        stack=stack or [],
        local_vars=locals_,
        global_vars=globals_,
        path_constraints=constraints,
        pc=pc,
    )
    # Provide enough dummy instructions for advance_pc()
    nop = make_instruction("NOP")
    state.current_instructions = [nop] * n_instrs
    return state


def make_dispatcher() -> OpcodeDispatcher:
    """Return an OpcodeDispatcher with all global handlers registered."""
    return OpcodeDispatcher()


def make_symbolic_int(name: str = "x") -> SymbolicValue:
    """Create a fresh symbolic integer."""
    sv, _ = SymbolicValue.symbolic_int(name)
    return sv


def make_symbolic_bool(name: str = "b") -> SymbolicValue:
    """Create a fresh symbolic boolean."""
    sv, _ = SymbolicValue.symbolic_bool(name)
    return sv


def make_symbolic_str(name: str = "s") -> SymbolicString:
    """Create a fresh symbolic string."""
    ss, _ = SymbolicString.symbolic(name)
    return ss


def make_symbolic(name: str = "v") -> SymbolicValue:
    """Create a fully polymorphic symbolic value."""
    sv, _ = SymbolicValue.symbolic(name)
    return sv


def from_const(value: object) -> SymbolicValue:
    """Shorthand for SymbolicValue.from_const()."""
    return SymbolicValue.from_const(value)


def solve(constraint: z3.BoolRef) -> bool:
    """Check if a Z3 constraint is satisfiable."""
    s = z3.Solver()
    s.add(constraint)
    return s.check() == z3.sat


def prove(constraint: z3.BoolRef) -> bool:
    """Check if a Z3 constraint is a tautology (negation is UNSAT)."""
    s = z3.Solver()
    s.add(z3.Not(constraint))
    return s.check() == z3.unsat


def solve_get(constraint: z3.BoolRef, *vars: z3.ExprRef) -> dict | None:
    """Solve a constraint and return a model dict, or None if UNSAT."""
    s = z3.Solver()
    s.add(constraint)
    if s.check() == z3.sat:
        m = s.model()
        return {v: m.evaluate(v) for v in vars}
    return None


def dispatch(opname: str, state: VMState, argval: Any = 0, arg: int = 0,
             argrepr: str = "", offset: int = 0,
             ctx: OpcodeDispatcher | None = None) -> OpcodeResult:
    """Dispatch a single opcode on a state and return the result."""
    instr = make_instruction(opname, argval=argval, arg=arg, argrepr=argrepr,
                             offset=offset)
    if ctx is None:
        ctx = make_dispatcher()
    return ctx.dispatch(instr, state)
