# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Abstract Interpretation Framework for pysymex.
This module provides a more sophisticated abstract interpretation engine
that goes beyond simple symbolic execution. It uses abstract domains to
soundly approximate program behavior while maintaining precision.
Features:
- Multiple abstract domains (intervals, signs, octagon, polyhedra)
- Widening/narrowing for loop analysis
- Reduced product domains
- Trace partitioning
- Context-sensitive analysis
"""

from __future__ import annotations

import logging
from types import CodeType

logger = logging.getLogger(__name__)

import dis
from collections import defaultdict

from pysymex._compat import get_starts_line
from pysymex.analysis.abstract.interpreter_state import (
    AbstractState,
    AbstractWarning,
    DivisionByZeroWarning,
    IndexOutOfBoundsWarning,
    NumericProduct,
)
from pysymex.analysis.abstract.interpreter_values import (
    AbstractValue,
    Congruence,
    Interval,
    Sign,
    SignValue,
)
from pysymex.analysis.flow_sensitive import BasicBlock, CFGBuilder, ControlFlowGraph
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

__all__ = [
    "AbstractAnalyzer",
    "AbstractInterpreter",
    "AbstractState",
    "AbstractValue",
    "AbstractWarning",
    "Congruence",
    "DivisionByZeroWarning",
    "IndexOutOfBoundsWarning",
    "Interval",
    "NumericProduct",
    "Sign",
    "SignValue",
]


class AbstractInterpreter:
    """
    Abstract interpreter for Python bytecode.

    **Theoretical Foundation:**
    Implements classic abstract interpretation over multiple domains (Interval,
    Sign, Congruence). It soundly approximates program behavior by evaluating
    bytecode effects on an abstract lattice where each point represents a
    set of possible concrete states.

    **Convergence Mechanics:**
    - uses a worklist-driven fixed-point iteration.
    - employs **Widening** at loop headers to ensure termination on infinite
      integer domains.
    - performs **Joining** (Least Upper Bound) at control-flow merge points.
    """

    _TRIVIAL_MAX_INSTRUCTIONS = 15

    _JUMP_OPCODES = frozenset(
        {
            "JUMP_FORWARD",
            "JUMP_BACKWARD",
            "JUMP_ABSOLUTE",
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_FORWARD_IF_TRUE",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_IF_NONE",
            "POP_JUMP_IF_NOT_NONE",
            "POP_JUMP_FORWARD_IF_NONE",
            "POP_JUMP_FORWARD_IF_NOT_NONE",
            "FOR_ITER",
            "SEND",
        }
    )

    def __init__(self) -> None:
        self.warnings: list[object] = []
        self._used_fast_path: bool = False

    @staticmethod
    def _is_trivial(code: CodeType) -> bool:
        """Check if a function is trivial (small + no branches)."""
        instructions = _cached_get_instructions(code)
        if len(instructions) > AbstractInterpreter._TRIVIAL_MAX_INSTRUCTIONS:
            return False
        for instr in instructions:
            if instr.opname in AbstractInterpreter._JUMP_OPCODES:
                return False
        return True

    def _analyze_trivial(
        self,
        code: CodeType,
        file_path: str,
    ) -> list[object]:
        """Fast-path analysis for trivial functions.

        Does a single linear pass — no CFG, no worklist, no widening.
        Only detects obvious issues like division by literal zero.
        """
        warnings: list[object] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        prev_const: object = None

        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno

            opname = instr.opname
            if opname == "LOAD_CONST":
                prev_const = instr.argval
            elif opname in (
                "BINARY_TRUE_DIVIDE",
                "BINARY_FLOOR_DIVIDE",
                "BINARY_MODULO",
                "BINARY_OP",
            ):
                is_div = True
                if opname == "BINARY_OP":
                    if instr.argrepr and not any(op in instr.argrepr for op in ("/", "//", "%")):
                        is_div = False

                if is_div and prev_const == 0:
                    warnings.append(
                        AbstractWarning(
                            kind="DIVISION_BY_ZERO",
                            message="Division by literal zero",
                            file=file_path,
                            line=current_line,
                            pc=instr.offset,
                        )
                    )
                prev_const = None
            else:
                prev_const = None

        return warnings

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[object]:
        """Analyze bytecode and return warnings."""
        self.warnings = []
        self._used_fast_path = False

        if self._is_trivial(code):
            self._used_fast_path = True
            return self._analyze_trivial(code, file_path)

        builder = CFGBuilder()
        cfg = builder.build(code)
        entry_state = AbstractState()
        for _i, arg in enumerate(code.co_varnames[: code.co_argcount]):
            entry_state.set(arg, NumericProduct.top())
        self._interpret_cfg(cfg, entry_state, code, file_path)
        return self.warnings

    def _interpret_cfg(
        self,
        cfg: ControlFlowGraph,
        entry_state: AbstractState,
        code: CodeType,
        file_path: str,
    ) -> dict[int, AbstractState]:
        """Interpret the CFG abstractly to reach a fixed-point.

        **Algorithm:**
        Iteratively propagates abstract states through the CFG until the
        least fixed-point is reached or the iteration limit is hit.

        Uses a widening operator after a small number of iterations per block
        to force convergence in domains with infinite ascending chains (like
        literal integer intervals).
        """
        states: dict[int, AbstractState] = {}
        if cfg.entry:
            states[cfg.entry.block_id] = entry_state
        worklist = [cfg.entry] if cfg.entry else []
        iteration_count: dict[int, int] = defaultdict(int)
        global_iterations = 0
        max_global_iterations = len(list(cfg.blocks)) * 10 + 100
        while worklist and global_iterations < max_global_iterations:
            global_iterations += 1
            block = worklist.pop(0)
            if not block:
                continue
            in_state = states.get(block.block_id, AbstractState.bottom())
            if in_state.is_bottom():
                continue
            out_state = self._transfer_block(block, in_state, code, file_path)
            for succ_id in block.successors:
                old_state = states.get(succ_id, AbstractState.bottom())
                succ_block = cfg.blocks.get(succ_id)

                is_backedge = succ_block is not None and block.start_pc >= succ_block.start_pc
                if is_backedge:
                    iteration_count[succ_id] += 1

                if iteration_count[succ_id] > 3:
                    new_state = old_state.widen(out_state)
                else:
                    new_state = old_state.join(out_state)

                if not new_state.leq(old_state):
                    states[succ_id] = new_state
                    if succ_block is not None and succ_block not in worklist:
                        worklist.append(succ_block)
        if worklist and global_iterations >= max_global_iterations:
            logger.warning(
                "Abstract interpreter hit iteration limit (%d) — analysis may be unsound",
                max_global_iterations,
            )
        return states

    def _transfer_block(
        self,
        block: BasicBlock,
        in_state: AbstractState,
        code: CodeType,
        file_path: str,
    ) -> AbstractState:
        """Transfer function for a basic block."""
        state = in_state.copy()
        current_line = block.start_pc
        for instr in block.instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            self._transfer_instruction(instr, state, current_line, code, file_path)
        return state

    def _transfer_instruction(
        self,
        instr: dis.Instruction,
        state: AbstractState,
        line: int,
        code: CodeType,
        file_path: str,
    ) -> None:
        """Transfer function for a single instruction.

        **Semantics Modeling:**
        Maps a concrete bytecode instruction to its abstract effect on the
        `AbstractState` (stack and environment).
        - **Numerical Ops**: Evaluated via interval/sign arithmetic.
        - **Flow Tracking**: Tracks type-tags and simple constant propagation.
        - **Approximation**: Opcodes with complex heap effects (e.g. `CALL`)
          result in a transition to `Top` (unknown state) to maintain soundness.
        """
        opname = instr.opname
        arg = instr.argval
        if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
            state.push(state.get(arg))
        elif opname == "LOAD_CONST":
            if isinstance(arg, (int, float)):
                state.push(NumericProduct.const(int(arg)))
            else:
                state.push(NumericProduct.top())
        elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            if state.stack:
                state.set(arg, state.pop())
        elif opname == "BINARY_OP":
            if len(state.stack) >= 2:
                right = state.pop()
                left = state.pop()
                op_name = instr.argrepr or ""
                if "**" in op_name:
                    state.push(NumericProduct.top())
                elif "+" in op_name:
                    state.push(left.add(right))
                elif "-" in op_name:
                    state.push(left.sub(right))
                elif "*" in op_name:
                    state.push(left.mul(right))
                elif "//" in op_name or "/" in op_name:
                    result, may_raise = left.div(right)
                    if may_raise:
                        confidence = "possible"
                        if right.must_be_non_zero():
                            confidence = "unlikely"
                        elif right.interval.is_const() and right.interval.get_const() == 0:
                            confidence = "definite"
                        if confidence != "unlikely":
                            self.warnings.append(
                                DivisionByZeroWarning(
                                    line=line,
                                    pc=instr.offset,
                                    variable="division",
                                    divisor=right,
                                    confidence=confidence,
                                )
                            )
                    state.push(result)
                elif "%" in op_name:
                    result, may_raise = left.mod(right)
                    if may_raise and not right.must_be_non_zero():
                        self.warnings.append(
                            DivisionByZeroWarning(
                                line=line,
                                pc=instr.offset,
                                variable="modulo",
                                divisor=right,
                                confidence="possible",
                            )
                        )
                    state.push(result)
                else:
                    state.push(NumericProduct.top())
        elif opname == "UNARY_NEGATIVE":
            if state.stack:
                val = state.pop()
                state.push(
                    NumericProduct(
                        val.interval.neg(),
                        val.sign.neg(),
                        Congruence.top(),
                    )
                )
        elif opname == "COMPARE_OP" or opname == "BINARY_SUBSCR":
            if len(state.stack) >= 2:
                state.pop()
                state.pop()
                state.push(NumericProduct.top())
        elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
            count = arg or 0
            for _ in range(count):
                if state.stack:
                    state.pop()
            state.push(NumericProduct.const(count))
        elif opname == "BUILD_MAP":
            count = arg or 0
            for _ in range(count * 2):
                if state.stack:
                    state.pop()
            state.push(NumericProduct.top())
        elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            arg_count = arg if arg is not None else 0
            for _ in range(arg_count):
                if state.stack:
                    state.pop()
            if state.stack:
                state.pop()
            state.push(NumericProduct.top())
        elif opname == "POP_TOP":
            if state.stack:
                state.pop()
        elif opname == "DUP_TOP":
            if state.stack:
                state.push(state.peek())
        elif opname == "ROT_TWO":
            if len(state.stack) >= 2:
                a = state.pop()
                b = state.pop()
                state.push(a)
                state.push(b)
        elif opname == "RETURN_VALUE":
            if state.stack:
                state.pop()
        elif opname == "LOAD_ATTR":
            if state.stack:
                state.pop()
            state.push(NumericProduct.top())
        elif opname == "STORE_ATTR":
            if len(state.stack) >= 2:
                state.pop()
                state.pop()
        else:
            try:
                effect = dis.stack_effect(instr.opcode, instr.arg or 0)
                if effect < 0:
                    for _ in range(-effect):
                        if state.stack:
                            state.pop()
                elif effect > 0:
                    for _ in range(effect):
                        state.push(NumericProduct.top())
            except (ValueError, TypeError):
                pass


class AbstractAnalyzer:
    """
    High-level interface for abstract interpretation analysis.
    """

    def __init__(self) -> None:
        self.interpreter = AbstractInterpreter()

    def analyze_function(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[object]:
        """Analyze a function for potential issues."""
        return self.interpreter.analyze(code, file_path)

    def analyze_module(
        self,
        module_code: CodeType,
        file_path: str = "<unknown>",
    ) -> dict[str, list[object]]:
        """Analyze all functions in a module."""
        results: dict[str, list[object]] = {}
        results["<module>"] = self.analyze_function(module_code, file_path)
        for const in module_code.co_consts:
            if isinstance(const, CodeType):
                func_name = const.co_name
                results[func_name] = self.analyze_function(const, file_path)
        return results
