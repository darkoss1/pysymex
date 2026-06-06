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

"""Bytecode stack simulation for available-expression analysis."""

from __future__ import annotations

import dis
from collections.abc import Iterable

from pysymex.analysis.static.dataflow.bytecode import (
    BINARY_OPCODE_OPERATORS,
    DELETE_OPS,
    LOAD_OPS,
    STORE_OPS,
    UNARY_OPCODE_OPERATORS,
    binary_operator_for_instruction,
    instruction_int_arg,
    unary_operator_for_instruction,
)
from pysymex.analysis.static.dataflow.types import Expression


class _ExpressionStack:
    """Internal simulated bytecode operand stack for tracked expressions."""

    def __init__(self) -> None:
        """Initialize an empty _ExpressionStack instance."""
        self.values: list[str] = []

    def push(self, value: str) -> None:
        """Push an operand expression string to the stack.

        Args:
            value: The operand representation as a string.
        """
        self.values.append(value)

    def pop(self) -> str:
        """Pop an operand expression string from the stack.

        Returns:
            The popped operand string, or "unknown" if stack was empty.
        """
        return self.values.pop() if self.values else "unknown"

    def clear_unknown(self) -> None:
        """Clear the stack and push a single "unknown" marker."""
        self.values.clear()
        self.push("unknown")

    def copy(self, index: int) -> None:
        """Copy the stack element at the specified 1-based index from the top and push it.

        Args:
            index: The 1-based index from the top of the stack.
        """
        if len(self.values) >= index:
            self.push(self.values[-index])
        else:
            self.push("unknown")

    def swap(self, index: int) -> None:
        """Swap the top element of the stack with the element at the specified 1-based index.

        Args:
            index: The 1-based index from the top of the stack.
        """
        if len(self.values) >= index:
            self.values[-1], self.values[-index] = self.values[-index], self.values[-1]


def collect_expressions_from_instructions(
    instructions: Iterable[dis.Instruction],
) -> set[Expression]:
    """Collect candidate expressions produced by a block."""
    expressions: set[Expression] = set()
    _simulate_expressions(instructions, expressions, collect_only=True)
    return expressions


def transfer_expressions_for_instructions(
    instructions: Iterable[dis.Instruction],
    in_fact: frozenset[Expression],
) -> frozenset[Expression]:
    """Apply available-expression transfer over a block."""
    result = set(in_fact)
    _simulate_expressions(instructions, result, collect_only=False)
    return frozenset(result)


def _simulate_expressions(
    instructions: Iterable[dis.Instruction],
    expressions: set[Expression],
    *,
    collect_only: bool,
) -> None:
    """Simulate a sequence of instructions to collect or kill available expressions.

    Args:
        instructions: Iterable of disassembly instructions to simulate.
        expressions: The set of expressions to update (add to or delete from).
        collect_only: If True, only collect new expressions and do not kill existing ones
            upon variable stores or deletes.
    """
    stack = _ExpressionStack()
    for instr in instructions:
        op = instr.opname
        if op in LOAD_OPS:
            stack.push(str(instr.argval))
        elif op == "LOAD_FAST_LOAD_FAST":
            arg1, arg2 = instr.argval
            stack.push(str(arg1))
            stack.push(str(arg2))
        elif op == "LOAD_CONST":
            stack.push(f"const_{instr.argval}")
        elif op in STORE_OPS:
            if not collect_only:
                var_name = str(instr.argval)
                _kill_expressions_using(expressions, var_name)
            stack.pop()
        elif op in DELETE_OPS:
            if not collect_only:
                var_name = str(instr.argval)
                _kill_expressions_using(expressions, var_name)
        elif op in {"BINARY_OP", "BINARY_SUBSCR"} or op in BINARY_OPCODE_OPERATORS:
            _handle_binary_expression(instr, expressions, stack)
        elif op == "UNARY_OP" or op in UNARY_OPCODE_OPERATORS:
            _handle_unary_expression(instr, expressions, stack)
        elif op == "DUP_TOP":
            val = stack.pop()
            stack.push(val)
            stack.push(val)
        elif op == "DUP_TOP_TWO":
            val1 = stack.pop()
            val2 = stack.pop()
            stack.push(val2)
            stack.push(val1)
            stack.push(val2)
            stack.push(val1)
        elif op == "ROT_TWO":
            val1 = stack.pop()
            val2 = stack.pop()
            stack.push(val1)
            stack.push(val2)
        elif op == "ROT_THREE":
            val1 = stack.pop()
            val2 = stack.pop()
            val3 = stack.pop()
            stack.push(val1)
            stack.push(val3)
            stack.push(val2)
        elif op == "SWAP":
            stack.swap(int(instr.argval) if instr.argval else 1)
        elif op == "COPY":
            stack.copy(int(instr.argval) if instr.argval else 1)
        elif op == "UNPACK_SEQUENCE":
            stack.pop()
            count = int(instr.argval) if instr.argval is not None else 0
            for _ in range(count):
                stack.push("unknown")
        elif op == "POP_TOP":
            stack.pop()
        elif "COMPARE_OP" in op:
            stack.pop()
            stack.pop()
            stack.push("unknown")
        elif op.startswith("BUILD_"):
            _handle_build(op, instr.argval, stack)
        elif op.startswith("CALL"):
            stack.clear_unknown()
        else:
            stack.values.clear()


def _kill_expressions_using(expressions: set[Expression], var_name: str) -> None:
    """Remove any expressions from the set that use the specified variable name.

    Args:
        expressions: The set of tracked expressions.
        var_name: The variable name whose redefinition kills using expressions.
    """
    expressions.difference_update({expr for expr in expressions if var_name in expr.operands})


def _handle_binary_expression(
    instr: dis.Instruction,
    expressions: set[Expression],
    stack: _ExpressionStack,
) -> None:
    """Handle binary operator simulation on the expression stack.

    Pops the right and left operands from the stack. If both operands are known,
    registers the binary expression and pushes the combined expression.
    Otherwise, pushes "unknown".

    Args:
        instr: The binary operation bytecode instruction.
        expressions: The set of tracked expressions.
        stack: The simulated expression stack.
    """
    right = stack.pop()
    left = stack.pop()
    operator = "[]" if instr.opname == "BINARY_SUBSCR" else binary_operator_for_instruction(instr)
    if left != "unknown" and right != "unknown":
        expressions.add(Expression(operator=operator, operands=(left, right)))
        stack.push(f"({left}{operator}{right})")
    else:
        stack.push("unknown")


def _handle_unary_expression(
    instr: dis.Instruction,
    expressions: set[Expression],
    stack: _ExpressionStack,
) -> None:
    """Handle unary operator simulation on the expression stack.

    Pops the operand from the stack. If the operand is known, registers the
    unary expression and pushes the combined expression. Otherwise, pushes "unknown".

    Args:
        instr: The unary operation bytecode instruction.
        expressions: The set of tracked expressions.
        stack: The simulated expression stack.
    """
    operand = stack.pop()
    operator = unary_operator_for_instruction(instr)
    if operand != "unknown":
        expressions.add(Expression(operator=operator, operands=(operand,)))
        stack.push(f"({operator}{operand})")
    else:
        stack.push("unknown")


def _handle_build(op: str, argval: object, stack: _ExpressionStack) -> None:
    """Pop elements consumed by a collection builder opcode and push "unknown".

    Args:
        op: The opcode name (e.g. BUILD_LIST, BUILD_MAP).
        argval: The instruction argument indicating count of elements/keys.
        stack: The simulated expression stack.
    """
    count = instruction_int_arg(argval) if argval is not None else 0
    if op == "BUILD_MAP":
        count *= 2
    elif op == "BUILD_CONST_KEY_MAP":
        count += 1
    for _ in range(count):
        stack.pop()
    stack.push("unknown")


__all__ = ["collect_expressions_from_instructions", "transfer_expressions_for_instructions"]
