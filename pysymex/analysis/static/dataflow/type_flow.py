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

"""Flow-sensitive type data-flow analysis."""

from __future__ import annotations

import dis

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.bytecode import (
    BINARY_OPCODE_OPERATORS,
    DELETE_OPS,
    LOAD_OPS,
    STORE_OPS,
    UNARY_OPCODE_OPERATORS,
    binary_operator_for_instruction,
    compare_operator_for_instruction,
    instruction_int_arg,
    unary_operator_for_instruction,
)
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis
from pysymex.analysis.static.types import PyType, TypeAnalyzer, TypeEnvironment


class TypeFlowAnalysis(DataFlowAnalysis[TypeEnvironment]):
    """Flow-sensitive type analysis."""

    def __init__(
        self,
        cfg: ControlFlowGraph,
        type_analyzer: TypeAnalyzer,
        initial_env: TypeEnvironment | None = None,
    ) -> None:
        """Initialize the TypeFlowAnalysis with a ControlFlowGraph and a TypeAnalyzer.

        Args:
            cfg: The control flow graph to perform type analysis on.
            type_analyzer: The analyzer helper used to infer types.
            initial_env: Optional starting type environment at the CFG boundary.
        """
        super().__init__(cfg)
        self.type_analyzer = type_analyzer
        self.initial_env = initial_env or TypeEnvironment()

    def initial_value(self) -> TypeEnvironment:
        """Return the initial value for type analysis (empty environment).

        Returns:
            An empty TypeEnvironment.
        """
        return TypeEnvironment()

    def boundary_value(self) -> TypeEnvironment:
        """Return the boundary value at the start/entry of the CFG.

        Returns:
            A copy of the initial type environment.
        """
        return self.initial_env.copy()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: TypeEnvironment,
    ) -> TypeEnvironment:
        """Transfer function: update types through the block."""
        env = in_fact.copy()
        stack: list[PyType] = []
        for instr in block.instructions:
            self._process_instruction(env, instr, stack)
        return env

    def _process_instruction(
        self,
        env: TypeEnvironment,
        instr: dis.Instruction,
        stack: list[PyType],
    ) -> None:
        """Process a single instruction for type flow."""
        op = instr.opname

        def push(t: PyType) -> None:
            stack.append(t)

        def pop() -> PyType:
            return stack.pop() if stack else PyType.unknown()

        if op == "LOAD_CONST":
            push(self._type_from_const(instr.argval))
        elif op in LOAD_OPS:
            push(env.get_type(str(instr.argval)))
        elif op == "LOAD_FAST_LOAD_FAST":
            arg1, arg2 = instr.argval
            push(env.get_type(str(arg1)))
            push(env.get_type(str(arg2)))
        elif op in STORE_OPS:
            env.set_type(str(instr.argval), pop())
        elif op in DELETE_OPS:
            env.delete_type(str(instr.argval))
        elif op == "DUP_TOP":
            val = pop()
            push(val)
            push(val)
        elif op == "DUP_TOP_TWO":
            val1 = pop()
            val2 = pop()
            push(val2)
            push(val1)
            push(val2)
            push(val1)
        elif op == "ROT_TWO":
            val1 = pop()
            val2 = pop()
            push(val1)
            push(val2)
        elif op == "ROT_THREE":
            val1 = pop()
            val2 = pop()
            val3 = pop()
            push(val1)
            push(val3)
            push(val2)
        elif op == "SWAP":
            idx = int(instr.argval) if instr.argval else 1
            if len(stack) >= idx:
                stack[-1], stack[-idx] = stack[-idx], stack[-1]
        elif op == "COPY":
            idx = int(instr.argval) if instr.argval else 1
            push(stack[-idx] if len(stack) >= idx else PyType.unknown())
        elif op == "UNPACK_SEQUENCE":
            pop()
            count = int(instr.argval) if instr.argval is not None else 0
            for _ in range(count):
                push(PyType.unknown())
        elif op == "POP_TOP":
            pop()
        elif op == "BINARY_SUBSCR":
            index_type = pop()
            container_type = pop()
            push(self.type_analyzer.type_engine.infer_subscript_result(container_type, index_type))
        elif op == "BINARY_OP":
            right_type = pop()
            left_type = pop()
            operator = binary_operator_for_instruction(instr)
            push(
                self.type_analyzer.type_engine.infer_binary_op_result(
                    operator, left_type, right_type
                )
            )
        elif op == "COMPARE_OP":
            right_type = pop()
            left_type = pop()
            operator = compare_operator_for_instruction(instr)
            push(
                self.type_analyzer.type_engine.infer_binary_op_result(
                    operator, left_type, right_type
                )
            )
        elif op in BINARY_OPCODE_OPERATORS:
            right_type = pop()
            left_type = pop()
            operator = binary_operator_for_instruction(instr)
            push(
                self.type_analyzer.type_engine.infer_binary_op_result(
                    operator, left_type, right_type
                )
            )
        elif op in UNARY_OPCODE_OPERATORS:
            operand_type = pop()
            push(
                self.type_analyzer.type_engine.infer_unary_op_result(
                    unary_operator_for_instruction(instr), operand_type
                )
            )
        elif op.startswith("BUILD_"):
            self._process_build_instruction(op, instr.argval, stack)
        elif op.startswith("CALL"):
            stack.clear()
            push(PyType.unknown())
        else:
            stack.clear()

    @staticmethod
    def _process_build_instruction(op: str, argval: object, stack: list[PyType]) -> None:
        """Process build collection opcodes to update the simulated type stack.

        Args:
            op: The collection building opcode.
            argval: The instruction argument indicating elements to build.
            stack: The simulated type stack of variable/expression types.
        """
        count = instruction_int_arg(argval) if argval is not None else 0
        if op == "BUILD_MAP":
            count *= 2
        elif op == "BUILD_CONST_KEY_MAP":
            count += 1
        for _ in range(count):
            stack.pop() if stack else PyType.unknown()
        if op == "BUILD_TUPLE":
            stack.append(PyType.tuple_type())
        else:
            stack.append(PyType.unknown())

    @staticmethod
    def _type_from_const(value: object) -> PyType:
        """Infer PyType from a constant value."""
        if value is None:
            return PyType.none_type()
        if isinstance(value, bool):
            return PyType.bool_type()
        if isinstance(value, int):
            return PyType.int_type()
        if isinstance(value, float):
            return PyType.float_type()
        if isinstance(value, str):
            return PyType.str_type()
        if isinstance(value, tuple):
            return PyType.tuple_type()
        return PyType.unknown()

    def meet(self, facts: list[TypeEnvironment]) -> TypeEnvironment:
        """Join environments at merge points."""
        if not facts:
            return TypeEnvironment()
        result = facts[0]
        for env in facts[1:]:
            result = result.join(env)
        return result

    def get_type_at(self, pc: int, var_name: str) -> PyType:
        """Get type of a variable at a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return PyType.unknown()
        env = self.get_in(block.id).copy()
        stack: list[PyType] = []
        for instr in block.instructions:
            if instr.offset >= pc:
                break
            self._process_instruction(env, instr, stack)
        return env.get_type(var_name)


__all__ = ["TypeFlowAnalysis"]
