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

"""
Data Flow Analysis Core for pysymex.

Contains the analysis engine classes: DataFlowAnalysis base class
and all concrete analysis implementations.
"""

from __future__ import annotations

import collections
import dis
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import (
    Generic,
)


from pysymex._compat import get_starts_line

from ..control.cfg import BasicBlock, ControlFlowGraph
from ..type_inference import PyType, TypeAnalyzer, TypeEnvironment
from .types import (
    Definition,
    DefUseChain,
    Expression,
    NullInfo,
    NullState,
    T,
    Use,
)

_get_line_number = get_starts_line

__all__ = [
    "AvailableExpressions",
    "DataFlowAnalysis",
    "DefUseAnalysis",
    "LiveVariables",
    "NullAnalysis",
    "ReachingDefinitions",
    "TypeFlowAnalysis",
]


class DataFlowAnalysis(ABC, Generic[T]):
    """
    Abstract base class for data flow analyses.

    Provides framework for:
    - Forward/backward analysis
    - Must/may analysis
    - Fixed-point iteration
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        self.cfg = cfg
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    @abstractmethod
    def initial_value(self) -> T:
        """Return the initial value for analysis."""

    @abstractmethod
    def boundary_value(self) -> T:
        """Return the boundary value (entry/exit)."""

    @abstractmethod
    def transfer(self, block: BasicBlock, in_fact: T) -> T:
        """Transfer function: compute output from input."""

    @abstractmethod
    def meet(self, facts: list[T]) -> T:
        """Meet operation: combine facts from multiple paths."""

    def is_forward(self) -> bool:
        """Return True for forward analysis, False for backward."""
        return True

    def analyze(self) -> None:
        """Analyze the CFG using a worklist algorithm for better performance."""
        if not self.cfg.blocks:
            return

        for block_id in self.cfg.blocks:
            if self.is_forward():
                if block_id == self.cfg.entry_block_id:
                    self.in_facts[block_id] = self.boundary_value()
                else:
                    self.in_facts[block_id] = self.initial_value()
                self.out_facts[block_id] = self.initial_value()
            else:
                if block_id in self.cfg.exit_block_ids:
                    self.out_facts[block_id] = self.boundary_value()
                else:
                    self.out_facts[block_id] = self.initial_value()
                self.in_facts[block_id] = self.initial_value()

        worklist = collections.deque(
            self.cfg.iter_blocks_forward() if self.is_forward() else self.cfg.iter_blocks_reverse()
        )
        on_worklist = {block.id for block in worklist}

        while worklist:
            block = worklist.popleft()
            on_worklist.remove(block.id)

            if self.is_forward():
                if block.id != self.cfg.entry_block_id:
                    pred_outs = [
                        self.out_facts.get(p, self.initial_value()) for p in block.predecessors
                    ]
                    new_in = self.meet(pred_outs) if pred_outs else self.initial_value()
                    if new_in != self.in_facts.get(block.id):
                        self.in_facts[block.id] = new_in

                new_out = self.transfer(block, self.in_facts.get(block.id, self.initial_value()))
                if new_out != self.out_facts.get(block.id):
                    self.out_facts[block.id] = new_out

                    for succ_id in block.successors:
                        if succ_id not in on_worklist:
                            worklist.append(self.cfg.blocks[succ_id])
                            on_worklist.add(succ_id)
            else:
                if block.id not in self.cfg.exit_block_ids:
                    succ_ins = [
                        self.in_facts.get(s, self.initial_value()) for s in block.successors
                    ]
                    new_out = self.meet(succ_ins) if succ_ins else self.initial_value()
                    if new_out != self.out_facts.get(block.id):
                        self.out_facts[block.id] = new_out

                new_in = self.transfer(block, self.out_facts.get(block.id, self.initial_value()))
                if new_in != self.in_facts.get(block.id):
                    self.in_facts[block.id] = new_in

                    for pred_id in block.predecessors:
                        if pred_id not in on_worklist:
                            worklist.append(self.cfg.blocks[pred_id])
                            on_worklist.add(pred_id)

    def get_in(self, block_id: int) -> T:
        """Get input facts for a block."""
        return self.in_facts.get(block_id, self.initial_value())

    def get_out(self, block_id: int) -> T:
        """Get output facts for a block."""
        return self.out_facts.get(block_id, self.initial_value())


class ReachingDefinitions(DataFlowAnalysis[frozenset[Definition]]):
    """
    Reaching definitions analysis.

    For each program point, computes which definitions may reach that point.
    Used for:
    - Building def-use chains
    - Detecting undefined variables
    - Detecting dead stores
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.all_defs: set[Definition] = set()
        self.defs_by_var: dict[str, set[Definition]] = defaultdict(set)
        self._collect_definitions()

    def _collect_definitions(self) -> None:
        """Collect all definitions in the CFG."""
        for block in self.cfg.blocks.values():
            for instr in block.instructions:
                if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    var_name = instr.argval
                    defn = Definition(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=_get_line_number(instr),
                    )
                    self.all_defs.add(defn)
                    self.defs_by_var[var_name].add(defn)

    def initial_value(self) -> frozenset[Definition]:
        return frozenset()

    def boundary_value(self) -> frozenset[Definition]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Definition],
    ) -> frozenset[Definition]:
        """Transfer function: gen - kill."""
        result = set(in_fact)
        for instr in block.instructions:
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
                defn = Definition(
                    var_name=var_name,
                    block_id=block.id,
                    pc=instr.offset,
                    line=_get_line_number(instr),
                )
                result.add(defn)
            elif instr.opname in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
        return frozenset(result)

    def meet(self, facts: list[frozenset[Definition]]) -> frozenset[Definition]:
        """Union: a definition reaches if it reaches on any path."""
        if not facts:
            return frozenset()
        result: set[Definition] = set()
        for f in facts:
            result |= f
        return frozenset(result)

    def get_reaching_defs_at(self, pc: int) -> frozenset[Definition]:
        """Get definitions reaching a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return frozenset()
        result = set(self.get_in(block.id))
        for instr in block.instructions:
            if instr.offset >= pc:
                break
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
                defn = Definition(
                    var_name=var_name,
                    block_id=block.id,
                    pc=instr.offset,
                    line=_get_line_number(instr),
                )
                result.add(defn)
            elif instr.opname in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
        return frozenset(result)


class LiveVariables(DataFlowAnalysis[frozenset[str]]):
    """
    Live variable analysis (backward).

    A variable is live at a point if it may be used before being redefined.
    Used for:
    - Dead code elimination
    - Register allocation
    - Detecting unused assignments
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)

    def is_forward(self) -> bool:
        return False

    def initial_value(self) -> frozenset[str]:
        return frozenset()

    def boundary_value(self) -> frozenset[str]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[str],
    ) -> frozenset[str]:
        """Transfer function: (out - kill) ∪ gen."""
        result = set(in_fact)
        for instr in reversed(block.instructions):
            var_name = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in {
                "STORE_NAME",
                "STORE_FAST",
                "STORE_GLOBAL",
                "STORE_DEREF",
                "DELETE_NAME",
                "DELETE_FAST",
                "DELETE_GLOBAL",
                "DELETE_DEREF",
            }:
                if var_name:
                    result.discard(var_name)
            if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                if var_name:
                    result.add(var_name)
        return frozenset(result)

    def meet(self, facts: list[frozenset[str]]) -> frozenset[str]:
        """Union: variable is live if live on any successor path."""
        if not facts:
            return frozenset()
        result: set[str] = set()
        for f in facts:
            result |= f
        return frozenset(result)

    def is_live_at(self, var_name: str, pc: int) -> bool:
        """Check if a variable is live at a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        live = set(self.get_out(block.id))
        for instr in reversed(block.instructions):
            if instr.offset < pc:
                break
            var = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in {
                "STORE_NAME",
                "STORE_FAST",
                "STORE_GLOBAL",
                "STORE_DEREF",
                "DELETE_NAME",
                "DELETE_FAST",
                "DELETE_GLOBAL",
                "DELETE_DEREF",
            }:
                if var:
                    live.discard(var)
            if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                if var:
                    live.add(var)
        return var_name in live


class DefUseAnalysis:
    """
    Builds def-use chains for a function.

    Combines reaching definitions with use information
    to create precise data flow information.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        self.cfg = cfg
        self.reaching_defs = ReachingDefinitions(cfg)
        self.chains: dict[Definition, DefUseChain] = {}
        self.reaching_defs.analyze()
        self._build_chains()

    def _build_chains(self) -> None:
        """Build def-use chains."""
        for defn in self.reaching_defs.all_defs:
            self.chains[defn] = DefUseChain(definition=defn)
        for block in self.cfg.blocks.values():
            reaching = set(self.reaching_defs.get_in(block.id))
            for instr in block.instructions:
                if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    var_name = instr.argval
                    to_remove = {d for d in reaching if d.var_name == var_name}
                    reaching -= to_remove
                    defn = Definition(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=_get_line_number(instr),
                    )
                    reaching.add(defn)
                elif instr.opname in {
                    "DELETE_NAME",
                    "DELETE_FAST",
                    "DELETE_GLOBAL",
                    "DELETE_DEREF",
                }:
                    var_name = instr.argval
                    to_remove = {d for d in reaching if d.var_name == var_name}
                    reaching -= to_remove
                if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                    var_name = instr.argval
                    use = Use(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=_get_line_number(instr),
                    )
                    for defn in reaching:
                        if defn.var_name == var_name:
                            if defn in self.chains:
                                self.chains[defn].add_use(use)

    def get_chain(self, definition: Definition) -> DefUseChain | None:
        """Get the def-use chain for a definition."""
        return self.chains.get(definition)

    def get_definitions_for_use(self, use: Use) -> set[Definition]:
        """Get all definitions that may reach a use."""
        reaching = self.reaching_defs.get_reaching_defs_at(use.pc)
        return {d for d in reaching if d.var_name == use.var_name}

    def find_dead_stores(self) -> list[Definition]:
        """Find definitions that are never used."""
        dead: list[Definition] = []
        for defn, chain in self.chains.items():
            if chain.is_dead():
                dead.append(defn)
        return dead


class AvailableExpressions(DataFlowAnalysis[frozenset[Expression]]):
    """
    Available expressions analysis.

    An expression is available at a point if it has been computed
    on all paths and its operands haven't been redefined.
    Used for:
    - Common subexpression elimination
    - Optimization
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.all_expressions: set[Expression] = set()
        self._collect_expressions()

    def _collect_expressions(self) -> None:
        """Collect all expressions in the CFG."""
        for block in self.cfg.blocks.values():
            stack: list[str] = []

            def push(s: str) -> None:
                stack.append(s)

            def pop() -> str:
                return stack.pop() if stack else "unknown"

            for instr in block.instructions:
                op = instr.opname
                if op in {
                    "LOAD_NAME",
                    "LOAD_FAST",
                    "LOAD_GLOBAL",
                    "LOAD_DEREF",
                    "LOAD_FAST_CHECK",
                    "LOAD_FAST_AND_CLEAR",
                    "LOAD_CLOSURE",
                }:
                    push(str(instr.argval))
                elif op == "LOAD_FAST_LOAD_FAST":
                    arg1, arg2 = instr.argval
                    push(str(arg1))
                    push(str(arg2))
                elif op == "LOAD_CONST":
                    push(f"const_{instr.argval}")
                elif op in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    pop()
                elif op in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
                    pass
                elif op in {"BINARY_OP", "BINARY_SUBSCR"}:
                    right = pop()
                    left = pop()
                    operator = instr.argrepr if op == "BINARY_OP" else "[]"
                    if left != "unknown" and right != "unknown":
                        expr = Expression(operator=operator, operands=(left, right))
                        self.all_expressions.add(expr)
                        push(f"({left}{operator}{right})")
                    else:
                        push("unknown")
                elif op == "UNARY_OP":
                    operand = pop()
                    if operand != "unknown":
                        expr = Expression(operator=instr.argrepr, operands=(operand,))
                        self.all_expressions.add(expr)
                        push(f"({instr.argrepr}{operand})")
                    else:
                        push("unknown")
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
                    if len(stack) >= idx:
                        push(stack[-idx])
                    else:
                        push("unknown")
                elif op == "UNPACK_SEQUENCE":
                    pop()
                    count = int(instr.argval) if instr.argval is not None else 0
                    for _ in range(count):
                        push("unknown")
                elif op == "POP_TOP":
                    pop()
                elif "INPLACE_" in op or "COMPARE_OP" in op:
                    pop()
                    pop()
                    push("unknown")
                elif op.startswith("BUILD_"):
                    count = int(instr.argval) if instr.argval is not None else 0
                    if op == "BUILD_MAP":
                        count *= 2
                    elif op == "BUILD_CONST_KEY_MAP":
                        count += 1
                    for _ in range(count):
                        pop()
                    push("unknown")
                elif op.startswith("CALL"):
                    stack.clear()
                    push("unknown")
                else:
                    stack.clear()

    def initial_value(self) -> frozenset[Expression]:
        return frozenset(self.all_expressions)

    def boundary_value(self) -> frozenset[Expression]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Expression],
    ) -> frozenset[Expression]:
        """Transfer function: gen ∪ (in - kill)."""
        result = set(in_fact)
        stack: list[str] = []

        def push(s: str) -> None:
            stack.append(s)

        def pop() -> str:
            return stack.pop() if stack else "unknown"

        for instr in block.instructions:
            op = instr.opname
            if op in {
                "LOAD_NAME",
                "LOAD_FAST",
                "LOAD_GLOBAL",
                "LOAD_DEREF",
                "LOAD_FAST_CHECK",
                "LOAD_FAST_AND_CLEAR",
                "LOAD_CLOSURE",
            }:
                push(str(instr.argval))
            elif op == "LOAD_FAST_LOAD_FAST":
                arg1, arg2 = instr.argval
                push(str(arg1))
                push(str(arg2))
            elif op == "LOAD_CONST":
                push(f"const_{instr.argval}")
            elif op in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = str(instr.argval)
                to_remove = {e for e in result if var_name in e.operands}
                result -= to_remove
                pop()
            elif op in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
                pass
            elif op in {"BINARY_OP", "BINARY_SUBSCR"}:
                right = pop()
                left = pop()
                operator = instr.argrepr if op == "BINARY_OP" else "[]"
                if left != "unknown" and right != "unknown":
                    expr = Expression(operator=operator, operands=(left, right))
                    result.add(expr)
                    push(f"({left}{operator}{right})")
                else:
                    push("unknown")
            elif op == "UNARY_OP":
                operand = pop()
                if operand != "unknown":
                    expr = Expression(operator=instr.argrepr, operands=(operand,))
                    result.add(expr)
                    push(f"({instr.argrepr}{operand})")
                else:
                    push("unknown")
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
                if len(stack) >= idx:
                    push(stack[-idx])
                else:
                    push("unknown")
            elif op == "UNPACK_SEQUENCE":
                pop()
                count = int(instr.argval) if instr.argval is not None else 0
                for _ in range(count):
                    push("unknown")
            elif op == "POP_TOP":
                pop()
            elif "INPLACE_" in op or "COMPARE_OP" in op:
                pop()
                pop()
                push("unknown")
            elif op.startswith("BUILD_"):
                count = int(instr.argval) if instr.argval is not None else 0
                if op == "BUILD_MAP":
                    count *= 2
                elif op == "BUILD_CONST_KEY_MAP":
                    count += 1
                for _ in range(count):
                    pop()
                push("unknown")
            elif op.startswith("CALL"):
                stack.clear()
                push("unknown")
            else:
                stack.clear()

        return frozenset(result)

    def meet(self, facts: list[frozenset[Expression]]) -> frozenset[Expression]:
        """Intersection: expression available only if available on all paths."""
        if not facts:
            return frozenset(self.all_expressions)
        result = set(facts[0])
        for f in facts[1:]:
            result &= f
        return frozenset(result)


class TypeFlowAnalysis(DataFlowAnalysis[TypeEnvironment]):
    """
    Flow-sensitive type analysis.

    Tracks types through control flow, handling:
    - Type narrowing from conditions
    - Type widening at merge points
    - Type refinement from isinstance/type guards
    """

    def __init__(
        self,
        cfg: ControlFlowGraph,
        type_analyzer: TypeAnalyzer,
        initial_env: TypeEnvironment | None = None,
    ) -> None:
        super().__init__(cfg)
        self.type_analyzer = type_analyzer
        self.initial_env = initial_env or TypeEnvironment()
        self.branch_conditions: dict[int, tuple[str, PyType, bool]] = {}

    def initial_value(self) -> TypeEnvironment:
        return TypeEnvironment()

    def boundary_value(self) -> TypeEnvironment:
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
        elif op in {
            "LOAD_NAME",
            "LOAD_FAST",
            "LOAD_GLOBAL",
            "LOAD_DEREF",
            "LOAD_FAST_CHECK",
            "LOAD_FAST_AND_CLEAR",
            "LOAD_CLOSURE",
        }:
            push(env.get_type(str(instr.argval)))
        elif op == "LOAD_FAST_LOAD_FAST":
            arg1, arg2 = instr.argval
            push(env.get_type(str(arg1)))
            push(env.get_type(str(arg2)))
        elif op in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            env.set_type(str(instr.argval), pop())
        elif op in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
            pass
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
            if len(stack) >= idx:
                push(stack[-idx])
            else:
                push(PyType.unknown())
        elif op == "UNPACK_SEQUENCE":
            pop()
            count = int(instr.argval) if instr.argval is not None else 0
            for _ in range(count):
                push(PyType.unknown())
        elif op == "POP_TOP":
            pop()
        elif "BINARY_" in op or "INPLACE_" in op or "COMPARE_OP" in op:
            pop()
            pop()
            push(PyType.unknown())
        elif "UNARY_" in op:
            pop()
            push(PyType.unknown())
        elif op.startswith("BUILD_"):
            count = int(instr.argval) if instr.argval is not None else 0
            if op == "BUILD_MAP":
                count *= 2
            elif op == "BUILD_CONST_KEY_MAP":
                count += 1
            for _ in range(count):
                pop()
            if op in {"BUILD_TUPLE", "BUILD_LIST", "BUILD_SET"}:
                if op == "BUILD_TUPLE":
                    push(PyType.tuple_type())
                else:
                    push(PyType.unknown())
            else:
                push(PyType.unknown())
        elif op.startswith("CALL"):
            stack.clear()
            push(PyType.unknown())
        else:
            stack.clear()

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
        if isinstance(value, bytes):
            return PyType.unknown()
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


class NullAnalysis(DataFlowAnalysis[NullInfo]):
    """
    Null/None pointer analysis.

    Tracks whether variables can be None at each program point.
    Handles narrowing from None checks.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.narrowing_conditions: dict[int, dict[str, NullState]] = {}

    def initial_value(self) -> NullInfo:
        return NullInfo()

    def boundary_value(self) -> NullInfo:
        return NullInfo()

    def transfer(self, block: BasicBlock, in_fact: NullInfo) -> NullInfo:
        """Transfer function for null analysis."""
        info = in_fact.copy()
        stack: list[NullState] = []

        def push(state: NullState) -> None:
            stack.append(state)

        def pop() -> NullState:
            return stack.pop() if stack else NullState.UNKNOWN

        for instr in block.instructions:
            op = instr.opname
            if op == "LOAD_CONST":
                if instr.argval is None:
                    push(NullState.DEFINITELY_NULL)
                else:
                    push(NullState.DEFINITELY_NOT_NULL)
            elif op in {
                "LOAD_NAME",
                "LOAD_FAST",
                "LOAD_GLOBAL",
                "LOAD_DEREF",
                "LOAD_FAST_CHECK",
                "LOAD_FAST_AND_CLEAR",
                "LOAD_CLOSURE",
            }:
                push(info.get_state(str(instr.argval)))
            elif op == "LOAD_FAST_LOAD_FAST":
                arg1, arg2 = instr.argval
                push(info.get_state(str(arg1)))
                push(info.get_state(str(arg2)))
            elif op in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                info.set_state(str(instr.argval), pop())
            elif op in {"DELETE_NAME", "DELETE_FAST", "DELETE_GLOBAL", "DELETE_DEREF"}:
                pass
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
                if len(stack) >= idx:
                    push(stack[-idx])
                else:
                    push(NullState.UNKNOWN)
            elif op == "UNPACK_SEQUENCE":
                pop()
                count = int(instr.argval) if instr.argval is not None else 0
                for _ in range(count):
                    push(NullState.UNKNOWN)
            elif op == "POP_TOP":
                pop()
            elif "BINARY_" in op or "INPLACE_" in op or "COMPARE_OP" in op:
                pop()
                pop()
                push(NullState.DEFINITELY_NOT_NULL)
            elif "UNARY_" in op:
                pop()
                push(NullState.DEFINITELY_NOT_NULL)
            elif op.startswith("BUILD_"):
                count = int(instr.argval) if instr.argval is not None else 0
                if op == "BUILD_MAP":
                    count *= 2
                elif op == "BUILD_CONST_KEY_MAP":
                    count += 1
                for _ in range(count):
                    pop()
                push(NullState.DEFINITELY_NOT_NULL)
            elif op.startswith("CALL"):
                stack.clear()
                push(NullState.MAYBE_NULL)
            else:
                stack.clear()

        narrowing = self.narrowing_conditions.get(block.id, {})
        for var_name, state in narrowing.items():
            info.set_state(var_name, state)
        return info

    def meet(self, facts: list[NullInfo]) -> NullInfo:
        """Join null infos."""
        if not facts:
            return NullInfo()
        result = facts[0]
        for info in facts[1:]:
            result = result.join(info)
        return result

    def is_definitely_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        info = self.get_in(block.id)
        return info.get_state(var_name) == NullState.DEFINITELY_NULL

    def is_definitely_not_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely not null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        info = self.get_in(block.id)
        return info.get_state(var_name) == NullState.DEFINITELY_NOT_NULL

    def may_be_null(self, var_name: str, pc: int) -> bool:
        """Check if variable may be null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return True
        info = self.get_in(block.id)
        state = info.get_state(var_name)
        return state in {
            NullState.DEFINITELY_NULL,
            NullState.MAYBE_NULL,
            NullState.UNKNOWN,
        }
