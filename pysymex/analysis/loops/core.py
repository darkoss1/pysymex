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

"""Loop analysis core logic for pysymex.
Loop detection, bound inference, induction variable detection,
summarization, invariant generation, and widening.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.loops.types import (
    InductionVariable,
    LoopBound,
    LoopInfo,
    LoopSummary,
)

if TYPE_CHECKING:
    from pysymex.core.state import VMState


class LoopDetector:
    """Detects loops in bytecode via control-flow graph analysis.

    Uses dominator computation to find back edges, then extracts
    loop bodies, exit PCs, and nesting information.
    """

    def __init__(self) -> None:
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list[dis.Instruction],
        entry_pc: int = 0,
    ) -> list[LoopInfo]:
        """Analyze control flow graph to detect loops."""

        self._loops = []
        self._back_edges = []
        cfg = self._build_cfg(instructions)
        dominators = self._compute_dominators(cfg, entry_pc)
        self._back_edges = self._find_back_edges(cfg, dominators)
        for from_pc, to_pc in self._back_edges:
            loop = self._build_loop_info(cfg, from_pc, to_pc)
            self._loops.append(loop)
        self._compute_nesting()
        return self._loops

    @property
    def loops(self) -> list[LoopInfo]:
        """Expose detected loops for tests and formal checks."""
        return self._loops

    def _build_cfg(self, instructions: list[dis.Instruction]) -> dict[int, set[int]]:
        """Build control flow graph from instructions."""
        cfg: dict[int, set[int]] = {}

        _unconditional_jumps = frozenset(
            {
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_BACKWARD_NO_INTERRUPT",
                "JUMP_ABSOLUTE",
                "JUMP",
                "JUMP_NO_INTERRUPT",
            }
        )
        _conditional_jumps = frozenset(
            {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_FALSE",
                "POP_JUMP_FORWARD_IF_NONE",
                "POP_JUMP_FORWARD_IF_NOT_NONE",
                "POP_JUMP_BACKWARD_IF_TRUE",
                "POP_JUMP_BACKWARD_IF_FALSE",
                "POP_JUMP_BACKWARD_IF_NONE",
                "POP_JUMP_BACKWARD_IF_NOT_NONE",
                "JUMP_IF_TRUE_OR_POP",
                "JUMP_IF_FALSE_OR_POP",
                "JUMP_IF_NOT_EXC_MATCH",
            }
        )
        for i, instr in enumerate(instructions):
            pc = instr.offset
            if pc not in cfg:
                cfg[pc] = set()
            if instr.opname in _unconditional_jumps:
                cfg[pc].add(instr.argval)
            elif instr.opname in _conditional_jumps:
                cfg[pc].add(instr.argval)
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
            elif instr.opname not in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
        return cfg

    def _compute_dominators(
        self,
        cfg: dict[int, set[int]],
        entry: int,
    ) -> dict[int, set[int]]:
        """Compute dominator sets for all nodes."""
        all_nodes = set(cfg.keys())
        for successors in cfg.values():
            all_nodes.update(successors)
        dom: dict[int, set[int]] = {entry: {entry}}
        for node in all_nodes:
            if node != entry:
                dom[node] = set(all_nodes)
        changed = True
        while changed:
            changed = False
            for node in all_nodes:
                if node == entry:
                    continue
                preds = [n for n, succs in cfg.items() if node in succs]
                if preds:
                    new_dom = dom.get(preds[0], all_nodes).copy()
                    for p in preds[1:]:
                        new_dom &= dom.get(p, all_nodes)
                    new_dom.add(node)
                    if new_dom != dom[node]:
                        dom[node] = new_dom
                        changed = True
        return dom

    def _find_back_edges(
        self,
        cfg: dict[int, set[int]],
        dominators: dict[int, set[int]],
    ) -> list[tuple[int, int]]:
        """Find back edges (loops) in CFG."""
        back_edges: list[tuple[int, int]] = []
        for from_pc, successors in cfg.items():
            for to_pc in successors:
                if to_pc in dominators.get(from_pc, set()):
                    back_edges.append((from_pc, to_pc))
        return back_edges

    def _build_loop_info(
        self,
        cfg: dict[int, set[int]],
        back_edge_pc: int,
        header_pc: int,
    ) -> LoopInfo:
        """Build loop info from back edge."""
        body_pcs = {header_pc, back_edge_pc}
        worklist = [back_edge_pc]
        reverse_cfg: dict[int, set[int]] = {}
        for src, dsts in cfg.items():
            for dst in dsts:
                if dst not in reverse_cfg:
                    reverse_cfg[dst] = set()
                reverse_cfg[dst].add(src)
        while worklist:
            pc = worklist.pop()
            for pred in reverse_cfg.get(pc, set()):
                if pred not in body_pcs and pred != header_pc:
                    body_pcs.add(pred)
                    worklist.append(pred)
        exit_pcs: set[int] = set()
        for pc in body_pcs:
            for succ in cfg.get(pc, set()):
                if succ not in body_pcs and succ != header_pc:
                    exit_pcs.add(succ)
        return LoopInfo(
            header_pc=header_pc,
            back_edge_pc=back_edge_pc,
            exit_pcs=exit_pcs,
            body_pcs=body_pcs,
        )

    def _compute_nesting(self) -> None:
        """Compute loop nesting relationships."""
        sorted_loops = sorted(self._loops, key=lambda lp: len(lp.body_pcs), reverse=True)
        for i, inner in enumerate(sorted_loops):
            for outer in sorted_loops[:i]:
                if inner.header_pc in outer.body_pcs:
                    if inner.parent is None or len(outer.body_pcs) < len(inner.parent.body_pcs):
                        if inner.parent is not None:
                            inner.parent.children.remove(inner)
                        inner.parent = outer
                        outer.children.append(inner)
                        inner.nesting_depth = outer.nesting_depth + 1

    def get_loop_at(self, pc: int) -> LoopInfo | None:
        """Get the innermost loop containing a PC."""
        candidates = [lp for lp in self._loops if lp.contains_pc(pc)]
        if not candidates:
            return None
        return max(candidates, key=lambda lp: lp.nesting_depth)


class LoopBoundInference:
    """Infers loop bounds from iterator state and loop structure.

    Caches results per loop header PC.
    """

    def __init__(self) -> None:
        self._cached_bounds: dict[int, LoopBound] = {}

    def infer_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bounds for a loop."""
        if loop.header_pc in self._cached_bounds:
            return self._cached_bounds[loop.header_pc]
        bound = self._try_extract_iterator_bound(state)
        if bound:
            self._cached_bounds[loop.header_pc] = bound
            return bound
        if self._is_range_loop(loop, state):
            bound = self._infer_range_bound(loop, state)
            self._cached_bounds[loop.header_pc] = bound
            return bound
        if self._is_counted_loop(loop, state):
            bound = self._infer_counted_bound(loop, state)
            self._cached_bounds[loop.header_pc] = bound
            return bound
        bound = self._infer_while_bound(loop, state)
        self._cached_bounds[loop.header_pc] = bound
        return bound

    def _try_extract_iterator_bound(self, state: VMState) -> LoopBound | None:
        """Try to extract bound from iterator on the stack."""
        from pysymex.core.iterators import SymbolicIterator, SymbolicRange

        if not state.stack:
            return None
        for item in reversed(state.stack[:3]):
            if isinstance(item, SymbolicIterator):
                bound = item.remaining_bound()
                if isinstance(bound, int):
                    return LoopBound.constant(bound)
                else:
                    return LoopBound.symbolic(bound)
            if isinstance(item, SymbolicRange):
                if getattr(item, "_is_concrete", False):
                    return LoopBound.constant(cast("int", item.length))
                else:
                    return LoopBound.symbolic(cast("z3.ArithRef", item.length))
        return None

    def _is_range_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop is a for i in range(...) loop by looking at stack/locals."""

        from pysymex.core.iterators import SymbolicRange

        for item in state.stack:
            if isinstance(item, SymbolicRange):
                return True
        return False

    def _is_counted_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop has a counting pattern."""
        return bool(loop.induction_vars)

    def _infer_range_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bound for range-based loop by analyzing iterator."""
        from pysymex.core.iterators import SymbolicRange

        for item in state.stack:
            if isinstance(item, SymbolicRange):
                length = item.length
                if isinstance(length, int):
                    return LoopBound.constant(length)
                else:
                    return LoopBound.symbolic(length)
        for obj in state.memory.values():
            if isinstance(obj, dict):
                for val in cast("dict[str, object]", obj).values():
                    if isinstance(val, SymbolicRange):
                        length = val.length
                        if isinstance(length, int):
                            return LoopBound.constant(length)
                        else:
                            return LoopBound.symbolic(length)
        return LoopBound.range(0, 1000)

    def _infer_counted_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bound for counted loop using induction variables."""
        for name, iv in loop.induction_vars.items():
            var = state.locals.get(name)
            if var is None:
                continue
            if hasattr(iv, "step") and hasattr(iv, "initial"):
                step_val = iv.step
                if isinstance(step_val, int):
                    step = step_val
                elif isinstance(step_val, z3.ArithRef) and z3.is_int_value(step_val):
                    step = step_val.as_long()
                else:
                    step = None
                if step is not None and step > 0:
                    var_expr_raw = getattr(var, "z3_int", None)
                    if var_expr_raw is None or not isinstance(var_expr_raw, z3.ExprRef):
                        continue
                    var_expr: z3.ExprRef = var_expr_raw
                    for constraint in reversed(state.path_constraints):
                        if isinstance(constraint, list):
                            continue
                        constraint_expr = cast("z3.ExprRef", constraint)
                        if z3.is_lt(constraint) or z3.is_le(constraint):
                            children = constraint_expr.children()
                            if len(children) == 2:
                                lhs, rhs = children[0], children[1]
                                if z3.eq(lhs, var_expr) or str(lhs) == str(var_expr):
                                    return LoopBound.symbolic(rhs)
        return LoopBound.range(0, 1000)

    def _infer_while_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bound for while loops from condition analysis."""
        for constraint in state.path_constraints:
            if z3.is_and(constraint) or z3.is_or(constraint):
                continue
            pass
        return LoopBound.range(0, 10000)


class InductionVariableDetector:
    """Detects induction variables in loop bodies."""

    def __init__(self) -> None:
        self._detected: dict[str, InductionVariable] = {}

    @staticmethod
    def _coerce_z3_int(value: object) -> z3.ArithRef:
        if isinstance(value, z3.ArithRef):
            return value
        z3_int = getattr(value, "z3_int", None)
        if isinstance(z3_int, z3.ArithRef):
            return z3_int
        if isinstance(value, (int, float)):
            return z3.IntVal(int(value))
        return z3.IntVal(0)

    def detect(
        self,
        loop: LoopInfo,
        instructions: list[dis.Instruction],
        state: VMState,
    ) -> dict[str, InductionVariable]:
        """Detect induction variables in loop body."""
        self._detected = {}
        body_instructions: list[dis.Instruction] = [
            instr for instr in instructions if instr.offset in loop.body_pcs
        ]
        stores: dict[str, list[tuple[int, dis.Instruction]]] = {}
        loads: dict[str, list[tuple[int, dis.Instruction]]] = {}
        for i, instr in enumerate(body_instructions):
            if instr.opname in ("STORE_FAST", "STORE_NAME"):
                name = instr.argval
                if name not in stores:
                    stores[name] = []
                stores[name].append((i, instr))
            elif instr.opname in ("LOAD_FAST", "LOAD_NAME"):
                name = instr.argval
                if name not in loads:
                    loads[name] = []
                loads[name].append((i, instr))
        modified_vars = set(stores.keys()) & set(loads.keys())
        for name in modified_vars:
            iv = self._analyze_modification_pattern(
                name, stores[name], loads[name], body_instructions, state
            )
            if iv:
                self._detected[name] = iv
        return self._detected

    def _analyze_modification_pattern(
        self,
        name: str,
        stores: list[tuple[int, dis.Instruction]],
        loads: list[tuple[int, dis.Instruction]],
        instructions: list[dis.Instruction],
        state: VMState,
    ) -> InductionVariable | None:
        """Analyze if variable follows induction pattern."""
        for store_idx, _store_instr in stores:
            if store_idx < 3:
                continue
            prev_instrs: list[dis.Instruction | None] = [
                instructions[store_idx - 3] if store_idx >= 3 else None,
                instructions[store_idx - 2] if store_idx >= 2 else None,
                instructions[store_idx - 1] if store_idx >= 1 else None,
            ]
            if (
                prev_instrs[0]
                and prev_instrs[0].opname in ("LOAD_FAST", "LOAD_NAME")
                and prev_instrs[0].argval == name
                and prev_instrs[1]
                and prev_instrs[1].opname == "LOAD_CONST"
                and prev_instrs[2]
                and prev_instrs[2].opname == "BINARY_OP"
            ):
                step_val = prev_instrs[1].argval
                if isinstance(step_val, (int, float)):
                    initial = state.locals.get(name)
                    direction = 1 if step_val > 0 else -1
                    return InductionVariable(
                        name=name,
                        initial=self._coerce_z3_int(initial),
                        step=z3.IntVal(int(step_val)),
                        direction=direction,
                    )
            if (
                prev_instrs[0]
                and prev_instrs[0].opname in ("LOAD_FAST", "LOAD_NAME")
                and prev_instrs[0].argval == name
                and prev_instrs[1]
                and prev_instrs[1].opname == "LOAD_CONST"
                and prev_instrs[1].argval == 1
                and prev_instrs[2]
                and "ADD" in prev_instrs[2].opname
            ):
                initial = state.locals.get(name)
                return InductionVariable(
                    name=name,
                    initial=self._coerce_z3_int(initial),
                    step=z3.IntVal(1),
                    direction=1,
                )
        return None


class LoopSummarizer:
    """Summarizes loop effects for closed-form computation."""

    def summarize(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopSummary | None:
        """Attempt to create a closed-form summary of loop effects."""
        if not loop.bound or not loop.bound.is_finite:
            return None
        if not loop.induction_vars:
            return None
        iterations = loop.bound.exact if loop.bound.exact is not None else loop.bound.upper
        effects: dict[str, z3.ExprRef] = {}
        for name, iv in loop.induction_vars.items():
            final_value = iv.final_value(iterations)
            effects[name] = final_value
        accumulator_effects = self._detect_accumulator_effects(loop, state, iterations)
        effects.update(accumulator_effects)
        return LoopSummary(
            iterations=iterations,
            variable_effects=effects,
            memory_effects={},
            invariants_verified=bool(loop.invariants),
            can_summarize=True,
        )

    def _detect_accumulator_effects(
        self,
        loop: LoopInfo,
        state: VMState,
        iterations: z3.ExprRef | int,
    ) -> dict[str, z3.ExprRef]:
        """Detect accumulator patterns like sum += iv (Arithmetic Series)."""
        effects: dict[str, z3.ExprRef] = {}

        instructions = getattr(state, "current_instructions", None)
        if not instructions:
            return effects

        iv_names = set(loop.induction_vars.keys())

        for i in range(len(instructions) - 3):
            instr1 = instructions[i]
            if getattr(instr1, "offset", -1) not in loop.body_pcs:
                continue

            if instr1.opname in ("LOAD_FAST", "LOAD_NAME"):
                acc_name = instr1.argval
                if isinstance(acc_name, str):
                    instr2 = instructions[i + 1]

                    if instr2.opname in ("LOAD_FAST", "LOAD_NAME") and instr2.argval in iv_names:
                        iv_name = instr2.argval
                        instr3 = instructions[i + 2]

                        if instr3.opname == "BINARY_OP" and getattr(instr3, "argrepr", "") in (
                            "+",
                            "+=",
                        ):
                            instr4 = instructions[i + 3]

                            if (
                                instr4.opname in ("STORE_FAST", "STORE_NAME")
                                and instr4.argval == acc_name
                            ):
                                iv = loop.induction_vars[str(iv_name)]
                                acc_val = state.locals.get(acc_name)

                                if acc_val is not None:
                                    acc_initial = getattr(acc_val, "z3_int", acc_val)
                                    if isinstance(acc_initial, z3.ExprRef):
                                        n = (
                                            z3.IntVal(iterations)
                                            if isinstance(iterations, int)
                                            else iterations
                                        )

                                        sum_n = (n * (n - z3.IntVal(1))) / z3.IntVal(2)
                                        total_addition = (n * iv.initial) + (sum_n * iv.step)
                                        effects[acc_name] = acc_initial + total_addition
        return effects

    def apply_summary(
        self,
        summary: LoopSummary,
        state: VMState,
    ) -> VMState:
        """Apply loop summary to state, skipping iteration."""
        new_state = state.copy()
        for name, final_value in summary.variable_effects.items():
            if name in new_state.locals:
                from pysymex.core.types import SymbolicValue

                new_state.locals[name] = SymbolicValue.from_z3(final_value, name)
        for addr, effects in summary.memory_effects.items():
            if addr in new_state.memory:
                mem_obj = new_state.memory[addr]
                if isinstance(mem_obj, dict):
                    from pysymex.core.types import SymbolicValue as SV

                    for attr, value in effects.items():
                        mem_obj[attr] = SV.from_z3(value, f"mem_{addr}_{attr}")
        return new_state


class LoopInvariantGenerator:
    """Generates loop invariants for verification."""

    def __init__(self) -> None:
        self._invariants: dict[int, list[z3.BoolRef]] = {}

    @staticmethod
    def _get_z3_int(value: object) -> z3.ArithRef | None:
        z3_int = getattr(value, "z3_int", None)
        return z3_int if isinstance(z3_int, z3.ArithRef) else None

    def generate_invariants(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> list[z3.BoolRef]:
        """Generate candidate invariants for a loop."""
        invariants: list[z3.BoolRef] = []
        for name, iv in loop.induction_vars.items():
            sym_var = state.locals.get(name)
            z3_int = self._get_z3_int(sym_var)
            if z3_int is not None:
                if iv.direction >= 0:
                    invariants.append(z3_int >= iv.initial)
                else:
                    invariants.append(z3_int <= iv.initial)
                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        invariants.append(z3_int <= final)
                    else:
                        invariants.append(z3_int >= final)
        from pysymex.core.iterators import SymbolicRange

        for item in state.stack:
            if isinstance(item, SymbolicRange):
                curr = (
                    item.current
                    if isinstance(item.current, z3.ArithRef)
                    else z3.IntVal(item.current)
                )
                start = item.start if isinstance(item.start, z3.ArithRef) else z3.IntVal(item.start)
                stop = item.stop if isinstance(item.stop, z3.ArithRef) else z3.IntVal(item.stop)
                invariants.append(curr >= start)
                invariants.append(curr <= stop)
        for constraint in state.path_constraints:
            invariants.append(constraint)
        return invariants

    def verify_invariant(
        self,
        invariant: z3.BoolRef,
        loop: LoopInfo,
        state: VMState,
    ) -> bool:
        """Verify that an invariant holds."""
        from pysymex.core.solver import is_satisfiable

        constraints = [*list(state.path_constraints), z3.Not(invariant)]
        return not is_satisfiable(constraints)


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def __init__(self, widening_threshold: int = 3) -> None:
        self.widening_threshold = widening_threshold
        self._iteration_count: dict[int, int] = {}

    def record_iteration(self, loop: LoopInfo) -> None:
        """Compat for legacy tests (global state)."""
        self._iteration_count[loop.header_pc] = self._iteration_count.get(loop.header_pc, 0) + 1

    def should_widen(self, loop: LoopInfo, current_count: int | None = None) -> bool:
        """Check if widening should be applied. Prefers path-sensitive count."""
        if current_count is not None:
            return current_count >= self.widening_threshold
        return self._iteration_count.get(loop.header_pc, 0) >= self.widening_threshold

    def widen_state(
        self,
        old_state: VMState,
        new_state: VMState,
        loop: LoopInfo,
    ) -> VMState:
        """Apply widening to generalize loop state.

        Creates fresh symbolic variables for all loop-variant variables and
        bounds them using induction-variable analysis.  The type discriminator
        constraints from ``SymbolicValue.symbolic()`` are added to the path
        so widened values retain proper typing.
        """
        from pysymex.core.types import SymbolicString, SymbolicValue, merge_taint

        widened = new_state.copy()

        handled_vars: set[str] = set()

        for name, iv in loop.induction_vars.items():
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                val_affinity = getattr(new_val, "affinity_type", None)
                if val_affinity == "int":
                    widened_sym, type_constraint = SymbolicValue.symbolic_int(f"{name}_widened")
                elif val_affinity == "bool":
                    widened_sym, type_constraint = SymbolicValue.symbolic_bool(f"{name}_widened")
                else:
                    widened_sym, type_constraint = SymbolicValue.symbolic(f"{name}_widened")

                widened.locals[name] = widened_sym
                widened.path_constraints = widened.path_constraints.append(type_constraint)
                handled_vars.add(name)

                if iv.direction >= 0:
                    widened.path_constraints = widened.path_constraints.append(
                        widened_sym.z3_int >= iv.initial
                    )
                else:
                    widened.path_constraints = widened.path_constraints.append(
                        widened_sym.z3_int <= iv.initial
                    )

                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        widened.path_constraints = widened.path_constraints.append(
                            widened_sym.z3_int <= final
                        )
                    else:
                        widened.path_constraints = widened.path_constraints.append(
                            widened_sym.z3_int >= final
                        )

        for name in set(old_state.locals.keys()) | set(new_state.locals.keys()):
            if name in handled_vars:
                continue

            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)

            try:
                if old_val == new_val:
                    continue
            except Exception:
                if old_val is new_val:
                    continue

            if old_val is not None and new_val is not None:
                if name in new_state.locals:
                    old_affinity = getattr(old_val, "affinity_type", None)
                    new_affinity = getattr(new_val, "affinity_type", None)
                    if old_affinity == new_affinity and old_affinity != "NoneType":
                        if old_affinity == "int":
                            widened_sym, type_constraint = SymbolicValue.symbolic_int(
                                f"{name}_widened"
                            )
                        elif old_affinity == "bool":
                            widened_sym, type_constraint = SymbolicValue.symbolic_bool(
                                f"{name}_widened"
                            )
                        elif old_affinity == "str":
                            widened_sym, type_constraint = SymbolicString.symbolic(
                                f"{name}_widened"
                            )
                        else:
                            widened_sym, type_constraint = SymbolicValue.symbolic(f"{name}_widened")
                    else:
                        widened_sym, type_constraint = SymbolicValue.symbolic(f"{name}_widened")

                    old_taint = getattr(old_val, "taint_labels", None)
                    new_taint = getattr(new_val, "taint_labels", None)
                    if old_taint or new_taint:
                        import dataclasses as _dc

                        widened_sym = _dc.replace(
                            widened_sym,
                            taint_labels=merge_taint(old_taint or set(), new_taint or set()),
                        )

                    widened.locals[name] = widened_sym
                    widened.path_constraints = widened.path_constraints.append(type_constraint)

        return widened


__all__ = [
    "InductionVariableDetector",
    "LoopBoundInference",
    "LoopDetector",
    "LoopInvariantGenerator",
    "LoopSummarizer",
    "LoopWidening",
]
