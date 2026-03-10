"""Loop analysis core logic for pysymex.
Loop detection, bound inference, induction variable detection,
summarization, invariant generation, and widening.
"""

from __future__ import annotations

import dis
from typing import (
    TYPE_CHECKING,
    cast,
)

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

    def __init__(self):
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list[dis.Instruction],
        entry_pc: int = 0,
    ) -> list[LoopInfo]:
        """Analyze control flow graph to detect loops."""
        cfg = self._build_cfg(instructions)
        dominators = self._compute_dominators(cfg, entry_pc)
        self._back_edges = self._find_back_edges(cfg, dominators)
        for from_pc, to_pc in self._back_edges:
            loop = self._build_loop_info(cfg, from_pc, to_pc)
            self._loops.append(loop)
        self._compute_nesting()
        return self._loops

    def _build_cfg(self, instructions: list[dis.Instruction]) -> dict[int, set[int]]:
        """Build control flow graph from instructions."""
        cfg: dict[int, set[int]] = {}
        for i, instr in enumerate(instructions):
            pc = instr.offset
            if pc not in cfg:
                cfg[pc] = set()
            if instr.opname in ("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"):
                cfg[pc].add(instr.argval)
            elif instr.opname in (
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
            ):
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

    def __init__(self):
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
                if item._is_concrete:
                    return LoopBound.constant(cast("int", item.length))
                else:
                    return LoopBound.symbolic(cast("z3.ArithRef", item.length))
        return None

    def _is_range_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop is a for i in range(...) loop."""
        if hasattr(state, "_instructions"):
            for _instr in state._instructions:
                instr = cast("dis.Instruction", _instr)
                if instr.offset == loop.header_pc:
                    if instr.opname in ("FOR_ITER", "GET_ITER"):
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
        for _addr, obj in state.memory.items():
            if isinstance(obj, dict):
                for _key, val in cast("dict[str, object]", obj).items():
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
                if isinstance(step_val, z3.ArithRef) or isinstance(step_val, int):
                    step = step_val if isinstance(step_val, int) else 1
                    if step > 0:
                        for constraint in state.path_constraints:
                            if z3.is_lt(constraint) or z3.is_le(constraint):
                                upper = (
                                    constraint.children()[1]
                                    if hasattr(constraint, "children")
                                    else None
                                )
                                if upper is not None:
                                    return LoopBound.symbolic(upper)
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

    def __init__(self):
        self._detected: dict[str, InductionVariable] = {}

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
                    if initial is None:
                        initial = z3.IntVal(0)
                    elif hasattr(initial, "z3_int"):
                        initial = initial.z3_int
                    elif not isinstance(initial, z3.ArithRef):
                        initial = z3.IntVal(
                            int(initial) if isinstance(initial, (int, float)) else 0
                        )
                    direction = 1 if step_val > 0 else -1
                    return InductionVariable(
                        name=name,
                        initial=initial,
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
                if initial is None:
                    initial = z3.IntVal(0)
                elif hasattr(initial, "z3_int"):
                    initial = initial.z3_int
                elif not isinstance(initial, z3.ArithRef):
                    initial = z3.IntVal(0)
                return InductionVariable(
                    name=name,
                    initial=initial,
                    step=z3.IntVal(1),
                    direction=1,
                )
        return None


class LoopSummarizer:
    """Summarizes loop effects for closed-form computation."""

    def __init__(self):
        pass

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
        """Detect accumulator patterns like sum += x."""
        effects: dict[str, z3.ExprRef] = {}
        for name, iv in loop.induction_vars.items():
            if iv.step == z3.IntVal(1) or iv.step == 1:
                initial = iv.initial
                if isinstance(iterations, int):
                    effects[f"{name}_final"] = initial + z3.IntVal(iterations)
                else:
                    effects[f"{name}_final"] = initial + iterations
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
                for attr, value in effects.items():
                    new_state.memory[addr][attr] = value
        return new_state


class LoopInvariantGenerator:
    """Generates loop invariants for verification."""

    def __init__(self):
        self._invariants: dict[int, list[z3.BoolRef]] = {}

    def generate_invariants(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> list[z3.BoolRef]:
        """Generate candidate invariants for a loop."""
        invariants: list[z3.BoolRef] = []
        for name, iv in loop.induction_vars.items():
            sym_var = state.locals.get(name)
            if sym_var and hasattr(sym_var, "z3_int"):
                invariants.append(sym_var.z3_int >= iv.initial)
                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        invariants.append(sym_var.z3_int <= final)
                    else:
                        invariants.append(sym_var.z3_int >= final)
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

        constraints = list(state.path_constraints) + [z3.Not(invariant)]
        return not is_satisfiable(constraints)


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def __init__(self, widening_threshold: int = 3):
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
        from pysymex.core.types import SymbolicValue

        widened = new_state.copy()
        for name, iv in loop.induction_vars.items():
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                widened_sym, type_constraint = SymbolicValue.symbolic(f"{name}_widened")
                widened.locals[name] = widened_sym
                widened.path_constraints.append(type_constraint)
                widened.path_constraints.append(widened_sym.z3_int >= iv.initial)
                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    widened.path_constraints.append(widened_sym.z3_int <= final)
        for name in set(old_state.locals.keys()) | set(new_state.locals.keys()):
            if name in loop.induction_vars:
                continue
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                if isinstance(old_val, SymbolicValue) and isinstance(new_val, SymbolicValue):
                    widened_sym, type_constraint = SymbolicValue.symbolic(f"{name}_widened")
                    widened.locals[name] = widened_sym
                    widened.path_constraints.append(type_constraint)
        return widened


__all__ = [
    "InductionVariableDetector",
    "LoopBoundInference",
    "LoopDetector",
    "LoopInvariantGenerator",
    "LoopSummarizer",
    "LoopWidening",
]
