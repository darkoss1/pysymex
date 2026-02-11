"""Loop analysis for PySpectre.
This module provides loop detection, bound inference, and invariant generation
for improving symbolic execution of loops.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
)
import z3

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class LoopType(Enum):
    """Classification of loop types."""

    FOR_RANGE = auto()
    FOR_ITER = auto()
    WHILE_COND = auto()
    WHILE_TRUE = auto()
    NESTED = auto()
    UNKNOWN = auto()


@dataclass
class LoopBound:
    """Represents loop iteration bounds."""

    lower: z3.ExprRef
    upper: z3.ExprRef
    exact: z3.ExprRef | None = None
    is_finite: bool = True

    @staticmethod
    def constant(n: int) -> LoopBound:
        """Create a constant bound."""
        val = z3.IntVal(n)
        return LoopBound(lower=val, upper=val, exact=val)

    @staticmethod
    def range(low: int, high: int) -> LoopBound:
        """Create a range bound."""
        return LoopBound(lower=z3.IntVal(low), upper=z3.IntVal(high))

    @staticmethod
    def unbounded() -> LoopBound:
        """Create an unbounded (potentially infinite) loop."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=z3.IntVal(2**31),
            is_finite=False,
        )

    @staticmethod
    def symbolic(expr: z3.ExprRef) -> LoopBound:
        """Create a symbolic bound."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=expr,
            exact=expr,
        )


@dataclass
class LoopInfo:
    """Information about a detected loop."""

    header_pc: int
    back_edge_pc: int
    exit_pcs: set[int]
    body_pcs: set[int]
    loop_type: LoopType = LoopType.UNKNOWN
    bound: LoopBound | None = None
    induction_vars: dict[str, InductionVariable] = field(default_factory=dict)
    invariants: list[z3.BoolRef] = field(default_factory=list)
    parent: LoopInfo | None = None
    children: list[LoopInfo] = field(default_factory=list)
    nesting_depth: int = 0

    def contains_pc(self, pc: int) -> bool:
        """Check if PC is inside this loop."""
        return pc in self.body_pcs or pc == self.header_pc

    def is_header(self, pc: int) -> bool:
        """Check if PC is the loop header."""
        return pc == self.header_pc

    def is_exit(self, pc: int) -> bool:
        """Check if PC is a loop exit."""
        return pc in self.exit_pcs


@dataclass
class InductionVariable:
    """An induction variable that changes predictably each iteration."""

    name: str
    initial: z3.ExprRef
    step: z3.ExprRef
    direction: int = 1

    def value_at_iteration(self, i: z3.ExprRef) -> z3.ExprRef:
        """Get value at iteration i."""
        return self.initial + self.step * i

    def final_value(self, iterations: z3.ExprRef) -> z3.ExprRef:
        """Get value after all iterations."""
        return self.initial + self.step * iterations


class LoopDetector:
    """Detects loops in bytecode using control flow analysis."""

    def __init__(self):
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list,
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

    def _build_cfg(self, instructions: list) -> dict[int, set[int]]:
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
                    new_dom = set.intersection(*[dom.get(p, all_nodes) for p in preds])
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
        back_edges = []
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
        exit_pcs = set()
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
        sorted_loops = sorted(self._loops, key=lambda l: len(l.body_pcs), reverse=True)
        for i, inner in enumerate(sorted_loops):
            for outer in sorted_loops[:i]:
                if inner.header_pc in outer.body_pcs:
                    inner.parent = outer
                    outer.children.append(inner)
                    inner.nesting_depth = outer.nesting_depth + 1
                    break

    def get_loop_at(self, pc: int) -> LoopInfo | None:
        """Get the innermost loop containing a PC."""
        candidates = [l for l in self._loops if l.contains_pc(pc)]
        if not candidates:
            return None
        return max(candidates, key=lambda l: l.nesting_depth)


class LoopBoundInference:
    """Infers loop bounds from loop structure and iterator state."""

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
        from pyspectre.core.iterators import SymbolicIterator, SymbolicRange

        if not state.stack:
            return None
        for item in reversed(state.stack[:3]):
            if isinstance(item, SymbolicIterator):
                bound = item.remaining_bound()
                if isinstance(bound, int):
                    return LoopBound.constant(bound)
                elif isinstance(bound, z3.ArithRef):
                    return LoopBound.symbolic(bound)
            if isinstance(item, SymbolicRange):
                if item._is_concrete:
                    return LoopBound.constant(item.length)
                else:
                    return LoopBound.symbolic(item.length)
        return None

    def _is_range_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop is a for i in range(...) loop."""
        if hasattr(state, "_instructions"):
            for instr in state._instructions:
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
        from pyspectre.core.iterators import SymbolicRange, LoopBounds

        for item in state.stack:
            if isinstance(item, SymbolicRange):
                length = item.length
                if isinstance(length, int):
                    return LoopBound.constant(length)
                elif isinstance(length, z3.ArithRef):
                    return LoopBound.symbolic(length)
        for addr, obj in state.memory.items():
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if isinstance(val, SymbolicRange):
                        length = val.length
                        if isinstance(length, int):
                            return LoopBound.constant(length)
                        elif isinstance(length, z3.ArithRef):
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
                init_val = iv.initial
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
        instructions: list,
        state: VMState,
    ) -> dict[str, InductionVariable]:
        """Detect induction variables in loop body."""
        self._detected = {}
        body_instructions = [instr for instr in instructions if instr.offset in loop.body_pcs]
        stores: dict[str, list] = {}
        loads: dict[str, list] = {}
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
        stores: list,
        loads: list,
        instructions: list,
        state: VMState,
    ) -> InductionVariable | None:
        """Analyze if variable follows induction pattern."""
        for store_idx, store_instr in stores:
            if store_idx < 3:
                continue
            prev_instrs = [
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


@dataclass
class LoopSummary:
    """Summary of loop effects for fast-path execution."""

    iterations: z3.ExprRef | int
    variable_effects: dict[str, z3.ExprRef]
    memory_effects: dict[int, dict[str, z3.ExprRef]]
    invariants_verified: bool = False
    can_summarize: bool = False


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
                from pyspectre.core.types import SymbolicValue

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
        invariants = []
        for name, iv in loop.induction_vars.items():
            sym_var = state.locals.get(name)
            if sym_var and hasattr(sym_var, "z3_int"):
                invariants.append(sym_var.z3_int >= iv.initial)
                if loop.bound is not None and loop.bound.upper is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        invariants.append(sym_var.z3_int <= final)
                    else:
                        invariants.append(sym_var.z3_int >= final)
        from pyspectre.core.iterators import SymbolicRange

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
        from pyspectre.core.solver import is_satisfiable

        constraints = list(state.path_constraints) + [z3.Not(invariant)]
        return not is_satisfiable(constraints)


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def __init__(self, widening_threshold: int = 3):
        self.widening_threshold = widening_threshold
        self._iteration_count: dict[int, int] = {}

    def should_widen(self, loop: LoopInfo) -> bool:
        """Check if widening should be applied."""
        count = self._iteration_count.get(loop.header_pc, 0)
        return count >= self.widening_threshold

    def record_iteration(self, loop: LoopInfo) -> None:
        """Record a loop iteration."""
        pc = loop.header_pc
        self._iteration_count[pc] = self._iteration_count.get(pc, 0) + 1

    def widen_state(
        self,
        old_state: VMState,
        new_state: VMState,
        loop: LoopInfo,
    ) -> VMState:
        """Apply widening to generalize loop state."""
        from pyspectre.core.types import SymbolicValue

        widened = new_state.copy()
        for name, iv in loop.induction_vars.items():
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                widened_sym, _constraint = SymbolicValue.symbolic(f"{name}_widened")
                widened.locals[name] = widened_sym
                widened.path_constraints.append(widened_sym.z3_int >= iv.initial)
                if loop.bound is not None and loop.bound.upper is not None:
                    final = iv.final_value(loop.bound.upper)
                    widened.path_constraints.append(widened_sym.z3_int <= final)
        for name in set(old_state.locals.keys()) | set(new_state.locals.keys()):
            if name in loop.induction_vars:
                continue
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                if isinstance(old_val, SymbolicValue) and isinstance(new_val, SymbolicValue):
                    widened_sym, _constraint = SymbolicValue.symbolic(f"{name}_widened")
                    widened.locals[name] = widened_sym
        return widened


__all__ = [
    "LoopType",
    "LoopBound",
    "LoopInfo",
    "InductionVariable",
    "LoopDetector",
    "LoopBoundInference",
    "InductionVariableDetector",
    "LoopSummary",
    "LoopSummarizer",
    "LoopInvariantGenerator",
    "LoopWidening",
]
