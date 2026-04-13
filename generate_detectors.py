import os

base_dir = "pysymex/analysis/detectors/logical"

files = {
    f"{base_dir}/__init__.py": """\
from pysymex.analysis.detectors.logical.base import LogicalContradictionDetector
from pysymex.analysis.detectors.logical.t1_local import *
from pysymex.analysis.detectors.logical.t2_multivar import *
from pysymex.analysis.detectors.logical.t3_path import *
from pysymex.analysis.detectors.logical.t4_interprocedural import *
from pysymex.analysis.detectors.logical.t5_temporal import *

def create_logic_detector() -> LogicalContradictionDetector:
    detector = LogicalContradictionDetector()
    
    # Tier 1
    detector.register_rule(RangeContradictionRule())
    detector.register_rule(ParityContradictionRule())
    detector.register_rule(ModularContradictionRule())
    detector.register_rule(SelfContradictionRule())
    detector.register_rule(ArithmeticImpossibilityRule())
    detector.register_rule(EqualityContradictionRule())
    detector.register_rule(ComplementContradictionRule())
    
    # Tier 2
    detector.register_rule(AntisymmetryRule())
    detector.register_rule(TriangleImpossibilityRule())
    detector.register_rule(SumImpossibilityRule())
    detector.register_rule(ProductSignContradictionRule())
    detector.register_rule(GcdImpossibilityRule())
    
    # Tier 3
    detector.register_rule(SequentialModularRule())
    detector.register_rule(PostAssignmentContradictionRule())
    detector.register_rule(LoopInvariantViolationRule())
    detector.register_rule(NarrowingContradictionRule())
    detector.register_rule(ReturnTypeContradictionRule())
    
    # Tier 4
    detector.register_rule(PostconditionContradictionRule())
    detector.register_rule(PreconditionImpossibilityRule())
    detector.register_rule(ApiContractViolationRule())
    detector.register_rule(TaintConstraintContradictionRule())
    detector.register_rule(NumericRangePropagationRule())
    
    # Tier 5
    detector.register_rule(StateImpossibilityRule())
    detector.register_rule(ResourceStateContradictionRule())
    detector.register_rule(ConcurrencyContradictionRule())
    
    return detector

__all__ = ["LogicalContradictionDetector", "create_logic_detector"]
""",
    f"{base_dir}/base.py": """\
from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING
import z3
from pysymex.analysis.detectors.base import Detector, Issue
from pysymex.analysis.detectors.types import IssueKind
from pysymex.core.solver.unsat import extract_unsat_core

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex._typing import _IsSatFn

@dataclass
class ContradictionContext:
    core: list[z3.BoolRef]
    branch_cond: z3.BoolRef
    path_constraints: list[z3.BoolRef]

class LogicRule(ABC):
    @property
    @abstractmethod
    def name(self) -> str: pass
    
    @property
    @abstractmethod
    def tier(self) -> int: pass

    @abstractmethod
    def matches(self, ctx: ContradictionContext) -> bool: pass

class LogicalContradictionDetector(Detector):
    name = "logical-contradiction"
    description = "Detects mathematically impossible paths indicating a flawed mental model."
    issue_kind = IssueKind.LOGICAL_CONTRADICTION
    relevant_opcodes = frozenset({
        "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE",
        "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_TRUE", "POP_JUMP_BACKWARD_IF_FALSE",
        "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP"
    })

    def __init__(self) -> None:
        self.rules: list[LogicRule] = []

    def register_rule(self, rule: LogicRule) -> None:
        self.rules.append(rule)

    def check(self, state: VMState, instruction: dis.Instruction, _solver_check: _IsSatFn) -> Issue | None:
        if not state.stack:
            return None

        from pysymex.execution.opcodes.base.control import get_truthy_expr
        cond = state.peek()
        cond_expr = get_truthy_expr(cond)

        if "FALSE" in instruction.opname:
            branch_cond_true = z3.Not(cond_expr)
            branch_cond_false = cond_expr
        else:
            branch_cond_true = cond_expr
            branch_cond_false = z3.Not(cond_expr)

        path_constraints = state.path_constraints.to_list()
        
        for branch_cond in (branch_cond_true, branch_cond_false):
            branch_path = path_constraints + [branch_cond]
            
            if not _solver_check(branch_path):
                core_result = extract_unsat_core(branch_path)
                
                if not core_result or not core_result.core:
                    core = [branch_cond]
                else:
                    core = core_result.core

                ctx = ContradictionContext(core, branch_cond, path_constraints)
                
                classification = "Unknown Logical Contradiction"
                for rule in sorted(self.rules, key=lambda r: r.tier):
                    if rule.matches(ctx):
                        classification = f"Tier {rule.tier}: {rule.name}"
                        break
                
                return Issue(
                    kind=self.issue_kind,
                    message=f"Logical Contradiction ({classification}): Path condition is mathematically impossible.",
                    constraints=core,
                    model=None,
                    pc=state.pc
                )

        return None
""",
    f"{base_dir}/utils.py": """\
from __future__ import annotations
from typing import Iterable
import z3

def get_variables(expr: z3.ExprRef) -> set[z3.ExprRef]:
    vars_set: set[z3.ExprRef] = set()
    worklist = [expr]
    seen = {expr.get_id()}
    ignore_patterns = ["_is_", "cmp_mixed", "type_constraint", "iter_"]
    while worklist:
        node = worklist.pop()
        if z3.is_const(node) and node.decl().arity() == 0:
            if node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                name = node.decl().name()
                if not any(pat in name for pat in ignore_patterns):
                    vars_set.add(node)
                continue
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
    return vars_set

def get_variables_for_core(core: Iterable[z3.ExprRef]) -> set[z3.ExprRef]:
    vars_set: set[z3.ExprRef] = set()
    for c in core:
        vars_set.update(get_variables(c))
    return vars_set

def has_operator(expr: z3.ExprRef, target_kinds: set[int]) -> bool:
    worklist = [expr]
    seen = {expr.get_id()}
    while worklist:
        node = worklist.pop()
        if z3.is_app(node):
            if node.decl().kind() in target_kinds:
                return True
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
    return False

def core_has_operator(core: Iterable[z3.ExprRef], target_kinds: set[int]) -> bool:
    for c in core:
        if has_operator(c, target_kinds):
            return True
    return False

def count_variables(core: Iterable[z3.ExprRef]) -> int:
    return len(get_variables_for_core(core))
""",
    
    # Tier 1
    f"{base_dir}/t1_local/__init__.py": """\
from .range import RangeContradictionRule
from .parity import ParityContradictionRule
from .modular import ModularContradictionRule
from .self_contradiction import SelfContradictionRule
from .arithmetic import ArithmeticImpossibilityRule
from .equality import EqualityContradictionRule
from .complement import ComplementContradictionRule

__all__ = [
    "RangeContradictionRule", "ParityContradictionRule", "ModularContradictionRule",
    "SelfContradictionRule", "ArithmeticImpossibilityRule", "EqualityContradictionRule",
    "ComplementContradictionRule"
]
""",
    f"{base_dir}/t1_local/range.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class RangeContradictionRule(LogicRule):
    name = "Range Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        core_str = " ".join(str(c) for c in ctx.core)
        has_gt = ">" in core_str or ("Not(" in core_str and "<=" in core_str)
        has_lt = "<" in core_str or ("Not(" in core_str and ">=" in core_str)
        return has_gt and has_lt
""",
    f"{base_dir}/t1_local/parity.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class ParityContradictionRule(LogicRule):
    name = "Parity Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        return "% 2" in " ".join(str(c) for c in ctx.core)
""",
    f"{base_dir}/t1_local/modular.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class ModularContradictionRule(LogicRule):
    name = "Modular Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        core_str = " ".join(str(c) for c in ctx.core)
        if "*" in core_str: return False
        return "%" in core_str
""",
    f"{base_dir}/t1_local/self_contradiction.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class SelfContradictionRule(LogicRule):
    name = "Self-Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        return count_variables(ctx.core) == 1 and len(ctx.core) == 1
""",
    f"{base_dir}/t1_local/arithmetic.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class ArithmeticImpossibilityRule(LogicRule):
    name = "Arithmetic Impossibility"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        core_str = " ".join(str(c) for c in ctx.core)
        if "%" in core_str: return False
        return ("+" in core_str or "*" in core_str or "-" in core_str) and "==" in core_str
""",
    f"{base_dir}/t1_local/equality.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class EqualityContradictionRule(LogicRule):
    name = "Equality Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        return sum(1 for c in ctx.core if "==" in str(c)) >= 2
""",
    f"{base_dir}/t1_local/complement.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class ComplementContradictionRule(LogicRule):
    name = "Complement Contradiction"
    tier = 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        return any("Not(" in str(c) for c in ctx.core)
""",

    # Tier 2
    f"{base_dir}/t2_multivar/__init__.py": """\
from .antisymmetry import AntisymmetryRule
from .triangle import TriangleImpossibilityRule
from .sum_impossibility import SumImpossibilityRule
from .product_sign import ProductSignContradictionRule
from .gcd_impossibility import GcdImpossibilityRule

__all__ = [
    "AntisymmetryRule", "TriangleImpossibilityRule", "SumImpossibilityRule",
    "ProductSignContradictionRule", "GcdImpossibilityRule"
]
""",
    f"{base_dir}/t2_multivar/antisymmetry.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class AntisymmetryRule(LogicRule):
    name = "Antisymmetry Violation"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 2: return False
        core_str = " ".join(str(c) for c in ctx.core)
        has_gt = ">" in core_str or ("Not(" in core_str and "<=" in core_str)
        has_lt = "<" in core_str or ("Not(" in core_str and ">=" in core_str)
        return has_gt or has_lt
""",
    f"{base_dir}/t2_multivar/triangle.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class TriangleImpossibilityRule(LogicRule):
    name = "Triangle Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 3 or len(ctx.core) < 3: return False
        core_str = " ".join(str(c) for c in ctx.core)
        has_gt = ">" in core_str or ("Not(" in core_str and "<=" in core_str)
        has_lt = "<" in core_str or ("Not(" in core_str and ">=" in core_str)
        return has_gt or has_lt
""",
    f"{base_dir}/t2_multivar/sum_impossibility.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class SumImpossibilityRule(LogicRule):
    name = "Sum Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        core_str = " ".join(str(c) for c in ctx.core)
        return "+" in core_str and "==" in core_str and (">" in core_str or "<" in core_str or "Not(" in core_str)
""",
    f"{base_dir}/t2_multivar/product_sign.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class ProductSignContradictionRule(LogicRule):
    name = "Product Sign Contradiction"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        core_str = " ".join(str(c) for c in ctx.core)
        return "*" in core_str and (">" in core_str or "<" in core_str or "Not(" in core_str)
""",
    f"{base_dir}/t2_multivar/gcd_impossibility.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class GcdImpossibilityRule(LogicRule):
    name = "GCD Impossibility"
    tier = 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2: return False
        return "%" in " ".join(str(c) for c in ctx.core)
""",

    # Tier 3
    f"{base_dir}/t3_path/__init__.py": """\
from .sequential_modular import SequentialModularRule
from .post_assignment import PostAssignmentContradictionRule
from .loop_invariant import LoopInvariantViolationRule
from .narrowing import NarrowingContradictionRule
from .return_type import ReturnTypeContradictionRule

__all__ = [
    "SequentialModularRule", "PostAssignmentContradictionRule", "LoopInvariantViolationRule",
    "NarrowingContradictionRule", "ReturnTypeContradictionRule"
]
""",
    f"{base_dir}/t3_path/sequential_modular.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class SequentialModularRule(LogicRule):
    name = "Sequential Modular Contradiction"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        core_str = " ".join(str(c) for c in ctx.core)
        return "%" in core_str and "*" in core_str
""",
    f"{base_dir}/t3_path/post_assignment.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class PostAssignmentContradictionRule(LogicRule):
    name = "Post-assignment Contradiction"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        core_str = " ".join(str(c) for c in ctx.core)
        has_eq = "==" in core_str
        has_cmp = ">" in core_str or "<" in core_str or "Not(" in core_str
        return has_eq and has_cmp and len(ctx.core) > 1
""",
    f"{base_dir}/t3_path/loop_invariant.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class LoopInvariantViolationRule(LogicRule):
    name = "Loop Invariant Violation"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        return False
""",
    f"{base_dir}/t3_path/narrowing.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class NarrowingContradictionRule(LogicRule):
    name = "Narrowing Contradiction"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        core_str = " ".join(str(c) for c in ctx.core)
        return len(ctx.core) >= 2 and (">" in core_str or "<" in core_str or "Not(" in core_str)
""",
    f"{base_dir}/t3_path/return_type.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class ReturnTypeContradictionRule(LogicRule):
    name = "Return Type Contradiction"
    tier = 3
    def matches(self, ctx: ContradictionContext) -> bool:
        return False
""",

    # Tier 4
    f"{base_dir}/t4_interprocedural/__init__.py": """\
from .postcondition import PostconditionContradictionRule
from .precondition import PreconditionImpossibilityRule
from .api_contract import ApiContractViolationRule
from .taint_constraint import TaintConstraintContradictionRule
from .range_propagation import NumericRangePropagationRule

__all__ = [
    "PostconditionContradictionRule", "PreconditionImpossibilityRule", "ApiContractViolationRule",
    "TaintConstraintContradictionRule", "NumericRangePropagationRule"
]
""",
    f"{base_dir}/t4_interprocedural/postcondition.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class PostconditionContradictionRule(LogicRule):
    name = "Postcondition Contradiction"
    tier = 4
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t4_interprocedural/precondition.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class PreconditionImpossibilityRule(LogicRule):
    name = "Precondition Impossibility"
    tier = 4
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t4_interprocedural/api_contract.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class ApiContractViolationRule(LogicRule):
    name = "API Contract Violation"
    tier = 4
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t4_interprocedural/taint_constraint.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class TaintConstraintContradictionRule(LogicRule):
    name = "Taint + Constraint Contradiction"
    tier = 4
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t4_interprocedural/range_propagation.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import core_has_operator

class NumericRangePropagationRule(LogicRule):
    name = "Numeric Range Propagation Contradiction"
    tier = 4
    def matches(self, ctx: ContradictionContext) -> bool:
        return len(ctx.core) >= 3 and core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_LE})
""",

    # Tier 5
    f"{base_dir}/t5_temporal/__init__.py": """\
from .state_impossibility import StateImpossibilityRule
from .resource_state import ResourceStateContradictionRule
from .concurrency import ConcurrencyContradictionRule

__all__ = [
    "StateImpossibilityRule", "ResourceStateContradictionRule", "ConcurrencyContradictionRule"
]
""",
    f"{base_dir}/t5_temporal/state_impossibility.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class StateImpossibilityRule(LogicRule):
    name = "State Impossibility"
    tier = 5
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t5_temporal/resource_state.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class ResourceStateContradictionRule(LogicRule):
    name = "Resource State Contradiction"
    tier = 5
    def matches(self, ctx: ContradictionContext) -> bool: return False
""",
    f"{base_dir}/t5_temporal/concurrency.py": """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext

class ConcurrencyContradictionRule(LogicRule):
    name = "Concurrency Contradiction"
    tier = 5
    def matches(self, ctx: ContradictionContext) -> bool: return False
"""
}

for path, content in files.items():
    with open(path, "w") as f:
        f.write(content)
print("done")
