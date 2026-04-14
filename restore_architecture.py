import os

base_dir = "pysymex/analysis/detectors/logical"

# Helper to write files with headers
def write_p(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("from __future__ import annotations\n" + content)

# --- Tier 1 ---
write_p(f"{base_dir}/t1_local/range.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_bounds, bounds_are_inconsistent

class RangeContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Range Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        bounds = extract_bounds(ctx.core)
        for var_bounds in bounds.values():
            if bounds_are_inconsistent(var_bounds):
                return True
        return False
""")

write_p(f"{base_dir}/t1_local/parity.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_modulo_equalities

class ParityContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Parity Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        mods = extract_modulo_equalities(ctx.core)
        parity_mods = [m for m in mods if m[1] == 2]
        remainders = {m[2] for m in parity_mods}
        return len(remainders) >= 2
""")

write_p(f"{base_dir}/t1_local/modular.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_modulo_equalities

class ModularContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Modular Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        mods = extract_modulo_equalities(ctx.core)
        if not mods: return False
        by_mod: dict[int, set[int]] = {}
        for _, m, r in mods:
            by_mod.setdefault(m, set()).add(r)
        return any(len(rs) >= 2 for rs in by_mod.values())
""")

write_p(f"{base_dir}/t1_local/self_contradiction.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class SelfContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Self-Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        return count_variables(ctx.core) == 1 and len(ctx.core) == 1
""")

write_p(f"{base_dir}/t1_local/arithmetic.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, is_sat_over_reals

class ArithmeticImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "Arithmetic Impossibility"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        return is_sat_over_reals(ctx.core)
""")

write_p(f"{base_dir}/t1_local/equality.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_var_const_equalities

class EqualityContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Equality Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        eqs = extract_var_const_equalities(ctx.core)
        for values in eqs.values():
            if len(values) >= 2: return True
        return False
""")

write_p(f"{base_dir}/t1_local/complement.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class ComplementContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Complement Contradiction"
    @property
    def tier(self) -> int: return 1
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1: return False
        return core_has_operator(ctx.core, {z3.Z3_OP_NOT})
""")

with open(f"{base_dir}/t1_local/__init__.py", "w") as f:
    f.write("""\
from .range import RangeContradictionRule
from .parity import ParityContradictionRule
from .modular import ModularContradictionRule
from .self_contradiction import SelfContradictionRule
from .arithmetic import ArithmeticImpossibilityRule
from .equality import EqualityContradictionRule
from .complement import ComplementContradictionRule

__all__ = [
    "RangeContradictionRule",
    "ParityContradictionRule",
    "ModularContradictionRule",
    "SelfContradictionRule",
    "ArithmeticImpossibilityRule",
    "EqualityContradictionRule",
    "ComplementContradictionRule",
]
""")

# --- Tier 2 ---
write_p(f"{base_dir}/t2_multivar/antisymmetry.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_var_var_comparisons

class AntisymmetryRule(LogicRule):
    @property
    def name(self) -> str: return "Antisymmetry Violation"
    @property
    def tier(self) -> int: return 2
    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 2: return False
        cmps = extract_var_var_comparisons(ctx.core)
        return len(cmps) >= 2
""")

write_p(f"{base_dir}/t2_multivar/triangle.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables

class TriangleImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "Triangle Impossibility"
    @property
    def tier(self) -> int: return 2
    def matches(self, ctx: ContradictionContext) -> bool:
        return count_variables(ctx.core) >= 3 and len(ctx.core) >= 3
""")

write_p(f"{base_dir}/t2_multivar/sum_impossibility.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class SumImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "Sum Impossibility"
    @property
    def tier(self) -> int: return 2
    def matches(self, ctx: ContradictionContext) -> bool:
        return core_has_operator(ctx.core, {z3.Z3_OP_ADD}) and count_variables(ctx.core) >= 2
""")

write_p(f"{base_dir}/t2_multivar/product_sign.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator

class ProductSignContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Product Sign Contradiction"
    @property
    def tier(self) -> int: return 2
    def matches(self, ctx: ContradictionContext) -> bool:
        return core_has_operator(ctx.core, {z3.Z3_OP_MUL}) and count_variables(ctx.core) >= 2
""")

write_p(f"{base_dir}/t2_multivar/gcd_impossibility.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables, extract_modulo_equalities

class GcdImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "GCD Impossibility"
    @property
    def tier(self) -> int: return 2
    def matches(self, ctx: ContradictionContext) -> bool:
        mods = extract_modulo_equalities(ctx.core)
        return count_variables(ctx.core) >= 2 and len(mods) >= 2
""")

with open(f"{base_dir}/t2_multivar/__init__.py", "w") as f:
    f.write("""\
from .antisymmetry import AntisymmetryRule
from .triangle import TriangleImpossibilityRule
from .sum_impossibility import SumImpossibilityRule
from .product_sign import ProductSignContradictionRule
from .gcd_impossibility import GcdImpossibilityRule

__all__ = [
    "AntisymmetryRule",
    "TriangleImpossibilityRule",
    "SumImpossibilityRule",
    "ProductSignContradictionRule",
    "GcdImpossibilityRule",
]
""")

# --- Tier 3 ---
write_p(f"{base_dir}/t3_path/sequential_modular.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import core_has_operator

class SequentialModularRule(LogicRule):
    @property
    def name(self) -> str: return "Sequential Modular Contradiction"
    @property
    def tier(self) -> int: return 3
    def matches(self, ctx: ContradictionContext) -> bool:
        return core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM}) and core_has_operator(ctx.core, {z3.Z3_OP_MUL, z3.Z3_OP_ADD})
""")

write_p(f"{base_dir}/t3_path/post_assignment.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import extract_var_const_equalities, extract_var_const_disequalities, extract_bounds

class PostAssignmentContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Post-assignment Contradiction"
    @property
    def tier(self) -> int: return 3
    def matches(self, ctx: ContradictionContext) -> bool:
        eqs = extract_var_const_equalities(ctx.core)
        diseqs = extract_var_const_disequalities(ctx.core)
        bounds = extract_bounds(ctx.core)
        for var, val_set in eqs.items():
            if var in diseqs and any(v in val_set for v in diseqs[var]): return True
            if var in bounds:
                b = bounds[var]
                for v in val_set:
                    if b["min"] is not None and v < b["min"]: return True
                    if b["max"] is not None and v > b["max"]: return True
                    if b["min_strict"] is not None and v <= b["min_strict"]: return True
                    if b["max_strict"] is not None and v >= b["max_strict"]: return True
        return False
""")

write_p(f"{base_dir}/t3_path/loop_invariant.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all

class LoopInvariantViolationRule(LogicRule):
    @property
    def name(self) -> str: return "Loop Invariant Violation"
    @property
    def tier(self) -> int: return 3
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        return any("invariant" in name.lower() for name in names)
""")

write_p(f"{base_dir}/t3_path/narrowing.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import extract_bounds, bounds_are_inconsistent

class NarrowingContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Narrowing Contradiction"
    @property
    def tier(self) -> int: return 3
    def matches(self, ctx: ContradictionContext) -> bool:
        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b): return True
        return False
""")

write_p(f"{base_dir}/t3_path/return_type.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import extract_bool_assignments

class ReturnTypeContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Return Type Contradiction"
    @property
    def tier(self) -> int: return 3
    def matches(self, ctx: ContradictionContext) -> bool:
        bools = extract_bool_assignments(ctx.core)
        for var, vals in bools.items():
            if "is_int" in var or "is_bool" in var:
                if len(vals) >= 2: return True
        return False
""")

with open(f"{base_dir}/t3_path/__init__.py", "w") as f:
    f.write("""\
from .sequential_modular import SequentialModularRule
from .post_assignment import PostAssignmentContradictionRule
from .loop_invariant import LoopInvariantViolationRule
from .narrowing import NarrowingContradictionRule
from .return_type import ReturnTypeContradictionRule

__all__ = [
    "SequentialModularRule",
    "PostAssignmentContradictionRule",
    "LoopInvariantViolationRule",
    "NarrowingContradictionRule",
    "ReturnTypeContradictionRule",
]
""")

# --- Tier 4 ---
write_p(f"{base_dir}/t4_interprocedural/postcondition.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bounds, bounds_are_inconsistent, extract_bool_assignments

class PostconditionContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Postcondition Contradiction"
    @property
    def tier(self) -> int: return 4
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("return" in n.lower() for n in names): return False
        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b): return True
        return any(len(v) >= 2 for v in extract_bool_assignments(ctx.core).values())
""")

write_p(f"{base_dir}/t4_interprocedural/precondition.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bounds, bounds_are_inconsistent, extract_var_const_equalities

class PreconditionImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "Precondition Impossibility"
    @property
    def tier(self) -> int: return 4
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any(n.startswith("arg_") for n in names): return False
        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b): return True
        return any(len(v) >= 2 for v in extract_var_const_equalities(ctx.core).values())
""")

write_p(f"{base_dir}/t4_interprocedural/api_contract.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bool_assignments

class ApiContractViolationRule(LogicRule):
    @property
    def name(self) -> str: return "API Contract Violation"
    @property
    def tier(self) -> int: return 4
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("havoc" in n.lower() or "call_result" in n.lower() for n in names): return False
        return any(len(v) >= 2 for v in extract_bool_assignments(ctx.core).values())
""")

write_p(f"{base_dir}/t4_interprocedural/taint_constraint.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bounds, bounds_are_inconsistent, extract_bool_assignments

class TaintConstraintContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Taint + Constraint Contradiction"
    @property
    def tier(self) -> int: return 4
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("taint" in n.lower() or "sanitiz" in n.lower() for n in names): return False
        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b): return True
        return any(len(v) >= 2 for v in extract_bool_assignments(ctx.core).values())
""")

write_p(f"{base_dir}/t4_interprocedural/range_propagation.py", """\
import z3
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bounds, bounds_are_inconsistent, extract_var_var_comparisons

class NumericRangePropagationRule(LogicRule):
    @property
    def name(self) -> str: return "Numeric Range Propagation Contradiction"
    @property
    def tier(self) -> int: return 4
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if len(names) < 2: return False
        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b): return True
        return len(extract_var_var_comparisons(ctx.core)) >= 2
""")

with open(f"{base_dir}/t4_interprocedural/__init__.py", "w") as f:
    f.write("""\
from .postcondition import PostconditionContradictionRule
from .precondition import PreconditionImpossibilityRule
from .api_contract import ApiContractViolationRule
from .taint_constraint import TaintConstraintContradictionRule
from .range_propagation import NumericRangePropagationRule

__all__ = [
    "PostconditionContradictionRule",
    "PreconditionImpossibilityRule",
    "ApiContractViolationRule",
    "TaintConstraintContradictionRule",
    "NumericRangePropagationRule",
]
""")

# --- Tier 5 ---
write_p(f"{base_dir}/t5_temporal/state_impossibility.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bool_assignments

class StateImpossibilityRule(LogicRule):
    @property
    def name(self) -> str: return "State Impossibility"
    @property
    def tier(self) -> int: return 5
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("state" in n.lower() for n in names): return False
        return any(len(v) >= 2 for v in extract_bool_assignments(ctx.core).values())
""")

write_p(f"{base_dir}/t5_temporal/resource_state.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_bool_assignments

class ResourceStateContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Resource State Contradiction"
    @property
    def tier(self) -> int: return 5
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("file" in n.lower() or "handle" in n.lower() or "socket" in n.lower() for n in names): return False
        return any(len(v) >= 2 for v in extract_bool_assignments(ctx.core).values())
""")

write_p(f"{base_dir}/t5_temporal/concurrency.py", """\
from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import get_variable_names_all, extract_var_var_comparisons

class ConcurrencyContradictionRule(LogicRule):
    @property
    def name(self) -> str: return "Concurrency Contradiction"
    @property
    def tier(self) -> int: return 5
    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        if not any("lock" in n.lower() or "thread" in n.lower() for n in names): return False
        return len(extract_var_var_comparisons(ctx.core)) >= 2
""")

with open(f"{base_dir}/t5_temporal/__init__.py", "w") as f:
    f.write("""\
from .state_impossibility import StateImpossibilityRule
from .resource_state import ResourceStateContradictionRule
from .concurrency import ConcurrencyContradictionRule

__all__ = [
    "StateImpossibilityRule",
    "ResourceStateContradictionRule",
    "ConcurrencyContradictionRule",
]
""")

print("done")
