from __future__ import annotations

from typing import Iterable, cast
import z3

def get_variables(expr: z3.ExprRef, *, include_internal: bool = False) -> set[z3.ExprRef]:
    """Recursively extract all uninterpreted constants (variables) from an expression."""
    vars_set: set[z3.ExprRef] = set()
    worklist = [expr]
    seen = {expr.get_id()}
    
    ignore_patterns = ["_is_", "cmp_mixed", "type_constraint", "iter_"]
    
    while worklist:
        node = worklist.pop()
        
        if z3.is_const(node) and node.decl().arity() == 0:
            if node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                name = node.decl().name()
                if include_internal or not any(pat in name for pat in ignore_patterns):
                    vars_set.add(node)
                continue
                
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
                
    return vars_set

def get_variables_for_core(core: Iterable[z3.ExprRef], *, include_internal: bool = False) -> set[z3.ExprRef]:
    """Extract all variables from an unsat core."""
    vars_set: set[z3.ExprRef] = set()
    for c in core:
        vars_set.update(get_variables(c, include_internal=include_internal))
    return vars_set

def count_variables(core: Iterable[z3.ExprRef]) -> int:
    """Return the number of unique variables in the unsat core."""
    return len(get_variables_for_core(core))


def iter_subexpressions(expr: z3.ExprRef) -> Iterable[z3.ExprRef]:
    """Yield expression nodes in depth-first order."""
    worklist = [expr]
    seen = {expr.get_id()}
    while worklist:
        node = worklist.pop()
        yield node
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)


def _unwrap_numeric(expr: z3.ExprRef) -> z3.ExprRef:
    """Strip common wrappers used by solver normalization."""
    node = expr
    while z3.is_app(node) and node.decl().kind() == z3.Z3_OP_TO_REAL and node.num_args() == 1:
        node = node.arg(0)
    return node


def _as_int_value(expr: z3.ExprRef) -> int | None:
    node = _unwrap_numeric(expr)
    try:
        if z3.is_int_value(node):
            return node.as_long()
    except Exception:
        return None
    return None


def _as_bool_value(expr: z3.ExprRef) -> bool | None:
    if z3.is_true(expr):
        return True
    if z3.is_false(expr):
        return False
    return None


def _extract_symbol_name(expr: z3.ExprRef) -> str | None:
    node = _unwrap_numeric(expr)
    if z3.is_const(node) and node.decl().arity() == 0 and node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
        return str(node.decl().name())
    return None


def _invert_comparison(op: str) -> str:
    return {
        ">": "<",
        ">=": "<=",
        "<": ">",
        "<=": ">=",
        "==": "==",
        "!=": "!=",
    }.get(op, op)


def _negate_comparison(op: str) -> str:
    return {
        ">": "<=",
        ">=": "<",
        "<": ">=",
        "<=": ">",
        "==": "!=",
        "!=": "==",
    }.get(op, op)


def _parse_cmp(expr: z3.ExprRef) -> tuple[str, z3.ExprRef, z3.ExprRef] | None:
    if z3.is_not(expr) and expr.num_args() == 1:
        inner = _parse_cmp(expr.arg(0))
        if inner is None:
            return None
        op, lhs, rhs = inner
        return (_negate_comparison(op), lhs, rhs)

    if not z3.is_app(expr):
        return None

    kind = expr.decl().kind()
    op = {
        z3.Z3_OP_GT: ">",
        z3.Z3_OP_GE: ">=",
        z3.Z3_OP_LT: "<",
        z3.Z3_OP_LE: "<=",
        z3.Z3_OP_EQ: "==",
        z3.Z3_OP_DISTINCT: "!=",
    }.get(kind)
    if op is None or expr.num_args() != 2:
        return None
    return (op, expr.arg(0), expr.arg(1))


def extract_var_const_comparisons(core: Iterable[z3.ExprRef]) -> list[tuple[str, str, int]]:
    """Extract comparisons such as x > 3 or x == 5 from a constraint core."""
    out: list[tuple[str, str, int]] = []
    for c in core:
        cmp_data = _parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        lname = _extract_symbol_name(lhs)
        rname = _extract_symbol_name(rhs)
        lconst = _as_int_value(lhs)
        rconst = _as_int_value(rhs)

        if lname is not None and rconst is not None:
            out.append((lname, op, rconst))
            continue
        if rname is not None and lconst is not None:
            out.append((rname, _invert_comparison(op), lconst))
    return out


def extract_var_var_comparisons(core: Iterable[z3.ExprRef]) -> list[tuple[str, str, str]]:
    """Extract comparisons such as x > y or a == b from a core."""
    out: list[tuple[str, str, str]] = []
    for c in core:
        cmp_data = _parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        lname = _extract_symbol_name(lhs)
        rname = _extract_symbol_name(rhs)
        if lname is not None and rname is not None and lname != rname:
            out.append((lname, op, rname))
    return out


def extract_var_const_equalities(core: Iterable[z3.ExprRef]) -> dict[str, set[int]]:
    """Return a map of variable -> set of constant equalities from the core."""
    result: dict[str, set[int]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        if op != "==":
            continue
        result.setdefault(var, set()).add(value)
    return result


def extract_var_const_disequalities(core: Iterable[z3.ExprRef]) -> dict[str, set[int]]:
    """Return a map of variable -> set of constant disequalities from the core."""
    result: dict[str, set[int]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        if op != "!=":
            continue
        result.setdefault(var, set()).add(value)
    return result


def extract_bounds(core: Iterable[z3.ExprRef]) -> dict[str, dict[str, int | None]]:
    """Compute approximate integer interval bounds per variable."""
    bounds: dict[str, dict[str, int | None]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        b = bounds.setdefault(
            var,
            {"min": None, "max": None, "min_strict": None, "max_strict": None},
        )
        if op == ">":
            b["min_strict"] = value if b["min_strict"] is None else max(int(b["min_strict"]), value)
        elif op == ">=":
            b["min"] = value if b["min"] is None else max(int(b["min"]), value)
        elif op == "<":
            b["max_strict"] = value if b["max_strict"] is None else min(int(b["max_strict"]), value)
        elif op == "<=":
            b["max"] = value if b["max"] is None else min(int(b["max"]), value)
    return bounds


def bounds_are_inconsistent(b: dict[str, int | None]) -> bool:
    """Check whether an interval descriptor is inconsistent."""
    min_val = b.get("min")
    max_val = b.get("max")
    min_strict = b.get("min_strict")
    max_strict = b.get("max_strict")

    if min_val is not None and max_val is not None and int(min_val) > int(max_val):
        return True
    if min_strict is not None and max_strict is not None and int(min_strict) >= int(max_strict):
        return True
    if min_strict is not None and max_val is not None and int(min_strict) >= int(max_val):
        return True
    if min_val is not None and max_strict is not None and int(min_val) >= int(max_strict):
        return True
    return False


def extract_modulo_equalities(core: Iterable[z3.ExprRef]) -> list[tuple[str, int, int]]:
    """Extract modulo equalities of the form x % m == r."""
    out: list[tuple[str, int, int]] = []
    for c in core:
        cmp_data = _parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        if op != "==":
            continue

        lhs_val = _as_int_value(lhs)
        rhs_val = _as_int_value(rhs)
        if lhs_val is not None:
            mod_term = rhs
            remainder = lhs_val
        elif rhs_val is not None:
            mod_term = lhs
            remainder = rhs_val
        else:
            continue

        mod_term = _unwrap_numeric(mod_term)
        if not z3.is_app(mod_term):
            continue
        if mod_term.decl().kind() not in (z3.Z3_OP_MOD, z3.Z3_OP_REM) or mod_term.num_args() != 2:
            continue
        var = _extract_symbol_name(mod_term.arg(0))
        modulus = _as_int_value(mod_term.arg(1))
        if var is None or modulus is None or modulus == 0:
            continue
        out.append((var, modulus, remainder))
    return out


def extract_bool_assignments(core: Iterable[z3.ExprRef]) -> dict[str, set[bool]]:
    """Extract direct boolean assignments from constraints."""
    values: dict[str, set[bool]] = {}
    for c in core:
        name = _extract_symbol_name(c)
        if name is not None and z3.is_bool(c):
            values.setdefault(name, set()).add(True)
            continue

        if z3.is_not(c) and c.num_args() == 1:
            inner = c.arg(0)
            inner_name = _extract_symbol_name(inner)
            if inner_name is not None and z3.is_bool(inner):
                values.setdefault(inner_name, set()).add(False)
                continue

        cmp_data = _parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        if op not in ("==", "!="):
            continue
        lname = _extract_symbol_name(lhs)
        rname = _extract_symbol_name(rhs)
        lbool = _as_bool_value(lhs)
        rbool = _as_bool_value(rhs)

        if lname is not None and rbool is not None:
            values.setdefault(lname, set()).add(rbool if op == "==" else (not rbool))
        elif rname is not None and lbool is not None:
            values.setdefault(rname, set()).add(lbool if op == "==" else (not lbool))
    return values

def has_operator(expr: z3.ExprRef, target_kinds: set[int]) -> bool:
    """Check if the expression uses any of the specified Z3 operator kinds."""
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
    """Check if the core uses any of the specified Z3 operator kinds."""
    for c in core:
        if has_operator(c, target_kinds):
            return True
    return False

def count_operator(expr: z3.ExprRef, target_kinds: set[int]) -> int:
    """Count how many times specific operators appear in the expression."""
    count = 0
    worklist = [expr]
    seen = {expr.get_id()}
    
    while worklist:
        node = worklist.pop()
        if z3.is_app(node):
            if node.decl().kind() in target_kinds:
                count += 1
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
    return count

def core_count_operator(core: Iterable[z3.ExprRef], target_kinds: set[int]) -> int:
    """Count occurrences of operators across the core."""
    return sum(count_operator(c, target_kinds) for c in core)

def relax_to_real(expr: z3.ExprRef, var_map: dict[z3.ExprRef, z3.ExprRef]) -> z3.ExprRef:
    """Translate an integer expression to a real expression to test for arithmetic impossibility."""
    if z3.is_const(expr) and expr.decl().arity() == 0:
        if expr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            if expr.sort() == z3.IntSort():
                if expr not in var_map:
                    var_map[expr] = z3.Real(expr.decl().name())
                return var_map[expr]
            return expr
        elif expr.sort() == z3.IntSort():
            return z3.RealVal(expr.as_long())
        return expr
        
    if z3.is_app(expr):
        decl = expr.decl()
        children = [relax_to_real(c, var_map) for c in expr.children()]
        
        # Mapping integer operators to real operators
        kind = decl.kind()
        if kind == z3.Z3_OP_ADD: return z3.Sum(*children)
        if kind == z3.Z3_OP_MUL: return z3.Product(*children)
        if kind == z3.Z3_OP_SUB: return children[0] - children[1] if len(children) == 2 else -children[0]
        if kind == z3.Z3_OP_DIV or kind == z3.Z3_OP_IDIV: return children[0] / children[1]
        if kind == z3.Z3_OP_EQ: return children[0] == children[1]
        if kind == z3.Z3_OP_DISTINCT: return children[0] != children[1]
        if kind == z3.Z3_OP_LT: return children[0] < children[1]
        if kind == z3.Z3_OP_LE: return children[0] <= children[1]
        if kind == z3.Z3_OP_GT: return children[0] > children[1]
        if kind == z3.Z3_OP_GE: return children[0] >= children[1]
        if kind == z3.Z3_OP_AND: return z3.And(*children)
        if kind == z3.Z3_OP_OR: return z3.Or(*children)
        if kind == z3.Z3_OP_NOT: return z3.Not(children[0])
        if kind == z3.Z3_OP_IMPLIES: return z3.Implies(children[0], children[1])
        if kind == z3.Z3_OP_ITE: return z3.If(children[0], children[1], children[2])
        
        # If it contains modulo or something we can't cleanly relax, return original
        return expr
        
    return expr

def is_sat_over_reals(core: list[z3.BoolRef]) -> bool:
    """Check if the core is SAT when integers are relaxed to reals.
    If it is UNSAT over Ints but SAT over Reals, it's an Arithmetic Impossibility (e.g. 2x=1).
    """
    solver = z3.Solver()
    var_map: dict[z3.ExprRef, z3.ExprRef] = {}
    for c in core:
        try:
            rc = relax_to_real(c, var_map)
            solver.add(cast(z3.BoolRef, rc))
        except Exception:
            return False # If relaxation fails, we assume it's not a pure arithmetic impossibility
    return solver.check() == z3.sat

def get_variable_names(core: Iterable[z3.ExprRef]) -> set[str]:
    """Get the string names of all variables in the core."""
    return {v.decl().name() for v in get_variables_for_core(core)}


def get_variable_names_all(core: Iterable[z3.ExprRef]) -> set[str]:
    """Get variable names including internal/type marker variables."""
    return {str(v.decl().name()) for v in get_variables_for_core(core, include_internal=True)}


def expr_contains_variable(expr: z3.ExprRef, variable_name: str) -> bool:
    """Check whether an expression contains a specific symbolic variable."""
    for node in iter_subexpressions(expr):
        name = _extract_symbol_name(node)
        if name == variable_name:
            return True
    return False

def extract_constants(expr: z3.ExprRef) -> list[int]:
    """Extract all integer constants from an expression."""
    consts = []
    worklist = [expr]
    while worklist:
        node = worklist.pop()
        if z3.is_int_value(node):
            consts.append(node.as_long())
        for child in node.children():
            worklist.append(child)
    return consts
