"""
Quantifier Core for pysymex.
Phase 21: Express "for all" and "exists" in contracts.
Provides:
- forall(var, range, condition) - Universal quantification
- exists(var, range, condition) - Existential quantification
- Z3 quantifier encoding
- Quantifier instantiation heuristics
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from typing import (
    cast,
)

import z3

from pysymex.contracts.quantifiers_types import (
    BoundSpec,
    Quantifier,
    QuantifierKind,
    QuantifierVar,
)
from pysymex.core.addressing import next_address


class QuantifierParser:
    """Parses quantifier expressions from contract strings.

    Supported syntax::

        forall(var, lower <= var < upper, condition)
        forall(var, var in collection, condition)
        exists(var, lower <= var < upper, condition)
        exists!(var, range, condition)   # Unique existence
    """

    QUANTIFIER_PATTERN = re.compile(
        r"(forall|exists|exists!)\s*\(\s*" r"(\w+)\s*,\s*" r"([^,]+)\s*,\s*" r"(.+)\s*\)$"
    )
    RANGE_PATTERN = re.compile(r"(\d+|\w+)\s*(<=?)\s*(\w+)\s*(<|<=)\s*(\d+|\w+|\w+\([^)]+\))")
    IN_PATTERN = re.compile(r"(\w+)\s+in\s+(\w+)")

    def __init__(self, context: dict[str, z3.ExprRef] | None = None):
        self.context = context or {}

    def parse(self, text: str) -> Quantifier | None:
        """Parse a quantifier expression."""
        text = text.strip()
        match = self.QUANTIFIER_PATTERN.match(text)
        if not match:
            return None
        kind_str, var_name, range_str, body_str = match.groups()
        if kind_str == "forall":
            kind = QuantifierKind.FORALL
        elif kind_str == "exists":
            kind = QuantifierKind.EXISTS
        elif kind_str == "exists!":
            kind = QuantifierKind.UNIQUE
        else:
            return None
        var = QuantifierVar(name=var_name, sort=z3.IntSort())
        bounds = self._parse_bounds(range_str, var_name)
        body = self._parse_body(body_str, {var_name: var.z3_var})
        return Quantifier(
            kind=kind,
            variables=[var],
            bounds=[bounds],
            body=body,
            original_text=text,
        )

    def _parse_bounds(self, range_str: str, var_name: str) -> BoundSpec:
        """Parse range/bounds specification."""
        range_str = range_str.strip()
        range_match = self.RANGE_PATTERN.match(range_str)
        if range_match:
            lower_val, lower_op, _matched_var, upper_op, upper_val = range_match.groups()
            return BoundSpec(
                lower=self._parse_expr(lower_val),
                upper=self._parse_expr(upper_val),
                lower_inclusive=(lower_op == "<="),
                upper_inclusive=(upper_op == "<="),
            )
        in_match = self.IN_PATTERN.match(range_str)
        if in_match:
            _matched_var, collection = in_match.groups()
            return BoundSpec(in_collection=self.context.get(collection))
        return BoundSpec()

    def _parse_expr(self, expr_str: str) -> z3.ExprRef:
        """Parse an expression to Z3."""
        expr_str = expr_str.strip()
        if expr_str in self.context:
            return self.context[expr_str]
        try:
            return z3.IntVal(int(expr_str))
        except ValueError:
            pass
        if expr_str.startswith("len(") and expr_str.endswith(")"):
            inner = expr_str[4:-1]
            if inner in self.context:
                return z3.Int(f"len_{inner }")
        return z3.Int(expr_str)

    def _parse_body(self, body_str: str, local_vars: dict[str, z3.ExprRef | None]) -> z3.BoolRef:
        """Parse body expression to Z3."""
        body_str = body_str.strip()
        full_context: dict[str, z3.ExprRef] = dict(self.context)
        for k, v in local_vars.items():
            if v is not None:
                full_context[k] = v
        try:
            return parse_condition_to_z3(body_str, full_context)
        except (SyntaxError, KeyError, TypeError, z3.Z3Exception):
            return z3.Bool(f"body_{body_str [:20 ]}")


def parse_condition_to_z3(
    condition: str,
    context: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """
    Parse a Python-like condition to Z3.
    Supports:
    - Comparisons: <, <=, >, >=, ==, !=
    - Boolean: and, or, not
    - Arithmetic: +, -, *, //, %
    - Indexing: x[i]
    - Attributes: x.length
    """
    try:
        tree = ast.parse(condition, mode="eval")
        return ConditionTranslator(context).visit(tree.body)
    except SyntaxError:
        return z3.Bool(f"cond_{hash (condition )}")


class ConditionTranslator(ast.NodeVisitor):
    """Translates a Python AST condition node to an equivalent Z3 expression."""

    def __init__(self, context: dict[str, z3.ExprRef]):
        self.context = context

    def visit_Compare(self, node: ast.Compare) -> z3.BoolRef:
        """Handle comparisons."""
        left = self.visit(node.left)
        comparisons: list[z3.BoolRef] = []
        prev = left
        for op, comp in zip(node.ops, node.comparators, strict=False):
            right = self.visit(comp)
            match op:
                case ast.Lt():
                    comparisons.append(prev < right)
                case ast.LtE():
                    comparisons.append(prev <= right)
                case ast.Gt():
                    comparisons.append(prev > right)
                case ast.GtE():
                    comparisons.append(prev >= right)
                case ast.Eq():
                    comparisons.append(prev == right)
                case ast.NotEq():
                    comparisons.append(prev != right)
                case _:
                    raise ValueError(f"Unsupported comparison: {type (op )}")
            prev = right
        return z3.And(*comparisons) if len(comparisons) > 1 else comparisons[0]

    def visit_BoolOp(self, node: ast.BoolOp) -> z3.BoolRef:
        """Handle and/or."""
        values = [self.visit(v) for v in node.values]
        match node.op:
            case ast.And():
                return z3.And(*values)
            case ast.Or():
                return z3.Or(*values)
            case _:
                raise ValueError(f"Unsupported bool op: {type (node .op )}")

    def visit_UnaryOp(self, node: ast.UnaryOp) -> z3.ExprRef:
        """Handle unary operators."""
        operand = self.visit(node.operand)
        match node.op:
            case ast.Not():
                return cast(z3.ExprRef, z3.Not(operand))
            case ast.USub():
                return -operand
            case ast.UAdd():
                return operand
            case _:
                raise ValueError(f"Unsupported unary op: {type (node .op )}")

    def visit_BinOp(self, node: ast.BinOp) -> z3.ExprRef:
        """Handle binary operators."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        match node.op:
            case ast.Add():
                return left + right
            case ast.Sub():
                return left - right
            case ast.Mult():
                return left * right
            case ast.FloorDiv():
                trunc = left / right
                return cast(z3.ExprRef, z3.If(
                    z3.Or(left % right == 0, right > 0),
                    trunc,
                    trunc - 1,
                ))
            case ast.Mod():
                return left % right
            case ast.Pow():
                return left**right
            case _:
                raise ValueError(f"Unsupported binary op: {type (node .op )}")

    def visit_Subscript(self, node: ast.Subscript) -> z3.ExprRef:
        """Handle indexing."""
        value = self.visit(node.value)
        index = self.visit(node.slice)
        return z3.Select(value, index)

    def visit_Attribute(self, node: ast.Attribute) -> z3.ExprRef:
        """Handle attribute access."""
        if isinstance(node.value, ast.Name):
            obj_name = node.value.id
            attr_name = node.attr
            if attr_name == "length":
                return z3.Int(f"len_{obj_name }")
            return z3.Int(f"{obj_name }_{attr_name }")
        return z3.Int(f"attr_{node .attr }")

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        """Handle variable names."""
        name = node.id
        if name in self.context:
            return self.context[name]
        return z3.Int(name)

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        """Handle constants."""
        match node.value:
            case bool() as v:
                return z3.BoolVal(v)
            case int() as v:
                return z3.IntVal(v)
            case float() as v:
                return z3.RealVal(v)
            case None:
                return z3.BoolVal(False)
            case _:
                raise ValueError(f"Unsupported constant type: {type (node.value )}")

    def visit_Call(self, node: ast.Call) -> z3.ExprRef:
        """Handle function calls."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "len" and len(node.args) == 1:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    return z3.Int(f"len_{arg .id }")
            if func_name == "abs" and len(node.args) == 1:
                arg = self.visit(node.args[0])
                return z3.If(arg >= 0, arg, -arg)
            if func_name == "min" and len(node.args) == 2:
                a, b = [self.visit(arg) for arg in node.args]
                return z3.If(a <= b, a, b)
            if func_name == "max" and len(node.args) == 2:
                a, b = [self.visit(arg) for arg in node.args]
                return z3.If(a >= b, a, b)
        return z3.Int(f"call_{next_address ()}")

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        """Fallback for unsupported nodes."""
        return z3.Int(f"unknown_{type (node ).__name__ }")


def forall(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str | Callable[[object], bool],
) -> Quantifier:
    """
    Create a universal quantifier.
    Examples:
        forall('i', (0, 10), 'x[i] >= 0')
        forall('i', '0 <= i < len(x)', 'x[i] > x[i-1]')  # Sorted
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower } <= {var } < {upper }"
    else:
        range_str = range_spec
    if isinstance(condition, str):
        cond_str = condition
    else:
        cond_str = str(condition)
    text = f"forall({var }, {range_str }, {cond_str })"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse universal quantifier: {text }")
    return result


def exists(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str | Callable[[object], bool],
) -> Quantifier:
    """
    Create an existential quantifier.
    Examples:
        exists('i', (0, 10), 'x[i] == target')
        exists('i', '0 <= i < len(x)', 'x[i] == 0')
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower } <= {var } < {upper }"
    else:
        range_str = range_spec
    if isinstance(condition, str):
        cond_str = condition
    else:
        cond_str = str(condition)
    text = f"exists({var }, {range_str }, {cond_str })"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse existential quantifier: {text }")
    return result


def exists_unique(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str | Callable[[object], bool],
) -> Quantifier:
    """
    Create a unique existential quantifier (exactly one).
    Examples:
        exists_unique('i', (0, 10), 'x[i] == target')
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower } <= {var } < {upper }"
    else:
        range_str = range_spec
    if isinstance(condition, str):
        cond_str = condition
    else:
        cond_str = str(condition)
    text = f"exists!({var }, {range_str }, {cond_str })"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse unique existential quantifier: {text }")
    return result


class QuantifierInstantiator:
    """Instantiates quantifiers with concrete values.

    For bounded quantifiers, enumerates all instances up to
    ``max_instantiations``.  For unbounded quantifiers, relies on
    E-matching triggers.

    Attributes:
        max_instantiations: Upper limit on enumerated instances.
    """

    def __init__(self, max_instantiations: int = 100):
        self.max_instantiations = max_instantiations

    def instantiate_bounded(
        self,
        quantifier: Quantifier,
        solver: z3.Solver,
    ) -> list[z3.BoolRef]:
        """
        Instantiate a bounded quantifier by enumeration.
        Only works for small integer bounds.
        """
        if quantifier.kind not in (QuantifierKind.FORALL, QuantifierKind.EXISTS):
            return []
        instances: list[z3.BoolRef] = []
        for var, bound in zip(quantifier.variables, quantifier.bounds, strict=False):
            if bound.lower is not None and bound.upper is not None:
                try:
                    lower = self._get_concrete_value(bound.lower, solver)
                    upper = self._get_concrete_value(bound.upper, solver)
                    if lower is None or upper is None:
                        continue
                    range_size = upper - lower
                    if range_size > self.max_instantiations:
                        continue
                    for i in range(lower, upper):
                        instance = z3.substitute(quantifier.body, (var.z3_var, z3.IntVal(i)))
                        instances.append(cast("z3.BoolRef", instance))
                except z3.Z3Exception:
                    continue
        return instances

    def _get_concrete_value(
        self,
        expr: z3.ExprRef,
        solver: z3.Solver,
    ) -> int | None:
        """Try to get concrete value for expression."""
        if z3.is_int_value(expr):
            return cast(z3.IntNumRef, expr).as_long()
        solver.push()
        v = z3.Int("__bound")
        solver.add(v == expr)
        if solver.check() == z3.sat:
            model = solver.model()
            result = model.eval(v)
            solver.pop()
            if z3.is_int_value(result):
                return cast(z3.IntNumRef, result).as_long()
        solver.pop()
        return None

    def add_triggers(
        self,
        quantifier: Quantifier,
        triggers: list[z3.ExprRef],
    ) -> z3.BoolRef:
        """
        Add E-matching triggers to quantifier.
        Triggers guide the solver on when to instantiate.
        """
        z3_expr = quantifier.to_z3()
        if not triggers:
            return z3_expr
        z3_vars = [v.z3_var for v in quantifier.variables]
        if quantifier.kind == QuantifierKind.FORALL:
            return z3.ForAll(
                z3_vars,
                z3.Implies(
                    z3.And(
                        *[
                            b.to_constraint(v.z3_var)
                            for v, b in zip(quantifier.variables, quantifier.bounds, strict=False)
                        ]
                    ),
                    quantifier.body,
                ),
                patterns=[z3.MultiPattern(*triggers)],
            )
        return z3_expr


class QuantifierVerifier:
    """Verifies quantified contracts via Z3 SMT solving.

    Attributes:
        timeout_ms: Solver timeout in milliseconds.
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def verify_forall(
        self,
        quantifier: Quantifier,
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool | None, dict[str, object] | None]:
        """
        Verify a forall quantifier.
        Returns (valid, counterexample or None).
        """
        assert quantifier.kind == QuantifierKind.FORALL
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        if context_constraints:
            for c in context_constraints:
                solver.add(c)
        z3_expr = quantifier.to_z3()
        solver.add(z3.Not(z3_expr))
        result = solver.check()
        if result == z3.unsat:
            return True, None
        elif result == z3.sat:
            model = solver.model()
            counterexample: dict[str, object] = {str(d.name()): model[d] for d in model.decls()}
            return False, counterexample
        else:
            return None, None

    def verify_exists(
        self,
        quantifier: Quantifier,
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool | None, dict[str, object] | None]:
        """
        Verify an exists quantifier.
        Returns (satisfiable, witness or None).
        """
        assert quantifier.kind == QuantifierKind.EXISTS
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        if context_constraints:
            for c in context_constraints:
                solver.add(c)
        z3_expr = quantifier.to_z3()
        solver.add(z3_expr)
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            witness: dict[str, object] = {str(d.name()): model[d] for d in model.decls()}
            return True, witness
        elif result == z3.unsat:
            return False, None
        else:
            return None, None


def _find_matching_paren(s: str, start: int) -> int:
    """Find the index of the matching closing parenthesis."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def extract_quantifiers(contract_string: str) -> list[Quantifier]:
    """
    Extract quantifiers from a contract string.
    Example:
        'forall(i, 0 <= i < len(x), x[i] >= 0) and result > 0'
        -> [Quantifier(FORALL, ...)]
    """
    quantifiers: list[Quantifier] = []
    parser = QuantifierParser()
    keywords = [
        ("forall", QuantifierKind.FORALL),
        ("exists!", QuantifierKind.UNIQUE),
        ("exists", QuantifierKind.EXISTS),
    ]
    for keyword, _kind in keywords:
        start = 0
        while True:
            idx = contract_string.find(keyword + "(", start)
            if idx == -1:
                break
            paren_start = idx + len(keyword)
            paren_end = _find_matching_paren(contract_string, paren_start)
            if paren_end == -1:
                start = idx + 1
                continue
            text = contract_string[idx : paren_end + 1]
            q = parser.parse(text)
            if q:
                quantifiers.append(q)
            start = paren_end + 1
    return quantifiers


def replace_quantifiers_with_z3(
    contract_string: str,
    context: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """
    Replace quantifiers in contract string with Z3 expressions.
    Returns the full contract as Z3.
    """
    quantifiers = extract_quantifiers(contract_string)
    remaining = contract_string
    z3_parts: list[z3.BoolRef] = []
    for q in quantifiers:
        z3_parts.append(q.to_z3())
        remaining = remaining.replace(q.original_text, "True")
    if remaining.strip() and remaining.strip() != "True":
        remaining_z3 = parse_condition_to_z3(remaining, context)
        z3_parts.append(remaining_z3)
    if not z3_parts:
        return z3.BoolVal(True)
    elif len(z3_parts) == 1:
        return z3_parts[0]
    else:
        return z3.And(*z3_parts)


__all__ = [
    "ConditionTranslator",
    "QuantifierInstantiator",
    "QuantifierParser",
    "QuantifierVerifier",
    "exists",
    "exists_unique",
    "extract_quantifiers",
    "forall",
    "parse_condition_to_z3",
    "replace_quantifiers_with_z3",
]
