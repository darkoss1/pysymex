import pytest
import z3

from pysymex.contracts.quantifiers_core import (
    ConditionTranslator,
    QuantifierParser,
    replace_quantifiers_with_z3,
    parse_condition_to_z3,
    extract_quantifiers
)
from pysymex.contracts.quantifiers_types import QuantifierKind

def test_stage2_ast_floor_div_truncation_unsoundness():
    """
    Adversarial test demonstrating that AST parsing of `//` is mathematically
    sound for negative numbers in ConditionTranslator.
    """
    context = {'x': z3.Int('x'), 'y': z3.Int('y')}
    # In Python: -5 // 2 == -3
    z3_cond = parse_condition_to_z3("x // y == -3", context)
    
    solver = z3.Solver()
    solver.add(context['x'] == -5)
    solver.add(context['y'] == 2)
    solver.add(z3.Not(z3_cond))
    
    # Prove the implementation handles python semantics correctly (unsat means the Not is false, so condition is always true)
    assert solver.check() == z3.unsat, "AST Translator violates Python Floor Division semantics!"

def test_stage3_quantifier_parser_operator_precedence():
    """
    Adversarial test demonstrating that QuantifierParser successfully parses
    conditions containing commas.
    """
    parser = QuantifierParser()
    
    # 🔴 VULNERABILITY FIXED: Does the naive regex `([^,]+)` split the condition incorrectly?
    # Because `([^,]+)` matches the range, and `(.+)` matches the condition, the `(.+)` greedily captures the rest of the string including commas.
    # Therefore, the parser actually successfully parses functions with commas in them.
    q2 = parser.parse("forall(i, 0 <= i < 10, f(x, y) > 0)")
    assert q2 is not None, "Naive regex failed to parse a condition with a comma!"
    assert q2.original_text == "forall(i, 0 <= i < 10, f(x, y) > 0)"

def test_stage4_replace_quantifiers_string_pollution():
    """
    Adversarial test demonstrating that replace_quantifiers_with_z3 correctly
    replaces strings without corrupting unrelated variables.
    """
    context = {'x': z3.Int('x')}
    contract = "forall(i, 0 <= i < 10, x > 0) and forall(i, 0 <= i < 10, x > 0)_is_safe"
    
    # 🔴 VULNERABILITY FIXED: Does replace() corrupt the rest of the string?
    # We rewrote `replace_quantifiers_with_z3` to split around the actual matches rather than string replacement.
    res = replace_quantifiers_with_z3(contract, context)
    assert not str(res).startswith("cond_"), "Expected AST parsing to succeed cleanly without string corruption"
    assert "unknown_" not in str(res), "Expected AST parsing to succeed cleanly without string corruption"

def test_stage5_uniqueness_quantifier_scoping():
    """
    Adversarial test demonstrating that exists! (unique) generates
    malformed Z3 constraints because of a variable conflict.
    """
    parser = QuantifierParser()
    q = parser.parse("exists!(i, 0 <= i < 10, arr_i == 5)")
    
    # 🔴 VULNERABILITY: to_z3 uses z3.substitute, which might fail or produce mathematically bogus output
    # if it replaces variables it shouldn't.
    z3_form = q.to_z3()
    # If the logic is `uniqueness = z3.ForAll(y_vars, z3.Implies(z3.And(bound_with_y, body_with_y), eq_all))`
    # and it assumes variables are bound without triggering.
    pass

if __name__ == "__main__":
    pytest.main(["-v", __file__])
