import ast
from unittest.mock import patch

import pytest
import z3
from pysymex.contracts.quantifiers.extraction import (
    extract_quantifiers,
    replace_quantifiers_with_z3,
)
from pysymex.contracts.quantifiers.factories import (
    exists,
    exists_unique,
    forall,
)
from pysymex.contracts.quantifiers.instantiation import QuantifierInstantiator
from pysymex.contracts.quantifiers.parser import QuantifierParser
from pysymex.contracts.quantifiers.translator import (
    ConditionTranslator,
    parse_condition_to_z3,
)
from pysymex.contracts.quantifiers.types import Quantifier, QuantifierKind
from pysymex.contracts.quantifiers.verification import QuantifierVerifier
from pysymex.core.solver.engine.incremental import IncrementalSolver


class TestQuantifierParser:
    """Test suite for QuantifierParser."""

    def test_parse(self) -> None:
        """Test parse behavior."""
        parser = QuantifierParser()
        q = parser.parse("forall(i, 0 <= i < 10, i > 0)")
        assert q is not None
        assert q.kind == QuantifierKind.FORALL
        assert len(q.variables) == 1
        assert q.variables[0].name == "i"

        assert parser.parse("invalid syntax") is None

    def test_malformed_bounds_are_rejected(self) -> None:
        """A parsed quantifier cannot silently become unbounded."""
        parser = QuantifierParser()
        with pytest.raises(ValueError, match="Unsupported quantifier bounds"):
            parser.parse("forall(i, malformed, i > 0)")


def test_parse_condition_to_z3() -> None:
    """Test parse_condition_to_z3 behavior."""
    x = z3.Int("x")
    res = parse_condition_to_z3("x > 0", {"x": x})
    assert z3.is_bool(res)

    with pytest.raises(ValueError, match="Invalid condition syntax"):
        parse_condition_to_z3("x > ", {"x": x})


class TestConditionTranslator:
    """Test suite for ConditionTranslator."""

    def test_visit_Compare(self) -> None:
        """Test visit_Compare behavior."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("x < 5", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_bool(res)

    def test_visit_BoolOp(self) -> None:
        """Test visit_BoolOp behavior."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("x < 5 and x > 0", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_bool(res)

    def test_visit_UnaryOp(self) -> None:
        """Test visit_UnaryOp behavior."""
        translator = ConditionTranslator({"x": z3.Int("x"), "b": z3.Bool("b")})
        tree = ast.parse("not b", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_visit_BinOp(self) -> None:
        """Test visit_BinOp behavior."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("x + 1", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_visit_Subscript(self) -> None:
        """Test visit_Subscript behavior."""
        arr = z3.Array("A", z3.IntSort(), z3.IntSort())
        translator = ConditionTranslator({"A": arr})
        tree = ast.parse("A[0]", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_visit_Attribute(self) -> None:
        """Test visit_Attribute behavior."""
        translator = ConditionTranslator({"obj.length": z3.Int("obj_length")})
        tree = ast.parse("obj.length", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_visit_Name(self) -> None:
        """Test visit_Name behavior."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("x", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_visit_Constant(self) -> None:
        """Test visit_Constant behavior."""
        translator = ConditionTranslator({})
        tree = ast.parse("42", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_none_constant_is_rejected(self) -> None:
        """None has no sound Boolean-value lowering in contract formulas."""
        with pytest.raises(ValueError, match="None constants are unsupported"):
            parse_condition_to_z3("None == False", {})

    def test_visit_Call(self) -> None:
        """Test visit_Call behavior."""
        translator = ConditionTranslator({"x": z3.Int("x"), "len_x": z3.Int("len_x")})
        tree = ast.parse("len(x)", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_unmodeled_call_is_rejected(self) -> None:
        """Unmodeled calls must not be replaced by unconstrained values."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("mystery(x)", mode="eval")
        with pytest.raises(ValueError, match="Unsupported contract call"):
            translator.visit(tree.body)

    def test_generic_visit(self) -> None:
        """Test generic_visit behavior."""
        translator = ConditionTranslator({})
        with pytest.raises(ValueError, match="Unsupported condition node"):
            translator.generic_visit(ast.Pass())


def test_forall() -> None:
    """Test forall behavior."""
    q = forall("i", (0, 10), "i > 0")
    assert isinstance(q, Quantifier)
    assert q.kind == QuantifierKind.FORALL


def test_exists() -> None:
    """Test exists behavior."""
    q = exists("i", (0, 10), "i == 5")
    assert isinstance(q, Quantifier)
    assert q.kind == QuantifierKind.EXISTS


def test_exists_unique() -> None:
    """Test exists_unique behavior."""
    q = exists_unique("i", (0, 10), "i == 5")
    assert isinstance(q, Quantifier)
    assert q.kind == QuantifierKind.UNIQUE


class TestQuantifierInstantiator:
    """Test suite for QuantifierInstantiator."""

    def test_instantiate_bounded(self) -> None:
        """Test instantiate_bounded behavior."""
        q = forall("i", (0, 2), "i >= 0")
        inst = QuantifierInstantiator()
        solver = IncrementalSolver()
        instances = inst.instantiate_bounded(q, solver)
        assert len(instances) == 2

    def test_add_triggers(self) -> None:
        """Test add_triggers behavior."""
        q = forall("i", (0, 2), "i >= 0")
        inst = QuantifierInstantiator()
        f = z3.Function("f", z3.IntSort(), z3.IntSort())
        z3_var = q.variables[0].z3_var
        assert z3_var is not None
        res = inst.add_triggers(q, [f(z3_var)])
        assert z3.is_bool(res)

    def test_instantiate_bounded_respects_inclusive_endpoints(self) -> None:
        parser = QuantifierParser()
        q = parser.parse("forall(i, 0 < i <= 2, i == 2)")
        assert q is not None

        instances = QuantifierInstantiator().instantiate_bounded(q)
        assert len(instances) == 2
        assert z3.is_false(z3.simplify(instances[0]))
        assert z3.is_true(z3.simplify(instances[1]))


class TestQuantifierVerifier:
    """Test suite for QuantifierVerifier."""

    def test_verify_forall(self) -> None:
        """Test verify_forall behavior."""
        v = QuantifierVerifier(timeout_ms=100)
        q = forall("i", (0, 10), "i >= 0")
        valid, counterexample = v.verify_forall(q)
        assert valid is True
        assert counterexample is None

    def test_verify_exists(self) -> None:
        """Test verify_exists behavior."""
        v = QuantifierVerifier(timeout_ms=100)
        q = exists("i", (0, 10), "i == 5")
        sat, witness = v.verify_exists(q)
        assert sat is True
        assert witness == {"i": 5}

    def test_verify_forall_returns_counterexample_assignment(self) -> None:
        verifier = QuantifierVerifier(timeout_ms=100)
        valid, counterexample = verifier.verify_forall(forall("i", (0, 10), "i > 0"))

        assert valid is False
        assert counterexample == {"i": 0}

    def test_existential_witness_is_not_captured_by_same_named_outer_symbol(self) -> None:
        verifier = QuantifierVerifier(timeout_ms=100)
        outer_i = z3.Int("i")

        sat, witness = verifier.verify_exists(exists("i", (0, 10), "i == 5"), [outer_i == 7])

        assert sat is True
        assert witness == {"i": 5}

    def test_wrong_quantifier_kind_is_rejected(self) -> None:
        verifier = QuantifierVerifier(timeout_ms=100)
        with pytest.raises(ValueError, match="FORALL"):
            verifier.verify_forall(exists("i", (0, 1), "i == 0"))
        with pytest.raises(ValueError, match="EXISTS"):
            verifier.verify_exists(forall("i", (0, 1), "i == 0"))

    def test_solver_failure_is_inconclusive(self) -> None:
        verifier = QuantifierVerifier(timeout_ms=100)
        quantifier = forall("i", (0, 1), "i >= 0")
        with patch(
            "pysymex.contracts.quantifiers.verification.IncrementalSolver.check",
            side_effect=RuntimeError("solver failed"),
        ):
            assert verifier.verify_forall(quantifier) == (None, None)


def test_extract_quantifiers() -> None:
    """Test extract_quantifiers behavior."""
    text = "forall(i, 0 <= i < 5, i > 0) and foo"
    qs = extract_quantifiers(text)
    assert len(qs) == 1
    assert qs[0].kind == QuantifierKind.FORALL


def test_quantifier_factories_reject_callable_bodies_explicitly() -> None:
    with pytest.raises(TypeError, match="must be string predicates"):
        forall("i", (0, 1), lambda i: i == 0)  # type: ignore[arg-type]


def test_quantifier_factory_accepts_signed_integer_bounds() -> None:
    quantifier = forall("i", (-2, 2), "i >= -2")
    assert z3.is_bool(quantifier.to_z3())


def test_extract_quantifiers_accepts_keyword_whitespace() -> None:
    """Extraction accepts the same whitespace form as QuantifierParser."""
    qs = extract_quantifiers("forall (i, 0 <= i < 1, i >= 0)")
    assert len(qs) == 1
    assert qs[0].kind == QuantifierKind.FORALL


def test_replace_quantifiers_with_z3() -> None:
    """Test replace_quantifiers_with_z3 behavior."""
    text = "forall(i, 0 <= i < 5, i > 0) and x > 0"
    res = replace_quantifiers_with_z3(text, {"x": z3.Int("x")})
    assert z3.is_bool(res)


def test_replace_quantifiers_preserves_or_and_not() -> None:
    """Boolean composition around quantified clauses must be retained exactly."""
    x = z3.Int("x")
    formula = replace_quantifiers_with_z3(
        "forall(i, 0 <= i < 1, i < 0) or x > 0",
        {"x": x},
    )
    solver = z3.Solver()
    solver.add(x == 1, z3.Not(formula))
    assert solver.check() == z3.unsat

    negated = replace_quantifiers_with_z3("not forall(i, 0 <= i < 1, i >= 0)", {})
    solver = z3.Solver()
    solver.add(negated)
    assert solver.check() == z3.unsat


def test_float_constant_is_rejected_without_ieee_model() -> None:
    """Python float predicates cannot be lowered as exact real arithmetic."""
    with pytest.raises(ValueError, match="Floating-point constants are unsupported"):
        parse_condition_to_z3("0.1 + 0.2 == 0.3", {})


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        ("1 // 0 == 1 // 0", "Floor division is unsupported"),
        ("3 % -2 == -1", "Modulo is unsupported"),
        ("0 ** -1 == 0", "Exponentiation is unsupported"),
    ],
)
def test_partial_or_non_cpython_arithmetic_is_rejected(condition: str, message: str) -> None:
    """Partial arithmetic cannot be treated as total SMT arithmetic."""
    with pytest.raises(ValueError, match=message):
        parse_condition_to_z3(condition, {})
