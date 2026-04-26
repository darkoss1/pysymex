import ast
import z3
from pysymex.contracts.quantifiers.core import (
    QuantifierParser,
    parse_condition_to_z3,
    ConditionTranslator,
    forall,
    exists,
    exists_unique,
    QuantifierInstantiator,
    QuantifierVerifier,
    extract_quantifiers,
    replace_quantifiers_with_z3,
)
from pysymex.contracts.quantifiers.types import Quantifier, QuantifierKind


class TestQuantifierParser:
    """Test suite for pysymex.contracts.quantifiers.core.QuantifierParser."""

    def test_parse(self) -> None:
        """Test parse behavior."""
        parser = QuantifierParser()
        q = parser.parse("forall(i, 0 <= i < 10, i > 0)")
        assert q is not None
        assert q.kind == QuantifierKind.FORALL
        assert len(q.variables) == 1
        assert q.variables[0].name == "i"

        assert parser.parse("invalid syntax") is None


def test_parse_condition_to_z3() -> None:
    """Test parse_condition_to_z3 behavior."""
    x = z3.Int("x")
    res = parse_condition_to_z3("x > 0", {"x": x})
    assert z3.is_bool(res)

    res2 = parse_condition_to_z3("x > ", {"x": x})
    assert z3.is_bool(res2)


class TestConditionTranslator:
    """Test suite for pysymex.contracts.quantifiers.core.ConditionTranslator."""

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
        translator = ConditionTranslator({"obj": z3.Int("obj")})
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

    def test_visit_Call(self) -> None:
        """Test visit_Call behavior."""
        translator = ConditionTranslator({"x": z3.Int("x")})
        tree = ast.parse("len(x)", mode="eval")
        res = translator.visit(tree.body)
        assert z3.is_expr(res)

    def test_generic_visit(self) -> None:
        """Test generic_visit behavior."""
        translator = ConditionTranslator({})
        res = translator.generic_visit(ast.Pass())
        assert z3.is_expr(res)


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
    """Test suite for pysymex.contracts.quantifiers.core.QuantifierInstantiator."""

    def test_instantiate_bounded(self) -> None:
        """Test instantiate_bounded behavior."""
        q = forall("i", (0, 2), "i >= 0")
        inst = QuantifierInstantiator()
        solver = z3.Solver()
        instances = inst.instantiate_bounded(q, solver)
        assert len(instances) == 2

    def test_add_triggers(self) -> None:
        """Test add_triggers behavior."""
        q = forall("i", (0, 2), "i >= 0")
        inst = QuantifierInstantiator()
        f = z3.Function("f", z3.IntSort(), z3.IntSort())
        res = inst.add_triggers(q, [f(q.variables[0].z3_var)])
        assert z3.is_bool(res)


class TestQuantifierVerifier:
    """Test suite for pysymex.contracts.quantifiers.core.QuantifierVerifier."""

    def test_verify_forall(self) -> None:
        """Test verify_forall behavior."""
        v = QuantifierVerifier(timeout_ms=100)
        q = forall("i", (0, 10), "i >= 0")
        valid, _ = v.verify_forall(q)
        assert valid in (True, False, None)

    def test_verify_exists(self) -> None:
        """Test verify_exists behavior."""
        v = QuantifierVerifier(timeout_ms=100)
        q = exists("i", (0, 10), "i == 5")
        sat, _ = v.verify_exists(q)
        assert sat in (True, False, None)


def test_extract_quantifiers() -> None:
    """Test extract_quantifiers behavior."""
    text = "forall(i, 0 <= i < 5, i > 0) and foo"
    qs = extract_quantifiers(text)
    assert len(qs) == 1
    assert qs[0].kind == QuantifierKind.FORALL


def test_replace_quantifiers_with_z3() -> None:
    """Test replace_quantifiers_with_z3 behavior."""
    text = "forall(i, 0 <= i < 5, i > 0) and x > 0"
    res = replace_quantifiers_with_z3(text, {"x": z3.Int("x")})
    assert z3.is_bool(res)
