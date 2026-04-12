import pytest
import z3
import ast
from pysymex.analysis.contracts.compiler import ContractCompiler

class TestContractCompiler:
    """Test suite for pysymex.analysis.contracts.compiler.ContractCompiler."""
    def test_compile_expression(self) -> None:
        """Test compile_expression behavior."""
        x = z3.Int("x")
        res = ContractCompiler.compile_expression("x > 0", {"x": x})
        assert isinstance(res, z3.BoolRef)
        
        # Test error handling for invalid syntax
        err = ContractCompiler.compile_expression("x > > 0", {"x": x})
        assert isinstance(err, z3.BoolRef) # Falls back to a dummy bool

    def test_visit_Compare(self) -> None:
        """Test visit_Compare behavior."""
        x = z3.Int("x")
        y = z3.Int("y")
        cc = ContractCompiler({"x": x, "y": y})
        
        node = ast.parse("x < y", mode="eval").body
        assert isinstance(node, ast.Compare)
        res = cc.visit_Compare(node)
        assert isinstance(res, z3.BoolRef)
        
        node2 = ast.parse("x <= y", mode="eval").body
        assert isinstance(node2, ast.Compare)
        res2 = cc.visit_Compare(node2)
        assert isinstance(res2, z3.BoolRef)

    def test_visit_BoolOp(self) -> None:
        """Test visit_BoolOp behavior."""
        x = z3.Bool("x")
        y = z3.Bool("y")
        cc = ContractCompiler({"x": x, "y": y})
        
        node = ast.parse("x and y", mode="eval").body
        assert isinstance(node, ast.BoolOp)
        res = cc.visit_BoolOp(node)
        assert isinstance(res, z3.BoolRef)

    def test_visit_UnaryOp(self) -> None:
        """Test visit_UnaryOp behavior."""
        x = z3.Bool("x")
        cc = ContractCompiler({"x": x})
        
        node = ast.parse("not x", mode="eval").body
        assert isinstance(node, ast.UnaryOp)
        res = cc.visit_UnaryOp(node)
        assert isinstance(res, z3.BoolRef)
        
        i = z3.Int("i")
        cc2 = ContractCompiler({"i": i})
        node2 = ast.parse("-i", mode="eval").body
        assert isinstance(node2, ast.UnaryOp)
        res2 = cc2.visit_UnaryOp(node2)
        assert isinstance(res2, z3.ExprRef)

    def test_visit_BinOp(self) -> None:
        """Test visit_BinOp behavior."""
        x = z3.Int("x")
        y = z3.Int("y")
        cc = ContractCompiler({"x": x, "y": y})
        
        node = ast.parse("x + y", mode="eval").body
        assert isinstance(node, ast.BinOp)
        res = cc.visit_BinOp(node)
        assert isinstance(res, z3.ArithRef)

        node2 = ast.parse("x ** 2", mode="eval").body
        assert isinstance(node2, ast.BinOp)
        res2 = cc.visit_BinOp(node2)
        assert isinstance(res2, z3.ArithRef)

    def test_visit_Name(self) -> None:
        """Test visit_Name behavior."""
        x = z3.Int("x")
        old_x = z3.Int("old_x")
        res_sym = z3.Int("__result__")
        cc = ContractCompiler({"x": x, "old_x": old_x, "__result__": res_sym})
        
        node = ast.parse("x", mode="eval").body
        assert isinstance(node, ast.Name)
        assert cc.visit_Name(node) is x

        node2 = ast.parse("result", mode="eval").body
        assert isinstance(node2, ast.Name)
        assert cc.visit_Name(node2) is res_sym

        node3 = ast.parse("old_x", mode="eval").body
        assert isinstance(node3, ast.Name)
        assert cc.visit_Name(node3) is old_x

    def test_visit_Attribute(self) -> None:
        """Test visit_Attribute behavior."""
        cc = ContractCompiler({})
        node = ast.parse("self.x", mode="eval").body
        assert isinstance(node, ast.Attribute)
        res = cc.visit_Attribute(node)
        assert isinstance(res, z3.ExprRef)
        assert "self.x" in cc.symbols

    def test_visit_Constant(self) -> None:
        """Test visit_Constant behavior."""
        cc = ContractCompiler({})
        node1 = ast.parse("42", mode="eval").body
        assert isinstance(node1, ast.Constant)
        res1 = cc.visit_Constant(node1)
        assert isinstance(res1, z3.IntNumRef)

        node2 = ast.parse("True", mode="eval").body
        assert isinstance(node2, ast.Constant)
        res2 = cc.visit_Constant(node2)
        assert z3.is_true(res2)

    def test_visit_Call(self) -> None:
        """Test visit_Call behavior."""
        x = z3.Int("x")
        old_x = z3.Int("old_x")
        cc = ContractCompiler({"x": x, "old_x": old_x})
        
        node1 = ast.parse("old(x)", mode="eval").body
        assert isinstance(node1, ast.Call)
        res1 = cc.visit_Call(node1)
        assert res1 is old_x
        
        node2 = ast.parse("abs(x)", mode="eval").body
        assert isinstance(node2, ast.Call)
        res2 = cc.visit_Call(node2)
        assert isinstance(res2, z3.ExprRef)
        
        node3 = ast.parse("max(x, 10)", mode="eval").body
        assert isinstance(node3, ast.Call)
        res3 = cc.visit_Call(node3)
        assert isinstance(res3, z3.ExprRef)

    def test_visit_IfExp(self) -> None:
        """Test visit_IfExp behavior."""
        x = z3.Int("x")
        y = z3.Int("y")
        cc = ContractCompiler({"x": x, "y": y})
        
        node = ast.parse("x if x > 0 else y", mode="eval").body
        assert isinstance(node, ast.IfExp)
        res = cc.visit_IfExp(node)
        assert isinstance(res, z3.ExprRef)

    def test_visit_Subscript(self) -> None:
        """Test visit_Subscript behavior."""
        cc = ContractCompiler({})
        node = ast.parse("arr[0]", mode="eval").body
        assert isinstance(node, ast.Subscript)
        res = cc.visit_Subscript(node)
        assert isinstance(res, z3.ExprRef)

    def test_generic_visit(self) -> None:
        """Test generic_visit behavior."""
        cc = ContractCompiler({})
        node = ast.parse("[1, 2, 3]", mode="eval").body
        res = cc.generic_visit(node)
        assert isinstance(res, z3.ExprRef)
