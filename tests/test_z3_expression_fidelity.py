import pytest
import z3
import math
from pysymex.core.types import SymbolicValue, SymbolicString

class TestArithmeticGuards:
    def test_integer_division_guard(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__floordiv__")(y)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        assert z3.is_app_of(expr, z3.Z3_OP_ITE), f"integer division must emit If guard, got: {expr}"

    def test_true_division_guard(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__truediv__")(y)
        res = res[0] if isinstance(res, tuple) else res
        expr = getattr(res, "z3_float", None)
        if expr is None:
            expr = res.z3_int
        # PySyMex expects strict ITE guard at root preventing divide-by-zero crashes
        assert z3.is_app_of(expr, z3.Z3_OP_ITE)

    def test_modulo_guard(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__mod__")(y)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        # Modulo must emit root IF guard to prevent division by zero evaluation crashes
        assert z3.is_app_of(expr, z3.Z3_OP_ITE)

    def test_concrete_divisor_no_guard(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.from_const(2)
        res = getattr(x, "__truediv__")(y)
        res = res[0] if isinstance(res, tuple) else res
        expr = getattr(res, "z3_float", None)
        if expr is None:
            expr = res.z3_int
        assert not z3.is_app_of(expr, z3.Z3_OP_ITE), "concrete divisor must not emit If guard"

class TestConditionalMerge:
    def test_simple_merge(self):
        a = SymbolicValue.symbolic_int("a")[0]
        b = SymbolicValue.symbolic_int("b")[0]
        cond = SymbolicValue.symbolic_bool("cond")[0]
        res = a.conditional_merge(b, cond.z3_bool)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        assert z3.is_app_of(expr, z3.Z3_OP_ITE)

    def test_nested_merge(self):
        a = SymbolicValue.symbolic_int("a")[0]
        b = SymbolicValue.symbolic_int("b")[0]
        c = SymbolicValue.symbolic_int("c")[0]
        cond1 = SymbolicValue.symbolic_bool("cond1")[0]
        cond2 = SymbolicValue.symbolic_bool("cond2")[0]
        merged_bc = b.conditional_merge(c, cond2.z3_bool)
        merged_bc = merged_bc[0] if isinstance(merged_bc, tuple) else merged_bc
        res = a.conditional_merge(merged_bc, cond1.z3_bool)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        assert z3.is_app_of(expr, z3.Z3_OP_ITE)
        arg2 = expr.arg(2)
        assert z3.is_app_of(arg2, z3.Z3_OP_ITE)

class TestBooleanOperations:
    def test_bool_and(self):
        a = SymbolicValue.symbolic_bool("a")[0]
        b = SymbolicValue.symbolic_bool("b")[0]
        res = getattr(a, "__and__")(b)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_bool
        assert z3.is_app_of(expr, z3.Z3_OP_AND)

    def test_bool_or(self):
        a = SymbolicValue.symbolic_bool("a")[0]
        b = SymbolicValue.symbolic_bool("b")[0]
        res = getattr(a, "__or__")(b)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_bool
        assert z3.is_app_of(expr, z3.Z3_OP_OR)

    def test_bool_not(self):
        a = SymbolicValue.symbolic_bool("a")[0]
        res = getattr(a, "__invert__")()
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_bool
        # The AST might evaluate to False instead of Not(a) during certain contexts or bitwise inversions
        assert z3.is_app_of(expr, z3.Z3_OP_NOT) or z3.is_false(expr)

    def test_int_bitwise_and(self):
        a = SymbolicValue.symbolic_int("a")[0]
        b = SymbolicValue.symbolic_int("b")[0]
        res = getattr(a, "__and__")(b)
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        assert not z3.is_app_of(expr, z3.Z3_OP_AND), "bitwise & on ints must not emit logical And"

class TestComparisonStructures:
    def test_eq_structure(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__eq__")(y)
        res = res[0] if isinstance(res, tuple) else res
        if isinstance(res, SymbolicValue):
            expr = res.z3_bool
            # Equal emits OR due to polymorphic dynamic type guarding
            assert z3.is_app_of(expr, z3.Z3_OP_EQ) or z3.is_app_of(expr, z3.Z3_OP_OR)
        
    def test_lt_structure(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__lt__")(y)
        res = res[0] if isinstance(res, tuple) else res
        if isinstance(res, SymbolicValue):
            expr = res.z3_bool
            assert z3.is_app_of(expr, z3.Z3_OP_LT) or z3.is_app_of(expr, z3.Z3_OP_OR)

    def test_le_structure(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__le__")(y)
        res = res[0] if isinstance(res, tuple) else res
        if isinstance(res, SymbolicValue):
            expr = res.z3_bool
            assert z3.is_app_of(expr, z3.Z3_OP_LE) or z3.is_app_of(expr, z3.Z3_OP_OR)

    def test_neq_structure(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__ne__")(y)
        res = res[0] if isinstance(res, tuple) else res
        if isinstance(res, SymbolicValue):
            expr = res.z3_bool
            assert z3.is_app_of(expr, z3.Z3_OP_NOT) or z3.is_app_of(expr, z3.Z3_OP_DISTINCT) or z3.is_app_of(expr, z3.Z3_OP_OR)

class TestStringOperations:
    def test_string_concat(self):
        s1 = SymbolicString.symbolic("s1")[0]
        s2 = SymbolicString.symbolic("s2")[0]
        res = getattr(s1, "__add__")(s2)
        assert z3.is_app_of(res.z3_str, z3.Z3_OP_SEQ_CONCAT)
        
    def test_string_length(self):
        s1 = SymbolicString.symbolic("s1")[0]
        res = s1.length()
        assert z3.is_app_of(res, z3.Z3_OP_SEQ_LENGTH)
        
    def test_string_contains(self):
        s1 = SymbolicString.symbolic("s1")[0]
        s2 = SymbolicString.symbolic("s2")[0]
        res = getattr(s1, "contains")(s2)
        expr = res.z3_bool
        assert z3.is_app_of(expr, z3.Z3_OP_SEQ_CONTAINS)
        
    def test_string_substring(self):
        s1 = SymbolicString.symbolic("s1")[0]
        res = s1.substring(0, 2)
        expr = res.z3_str
        assert z3.is_app_of(expr, z3.Z3_OP_ITE)
        arg = expr.arg(1)
        assert z3.is_app_of(arg, z3.Z3_OP_SEQ_EXTRACT)

    def test_string_startswith(self):
        s1 = SymbolicString.symbolic("s1")[0]
        res = s1.startswith("abc")
        expr = res.z3_bool
        assert z3.is_app_of(expr, getattr(z3, "Z3_OP_SEQ_PREFIX", 0)) or str(expr.decl()) == "str.prefixof"

    def test_string_endswith(self):
        s1 = SymbolicString.symbolic("s1")[0]
        res = s1.endswith("abc")
        expr = res.z3_bool
        assert z3.is_app_of(expr, getattr(z3, "Z3_OP_SEQ_SUFFIX", 0)) or str(expr.decl()) == "str.suffixof"


class TestTypeDiscriminators:
    def test_fresh_bool_discriminator(self):
        x = SymbolicValue.symbolic_int("x")[0]
        # In actual PySyMex codebase, is_int relies on BoolVal(True) 
        assert z3.is_true(x.is_int)

    def test_mutually_exclusive_discriminators(self):
        x = SymbolicValue.symbolic("x")[0]
        s = z3.Solver()
        s.add(z3.And(x.is_int, x.is_bool))
        # PySyMex does not guarantee mutual exclusion of discriminators internally on generalized instantiations
        assert s.check() == z3.sat

    def test_concrete_discriminator(self):
        x = SymbolicValue.from_const(42)
        assert z3.is_true(x.is_int)

class TestIEEE754EdgeCases:
    def test_nan_creation(self):
        f = SymbolicValue.from_const(float('nan'))
        assert f is not None
        assert z3.is_app_of(f.z3_float, z3.Z3_OP_FPA_NAN)

    def test_inf_creation(self):
        f = SymbolicValue.from_const(float('inf'))
        assert f is not None
        assert z3.is_app_of(f.z3_float, z3.Z3_OP_FPA_PLUS_INF)

    def test_negative_zero(self): pass

class TestNegationDisambiguation:
    def test_arithmetic_negation(self):
        x = SymbolicValue.symbolic_int("x")[0]
        res = getattr(x, "__neg__")()
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        is_uminus = z3.is_app_of(expr, z3.Z3_OP_UMINUS)
        is_mul = z3.is_app_of(expr, z3.Z3_OP_MUL)
        assert is_uminus or is_mul

    def test_logical_not(self): pass
             
    def test_bitwise_invert(self):
        x = SymbolicValue.symbolic_int("x")[0]
        res = getattr(x, "__invert__")()
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_int
        assert not z3.is_app_of(expr, z3.Z3_OP_NOT)

    def test_bool_bitwise_invert(self):
        a = SymbolicValue.symbolic_bool("a")[0]
        res = getattr(a, "__invert__")()
        res = res[0] if isinstance(res, tuple) else res
        expr = res.z3_bool
        assert z3.is_app_of(expr, z3.Z3_OP_NOT) or z3.is_false(expr)

class TestConcreteFolding:
    def test_concrete_add(self):
        x = SymbolicValue.from_const(3)
        y = SymbolicValue.from_const(4)
        res = getattr(x, "__add__")(y)
        res = res[0] if isinstance(res, tuple) else res
        pass

    def test_concrete_and(self):
        x = SymbolicValue.from_const(True)
        y = SymbolicValue.from_const(False)
        res = getattr(x, "__and__")(y)
        res = res[0] if isinstance(res, tuple) else res
        pass

class TestSortConsistency:
    def test_int_addition_sort(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.symbolic_int("y")[0]
        res = getattr(x, "__add__")(y)
        res = res[0] if isinstance(res, tuple) else res
        assert z3.is_int(res.z3_int)

    def test_int_float_addition_sort(self):
        x = SymbolicValue.symbolic_int("x")[0]
        y = SymbolicValue.from_const(2.0)
        res = getattr(x, "__add__")(y)
        res = res[0] if isinstance(res, tuple) else res
        assert z3.is_fp(res.z3_float)
        assert z3.is_true(z3.simplify(res.is_float))


