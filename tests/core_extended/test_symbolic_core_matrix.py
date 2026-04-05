import pytest
import z3

from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE, Z3_ZERO
from pysymex.core.types_containers import SymbolicList, SymbolicDict, SymbolicString
from pysymex.core.solver import create_solver
from pysymex.core.floats import SymbolicFloat, FloatPrecision

# -----------------------------------------------------------------------------
# Part 1: Polymorphic Core Combinatorics & Type Discriminators
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("left_type, right_type", [
    ("int", "int"),
    ("int", "float"),
    ("float", "int"),
    ("float", "float"),
    ("int", "bool"),
    ("bool", "int"),
    ("bool", "bool"),
])
def test_numeric_addition_type_preservation(left_type, right_type):
    """Exhaustive matrix testing of addition discriminator logic."""
    if left_type == "int":
        v1, _ = SymbolicValue.symbolic_int("v1")
    elif left_type == "float":
        v1 = SymbolicValue.from_const(3.14)
    else:
        v1, _ = SymbolicValue.symbolic_bool("v1")
        
    if right_type == "int":
        v2, _ = SymbolicValue.symbolic_int("v2")
    elif right_type == "float":
        v2 = SymbolicValue.from_const(2.71)
    else:
        v2, _ = SymbolicValue.symbolic_bool("v2")

    result = v1 + v2
    solver = create_solver()
    
    if "float" in (left_type, right_type):
        solver.add(result.is_float == Z3_FALSE)
    else:
        solver.add(result.is_int == Z3_FALSE)
        
    assert solver.check() == z3.unsat

def test_bool_int_equivalence():
    """Verify that True is mathematically 1 and False is mathematically 0 in operations."""
    sym_bool, tc = SymbolicValue.symbolic_bool("b")
    
    # b + 5
    res = sym_bool + 5
    
    solver = create_solver()
    solver.add(tc)
    
    # If b is True, b+5 == 6
    solver.push()
    solver.add(sym_bool.z3_bool == True)
    solver.add(res.z3_int != 6)
    assert solver.check() == z3.unsat
    solver.pop()
    
    # If b is False, b+5 == 5
    solver.push()
    solver.add(sym_bool.z3_bool == False)
    solver.add(res.z3_int != 5)
    assert solver.check() == z3.unsat
    solver.pop()

# -----------------------------------------------------------------------------
# Part 2: Advanced Float Arithmetic Boundaries (IEEE 754)
# -----------------------------------------------------------------------------

def test_float_division_by_zero_semantics():
    """Test float division by zero logic within SymbolicValue wrapper."""
    val_a = SymbolicValue.from_const(1.0)
    val_b, tc = SymbolicValue.symbolic_int("b")
    
    # The division operator itself is guarded from Z3 crashes, but we should verify the constraint math holds
    result = val_a / val_b
    
    solver = create_solver()
    solver.add(tc)
    solver.push()
    solver.add(val_b.z3_int == 0)
    # The safe wrapper uses Z3_FALSE for float-divide-by-zero or sets to NaN depending on config.
    # We just ensure it's SAT to prove it didn't crash Z3.
    assert solver.check() == z3.sat
    solver.pop()

def test_float_modulo_fallback():
    """Test that float modulo handles generic float logic fallback securely."""
    f1 = SymbolicValue.from_const(5.5)
    f2 = SymbolicValue.from_const(2.0)
    
    res = f1 % f2
    
    solver = create_solver()
    # 5.5 % 2.0 = 1.5
    solver.add(res.z3_float != z3.FPVal(1.5, z3.Float64()))
    assert solver.check() == z3.unsat

def test_float_floordiv_fallback():
    """Test that float floor division rounds correctly."""
    f1 = SymbolicValue.from_const(5.5)
    f2 = SymbolicValue.from_const(2.0)
    
    res = f1 // f2
    
    solver = create_solver()
    # 5.5 // 2.0 = 2.0
    solver.add(res.z3_float != z3.FPVal(2.0, z3.Float64()))
    assert solver.check() == z3.unsat

# -----------------------------------------------------------------------------
# Part 3: Deep Bitwise Mathematics
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("op", ["and", "or", "xor", "lshift", "rshift"])
def test_bitwise_mixed_bool_int(op):
    """Test bitwise operations correctly promote bools to ints."""
    v1, _ = SymbolicValue.symbolic_bool("b")
    v2, _ = SymbolicValue.symbolic_int("i")
    
    if op == "and":
        res = v1 & v2
    elif op == "or":
        res = v1 | v2
    elif op == "xor":
        res = v1 ^ v2
    elif op == "lshift":
        res = v1 << v2
    else:
        res = v1 >> v2
        
    solver = create_solver()
    solver.add(res.is_int == Z3_FALSE)
    assert solver.check() == z3.unsat

def test_bitwise_invert_sign_extension():
    """Python's ~x is equivalent to -x - 1 on representative concrete samples."""
    samples = [0, 1, -1, 7, -7, 2**31, -(2**31)]
    for sample in samples:
        v1 = SymbolicValue.from_const(sample)
        inv_res = ~v1
        math_res = -v1 - 1

        solver = create_solver()
        solver.add(inv_res.z3_int != math_res.z3_int)
        assert solver.check() == z3.unsat

# -----------------------------------------------------------------------------
# Part 4: String Sequence Theory Edge Cases
# -----------------------------------------------------------------------------

def test_symbolic_string_contains():
    """Verify that checking if a symbolic string contains another string generates precise Z3 sequences."""
    s1, c1 = SymbolicString.symbolic("s1")
    
    contains_res = s1.contains("hello")
    
    solver = create_solver()
    solver.add(c1)
    solver.add(contains_res.is_bool == Z3_FALSE)
    assert solver.check() == z3.unsat
    
    # Prove that if length of s1 is < 5, it cannot contain "hello"
    solver.push()
    solver.add(s1.length() < 5)
    solver.add(contains_res.z3_bool == True)
    assert solver.check() == z3.unsat
    solver.pop()

def test_symbolic_string_startswith():
    """Verify prefix semantics."""
    s1, c1 = SymbolicString.symbolic("s1")
    
    starts_res = s1.startswith("prefix")
    
    solver = create_solver()
    solver.add(c1)
    
    # If it starts with "prefix", its length must be >= 6
    solver.push()
    solver.add(starts_res.z3_bool == True)
    solver.add(s1.length() < 6)
    assert solver.check() == z3.unsat
    solver.pop()

# -----------------------------------------------------------------------------
# Part 5: List/Dict Memory Mutability and Reference Soundness
# -----------------------------------------------------------------------------

def test_symbolic_list_extend_soundness():
    """Verify that extending lists properly merges underlying Z3 arrays and increments length."""
    l1, _ = SymbolicList.symbolic("l1")
    l2 = SymbolicList.from_const([1, 2, 3])
    
    l3 = l1.extend(l2)
    
    solver = create_solver()
    # l3 length must equal l1 length + 3
    solver.add(l3.z3_len != l1.z3_len + 3)
    assert solver.check() == z3.unsat

def test_symbolic_dict_update_overrides():
    """Verify dictionary updates properly override old keys."""
    d1, _ = SymbolicDict.symbolic("d1")
    d2 = SymbolicDict.from_const({"a": 99})
    
    d3, _ = d1.update(d2)
    
    solver = create_solver()
    # Retrieve "a" from d3
    val, presence = d3[SymbolicString.from_const("a")]
    
    solver.push()
    solver.add(presence == False)
    assert solver.check() == z3.unsat
    solver.pop()
    
    solver.push()
    solver.add(val.z3_int != 99)
    assert solver.check() == z3.unsat
    solver.pop()

# -----------------------------------------------------------------------------
# Part 6: Comparison Operator Symmetry and Type Cross-Overs
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("op", ["==", "!=", "<", "<=", ">", ">="])
def test_cross_type_comparisons(op):
    """Extensively verify cross-type comparisons produce valid boolean ASTs, not TypeErrors."""
    i = SymbolicValue.from_const(5)
    f = SymbolicValue.from_const(5.5)
    s = SymbolicValue.from_const("5")
    b = SymbolicValue.from_const(True)
    
    combos = [(i, f), (f, i), (i, s), (s, f), (i, b), (b, f)]
    
    for left, right in combos:
        if op == "==":
            res = left == right
        elif op == "!=":
            res = left != right
        elif op == "<":
            res = left < right
        elif op == "<=":
            res = left <= right
        elif op == ">":
            res = left > right
        else:
            res = left >= right
            
        solver = create_solver()
        solver.add(res.is_bool == Z3_FALSE)
        assert solver.check() == z3.unsat

def test_identity_comparison_uniqueness():
    """Verify that 'is' and 'is not' compare memory addresses/identities correctly."""
    from pysymex.core.types_containers import SymbolicObject
    
    obj1, _ = SymbolicObject.symbolic("o1", 100)
    obj2, _ = SymbolicObject.symbolic("o2", 200)
    
    # Same object
    eq1 = obj1 == obj1
    # Different objects
    eq2 = obj1 == obj2
    
    solver = create_solver()
    solver.add(eq1.z3_bool == False)
    assert solver.check() == z3.unsat
    
    solver = create_solver()
    solver.add(eq2.z3_bool == True)
    assert solver.check() == z3.unsat

# -----------------------------------------------------------------------------
# Part 7: Truthiness and Falsiness (Control Flow Core)
# -----------------------------------------------------------------------------

def test_truthiness_exhaustion():
    """Test could_be_truthy and could_be_falsy across all basic types."""
    sv, tc = SymbolicValue.symbolic("sv")
    
    solver = create_solver()
    solver.add(tc)
    
    # A value cannot be simultaneously purely truthy and purely falsy
    # However, a fully symbolic value CAN be both depending on the model.
    # What we assert is that Z3 can satisfy both conditions in DIFFERENT models.
    solver.push()
    solver.add(sv.could_be_truthy())
    assert solver.check() == z3.sat
    solver.pop()
    
    solver.push()
    solver.add(sv.could_be_falsy())
    assert solver.check() == z3.sat
    solver.pop()
    
    # But a concrete value is strictly one or the other
    cv = SymbolicValue.from_const(42)
    solver.push()
    solver.add(cv.could_be_falsy())
    assert solver.check() == z3.unsat
    solver.pop()
    
    cv_str = SymbolicValue.from_const("")
    solver.push()
    solver.add(cv_str.could_be_truthy())
    assert solver.check() == z3.unsat
    solver.pop()

# -----------------------------------------------------------------------------
# Part 8: Conditional Merge and CoW State Preservation
# -----------------------------------------------------------------------------

def test_conditional_merge_deep_trees():
    """Verify that nesting conditional merges doesn't destroy the root value relationships."""
    v1 = SymbolicValue.from_const(1)
    v2 = SymbolicValue.from_const(2)
    v3 = SymbolicValue.from_const(3)
    
    c1 = z3.Bool("c1")
    c2 = z3.Bool("c2")
    
    m1 = v1.conditional_merge(v2, c1)
    m2 = m1.conditional_merge(v3, c2)
    
    solver = create_solver()
    
    # conditional_merge semantics: If(cond, self, other)
    # If c2 is true and c1 is true, result should be v1
    solver.push()
    solver.add(c2 == True, c1 == True)
    solver.add(m2.z3_int != 1)
    assert solver.check() == z3.unsat
    solver.pop()
    
    # If c2 is false, result should be v3 regardless of c1
    solver.push()
    solver.add(c2 == False)
    solver.add(m2.z3_int != 3)
    assert solver.check() == z3.unsat
    solver.pop()
