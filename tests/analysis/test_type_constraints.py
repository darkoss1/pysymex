"""Tests for type_constraints module.

Tests the Z3-based type constraint analysis including:
- Symbolic type creation
- Subtype checking
- Type compatibility
- Union/intersection types
- Protocol verification
"""

import pytest

import z3


from pysymex.analysis.type_constraints import (
    TypeConstraintChecker,
    TypeEncoder,
    TypeIssue,
    TypeIssueKind,
    TypeKind,
    SymbolicType,
    Variance,
)


class TestSymbolicType:
    """Tests for SymbolicType class."""

    def test_int_type(self):
        """Test int type creation."""

        t = SymbolicType.int_type()

        assert t.kind == TypeKind.INT

        assert t.name == "int"

    def test_float_type(self):
        """Test float type creation."""

        t = SymbolicType.float_type()

        assert t.kind == TypeKind.FLOAT

        assert t.name == "float"

    def test_bool_type(self):
        """Test bool type creation."""

        t = SymbolicType.bool_type()

        assert t.kind == TypeKind.BOOL

        assert t.name == "bool"

    def test_str_type(self):
        """Test str type creation."""

        t = SymbolicType.str_type()

        assert t.kind == TypeKind.STR

        assert t.name == "str"

    def test_none_type(self):
        """Test None type creation."""

        t = SymbolicType.none_type()

        assert t.kind == TypeKind.NONE

        assert t.name == "None"

    def test_any_type(self):
        """Test Any type creation."""

        t = SymbolicType.any_type()

        assert t.kind == TypeKind.ANY

        assert t.name == "Any"

    def test_never_type(self):
        """Test Never type creation."""

        t = SymbolicType.never_type()

        assert t.kind == TypeKind.NEVER

        assert t.name == "Never"

    def test_list_of(self):
        """Test list type creation."""

        element = SymbolicType.int_type()

        t = SymbolicType.list_of(element)

        assert t.kind == TypeKind.LIST

        assert len(t.args) == 1

        assert t.args[0].kind == TypeKind.INT

    def test_dict_of(self):
        """Test dict type creation."""

        key = SymbolicType.str_type()

        val = SymbolicType.int_type()

        t = SymbolicType.dict_of(key, val)

        assert t.kind == TypeKind.DICT

        assert len(t.args) == 2

    def test_tuple_of(self):
        """Test tuple type creation."""

        t = SymbolicType.tuple_of(
            SymbolicType.int_type(),
            SymbolicType.str_type(),
        )

        assert t.kind == TypeKind.TUPLE

        assert len(t.args) == 2

    def test_union_of(self):
        """Test union type creation."""

        t = SymbolicType.union_of(
            SymbolicType.int_type(),
            SymbolicType.str_type(),
        )

        assert t.kind == TypeKind.UNION

        assert len(t.args) == 2

    def test_union_flattening(self):
        """Test union type flattening."""

        inner = SymbolicType.union_of(
            SymbolicType.int_type(),
            SymbolicType.str_type(),
        )

        outer = SymbolicType.union_of(inner, SymbolicType.float_type())

        assert outer.kind == TypeKind.UNION

        assert len(outer.args) == 3

    def test_optional_of(self):
        """Test optional type creation."""

        t = SymbolicType.optional_of(SymbolicType.int_type())

        assert t.kind == TypeKind.UNION

        kinds = {arg.kind for arg in t.args}

        assert TypeKind.INT in kinds

        assert TypeKind.NONE in kinds

    def test_callable_type(self):
        """Test callable type creation."""

        t = SymbolicType.callable_type(
            [SymbolicType.int_type(), SymbolicType.str_type()],
            SymbolicType.bool_type(),
        )

        assert t.kind == TypeKind.CALLABLE

        assert t.args[-1].kind == TypeKind.BOOL

    def test_type_var(self):
        """Test type variable creation."""

        t = SymbolicType.type_var("T")

        assert t.kind == TypeKind.TYPE_VAR

        assert t.name == "T"

    def test_type_var_with_bound(self):
        """Test type variable with bound."""

        t = SymbolicType.type_var(
            "T",
            SymbolicType.int_type(),
            variance=Variance.COVARIANT,
        )

        assert t.kind == TypeKind.TYPE_VAR

        assert t.variance == Variance.COVARIANT

    def test_literal_type(self):
        """Test literal type creation."""

        t = SymbolicType.literal(1, 2, 3)

        assert t.kind == TypeKind.LITERAL

        assert t.literal_values == frozenset({1, 2, 3})

    def test_str_representation(self):
        """Test string representation."""

        t = SymbolicType.list_of(SymbolicType.int_type())

        s = str(t)

        assert "list" in s

        assert "int" in s

    def test_immutability(self):
        """Test that SymbolicType is hashable (frozen)."""

        t1 = SymbolicType.int_type()

        t2 = SymbolicType.int_type()

        s = {t1, t2}

        assert len(s) == 1


class TestTypeEncoder:
    """Tests for TypeEncoder class."""

    @pytest.fixture
    def encoder(self):
        return TypeEncoder()

    def test_encoder_creation(self, encoder):
        """Test encoder initialization."""

        assert encoder.TypeSort is not None

        assert encoder.int_t is not None

        assert encoder.float_t is not None

    def test_encode_primitive(self, encoder):
        """Test encoding primitive types."""

        int_z3 = encoder.encode(SymbolicType.int_type())

        assert int_z3 == encoder.int_t

    def test_encode_caching(self, encoder):
        """Test that encoding is cached."""

        t = SymbolicType.int_type()

        z1 = encoder.encode(t)

        z2 = encoder.encode(t)

        assert z1 is z2

    def test_get_axioms(self, encoder):
        """Test axiom generation."""

        axioms = encoder.get_axioms()

        assert len(axioms) > 0

        for ax in axioms:
            assert isinstance(ax, z3.ExprRef)


class TestTypeConstraintChecker:
    """Tests for TypeConstraintChecker class."""

    @pytest.fixture
    def checker(self):
        return TypeConstraintChecker()

    def test_checker_creation(self, checker):
        """Test checker initialization."""

        assert checker.timeout_ms == 5000

        assert checker.encoder is not None

    def test_is_subtype_reflexive(self, checker):
        """Test subtype reflexivity (T <: T)."""

        t = SymbolicType.int_type()

        is_sub, reason = checker.is_subtype(t, t)

        assert is_sub is True

    def test_is_subtype_any(self, checker):
        """Test that everything is subtype of Any."""

        t = SymbolicType.int_type()

        any_t = SymbolicType.any_type()

        is_sub, reason = checker.is_subtype(t, any_t)

        assert is_sub is True

    def test_is_subtype_never(self, checker):
        """Test that Never is subtype of everything."""

        never_t = SymbolicType.never_type()

        t = SymbolicType.int_type()

        is_sub, reason = checker.is_subtype(never_t, t)

        assert is_sub is True

    def test_is_subtype_union_member(self, checker):
        """Test subtype of union member."""

        int_t = SymbolicType.int_type()

        union_t = SymbolicType.union_of(
            SymbolicType.int_type(),
            SymbolicType.str_type(),
        )

        is_sub, reason = checker.is_subtype(int_t, union_t)

        assert is_sub is True

    def test_is_subtype_union_all_members(self, checker):
        """Test union subtype (all members must be subtypes)."""

        union_t = SymbolicType.union_of(
            SymbolicType.int_type(),
            SymbolicType.str_type(),
        )

        any_t = SymbolicType.any_type()

        is_sub, reason = checker.is_subtype(union_t, any_t)

        assert is_sub is True

    def test_is_subtype_literal(self, checker):
        """Test literal type subtyping."""

        lit_t = SymbolicType.literal(1, 2, 3)

        int_t = SymbolicType.int_type()

        is_sub, reason = checker.is_subtype(lit_t, int_t)

        assert is_sub is True

    def test_is_not_subtype(self, checker):
        """Test non-subtype relationship."""

        str_t = SymbolicType.str_type()

        int_t = SymbolicType.int_type()

        is_sub, reason = checker.is_subtype(str_t, int_t)

        assert is_sub is False

        assert reason is not None

    def test_check_assignment_valid(self, checker):
        """Test valid assignment check."""

        target = SymbolicType.int_type()

        value = SymbolicType.int_type()

        issue = checker.check_assignment(target, value)

        assert issue is None

    def test_check_assignment_invalid(self, checker):
        """Test invalid assignment check."""

        target = SymbolicType.int_type()

        value = SymbolicType.str_type()

        issue = checker.check_assignment(target, value)

        assert issue is not None

        assert issue.kind == TypeIssueKind.INCOMPATIBLE_TYPES

    def test_check_return_valid(self, checker):
        """Test valid return type check."""

        declared = SymbolicType.int_type()

        actual = SymbolicType.int_type()

        issue = checker.check_return(declared, actual)

        assert issue is None

    def test_check_return_invalid(self, checker):
        """Test invalid return type check."""

        declared = SymbolicType.int_type()

        actual = SymbolicType.str_type()

        issue = checker.check_return(declared, actual)

        assert issue is not None

        assert issue.kind == TypeIssueKind.INCOMPATIBLE_RETURN

    def test_checker_reset(self, checker):
        """Test checker reset."""

        checker.reset()


class TestTypeIssue:
    """Tests for TypeIssue class."""

    def test_issue_creation(self):
        """Test issue creation."""

        issue = TypeIssue(
            kind=TypeIssueKind.INCOMPATIBLE_TYPES,
            message="Cannot assign str to int",
            expected_type=SymbolicType.int_type(),
            actual_type=SymbolicType.str_type(),
            line_number=42,
        )

        assert issue.kind == TypeIssueKind.INCOMPATIBLE_TYPES

        assert issue.line_number == 42

    def test_issue_format(self):
        """Test issue formatting."""

        issue = TypeIssue(
            kind=TypeIssueKind.INCOMPATIBLE_TYPES,
            message="Cannot assign str to int",
            expected_type=SymbolicType.int_type(),
            actual_type=SymbolicType.str_type(),
            line_number=42,
        )

        formatted = issue.format()

        assert "INCOMPATIBLE_TYPES" in formatted

        assert "42" in formatted


class TestTypeIssueKind:
    """Tests for TypeIssueKind enum."""

    def test_assignment_issues(self):
        """Test assignment-related issue kinds exist."""

        assert TypeIssueKind.INCOMPATIBLE_TYPES

        assert TypeIssueKind.INCOMPATIBLE_RETURN

        assert TypeIssueKind.INCOMPATIBLE_ARGUMENT

    def test_call_issues(self):
        """Test call-related issue kinds exist."""

        assert TypeIssueKind.TOO_FEW_ARGUMENTS

        assert TypeIssueKind.TOO_MANY_ARGUMENTS

        assert TypeIssueKind.UNEXPECTED_KEYWORD

    def test_none_issues(self):
        """Test None-related issue kinds exist."""

        assert TypeIssueKind.POSSIBLE_NONE

        assert TypeIssueKind.NONE_NOT_ALLOWED


class TestVariance:
    """Tests for Variance enum."""

    def test_variance_values(self):
        """Test variance enum values exist."""

        assert Variance.INVARIANT

        assert Variance.COVARIANT

        assert Variance.CONTRAVARIANT


class TestTypeKind:
    """Tests for TypeKind enum."""

    def test_primitive_kinds(self):
        """Test primitive type kinds exist."""

        assert TypeKind.INT

        assert TypeKind.FLOAT

        assert TypeKind.BOOL

        assert TypeKind.STR

        assert TypeKind.NONE

    def test_compound_kinds(self):
        """Test compound type kinds exist."""

        assert TypeKind.LIST

        assert TypeKind.TUPLE

        assert TypeKind.DICT

        assert TypeKind.SET

    def test_special_kinds(self):
        """Test special type kinds exist."""

        assert TypeKind.ANY

        assert TypeKind.NEVER

        assert TypeKind.UNION

        assert TypeKind.PROTOCOL
