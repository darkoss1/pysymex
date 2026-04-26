import z3
from pysymex.analysis.type_constraints.encoder import TypeEncoder
from pysymex.analysis.type_constraints.types import SymbolicType


class TestTypeEncoder:
    """Test suite for pysymex.analysis.type_constraints.encoder.TypeEncoder."""

    def test_encode(self) -> None:
        """Test encode behavior."""
        encoder = TypeEncoder()

        # Primitive types
        t_int = encoder.encode(SymbolicType.int_type())
        assert t_int is not None
        assert str(t_int) == "int_t"

        t_float = encoder.encode(SymbolicType.float_type())
        assert str(t_float) == "float_t"

        t_bool = encoder.encode(SymbolicType.bool_type())
        assert str(t_bool) == "bool_t"

        t_str = encoder.encode(SymbolicType.str_type())
        assert str(t_str) == "str_t"

        t_none = encoder.encode(SymbolicType.none_type())
        assert str(t_none) == "none_t"

        t_any = encoder.encode(SymbolicType.any_type())
        assert str(t_any) == "any_t"

        t_never = encoder.encode(SymbolicType.never_type())
        assert str(t_never) == "never_t"

        t_obj = encoder.encode(SymbolicType.class_type("object"))
        assert "type_1" in str(t_obj)

        t_int_again = encoder.encode(SymbolicType.int_type())
        assert t_int is t_int_again

    def test_get_axioms(self) -> None:
        """Test get_axioms behavior."""
        encoder = TypeEncoder()
        axioms = encoder.get_axioms()
        assert len(axioms) > 0
        assert isinstance(axioms[0], z3.ExprRef)
