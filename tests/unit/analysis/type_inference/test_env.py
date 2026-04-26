from pysymex.analysis.type_inference.env import TypeEnvironment
from pysymex.analysis.type_inference.kinds import PyType, TypeKind


class TestTypeEnvironment:
    """Test suite for pysymex.analysis.type_inference.env.TypeEnvironment."""

    def test_get_type(self) -> None:
        """Test get_type behavior."""
        env = TypeEnvironment()
        assert env.get_type("x").kind == TypeKind.UNKNOWN
        env.set_type("x", PyType.int_())
        assert env.get_type("x").kind == TypeKind.INT

        # Test builtin
        assert env.get_type("len").kind == TypeKind.CALLABLE

    def test_set_type(self) -> None:
        """Test set_type behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.str_())
        assert "x" in env.definitely_assigned
        assert "x" in env.maybe_assigned
        assert env.get_type("x").kind == TypeKind.STR

    def test_refine_type(self) -> None:
        """Test refine_type behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.any_())
        env.refine_type("x", PyType.int_())
        assert env.get_type("x").kind == TypeKind.INT

    def test_clear_refinement(self) -> None:
        """Test clear_refinement behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.any_())
        env.refine_type("x", PyType.int_())
        env.clear_refinement("x")
        assert env.get_type("x").kind == TypeKind.ANY

    def test_copy(self) -> None:
        """Test copy behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.int_())
        copied = env.copy()
        assert copied.get_type("x").kind == TypeKind.INT
        copied.set_type("y", PyType.str_())
        assert env.get_type("y").kind == TypeKind.UNKNOWN

    def test_join(self) -> None:
        """Test join behavior."""
        e1 = TypeEnvironment()
        e1.set_type("x", PyType.int_())
        e1.set_type("y", PyType.int_())
        e2 = TypeEnvironment()
        e2.set_type("x", PyType.str_())
        joined = e1.join(e2)
        assert joined.get_type("x").kind == TypeKind.UNION
        assert joined.get_type("y").kind == TypeKind.UNKNOWN
        assert "x" in joined.definitely_assigned
        assert "y" not in joined.definitely_assigned

    def test_enter_scope(self) -> None:
        """Test enter_scope behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.int_())
        child = env.enter_scope()
        assert child.get_type("x").kind == TypeKind.INT
        child.set_type("x", PyType.str_())
        assert child.get_type("x").kind == TypeKind.STR
        assert env.get_type("x").kind == TypeKind.INT
