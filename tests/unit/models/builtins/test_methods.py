from pysymex.analysis.type_inference import TypeKind
import pysymex.models.builtins.methods as methods

class TestMethodModels:
    """Test suite for pysymex.models.builtins.methods.MethodModels."""

    def test_faithfulness(self) -> None:
        """Known method lookup returns a populated summary."""
        summary = methods.MethodModels.get(TypeKind.STR, "upper")
        assert summary is not None
        assert summary.name == "str.upper"
        assert summary.is_pure is True

    def test_error_path(self) -> None:
        """Unknown method lookup returns None."""
        assert methods.MethodModels.get(TypeKind.STR, "missing_method") is None
