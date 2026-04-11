from pysymex.analysis.type_inference import TypeKind
import pysymex.models.builtins.analysis as analysis

class TestBuiltinModels:
    """Test suite for pysymex.models.builtins.analysis.BuiltinModels."""

    def test_faithfulness(self) -> None:
        """Built-in summary lookup returns the expected summary metadata."""
        summary = analysis.BuiltinModels.get("len")
        assert summary is not None
        assert summary.name == "len"
        assert summary.return_type is not None
        assert summary.return_type.kind is TypeKind.INT

    def test_error_path(self) -> None:
        """Unknown built-in name lookup follows the None fallback path."""
        assert analysis.BuiltinModels.get("does_not_exist") is None
