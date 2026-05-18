from pysymex.core.types import SymbolicString, SymbolicType
from pysymex.core.types.base import SymbolicType as BaseSymbolicType
from pysymex.core.types import floats
from pysymex.core.types.scalars import SymbolicString as ScalarSymbolicString


def test_public_symbolic_type_export_uses_base_ssot() -> None:
    assert SymbolicType is BaseSymbolicType


def test_public_symbolic_string_export_uses_scalars_ssot() -> None:
    assert SymbolicString is ScalarSymbolicString


def test_advanced_float_module_keeps_symbolic_float_alias() -> None:
    assert floats.SymbolicFloat is floats.AdvancedSymbolicFloat
