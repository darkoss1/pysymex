import z3

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.containers.sequences import SymbolicSet
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.factory import symbolic_from_python
from pysymex.core.types.base import SymbolicType as BaseSymbolicType
from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
from pysymex.core.types.scalars.strings import SymbolicString as ScalarSymbolicString


def test_public_symbolic_type_export_uses_base_ssot() -> None:
    assert SymbolicType is BaseSymbolicType


def test_public_symbolic_string_export_uses_scalars_ssot() -> None:
    assert SymbolicString is ScalarSymbolicString


def test_advanced_float_type_uses_canonical_module() -> None:
    assert AdvancedSymbolicFloat.__name__ == "AdvancedSymbolicFloat"


def test_split_numeric_modules_preserve_public_numeric_imports() -> None:
    from pysymex.core.types.numeric.bool import SymbolicBool as CanonicalBool
    from pysymex.core.types.numeric.float import SymbolicFloat as CanonicalFloat
    from pysymex.core.types.numeric.int import SymbolicInt as CanonicalInt

    assert CanonicalBool.__name__ == "SymbolicBool"
    assert CanonicalFloat.__name__ == "SymbolicFloat"
    assert CanonicalInt.__name__ == "SymbolicInt"


def test_split_container_modules_preserve_public_container_imports() -> None:
    from pysymex.core.types.containers.dicts import SymbolicDict as CanonicalDict
    from pysymex.core.types.containers.lists import SymbolicList as CanonicalList
    from pysymex.core.types.containers.objects import SymbolicObject as CanonicalObject
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.core.types.containers.lists import SymbolicList
    from pysymex.core.types.containers.objects import SymbolicObject

    assert SymbolicDict is CanonicalDict
    assert SymbolicList is CanonicalList
    assert SymbolicObject is CanonicalObject


def test_split_scalar_modules_preserve_public_scalar_imports() -> None:
    from pysymex.core.types.scalars.strings import SymbolicString as CanonicalString
    from pysymex.core.types.scalars.values import SymbolicValue as CanonicalValue
    from pysymex.core.types.scalars.strings import SymbolicString
    from pysymex.core.types.scalars.values import SymbolicValue

    assert SymbolicString is CanonicalString
    assert SymbolicValue is CanonicalValue


def test_symbolic_from_python_preserves_concrete_dict_membership() -> None:
    value = symbolic_from_python({"answer": 42})

    assert isinstance(value, SymbolicDict)
    assert "answer" in value
    assert "missing" not in value
    found, concrete_value = value.concrete_value_for_key("answer")
    assert found is True
    assert concrete_value is not None


def test_symbolic_from_python_preserves_concrete_integer_set_membership() -> None:
    value = symbolic_from_python({1, 3})

    assert isinstance(value, SymbolicSet)
    assert z3.is_true(value.contains(SymbolicInt.concrete(1)).z3_bool)
    assert z3.is_false(value.contains(SymbolicInt.concrete(2)).z3_bool)
    assert z3.is_int_value(value.length.z3_int)
    assert value.length.z3_int.as_long() == 2
