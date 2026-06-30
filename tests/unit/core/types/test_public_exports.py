import subprocess
import sys

from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.base import SymbolicType as BaseSymbolicType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.strings import SymbolicString as ScalarSymbolicString


def test_public_symbolic_type_export_uses_base_ssot() -> None:
    assert SymbolicType is BaseSymbolicType


def test_public_symbolic_string_export_uses_scalars_ssot() -> None:
    assert SymbolicString is ScalarSymbolicString


def test_split_numeric_modules_preserve_public_numeric_imports() -> None:
    from pysymex._internal.core.types.numeric.bool import SymbolicBool as CanonicalBool
    from pysymex._internal.core.types.numeric.float import SymbolicFloat as CanonicalFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt as CanonicalInt

    assert CanonicalBool.__name__ == "SymbolicBool"
    assert CanonicalFloat.__name__ == "SymbolicFloat"
    assert CanonicalInt.__name__ == "SymbolicInt"


def test_split_container_modules_preserve_public_container_imports() -> None:
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.core.types.containers.dicts import SymbolicDict as CanonicalDict
    from pysymex._internal.core.types.containers.iterators import SymbolicIterator
    from pysymex._internal.core.types.containers.iterators import (
        SymbolicIterator as CanonicalIterator,
    )
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.lists import SymbolicList as CanonicalList
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.core.types.containers.objects import SymbolicObject as CanonicalObject
    from pysymex._internal.core.types.containers.sets import SymbolicSet
    from pysymex._internal.core.types.containers.sets import SymbolicSet as CanonicalSet
    from pysymex._internal.core.types.containers.tuples import SymbolicTuple
    from pysymex._internal.core.types.containers.tuples import SymbolicTuple as CanonicalTuple

    assert SymbolicDict is CanonicalDict
    assert SymbolicList is CanonicalList
    assert SymbolicObject is CanonicalObject
    assert SymbolicIterator is CanonicalIterator
    assert SymbolicSet is CanonicalSet
    assert SymbolicTuple is CanonicalTuple


def test_split_scalar_modules_preserve_public_scalar_imports() -> None:
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.core.types.scalars.strings import SymbolicString as CanonicalString
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.core.types.scalars.values import SymbolicValue as CanonicalValue

    assert SymbolicString is CanonicalString
    assert SymbolicValue is CanonicalValue


def test_scalar_string_module_imports_in_fresh_interpreter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import pysymex._internal.core.types.scalars.strings; import pysymex._internal.core.types.scalars.values",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
