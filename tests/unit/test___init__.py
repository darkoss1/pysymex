import subprocess
import sys

import pytest

import pysymex
from pysymex._internal.config.defaults import VERSION


def test_getattr_available() -> None:
    """Test __getattr__ returns correct value for available property."""
    val = getattr(pysymex, "Z3_AVAILABLE")
    assert isinstance(val, bool)


def test_import_does_not_eagerly_import_z3_or_logger() -> None:
    """Importing the root package should not validate runtime-only dependencies."""
    code = (
        "import sys\n"
        "import pysymex\n"
        "print('z3' in sys.modules)\n"
        "print('pysymex._internal.logging' in sys.modules)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.splitlines() == ["False", "False"]


def test_getattr_missing() -> None:
    """Test __getattr__ raises AttributeError for missing export."""
    with pytest.raises(AttributeError, match="has no attribute"):
        getattr(pysymex, "NON_EXISTENT_ATTRIBUTE")


def test_root_package_exports_version() -> None:
    assert pysymex.__version__ == VERSION


def test_dir_uses_regular_module_attributes() -> None:
    """Fresh root package ``dir`` should not be a lazy-export facade."""
    code = (
        "import pysymex\n"
        "exports = dir(pysymex)\n"
        "print('__version__' in exports)\n"
        "print('__getattr__' in exports)\n"
        "print('Z3_AVAILABLE' in exports)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.splitlines() == ["True", "True", "False"]
