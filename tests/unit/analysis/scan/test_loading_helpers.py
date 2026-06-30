"""Tests for scan loading helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pysymex._internal.analysis.scan.loading.globals import build_module_globals
from pysymex._internal.analysis.scan.loading.source.paths import SourceScanPaths
from pysymex._internal.analysis.scan.loading.stdlib.imports import StdlibImports
from pysymex._internal.scanner.code import get_code_objects_with_context


def test_safe_stdlib_import_accepts_stdlib_modules() -> None:
    """Standard-library modules are eligible for optional concrete binding."""
    assert StdlibImports.is_safe("math") is True
    assert StdlibImports.is_safe("subprocess") is True


def test_default_scanner_module_identity_is_stable_across_python_hash_seeds() -> None:
    """Modeled stdlib identities must not vary between scanner worker processes."""
    script = (
        "from pysymex._internal.analysis.scan.loading.environment import ModuleGlobals; "
        'print(ModuleGlobals.default()["os"].address)'
    )
    addresses: list[str] = []
    for seed in ("1", "2"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        address = subprocess.check_output(
            [sys.executable, "-c", script],
            env=environment,
            text=True,
        ).strip()
        addresses.append(address)

    assert addresses[0] == addresses[1]


def test_build_module_globals_binds_literal_top_level_constants(tmp_path: Path) -> None:
    """Literal top-level constants are safe globals for compile-only scans."""
    content = (
        "GLOBAL_NONE: object = None\nGLOBAL_COUNT = 3\n\ndef target():\n    return GLOBAL_NONE\n"
    )
    code = compile(content, str(tmp_path / "sample.py"), "exec")
    code_with_context = get_code_objects_with_context(code)

    module_globals = build_module_globals(
        content=content,
        file_path=tmp_path / "sample.py",
        full_module_name="sample",
        package_name="",
        all_code_with_context=code_with_context,
    )

    assert "GLOBAL_NONE" in module_globals
    assert module_globals["GLOBAL_NONE"] is None
    assert module_globals["GLOBAL_COUNT"] == 3


def test_build_module_globals_source_functions_shadow_seeded_builtins(tmp_path: Path) -> None:
    """Top-level source functions must override seeded builtin globals like CPython."""
    content = "def len(value: object) -> int:\n    return 0\n"
    code = compile(content, str(tmp_path / "sample.py"), "exec")
    code_with_context = get_code_objects_with_context(code)

    module_globals = build_module_globals(
        content=content,
        file_path=tmp_path / "sample.py",
        full_module_name="sample",
        package_name="",
        all_code_with_context=code_with_context,
    )

    shadowed_len = module_globals["len"]
    assert callable(shadowed_len)
    assert getattr(shadowed_len, "__module__", None) != "builtins"


def test_collect_top_level_function_names_excludes_top_level_classes() -> None:
    """Class code objects must not be bound as helper functions."""
    src = """
class Kind:
    VALUE = 1

def helper(x: int) -> int:
    return x + 1
"""
    names = SourceScanPaths.top_level_functions(src, Path("sample.py"))
    assert names == {"helper"}
