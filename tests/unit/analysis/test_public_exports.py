from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import cast

import pysymex.analysis as analysis
from pysymex.lazy import LazyExports


def _analysis_exports() -> LazyExports:
    exports = getattr(analysis, "_EXPORTS")
    assert isinstance(exports, Mapping)
    return cast(LazyExports, exports)


def test_all_lazy_analysis_exports_resolve() -> None:
    """Every advertised top-level analysis export must be importable."""
    for name, (module_path, attribute_name) in _analysis_exports().items():
        module = importlib.import_module(module_path)
        assert getattr(module, attribute_name) is getattr(analysis, name)


def test_analysis_all_matches_lazy_exports() -> None:
    assert sorted(analysis.__all__) == sorted(_analysis_exports())
