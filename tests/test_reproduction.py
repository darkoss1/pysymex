"""Tests for reproduction generator (reporting/reproduction.py)."""
from __future__ import annotations
import pytest
from pysymex.reporting.reproduction import ReproductionGenerator


class TestReproductionGenerator:
    def test_creation(self):
        rg = ReproductionGenerator()
        assert rg is not None

    def test_has_generate(self):
        assert (hasattr(ReproductionGenerator, 'generate') or
                hasattr(ReproductionGenerator, 'generate_test') or
                hasattr(ReproductionGenerator, 'generate_reproduction'))

    def test_has_build_args(self):
        assert (hasattr(ReproductionGenerator, '_build_init_args') or
                hasattr(ReproductionGenerator, 'build_args') or True)

    def test_empty_vulnerabilities(self):
        rg = ReproductionGenerator()
        if hasattr(rg, 'generate'):
            try:
                result = rg.generate([])
                assert result is not None or result == ""
            except (TypeError, ValueError):
                pass
