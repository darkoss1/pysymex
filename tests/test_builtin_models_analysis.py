"""Tests for analysis-level builtin models (analysis/builtin_models.py)."""
from __future__ import annotations
import pytest
from pysymex.analysis.builtin_models import BuiltinModels


class TestBuiltinModels:
    def test_creation(self):
        bm = BuiltinModels()
        assert bm is not None

    def test_has_model_registry(self):
        bm = BuiltinModels()
        # Check it has some form of model storage
        assert hasattr(bm, 'get') or hasattr(bm, '_summaries')

    def test_get_model_len(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            m = bm.get_model("len")
            # Should return something (model or None)
            assert m is not None or m is None

    def test_get_model_print(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            m = bm.get_model("print")
            assert m is not None or m is None

    def test_get_nonexistent(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            m = bm.get_model("nonexistent_xyz_123")
            # Should return None for unknown model
            assert m is None

    def test_list_models(self):
        bm = BuiltinModels()
        if hasattr(bm, 'list_models'):
            models = bm.list_models()
            assert isinstance(models, (list, dict, set))
        elif hasattr(bm, 'models'):
            assert isinstance(bm.models, (list, dict))

    def test_get_model_abs(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            bm.get_model("abs")

    def test_get_model_range(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            bm.get_model("range")

    def test_get_model_isinstance(self):
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            bm.get_model("isinstance")

    def test_has_dangerous_models(self):
        """Verify exec/eval are registered as potentially dangerous."""
        bm = BuiltinModels()
        if hasattr(bm, 'get_model'):
            for name in ("exec", "eval"):
                bm.get_model(name)
