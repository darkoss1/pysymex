from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _load_math_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "math.py"
    spec = importlib.util.spec_from_file_location(
        "pysymex_models_stdlib_math_additional", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib math models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


math_models = _load_math_models()


@pytest.mark.parametrize(
    "class_name",
    [
        "MathSqrtModel",
        "MathCeilModel",
        "MathFloorModel",
        "MathLogModel",
        "MathExpModel",
        "MathSinModel",
        "MathCosModel",
        "MathTanModel",
    ],
)
def test_stdlib_math_model_classes_exist(class_name: str) -> None:
    assert hasattr(math_models, class_name)


def test_stdlib_auto_discovery_math_registry() -> None:
    names = [type(model).__name__ for model in math_models.math_models]
    assert "MathSqrtModel" in names
    assert "MathIsCloseModel" in names
