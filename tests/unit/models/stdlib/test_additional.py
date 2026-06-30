from __future__ import annotations

import pytest

import pysymex._internal.models.stdlib.math.registry as math_models


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
