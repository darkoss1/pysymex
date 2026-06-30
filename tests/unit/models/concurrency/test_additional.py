from __future__ import annotations

import pytest

from pysymex._internal.models.registry import RuntimeModelRegistry


@pytest.mark.parametrize("name", ["Thread", "Lock", "RLock", "Barrier"])
def test_threading_registry_smoke(name: str) -> None:
    model = RuntimeModelRegistry.default().resolve(f"threading.{name}")
    assert model is not None
    assert model.qualname == f"threading.{name}"


def test_unknown_threading_model_is_not_registered() -> None:
    assert RuntimeModelRegistry.default().resolve("threading.missing") is None
