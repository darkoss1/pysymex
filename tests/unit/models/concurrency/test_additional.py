from __future__ import annotations

import pytest

import pysymex.models.concurrency.asyncio as asyncio_models
import pysymex.models.concurrency.threading as threading_models


@pytest.mark.parametrize("name", ["Task", "Event", "Lock", "Future"])
def test_asyncio_registry_smoke(name: str) -> None:
    assert asyncio_models.get_asyncio_model(name) is not None


@pytest.mark.parametrize("name", ["Thread", "Lock", "RLock", "Barrier"])
def test_threading_registry_smoke(name: str) -> None:
    assert threading_models.get_threading_model(name) is not None


def test_concurrency_auto_discovery_mappings() -> None:
    assert "Task" in asyncio_models.ASYNCIO_MODELS
    assert "Lock" in threading_models.THREADING_MODELS
