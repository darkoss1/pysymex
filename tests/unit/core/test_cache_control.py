from __future__ import annotations

from pytest import MonkeyPatch

from pysymex.core.cache import get_exception_entries, get_instructions
import pysymex.core.cache.control as cache_control_mod
from pysymex.core.cache.control import clear_process_caches, process_caches_disabled
from pysymex.execution.engine import line_mapping_cache_stats


def _sample() -> int:
    return 1


def test_clear_process_caches_invokes_registered_clearers(monkeypatch: MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cache_control_mod, "_PROCESS_CACHE_CLEARERS", {})

    cache_control_mod.register_process_cache_clearer(
        "unit.marker",
        lambda: calls.append("cleared"),
    )

    cache_control_mod.clear_process_caches()

    assert calls == ["cleared"]


def test_process_caches_disabled_bypasses_instruction_lrus() -> None:
    clear_process_caches()

    with process_caches_disabled():
        assert get_instructions(_sample.__code__)
        assert get_exception_entries(_sample.__code__) == ()

    assert get_instructions.cache_info().currsize == 0
    assert get_exception_entries.cache_info().currsize == 0
    assert line_mapping_cache_stats()["currsize"] == 0


def test_clear_process_caches_removes_existing_instruction_lru_entries() -> None:
    get_instructions(_sample.__code__)
    get_exception_entries(_sample.__code__)
    assert get_instructions.cache_info().currsize >= 1
    assert get_exception_entries.cache_info().currsize >= 1

    clear_process_caches()

    assert get_instructions.cache_info().currsize == 0
    assert get_exception_entries.cache_info().currsize == 0
