from __future__ import annotations

import pathlib

from tests.conftest import PROJECT_ROOT, centralized_pytest_basetemp


def test_relative_pytest_basetemp_overrides_are_centralized() -> None:
    """Keep ad hoc pytest temp roots inside the configured runtime directory."""
    assert centralized_pytest_basetemp(".pytest_tmp_focus") == (
        PROJECT_ROOT / ".tmp" / "pytest" / "tmp" / ".pytest_tmp_focus"
    )


def test_configured_pytest_runtime_basetemp_is_not_rewritten() -> None:
    """Preserve the canonical basetemp configured in ``pyproject.toml``."""
    assert centralized_pytest_basetemp(".tmp/pytest/tmp") is None


def test_absolute_pytest_basetemp_is_not_rewritten() -> None:
    """Respect intentionally external absolute basetemp paths."""
    absolute_path = pathlib.Path(pathlib.Path.cwd().anchor) / "tmp" / ".pytest_tmp_external"

    assert centralized_pytest_basetemp(absolute_path) is None
