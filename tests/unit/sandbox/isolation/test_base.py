from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pysymex._internal.config.sandbox.types import SandboxConfig
from pysymex._internal.sandbox.isolation.base import IsolationBackend
from pysymex._internal.sandbox.types import SandboxResult


class _TestIsolationBackend(IsolationBackend):
    @property
    def is_available(self) -> bool:
        return True

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        raise NotImplementedError


def test_create_jail_does_not_collide_when_time_ns_repeats(tmp_path: Path) -> None:
    first = _TestIsolationBackend(SandboxConfig(working_directory=tmp_path))
    second = _TestIsolationBackend(SandboxConfig(working_directory=tmp_path))

    try:
        with patch("pysymex._internal.sandbox.isolation.base.time.time_ns", return_value=1):
            first.setup()
            second.setup()

        first_jail = first.jail_path
        second_jail = second.jail_path

        assert first_jail is not None
        assert second_jail is not None

        assert first_jail != second_jail
        assert first_jail.exists()
        assert second_jail.exists()
    finally:
        first.cleanup()
        second.cleanup()
