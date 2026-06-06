"""Shared state contract for Docker test runner mixins."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from tests.docker.models import TestResult


class DockerRunnerState:
    """State and cross-mixin methods required by Docker runner mixins."""

    PYTHON_VERSIONS: ClassVar[tuple[str, ...]]
    SERVICE_NAMES: ClassVar[dict[str, str]]
    STARTUP_TIMEOUT: ClassVar[float]
    COMPOSE_TIMEOUT: ClassVar[float]
    TEST_TIMEOUT: ClassVar[float]
    MAX_RETRIES: ClassVar[int]

    pytest_args: list[str]
    project_root: Path
    compose_project: str
    _container_ids: dict[str, str]
    _docker_started: bool
    _last_docker_error: str | None
    prompt_wsl_update: bool
    assume_yes: bool

    def container_id_for_version(self, version: str) -> str | None:
        """Return the current container ID for a Python version, if known."""
        return self._container_ids.get(version)

    def ensure_containers_running(self) -> dict[str, bool]:
        """Ensure all Docker containers are running."""
        raise NotImplementedError

    def run_tests_in_container(self, version: str, retry_count: int = 0) -> TestResult:
        """Run pytest in a specific Docker container."""
        raise NotImplementedError
