"""Core Docker test runner class."""

from __future__ import annotations

import atexit
import hashlib
from pathlib import Path
from typing import ClassVar

from tests.docker.daemon import DockerDaemonMixin
from tests.docker.execution import DockerExecutionMixin


class DockerTestRunner(DockerDaemonMixin, DockerExecutionMixin):
    """Manages parallel test execution across Docker containers."""

    PYTHON_VERSIONS: ClassVar[tuple[str, ...]] = ("3.11", "3.12", "3.13")
    SERVICE_NAMES: ClassVar[dict[str, str]] = {
        "3.11": "python311",
        "3.12": "python312",
        "3.13": "python313",
    }
    STARTUP_TIMEOUT = 30.0
    COMPOSE_TIMEOUT = 900.0
    TEST_TIMEOUT = 600.0
    MAX_RETRIES = 2

    def __init__(
        self,
        pytest_args: list[str],
        *,
        prompt_wsl_update: bool = False,
        assume_yes: bool = False,
    ) -> None:
        """Initialize the test runner."""
        self.pytest_args = pytest_args
        self.project_root = Path(__file__).resolve().parents[2]
        self.compose_project = _compose_project_name(self.project_root)
        self._container_ids: dict[str, str] = {}
        self._docker_started = False
        self._last_docker_error: str | None = None
        self.prompt_wsl_update = prompt_wsl_update
        self.assume_yes = assume_yes
        atexit.register(self._cleanup)


def _compose_project_name(project_root: Path) -> str:
    """Build a deterministic Docker Compose project name scoped to one checkout."""
    root_text = str(project_root.resolve()).lower()
    digest = hashlib.sha1(root_text.encode("utf-8")).hexdigest()[:12]
    return f"pysymex-{digest}"
