"""Container lifecycle operations for the Docker test runner."""

from __future__ import annotations

import subprocess
import time

from tests.docker.protocols import DockerRunnerState


class DockerContainerLifecycleMixin(DockerRunnerState):
    """Docker container existence, startup, compose fallback, and readiness checks."""

    def _compose_commands(self, *args: str) -> tuple[list[str], list[str]]:
        """Return Docker Compose command variants scoped to this runner's project."""
        return (
            ["docker", "compose", "-p", self.compose_project, *args],
            ["docker-compose", "-p", self.compose_project, *args],
        )

    def _compose_container_id(self, version: str) -> str | None:
        """Resolve the current Compose service container ID for a Python version."""
        service_name = self.SERVICE_NAMES[version]
        for command in self._compose_commands("ps", "-q", service_name):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                    cwd=self.project_root,
                )
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                continue

            if result.returncode == 0:
                container_id = result.stdout.strip().splitlines()
                if container_id:
                    return container_id[0]
                return None

        return None

    def _check_container_running(self, container_identifier: str) -> bool:
        """Check if a Docker container is running."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_identifier],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip() == "true"
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def _start_container(self, version: str) -> bool:
        """Start a Docker container."""
        service_name = self.SERVICE_NAMES[version]
        print(
            "Starting Docker Compose service "
            f"{service_name} in project {self.compose_project}..."
        )
        return self._compose_up_service(version)

    def _compose_up_service(self, version: str) -> bool:
        """Create or start a Docker Compose service for a Python version."""
        service_name = self.SERVICE_NAMES[version]
        for command in self._compose_commands("up", "-d", "--build", service_name):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.COMPOSE_TIMEOUT,
                    cwd=self.project_root,
                )
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                print(f"{' '.join(command)} timed out.")
                return False

            if result.returncode == 0:
                return True

            error = (result.stderr or result.stdout).strip()
            if error:
                print(f"{' '.join(command)} failed: {error}")

        return False

    def _wait_for_container(self, container_identifier: str) -> bool:
        """Wait for container to be ready."""
        start = time.time()
        while time.time() - start < self.STARTUP_TIMEOUT:
            if self._check_container_running(container_identifier):
                try:
                    result = subprocess.run(
                        [
                            "docker",
                            "exec",
                            container_identifier,
                            "python",
                            "-c",
                            "import sys; print(sys.version)",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            time.sleep(1)
        return False
