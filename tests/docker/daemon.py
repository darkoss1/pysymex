"""Docker daemon and container lifecycle operations for the test runner."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from typing import cast

from tests.docker.commands import command_error_text
from tests.docker.containers import DockerContainerLifecycleMixin
from tests.docker.protocols import DockerRunnerState
from tests.docker.windows import collect_windows_backend_diagnostics
from tests.docker.windows import restart_docker_desktop
from tests.docker.windows import run_winget_wsl_upgrade
from tests.docker.windows import run_wsl_update
from tests.docker.windows import winget_wsl_repair_is_relevant

_LEGACY_CONTAINER_NAMES = {
    "3.11": "pysymex-python311",
    "3.12": "pysymex-python312",
    "3.13": "pysymex-python313",
}
_WORKSPACE_PYTEST_RUNTIME_CLEANUP_SCRIPT = r"""
from pathlib import Path
import os
import shutil
import stat
import sys

workspace = Path("/workspace").resolve()
target = workspace / ".pytest_runtime"
if not target.exists() and not target.is_symlink():
    raise SystemExit(0)
if target.parent.resolve() != workspace or target.name != ".pytest_runtime":
    print(f"refusing unexpected cleanup target: {target}", file=sys.stderr)
    raise SystemExit(2)
if target.is_symlink() or not target.is_dir():
    print(f"refusing non-directory cleanup target: {target}", file=sys.stderr)
    raise SystemExit(3)

def on_rm_error(function, path, _exc_info):
    os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    function(path)

try:
    shutil.rmtree(target, onerror=on_rm_error)
except PermissionError as exc:
    print(f"existing pytest runtime directory is not removable from Docker: {exc}", file=sys.stderr)
    raise SystemExit(4) from exc
"""


def _matches_current_container_id(container_id: str, current_container_ids: tuple[str, ...]) -> bool:
    """Return whether a short or full Docker ID identifies a current service container."""
    return any(
        current_id == container_id
        or current_id.startswith(container_id)
        or container_id.startswith(current_id)
        for current_id in current_container_ids
    )


class DockerDaemonMixin(DockerContainerLifecycleMixin, DockerRunnerState):
    """Docker daemon and container lifecycle methods."""

    def _cleanup(self) -> None:
        """Cleanup resources on exit."""
        if self._docker_started:
            print("Docker was started by this script. It will remain running for future use.")
            print("To stop Docker Desktop manually:")
            if platform.system() == "Windows":
                print(
                    "  - Right-click the Docker Desktop icon in the system tray and select 'Quit Docker Desktop'"
                )
            elif platform.system() == "Linux":
                print("  - Run: sudo systemctl stop docker")

    def ensure_containers_running(self) -> dict[str, bool]:
        """Ensure all Docker containers are running."""
        if not self._ensure_docker_daemon_running():
            print("ERROR: Failed to start Docker daemon. Aborting.")
            return {version: False for version in self.PYTHON_VERSIONS}

        running: dict[str, bool] = {}
        print(f"Docker Compose project: {self.compose_project}")
        self._cleanup_legacy_project_containers()
        for version in self.PYTHON_VERSIONS:
            service_name = self.SERVICE_NAMES[version]
            container_id = self._compose_container_id(version)
            if container_id is None or not self._check_container_running(container_id):
                if not self._start_container(version):
                    print(f"ERROR: Failed to issue start command for service {service_name}")
                    running[version] = False
                    continue

                container_id = self._compose_container_id(version)
                if container_id is None:
                    print(f"ERROR: Compose did not report a container for service {service_name}")
                    running[version] = False
                    continue

            if self._wait_for_container(container_id):
                self._container_ids[version] = container_id
                running[version] = True
            else:
                print(f"ERROR: Failed to start service {service_name}")
                running[version] = False
        self._cleanup_stale_checkout_containers()
        return running

    def _cleanup_workspace_pytest_runtime(self) -> None:
        """Remove only this checkout's generated pytest runtime directory via Docker."""
        for version in self.PYTHON_VERSIONS:
            container_id = self._container_ids.get(version)
            if container_id is None:
                continue
            labels = self._container_labels(container_id)
            if not self._container_belongs_to_current_checkout(labels):
                continue
            try:
                result = subprocess.run(
                    [
                        "docker",
                        "exec",
                        "--user",
                        "root",
                        container_id,
                        "python",
                        "-I",
                        "-B",
                        "-c",
                        _WORKSPACE_PYTEST_RUNTIME_CLEANUP_SCRIPT,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                print(f"WARNING: Could not clean Docker pytest runtime directory: {exc}")
                return
            if result.returncode != 0:
                print(
                    "WARNING: Could not clean legacy Docker pytest runtime directory; "
                    "Docker tests will use container-local /tmp scratch paths. "
                    f"{command_error_text(result)}"
                )
            return

    def _cleanup_stale_checkout_containers(self) -> None:
        """Remove stale Compose containers from this checkout without touching other projects."""
        container_ids = self._list_project_container_ids()
        if not container_ids:
            return

        current_container_ids = tuple(self._container_ids.values())
        expected_services = set(self.SERVICE_NAMES.values())
        for container_id in container_ids:
            if _matches_current_container_id(container_id, current_container_ids):
                continue
            labels = self._container_labels(container_id)
            if not self._container_belongs_to_current_checkout(labels):
                continue
            service = labels.get("com.docker.compose.service") if labels else None
            if service not in expected_services:
                continue
            result = subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if result.returncode == 0:
                print(f"Removed stale Docker container {container_id} for service {service}.")

    def _list_project_container_ids(self) -> list[str]:
        """Return Docker container IDs that claim this runner's Compose project."""
        try:
            result = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    f"label=com.docker.compose.project={self.compose_project}",
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _cleanup_legacy_project_containers(self) -> None:
        """Remove old fixed-name containers that belong to this checkout."""
        config_file = str((self.project_root / "docker-compose.yml").resolve())
        working_dir = str(self.project_root.resolve())
        for version in self.PYTHON_VERSIONS:
            legacy_name = _LEGACY_CONTAINER_NAMES.get(version)
            if legacy_name is None:
                continue
            labels = self._container_labels(legacy_name)
            if labels is None:
                continue
            if labels.get("com.docker.compose.project.working_dir") != working_dir:
                continue
            if labels.get("com.docker.compose.project.config_files") != config_file:
                continue
            result = subprocess.run(
                ["docker", "rm", "-f", legacy_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if result.returncode == 0:
                print(f"Removed legacy Docker container {legacy_name}.")

    @staticmethod
    def _container_labels(container_name: str) -> dict[str, str] | None:
        """Return Docker labels for a container, or None when absent."""
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    container_name,
                    "--format",
                    "{{json .Config.Labels}}",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        try:
            raw_labels: object = json.loads(result.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return None
        if not isinstance(raw_labels, dict):
            return None
        labels_obj = cast("dict[object, object]", raw_labels)
        labels: dict[str, str] = {}
        for key, value in labels_obj.items():
            if isinstance(key, str) and isinstance(value, str):
                labels[key] = value
        return labels

    def _container_belongs_to_current_checkout(self, labels: dict[str, str] | None) -> bool:
        """Return whether Docker labels identify the current Compose checkout."""
        if labels is None:
            return False
        config_file = str((self.project_root / "docker-compose.yml").resolve())
        working_dir = str(self.project_root.resolve())
        return (
            labels.get("com.docker.compose.project.working_dir") == working_dir
            and labels.get("com.docker.compose.project.config_files") == config_file
        )

    def _ensure_docker_daemon_running(self) -> bool:
        """Ensure Docker daemon is running, starting it if necessary."""
        if self._check_docker_daemon(quiet=False):
            return True

        system = platform.system()

        if system == "Windows":
            if self._windows_backend_is_blocked():
                if not self._try_update_wsl_then_retry():
                    print("ERROR: Docker Desktop Linux engine is blocked before startup.")
                    print("Update or repair WSL, then run this script again.")
                    return False
                if self._check_docker_daemon(quiet=False):
                    return True
                print("Docker daemon is not running after WSL update. Attempting to start...")
                return self._start_docker_windows()
            print("Docker daemon is not running. Attempting to start...")
            return self._start_docker_windows()
        if system == "Linux":
            print("Docker daemon is not running. Attempting to start...")
            return self._start_docker_linux()
        print(f"ERROR: Unsupported platform: {system}")
        print("This script supports Windows and Linux only.")
        return False

    def _check_docker_daemon(self, timeout: float = 10.0, *, quiet: bool = True) -> bool:
        """Check if Docker daemon is running."""
        self._last_docker_error = None
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return True
            self._last_docker_error = command_error_text(result)
            if not quiet:
                print("Docker daemon check failed:")
                self._print_last_docker_error()
            return False
        except FileNotFoundError:
            self._last_docker_error = "Docker command not found."
            if quiet:
                return False
            print("ERROR: Docker command not found.")
            print("\nPlease install Docker:")
            if platform.system() == "Windows":
                print("  Download Docker Desktop for Windows from:")
                print("  https://www.docker.com/products/docker-desktop/")
                print("\nAfter installation, start Docker Desktop and run this script again.")
            elif platform.system() == "Linux":
                print("  Install Docker Engine using:")
                print("  curl -fsSL https://get.docker.com -o get-docker.sh")
                print("  sudo sh get-docker.sh")
                print("\nThen start the Docker daemon:")
                print("  sudo systemctl start docker")
                print("  sudo usermod -aG docker $USER")
            return False
        except subprocess.TimeoutExpired:
            self._last_docker_error = f"docker info timed out after {timeout:.1f}s."
            return False

    def _print_last_docker_error(self) -> None:
        """Print the last captured Docker daemon error without hiding multiline detail."""
        if self._last_docker_error is None:
            return
        for line in self._last_docker_error.splitlines():
            print(f"  {line}")

    def _windows_backend_is_blocked(self) -> bool:
        """Print Windows Docker Desktop diagnostics and return true for known WSL blockers."""
        diagnostics = collect_windows_backend_diagnostics()
        if diagnostics.lines:
            print("Docker Desktop Windows diagnostics:")
            for diagnostic in diagnostics.lines:
                for line in diagnostic.splitlines():
                    print(f"  {line}")
        return diagnostics.blocked

    def _try_update_wsl_then_retry(self) -> bool:
        """Update WSL and restart Docker only when explicitly enabled and confirmed."""
        if not self.prompt_wsl_update:
            print("WSL update prompt disabled. Re-run with --update-wsl to offer remediation.")
            return False

        if not self._confirm_wsl_update():
            print("Skipping WSL update at user request.")
            return False

        print("Running: wsl --update")
        status, output = run_wsl_update()
        if output:
            self._print_command_output("WSL update output", output)
        if status != 0:
            print("ERROR: wsl --update failed.")
            if not winget_wsl_repair_is_relevant(output):
                return False
            if not self._try_winget_wsl_upgrade():
                return False

        if not self._restart_docker_desktop_after_wsl_update():
            return False

        print("WSL update completed. Re-checking Docker daemon...")
        return True

    def _try_winget_wsl_upgrade(self) -> bool:
        """Fallback to the WSL package upgrade when `wsl --update` is itself broken."""
        print("Falling back to: winget upgrade --id Microsoft.WSL")
        status, output = run_winget_wsl_upgrade()
        if output:
            self._print_command_output("winget WSL upgrade output", output)
        if status == 0:
            return True
        print("ERROR: winget WSL upgrade failed.")
        return False

    def _restart_docker_desktop_after_wsl_update(self) -> bool:
        """Restart Docker Desktop after WSL package maintenance."""
        print("Restarting Docker Desktop after WSL update...")
        status, output = restart_docker_desktop()
        if output:
            self._print_command_output("Docker Desktop restart output", output)
        if status == 0:
            return True
        print("ERROR: Docker Desktop restart failed after WSL update.")
        return False

    def _print_command_output(self, label: str, output: str) -> None:
        """Print normalized multiline command output with a stable label."""
        print(f"{label}:")
        for line in output.splitlines():
            print(f"  {line}")

    def _confirm_wsl_update(self) -> bool:
        """Ask for confirmation before running a host-level WSL update command."""
        if self.assume_yes:
            print("Assuming yes for WSL update because --yes was provided.")
            return True

        if not sys.stdin.isatty():
            print("Cannot prompt for WSL update because stdin is not interactive.")
            print("Re-run with --update-wsl --yes to allow noninteractive remediation.")
            return False

        answer = input("Run 'wsl --update' now? [y/N] ").strip().lower()
        return answer in {"y", "yes"}

    def _start_docker_windows(self) -> bool:
        """Start Docker Desktop on Windows."""
        try:
            docker_desktop_paths = [
                r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
                r"C:\Program Files\Docker\Docker\DockerCli.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Docker\Docker Desktop\Docker Desktop.exe"),
            ]

            for path in docker_desktop_paths:
                if os.path.exists(path):
                    print(f"Starting Docker Desktop from {path}...")
                    try:
                        subprocess.Popen([path])
                        self._docker_started = True
                        max_wait = 120
                        print(f"Waiting up to {max_wait} seconds for Docker to start...")
                        for i in range(max_wait):
                            if self._check_docker_daemon(timeout=2.0):
                                print("Docker Desktop started successfully.")
                                return True
                            if (i + 1) % 5 == 0:
                                print(f"Waiting for Docker to start... ({i + 1}/{max_wait}s)")
                            time.sleep(1)
                        print("ERROR: Timeout waiting for Docker Desktop to start.")
                        print("Docker Desktop may be starting in the background.")
                        self._print_last_docker_error()
                        print("On Windows, verify Docker Desktop's Linux engine and WSL 2 setup.")
                        print("Please wait a moment and run this script again.")
                        return False
                    except Exception as e:
                        print(f"ERROR: Failed to start Docker Desktop: {e}")
                        return False

            print("ERROR: Could not find Docker Desktop executable.")
            print("\nPlease install Docker Desktop:")
            print("  1. Download from: https://www.docker.com/products/docker-desktop/")
            print("  2. Install Docker Desktop for Windows")
            print("  3. Start Docker Desktop from the Start menu")
            print("  4. Run this script again")
            return False

        except Exception as e:
            print(f"ERROR: Unexpected error starting Docker Desktop: {e}")
            return False

    def _start_docker_linux(self) -> bool:
        """Start Docker daemon on Linux."""
        try:
            print("Attempting to start Docker daemon via systemctl...")
            result = subprocess.run(
                ["sudo", "systemctl", "start", "docker"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                self._docker_started = True
                max_wait = 30
                print(f"Waiting up to {max_wait} seconds for Docker daemon...")
                for i in range(max_wait):
                    if self._check_docker_daemon(timeout=2.0):
                        print("Docker daemon started successfully.")
                        return True
                    if (i + 1) % 5 == 0:
                        print(f"Waiting for Docker daemon... ({i + 1}/{max_wait}s)")
                    time.sleep(1)
                print("ERROR: Timeout waiting for Docker daemon to start.")
                return False

            print(f"ERROR: systemctl failed: {result.stderr}")
            return self._start_docker_linux_with_service()

        except subprocess.TimeoutExpired:
            print("ERROR: Timeout starting Docker daemon.")
            return False
        except FileNotFoundError:
            print("ERROR: sudo command not found. Please install sudo.")
            return False
        except Exception as e:
            print(f"ERROR: Unexpected error starting Docker daemon: {e}")
            return False

    def _start_docker_linux_with_service(self) -> bool:
        """Start Docker daemon on Linux via the service command fallback."""
        print("Attempting to start Docker daemon via service command...")
        result = subprocess.run(
            ["sudo", "service", "docker", "start"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            self._docker_started = True
            max_wait = 30
            print(f"Waiting up to {max_wait} seconds for Docker daemon (fallback)...")
            for i in range(max_wait):
                if self._check_docker_daemon(timeout=2.0):
                    print("Docker daemon started successfully.")
                    return True
                if (i + 1) % 5 == 0:
                    print(f"Waiting for Docker daemon... ({i + 1}/{max_wait}s)")
                time.sleep(1)
        print("ERROR: Failed to start Docker daemon.")
        print("\nPlease install and start Docker manually:")
        print("  1. Install Docker Engine:")
        print("     curl -fsSL https://get.docker.com -o get-docker.sh")
        print("     sudo sh get-docker.sh")
        print("  2. Add your user to the docker group:")
        print("     sudo usermod -aG docker $USER")
        print("  3. Start the Docker daemon:")
        print("     sudo systemctl start docker")
        print("  4. Log out and log back in for group changes to take effect")
        print("  5. Run this script again")
        return False
