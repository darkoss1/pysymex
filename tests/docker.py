"""Parallel Docker test runner for pysymex across multiple Python versions.

This script runs pytest in parallel across Docker containers for Python 3.11, 3.12, and 3.13,
providing stable, reliable test execution with comprehensive result reporting.

Usage:
    python tests/docker.py [pytest_args...]

Example:
    python tests/docker.py -v tests/unit/
    python tests/docker.py -k "test_analyze"
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final


class TestStatus(Enum):
    """Status of test execution."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True)
class TestResult:
    """Result of test execution for a single Python version."""

    version: str
    container_name: str
    status: TestStatus
    exit_code: int | None
    duration: float
    passed: int
    failed: int
    errors: int
    skipped: int
    xfailed: int
    xpassed: int
    total: int
    output: str
    error_output: str


class DockerTestRunner:
    """Manages parallel test execution across Docker containers."""

    PYTHON_VERSIONS: Final = ["3.11", "3.12", "3.13"]
    CONTAINER_NAMES: Final = {
        "3.11": "pysymex-python311",
        "3.12": "pysymex-python312",
        "3.13": "pysymex-python313",
    }
    SERVICE_NAMES: Final = {
        "3.11": "python311",
        "3.12": "python312",
        "3.13": "python313",
    }
    STARTUP_TIMEOUT: Final = 30.0  # seconds
    COMPOSE_TIMEOUT: Final = 900.0  # 15 minutes
    TEST_TIMEOUT: Final = 600.0  # 10 minutes
    MAX_RETRIES: Final = 2

    def __init__(self, pytest_args: list[str]) -> None:
        """Initialize the test runner.

        Args:
            pytest_args: Additional arguments to pass to pytest.
        """
        self.pytest_args = pytest_args
        self.project_root = Path(__file__).parent.parent
        self._docker_started = False
        # Register cleanup handler
        atexit.register(self._cleanup)

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
        """Ensure all Docker containers are running.

        Returns:
            Dictionary mapping Python version to whether container is running.
        """
        # First ensure Docker daemon is running
        if not self._ensure_docker_daemon_running():
            print("ERROR: Failed to start Docker daemon. Aborting.")
            return {version: False for version in self.PYTHON_VERSIONS}

        running: dict[str, bool] = {}
        for version in self.PYTHON_VERSIONS:
            container_name = self.CONTAINER_NAMES[version]
            status = self._check_container_running(container_name)
            if not status:
                print(f"Starting container {container_name}...")
                if not self._start_container(version):
                    print(f"ERROR: Failed to issue start command for {container_name}")
                    running[version] = False
                    continue
                # Wait for container to be healthy
                if self._wait_for_container(container_name):
                    running[version] = True
                else:
                    print(f"ERROR: Failed to start container {container_name}")
                    running[version] = False
            else:
                running[version] = True
        return running

    def _ensure_docker_daemon_running(self) -> bool:
        """Ensure Docker daemon is running, starting it if necessary.

        Returns:
            True if Docker daemon is running, False otherwise.
        """
        if self._check_docker_daemon():
            return True

        print("Docker daemon is not running. Attempting to start...")
        system = platform.system()

        if system == "Windows":
            return self._start_docker_windows()
        elif system == "Linux":
            return self._start_docker_linux()
        else:
            print(f"ERROR: Unsupported platform: {system}")
            print("This script supports Windows and Linux only.")
            return False

    def _check_docker_daemon(self, timeout: float = 10.0) -> bool:
        """Check if Docker daemon is running.

        Returns:
            True if Docker daemon is running, False otherwise.
        """
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode == 0
        except FileNotFoundError:
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
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False

    def _start_docker_windows(self) -> bool:
        """Start Docker Desktop on Windows.

        Returns:
            True if Docker Desktop started successfully, False otherwise.
        """
        try:
            # Try to start Docker Desktop via the executable
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
                        # Wait for Docker to start
                        max_wait = 120  # 120 seconds timeout for Windows
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
        """Start Docker daemon on Linux.

        Returns:
            True if Docker daemon started successfully, False otherwise.
        """
        try:
            # Try to start docker service using systemctl
            print("Attempting to start Docker daemon via systemctl...")
            result = subprocess.run(
                ["sudo", "systemctl", "start", "docker"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                self._docker_started = True
                # Wait for Docker to start
                max_wait = 30  # 30 seconds is safer for Linux startup
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
            else:
                print(f"ERROR: systemctl failed: {result.stderr}")
                # Try service command as fallback
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

        except subprocess.TimeoutExpired:
            print("ERROR: Timeout starting Docker daemon.")
            return False
        except FileNotFoundError:
            print("ERROR: sudo command not found. Please install sudo.")
            return False
        except Exception as e:
            print(f"ERROR: Unexpected error starting Docker daemon: {e}")
            return False

    def _check_container_running(self, container_name: str) -> bool:
        """Check if a Docker container is running.

        Args:
            container_name: Name of the container to check.

        Returns:
            True if container is running, False otherwise.
        """
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip() == "true"
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def _check_container_exists(self, container_name: str) -> bool:
        """Check if a Docker container exists.

        Args:
            container_name: Name of the container to check.

        Returns:
            True if Docker knows about the container, False otherwise.
        """
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.Id}}", container_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def _start_container(self, version: str) -> bool:
        """Start a Docker container.

        Args:
            version: Python version whose container should be started.

        Returns:
            True if container started successfully, False otherwise.
        """
        container_name = self.CONTAINER_NAMES[version]
        if not self._check_container_exists(container_name):
            print(f"Container {container_name} does not exist. Creating it with Docker Compose...")
            return self._compose_up_service(version)

        try:
            result = subprocess.run(
                ["docker", "start", container_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True

            error = (result.stderr or result.stdout).strip()
            if error:
                print(f"docker start failed for {container_name}: {error}")
            print(f"Falling back to Docker Compose for {container_name}...")
            return self._compose_up_service(version)
        except subprocess.TimeoutExpired:
            print(f"docker start timed out for {container_name}. Falling back to Docker Compose...")
            return self._compose_up_service(version)
        except FileNotFoundError:
            return False

    def _compose_up_service(self, version: str) -> bool:
        """Create or start a Docker Compose service for a Python version."""
        service_name = self.SERVICE_NAMES[version]
        commands = (
            ["docker", "compose", "up", "-d", "--build", service_name],
            ["docker-compose", "up", "-d", "--build", service_name],
        )
        for command in commands:
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

    def _wait_for_container(self, container_name: str) -> bool:
        """Wait for container to be ready.

        Args:
            container_name: Name of the container to wait for.

        Returns:
            True if container became ready, False if timeout.
        """
        start = time.time()
        while time.time() - start < self.STARTUP_TIMEOUT:
            if self._check_container_running(container_name):
                # Additional check: verify Python is accessible
                try:
                    result = subprocess.run(
                        [
                            "docker",
                            "exec",
                            container_name,
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

    def run_tests_in_container(self, version: str, retry_count: int = 0) -> TestResult:
        """Run pytest in a specific Docker container.

        Args:
            version: Python version (e.g., "3.11").
            retry_count: Current retry attempt number.

        Returns:
            TestResult containing execution details.
        """
        container_name = self.CONTAINER_NAMES[version]
        start_time = time.time()

        # Build pytest command
        pytest_cmd = [
            "docker",
            "exec",
            container_name,
            "python",
            "-m",
            "pytest",
            "-v",
            "--tb=short",
            "--no-header",
            "-q",
        ] + self.pytest_args

        try:
            result = subprocess.run(
                pytest_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.TEST_TIMEOUT,
                cwd=self.project_root,
            )
            duration = time.time() - start_time
            output = result.stdout
            error_output = result.stderr

            # Parse pytest output
            stats = self._parse_pytest_output(output + error_output)

            if result.returncode == 0:
                status = TestStatus.SUCCESS
            else:
                status = TestStatus.FAILURE

            return TestResult(
                version=version,
                container_name=container_name,
                status=status,
                exit_code=result.returncode,
                duration=duration,
                passed=stats.get("passed", 0),
                failed=stats.get("failed", 0),
                errors=stats.get("errors", 0),
                skipped=stats.get("skipped", 0),
                xfailed=stats.get("xfailed", 0),
                xpassed=stats.get("xpassed", 0),
                total=stats.get("total", 0),
                output=output,
                error_output=error_output,
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return TestResult(
                version=version,
                container_name=container_name,
                status=TestStatus.TIMEOUT,
                exit_code=None,
                duration=duration,
                passed=0,
                failed=0,
                errors=0,
                skipped=0,
                xfailed=0,
                xpassed=0,
                total=0,
                output="",
                error_output="Test execution timed out",
            )

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            duration = time.time() - start_time
            return TestResult(
                version=version,
                container_name=container_name,
                status=TestStatus.ERROR,
                exit_code=None,
                duration=duration,
                passed=0,
                failed=0,
                errors=0,
                skipped=0,
                xfailed=0,
                xpassed=0,
                total=0,
                output="",
                error_output=str(e),
            )

    def _parse_pytest_output(self, output: str) -> dict[str, int]:
        """Parse pytest output to extract test statistics.

        Args:
            output: Combined stdout and stderr from pytest.

        Returns:
            Dictionary with keys: passed, failed, errors, skipped, total.
        """
        stats = {
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "total": 0,
        }
        summary_line: str | None = None
        for line in reversed(output.splitlines()):
            text = line.strip()
            if " in " in text and any(
                token in text
                for token in (
                    "passed",
                    "failed",
                    "error",
                    "errors",
                    "skipped",
                    "xfailed",
                    "xpassed",
                )
            ):
                summary_line = text
                break
        if summary_line is None:
            return stats

        for count_text, label in re.findall(
            r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)\b",
            summary_line,
        ):
            count = int(count_text)
            if label == "passed":
                stats["passed"] = count
            elif label == "failed":
                stats["failed"] = count
            elif label in ("error", "errors"):
                stats["errors"] = count
            elif label == "skipped":
                stats["skipped"] = count
            elif label == "xfailed":
                stats["xfailed"] = count
            elif label == "xpassed":
                stats["xpassed"] = count

        stats["total"] = (
            stats["passed"]
            + stats["failed"]
            + stats["errors"]
            + stats["skipped"]
            + stats["xfailed"]
            + stats["xpassed"]
        )

        return stats

    def run_all_tests(self) -> dict[str, TestResult]:
        """Run tests in all containers in parallel.

        Returns:
            Dictionary mapping Python version to TestResult.
        """
        print("Ensuring Docker containers are running...")
        running = self.ensure_containers_running()

        if not all(running.values()):
            print("ERROR: Not all containers are running. Aborting.")
            return {
                version: TestResult(
                    version=version,
                    container_name=self.CONTAINER_NAMES[version],
                    status=TestStatus.ERROR,
                    exit_code=None,
                    duration=0.0,
                    passed=0,
                    failed=0,
                    errors=0,
                    skipped=0,
                    xfailed=0,
                    xpassed=0,
                    total=0,
                    output="",
                    error_output="Container not running",
                )
                for version in self.PYTHON_VERSIONS
            }

        print(f"Running tests in parallel across {len(running)} Python versions...")
        print(f"Pytest arguments: {' '.join(self.pytest_args) if self.pytest_args else 'default'}")
        print()

        results: dict[str, TestResult] = {}

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.PYTHON_VERSIONS)
        ) as executor:
            future_to_version = {
                executor.submit(self.run_tests_in_container, version): version
                for version in self.PYTHON_VERSIONS
            }

            for future in concurrent.futures.as_completed(future_to_version):
                version = future_to_version[future]
                try:
                    result = future.result()
                    results[version] = result
                except Exception as e:
                    results[version] = TestResult(
                        version=version,
                        container_name=self.CONTAINER_NAMES[version],
                        status=TestStatus.ERROR,
                        exit_code=None,
                        duration=0.0,
                        passed=0,
                        failed=0,
                        errors=0,
                        skipped=0,
                        xfailed=0,
                        xpassed=0,
                        total=0,
                        output="",
                        error_output=str(e),
                    )

        return results

    def print_results(self, results: dict[str, TestResult]) -> int:
        """Print formatted test results.

        Args:
            results: Dictionary mapping Python version to TestResult.

        Returns:
            Exit code (0 if all successful, 1 otherwise).
        """
        print("=" * 80)
        print("DOCKER TEST RESULTS")
        print("=" * 80)
        print()
        check_symbol = "✓"
        fail_symbol = "✗"
        encoding = sys.stdout.encoding or "utf-8"
        try:
            check_symbol.encode(encoding)
            fail_symbol.encode(encoding)
        except UnicodeEncodeError:
            check_symbol = "OK"
            fail_symbol = "X"
        for version in sorted(results.keys()):
            result = results[version]
            status_symbol = check_symbol if result.status == TestStatus.SUCCESS else fail_symbol
            status_color = "\033[92m" if result.status == TestStatus.SUCCESS else "\033[91m"
            reset_color = "\033[0m"

            print(
                f"{status_color}{status_symbol} Python {version}{reset_color} ({result.container_name})"
            )
            print(f"  Status: {result.status.value}")
            print(f"  Duration: {result.duration:.2f}s")
            print(f"  Tests: {result.total} total")
            print(f"    Passed: {result.passed}")
            print(f"    Failed: {result.failed}")
            print(f"    Errors: {result.errors}")
            print(f"    Skipped: {result.skipped}")
            print(f"    XFailed: {result.xfailed}")
            print(f"    XPassed: {result.xpassed}")

            if result.status != TestStatus.SUCCESS and result.error_output:
                print(f"  Error: {result.error_output[:200]}")

            print()

        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)

        total_passed = sum(r.passed for r in results.values())
        total_failed = sum(r.failed for r in results.values())
        total_errors = sum(r.errors for r in results.values())
        total_skipped = sum(r.skipped for r in results.values())
        total_xfailed = sum(r.xfailed for r in results.values())
        total_xpassed = sum(r.xpassed for r in results.values())
        total_tests = sum(r.total for r in results.values())

        print(f"Total tests across all versions: {total_tests}")
        print(f"  Passed: {total_passed}")
        print(f"  Failed: {total_failed}")
        print(f"  Errors: {total_errors}")
        print(f"  Skipped: {total_skipped}")
        print(f"  XFailed: {total_xfailed}")
        print(f"  XPassed: {total_xpassed}")
        print()

        successful_versions = sum(1 for r in results.values() if r.status == TestStatus.SUCCESS)
        print(f"Successful Python versions: {successful_versions}/{len(results)}")

        if successful_versions == len(results):
            print(f"\n{check_symbol} All tests passed across all Python versions!")
            return 0
        else:
            print(f"\n{fail_symbol} Some tests failed. See details above.")
            return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run pysymex tests in parallel across Docker containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/docker.py                    # Run all tests
  python tests/docker.py -- -v tests/unit/  # Run unit tests with verbose output
  python tests/docker.py -- -k test_analyze # Run tests matching pattern
        """,
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        default=[],
        help="Additional arguments to pass to pytest (use -- to separate)",
    )

    args, unknown = parser.parse_known_args()
    # Combine known and unknown args for pytest
    pytest_args = args.pytest_args + unknown

    runner = DockerTestRunner(pytest_args)
    results = runner.run_all_tests()
    return runner.print_results(results)


if __name__ == "__main__":
    sys.exit(main())
