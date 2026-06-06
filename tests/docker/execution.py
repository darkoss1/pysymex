"""Pytest execution and result reporting for the Docker test runner."""

from __future__ import annotations

import concurrent.futures
import re
import subprocess
import time

from tests.docker.models import TestResult, TestStatus
from tests.docker.protocols import DockerRunnerState
from tests.docker.reporting import DockerReportingMixin

DOCKER_PYTEST_CACHE_DIR = "/tmp/pysymex-pytest-cache"
DOCKER_PYTEST_BASETEMP = "/tmp/pysymex-pytest-tmp"
DOCKER_PYTHONPYCACHEPREFIX = "/tmp/pysymex-pycache"


def container_display_name(runner: DockerRunnerState, version: str) -> str:
    """Return a project-scoped human-readable name for a runner container."""
    service_name = runner.SERVICE_NAMES[version]
    container_id = runner.container_id_for_version(version)
    display = f"{runner.compose_project}/{service_name}"
    if container_id is not None:
        return f"{display}@{container_id[:12]}"
    return display


def container_not_running_result(runner: DockerRunnerState, version: str) -> TestResult:
    """Build a standard result for a container that could not be started."""
    return TestResult(
        version=version,
        container_name=container_display_name(runner, version),
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
        error_output="Container not running; Docker daemon or Compose startup failed",
    )


def execution_error_result(runner: DockerRunnerState, version: str, error: Exception) -> TestResult:
    """Build a standard result for an unexpected runner error."""
    return TestResult(
        version=version,
        container_name=container_display_name(runner, version),
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
        error_output=str(error),
    )


class DockerExecutionMixin(DockerReportingMixin, DockerRunnerState):
    """Docker pytest execution and result reporting methods."""

    def run_tests_in_container(
        self,
        version: str,
        retry_count: int = 0,
    ) -> TestResult:
        """Run pytest in a specific Docker container."""
        _ = retry_count
        container_id = self._container_ids.get(version)
        if container_id is None:
            return container_not_running_result(self, version)

        container_name = container_display_name(self, version)
        start_time = time.time()

        pytest_cmd = [
            "docker",
            "exec",
            "-e",
            f"PYTHONPYCACHEPREFIX={DOCKER_PYTHONPYCACHEPREFIX}",
            container_id,
            "python",
            "-m",
            "pytest",
            "-v",
            "--tb=short",
            "--no-header",
            "-q",
            "-o",
            f"cache_dir={DOCKER_PYTEST_CACHE_DIR}",
            f"--basetemp={DOCKER_PYTEST_BASETEMP}",
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
            stats = self._parse_pytest_output(output + error_output)
            status = TestStatus.SUCCESS if result.returncode == 0 else TestStatus.FAILURE

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

        except (FileNotFoundError, subprocess.CalledProcessError) as error:
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
                error_output=str(error),
            )

    def _parse_pytest_output(self, output: str) -> dict[str, int]:
        """Parse pytest output to extract test statistics."""
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
        """Run tests in all containers in parallel."""
        print("Ensuring Docker containers are running...")
        running = self.ensure_containers_running()
        cleanup_workspace = getattr(self, "_cleanup_workspace_pytest_runtime", None)
        if callable(cleanup_workspace):
            cleanup_workspace()

        results = {
            version: container_not_running_result(self, version)
            for version in self.PYTHON_VERSIONS
            if not running.get(version, False)
        }
        versions_to_run = [
            version for version in self.PYTHON_VERSIONS if running.get(version, False)
        ]

        if not versions_to_run:
            print("ERROR: No Docker containers are running. Aborting.")
            return results

        if len(versions_to_run) != len(self.PYTHON_VERSIONS):
            unavailable = sorted(set(self.PYTHON_VERSIONS) - set(versions_to_run))
            print(
                "WARNING: Some containers are unavailable. "
                f"Running available versions only: {', '.join(versions_to_run)}."
            )
            print(f"Unavailable versions: {', '.join(unavailable)}")

        print(f"Running tests in parallel across {len(versions_to_run)} Python versions...")
        print(f"Pytest arguments: {' '.join(self.pytest_args) if self.pytest_args else 'default'}")
        print()

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(versions_to_run)) as executor:
            future_to_version = {
                executor.submit(self.run_tests_in_container, version): version
                for version in versions_to_run
            }

            for future in concurrent.futures.as_completed(future_to_version):
                version = future_to_version[future]
                try:
                    result = future.result()
                    results[version] = result
                except Exception as error:
                    results[version] = execution_error_result(self, version, error)

        return results

    def print_results(self, results: dict[str, TestResult]) -> int:
        """Print formatted test results."""
        return super().print_results(results)
