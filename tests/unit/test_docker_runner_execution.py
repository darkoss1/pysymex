from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

import tests.docker.execution as execution_module
from tests.docker.execution import (
    DOCKER_PYTEST_BASETEMP,
    DOCKER_PYTEST_CACHE_DIR,
    DOCKER_PYTHONPYCACHEPREFIX,
    DockerExecutionMixin,
)
from tests.docker.models import TestResult as DockerTestResult
from tests.docker.models import TestStatus as DockerTestStatus


class _ExecutionRunner(DockerExecutionMixin):
    PYTHON_VERSIONS: ClassVar[tuple[str, ...]] = ("3.11", "3.12")
    SERVICE_NAMES: ClassVar[dict[str, str]] = {
        "3.11": "python311",
        "3.12": "python312",
    }
    STARTUP_TIMEOUT: ClassVar[float] = 1.0
    COMPOSE_TIMEOUT: ClassVar[float] = 1.0
    TEST_TIMEOUT: ClassVar[float] = 1.0
    MAX_RETRIES: ClassVar[int] = 0

    def __init__(self, running: dict[str, bool]) -> None:
        self.pytest_args: list[str] = []
        self.project_root = Path(".")
        self.compose_project = "pysymex-test"
        self._container_ids = {
            version: f"container{version.replace('.', '')}"
            for version, is_running in running.items()
            if is_running
        }
        self._docker_started = False
        self._last_docker_error: str | None = None
        self.prompt_wsl_update = False
        self.assume_yes = False
        self._running = running
        self.ran_versions: list[str] = []

    def ensure_containers_running(self) -> dict[str, bool]:
        return self._running

    def run_tests_in_container(
        self,
        version: str,
        retry_count: int = 0,
    ) -> DockerTestResult:
        _ = retry_count
        self.ran_versions.append(version)
        return DockerTestResult(
            version=version,
            container_name=f"{self.compose_project}/{self.SERVICE_NAMES[version]}",
            status=DockerTestStatus.SUCCESS,
            exit_code=0,
            duration=0.25,
            passed=3,
            failed=0,
            errors=0,
            skipped=0,
            xfailed=0,
            xpassed=0,
            total=3,
            output="3 passed",
            error_output="",
        )


def test_run_all_tests_runs_available_versions_and_marks_unavailable_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _ExecutionRunner({"3.11": True, "3.12": False})

    results = runner.run_all_tests()
    output = capsys.readouterr().out

    assert runner.ran_versions == ["3.11"]
    assert results["3.11"].status is DockerTestStatus.SUCCESS
    assert results["3.12"].status is DockerTestStatus.ERROR
    assert results["3.12"].error_output == (
        "Container not running; Docker daemon or Compose startup failed"
    )
    assert "Running available versions only: 3.11" in output
    assert "Unavailable versions: 3.12" in output


def test_run_all_tests_cleans_workspace_runtime_before_workers() -> None:
    runner = _ExecutionRunner({"3.11": True, "3.12": False})
    cleanup_calls: list[list[str]] = []

    def cleanup_workspace() -> None:
        cleanup_calls.append(list(runner.ran_versions))

    setattr(runner, "_cleanup_workspace_pytest_runtime", cleanup_workspace)

    runner.run_all_tests()

    assert cleanup_calls == [[]]
    assert runner.ran_versions == ["3.11"]


def test_run_all_tests_reports_all_versions_unavailable_without_starting_workers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _ExecutionRunner({"3.11": False, "3.12": False})

    results = runner.run_all_tests()
    output = capsys.readouterr().out

    assert runner.ran_versions == []
    assert {version: result.status for version, result in results.items()} == {
        "3.11": DockerTestStatus.ERROR,
        "3.12": DockerTestStatus.ERROR,
    }
    assert "ERROR: No Docker containers are running. Aborting." in output


def test_run_tests_in_container_uses_container_local_pytest_scratch_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _ExecutionRunner({"3.11": True})
    captured_command: list[str] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> execution_module.subprocess.CompletedProcess[str]:
        _ = kwargs
        captured_command.extend(command)
        return execution_module.subprocess.CompletedProcess(
            command,
            0,
            stdout="1 passed in 0.01s",
            stderr="",
        )

    monkeypatch.setattr(execution_module.subprocess, "run", fake_run)

    result = DockerExecutionMixin.run_tests_in_container(runner, "3.11")

    assert result.status is DockerTestStatus.SUCCESS
    assert result.container_name == "pysymex-test/python311@container311"
    assert captured_command[:5] == [
        "docker",
        "exec",
        "-e",
        f"PYTHONPYCACHEPREFIX={DOCKER_PYTHONPYCACHEPREFIX}",
        "container311",
    ]
    assert f"cache_dir={DOCKER_PYTEST_CACHE_DIR}" in captured_command
    assert f"--basetemp={DOCKER_PYTEST_BASETEMP}" in captured_command
    assert "pysymex-python311" not in captured_command
    assert ".pytest_runtime" not in " ".join(captured_command)
