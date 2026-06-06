from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import ClassVar

import pytest

import tests.docker.daemon as daemon_module
from tests.docker.daemon import DockerDaemonMixin


class _CleanupRunner(DockerDaemonMixin):
    PYTHON_VERSIONS: ClassVar[tuple[str, ...]] = ("3.11",)
    SERVICE_NAMES: ClassVar[dict[str, str]] = {"3.11": "python311"}
    STARTUP_TIMEOUT: ClassVar[float] = 1.0
    COMPOSE_TIMEOUT: ClassVar[float] = 1.0
    TEST_TIMEOUT: ClassVar[float] = 1.0
    MAX_RETRIES: ClassVar[int] = 0

    def __init__(self) -> None:
        self.pytest_args: list[str] = []
        self.project_root = Path(".")
        self.compose_project = "pysymex-test"
        self._container_ids = {"3.11": "container-311"}
        self._docker_started = False
        self._last_docker_error: str | None = None
        self.prompt_wsl_update = False
        self.assume_yes = False

    def cleanup_workspace_pytest_runtime_for_test(self) -> None:
        self._cleanup_workspace_pytest_runtime()

    def cleanup_stale_checkout_containers_for_test(self) -> None:
        self._cleanup_stale_checkout_containers()

    def set_container_id_for_test(self, version: str, container_id: str) -> None:
        self._container_ids[version] = container_id


def test_workspace_pytest_runtime_cleanup_is_label_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CleanupRunner()
    config_file = str((runner.project_root / "docker-compose.yml").resolve())
    working_dir = str(runner.project_root.resolve())
    calls: list[tuple[str, ...]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if command_key == (
            "docker",
            "inspect",
            "container-311",
            "--format",
            "{{json .Config.Labels}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "com.docker.compose.project.working_dir": working_dir,
                        "com.docker.compose.project.config_files": config_file,
                    }
                ),
                stderr="",
            )
        if command_key[:5] == ("docker", "exec", "--user", "root", "container-311"):
            assert command_key[5:9] == ("python", "-I", "-B", "-c")
            assert 'Path("/workspace").resolve()' in command_key[9]
            assert '".pytest_runtime"' in command_key[9]
            assert "shutil.rmtree(target, onerror=on_rm_error)" in command_key[9]
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)

    runner.cleanup_workspace_pytest_runtime_for_test()

    assert calls[0] == (
        "docker",
        "inspect",
        "container-311",
        "--format",
        "{{json .Config.Labels}}",
    )
    assert calls[1][:5] == ("docker", "exec", "--user", "root", "container-311")


def test_workspace_pytest_runtime_cleanup_skips_unrelated_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CleanupRunner()
    calls: list[tuple[str, ...]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        calls.append(tuple(command))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "com.docker.compose.project.working_dir": "/different/checkout",
                    "com.docker.compose.project.config_files": "/different/docker-compose.yml",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)

    runner.cleanup_workspace_pytest_runtime_for_test()

    assert calls == [
        (
            "docker",
            "inspect",
            "container-311",
            "--format",
            "{{json .Config.Labels}}",
        )
    ]


def test_stale_checkout_container_cleanup_keeps_current_container_and_removes_stale(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _CleanupRunner()
    runner.set_container_id_for_test(
        "3.11",
        "aaaaaaaaaaaa999999999999999999999999999999999999",
    )
    config_file = str((runner.project_root / "docker-compose.yml").resolve())
    working_dir = str(runner.project_root.resolve())
    calls: list[tuple[str, ...]] = []

    def labels_for(service: str) -> str:
        return json.dumps(
            {
                "com.docker.compose.project.working_dir": working_dir,
                "com.docker.compose.project.config_files": config_file,
                "com.docker.compose.service": service,
            }
        )

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if command_key == (
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=com.docker.compose.project=pysymex-test",
            "--format",
            "{{.ID}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="aaaaaaaaaaaa\nbbbbbbbbbbbb\ncccccccccccc\ndddddddddddd\n",
                stderr="",
            )
        if command_key == (
            "docker",
            "inspect",
            "bbbbbbbbbbbb",
            "--format",
            "{{json .Config.Labels}}",
        ):
            return subprocess.CompletedProcess(
                command, 0, stdout=labels_for("python311"), stderr=""
            )
        if command_key == (
            "docker",
            "inspect",
            "cccccccccccc",
            "--format",
            "{{json .Config.Labels}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "com.docker.compose.project.working_dir": "/other",
                        "com.docker.compose.project.config_files": "/other/docker-compose.yml",
                        "com.docker.compose.service": "python311",
                    }
                ),
                stderr="",
            )
        if command_key == (
            "docker",
            "inspect",
            "dddddddddddd",
            "--format",
            "{{json .Config.Labels}}",
        ):
            return subprocess.CompletedProcess(command, 0, stdout=labels_for("postgres"), stderr="")
        if command_key == ("docker", "rm", "-f", "bbbbbbbbbbbb"):
            return subprocess.CompletedProcess(command, 0, stdout="bbbbbbbbbbbb\n", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)

    runner.cleanup_stale_checkout_containers_for_test()
    output = capsys.readouterr().out

    assert ("docker", "rm", "-f", "bbbbbbbbbbbb") in calls
    assert ("docker", "inspect", "aaaaaaaaaaaa", "--format", "{{json .Config.Labels}}") not in calls
    assert "Removed stale Docker container bbbbbbbbbbbb for service python311." in output
