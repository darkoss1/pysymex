from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import ClassVar

import pytest

import tests.docker.commands as commands_module
import tests.docker.daemon as daemon_module
import tests.docker.windows as windows_module
from tests.docker.daemon import DockerDaemonMixin


class _DaemonRunner(DockerDaemonMixin):
    PYTHON_VERSIONS: ClassVar[tuple[str, ...]] = ("3.11",)
    SERVICE_NAMES: ClassVar[dict[str, str]] = {"3.11": "python311"}
    STARTUP_TIMEOUT: ClassVar[float] = 1.0
    COMPOSE_TIMEOUT: ClassVar[float] = 1.0
    TEST_TIMEOUT: ClassVar[float] = 1.0
    MAX_RETRIES: ClassVar[int] = 0

    def __init__(self, *, prompt_wsl_update: bool = False, assume_yes: bool = False) -> None:
        self.pytest_args: list[str] = []
        self.project_root = Path(".")
        self.compose_project = "pysymex-test"
        self._container_ids: dict[str, str] = {}
        self._docker_started = False
        self._last_docker_error: str | None = None
        self.prompt_wsl_update = prompt_wsl_update
        self.assume_yes = assume_yes


def _missing_legacy_inspect(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    if tuple(command) == (
        "docker",
        "inspect",
        "pysymex-python311",
        "--format",
        "{{json .Config.Labels}}",
    ):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="No such object")
    return None


def _empty_project_container_list(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    if tuple(command) == (
        "docker",
        "ps",
        "-a",
        "--filter",
        "label=com.docker.compose.project=pysymex-test",
        "--format",
        "{{.ID}}",
    ):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    return None


def _legacy_cleanup_command(command: tuple[str, ...]) -> bool:
    return command in {
        (
            "docker",
            "inspect",
            "pysymex-python311",
            "--format",
            "{{json .Config.Labels}}",
        ),
        ("docker", "rm", "-f", "pysymex-python311"),
    }


def _assert_no_legacy_runtime_container_name(calls: list[tuple[str, ...]]) -> None:
    runtime_calls = [call for call in calls if not _legacy_cleanup_command(call)]
    assert all("pysymex-python311" not in part for call in runtime_calls for part in call)


def test_daemon_check_reports_docker_cli_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="failed to connect to the docker API at npipe:////./pipe/docker_engine",
        )

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)
    monkeypatch.setattr(daemon_module.platform, "system", lambda: "UnsupportedOS")

    result = _DaemonRunner().ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": False}
    assert "Docker daemon check failed:" in output
    assert "failed to connect to the docker API" in output
    assert "ERROR: Unsupported platform: UnsupportedOS" in output


def test_windows_wsl_backend_failure_stops_before_desktop_start(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if legacy_result := _missing_legacy_inspect(command):
            return legacy_result
        if command_key == ("docker", "info"):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="daemon unavailable")
        if command_key == (
            "docker",
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="npipe:////./pipe/dockerDesktopLinuxEngine\n",
                stderr="",
            )
        if command_key == ("docker", "desktop", "status"):
            return subprocess.CompletedProcess(
                command, 0, stdout="Status              starting", stderr=""
            )
        if command_key == ("docker", "desktop", "engine", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="linux *", stderr="")
        if command_key == ("wsl", "--status"):
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="W\x00S\x00L\x00 \x00n\x00e\x00e\x00d\x00s\x00 \x00u\x00p\x00d\x00a\x00t\x00i\x00n\x00g\x00",
            )
        raise AssertionError(f"Unexpected command: {command}")

    def fake_popen(command: list[str]) -> None:
        raise AssertionError(f"Docker Desktop should not be started: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)
    monkeypatch.setattr(commands_module.subprocess, "run", fake_run)
    monkeypatch.setattr(daemon_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_module.platform, "system", lambda: "Windows")

    result = _DaemonRunner().ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": False}
    assert ("wsl", "--status") in calls
    assert "Docker Desktop Windows diagnostics:" in output
    assert "Docker context endpoint: npipe:////./pipe/dockerDesktopLinuxEngine" in output
    assert "WSL needs updating" in output
    assert "WSL update prompt disabled." in output
    assert "ERROR: Docker Desktop Linux engine is blocked before startup." in output


def test_windows_wsl_update_option_runs_update_and_retries_docker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    docker_info_calls = 0

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal docker_info_calls

        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if legacy_result := _missing_legacy_inspect(command):
            return legacy_result
        if project_containers := _empty_project_container_list(command):
            return project_containers
        if command_key == ("docker", "info"):
            docker_info_calls += 1
            if docker_info_calls == 1:
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="daemon unavailable"
                )
            return subprocess.CompletedProcess(command, 0, stdout="Server: ready", stderr="")
        if command_key == (
            "docker",
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="npipe:////./pipe/dockerDesktopLinuxEngine\n",
                stderr="",
            )
        if command_key == ("docker", "desktop", "status"):
            return subprocess.CompletedProcess(
                command, 0, stdout="Status              starting", stderr=""
            )
        if command_key == ("docker", "desktop", "engine", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="linux *", stderr="")
        if command_key == ("wsl", "--status"):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="WSL needs updating")
        if command_key == ("wsl", "--update"):
            return subprocess.CompletedProcess(command, 0, stdout="Update complete", stderr="")
        if command_key == ("docker", "desktop", "restart"):
            return subprocess.CompletedProcess(
                command, 0, stdout="Restarted Docker Desktop", stderr=""
            )
        if command_key == ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311"):
            return subprocess.CompletedProcess(command, 0, stdout="container-311\n", stderr="")
        if command_key == (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "container-311",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
        if command_key == (
            "docker",
            "exec",
            "container-311",
            "python",
            "-c",
            "import sys; print(sys.version)",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="3.11.9\n", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)
    monkeypatch.setattr(commands_module.subprocess, "run", fake_run)
    monkeypatch.setattr(daemon_module.platform, "system", lambda: "Windows")

    result = _DaemonRunner(prompt_wsl_update=True, assume_yes=True).ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": True}
    assert ("wsl", "--update") in calls
    assert ("docker", "desktop", "restart") in calls
    assert ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311") in calls
    assert (
        "docker",
        "exec",
        "container-311",
        "python",
        "-c",
        "import sys; print(sys.version)",
    ) in calls
    _assert_no_legacy_runtime_container_name(calls)
    assert docker_info_calls == 2
    assert "Assuming yes for WSL update because --yes was provided." in output
    assert "Docker Compose project: pysymex-test" in output
    assert "Restarting Docker Desktop after WSL update..." in output
    assert "WSL update completed. Re-checking Docker daemon..." in output


def test_windows_wsl_update_falls_back_to_winget_and_restarts_docker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    docker_info_calls = 0

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal docker_info_calls

        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if legacy_result := _missing_legacy_inspect(command):
            return legacy_result
        if project_containers := _empty_project_container_list(command):
            return project_containers
        if command_key == ("docker", "info"):
            docker_info_calls += 1
            if docker_info_calls == 1:
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="daemon unavailable"
                )
            return subprocess.CompletedProcess(command, 0, stdout="Server: ready", stderr="")
        if command_key == (
            "docker",
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="npipe:////./pipe/dockerDesktopLinuxEngine\n",
                stderr="",
            )
        if command_key == ("docker", "desktop", "status"):
            return subprocess.CompletedProcess(
                command, 0, stdout="Status              starting", stderr=""
            )
        if command_key == ("docker", "desktop", "engine", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="linux *", stderr="")
        if command_key == ("wsl", "--status"):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="WSL needs updating")
        if command_key == ("wsl", "--update"):
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="Class not registered\nError code: Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG",
            )
        if command_key == windows_module.WINGET_WSL_UPGRADE_COMMAND:
            return subprocess.CompletedProcess(
                command, 0, stdout="Successfully installed", stderr=""
            )
        if command_key == ("docker", "desktop", "restart"):
            return subprocess.CompletedProcess(
                command, 0, stdout="Restarted Docker Desktop", stderr=""
            )
        if command_key == ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311"):
            return subprocess.CompletedProcess(command, 0, stdout="container-311\n", stderr="")
        if command_key == (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "container-311",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
        if command_key == (
            "docker",
            "exec",
            "container-311",
            "python",
            "-c",
            "import sys; print(sys.version)",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="3.11.9\n", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)
    monkeypatch.setattr(commands_module.subprocess, "run", fake_run)
    monkeypatch.setattr(daemon_module.platform, "system", lambda: "Windows")

    result = _DaemonRunner(prompt_wsl_update=True, assume_yes=True).ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": True}
    assert ("wsl", "--update") in calls
    assert windows_module.WINGET_WSL_UPGRADE_COMMAND in calls
    assert ("docker", "desktop", "restart") in calls
    assert ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311") in calls
    assert (
        "docker",
        "exec",
        "container-311",
        "python",
        "-c",
        "import sys; print(sys.version)",
    ) in calls
    _assert_no_legacy_runtime_container_name(calls)
    assert docker_info_calls == 2
    assert "Falling back to: winget upgrade --id Microsoft.WSL" in output
    assert "winget WSL upgrade output:" in output
    assert "WSL update completed. Re-checking Docker daemon..." in output


def test_container_start_uses_scoped_compose_project_not_global_name(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    compose_ps_calls = 0

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal compose_ps_calls

        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if legacy_result := _missing_legacy_inspect(command):
            return legacy_result
        if project_containers := _empty_project_container_list(command):
            return project_containers
        if command_key == ("docker", "info"):
            return subprocess.CompletedProcess(command, 0, stdout="Server: ready", stderr="")
        if command_key == ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311"):
            compose_ps_calls += 1
            if compose_ps_calls == 1:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(command, 0, stdout="container-311\n", stderr="")
        if command_key == (
            "docker",
            "compose",
            "-p",
            "pysymex-test",
            "up",
            "-d",
            "--build",
            "python311",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="created", stderr="")
        if command_key == (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "container-311",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
        if command_key == (
            "docker",
            "exec",
            "container-311",
            "python",
            "-c",
            "import sys; print(sys.version)",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="3.11.9\n", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)

    result = _DaemonRunner().ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": True}
    assert compose_ps_calls == 2
    assert (
        "docker",
        "compose",
        "-p",
        "pysymex-test",
        "up",
        "-d",
        "--build",
        "python311",
    ) in calls
    _assert_no_legacy_runtime_container_name(calls)
    assert "Starting Docker Compose service python311 in project pysymex-test..." in output


def test_legacy_container_cleanup_is_scoped_to_current_checkout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    runner = _DaemonRunner()
    config_file = str((runner.project_root / "docker-compose.yml").resolve())
    working_dir = str(runner.project_root.resolve())

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        command_key = tuple(command)
        calls.append(command_key)
        if project_containers := _empty_project_container_list(command):
            return project_containers
        if command_key == ("docker", "info"):
            return subprocess.CompletedProcess(command, 0, stdout="Server: ready", stderr="")
        if command_key == (
            "docker",
            "inspect",
            "pysymex-python311",
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
        if command_key == ("docker", "rm", "-f", "pysymex-python311"):
            return subprocess.CompletedProcess(command, 0, stdout="pysymex-python311\n", stderr="")
        if command_key == ("docker", "compose", "-p", "pysymex-test", "ps", "-q", "python311"):
            return subprocess.CompletedProcess(command, 0, stdout="container-311\n", stderr="")
        if command_key == (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "container-311",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
        if command_key == (
            "docker",
            "exec",
            "container-311",
            "python",
            "-c",
            "import sys; print(sys.version)",
        ):
            return subprocess.CompletedProcess(command, 0, stdout="3.11.9\n", stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(daemon_module.subprocess, "run", fake_run)

    result = runner.ensure_containers_running()
    output = capsys.readouterr().out

    assert result == {"3.11": True}
    assert ("docker", "rm", "-f", "pysymex-python311") in calls
    assert "Removed legacy Docker container pysymex-python311." in output
