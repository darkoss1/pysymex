"""Windows Docker Desktop and WSL diagnostics for the Docker test runner."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from tests.docker.commands import probe_command

WSL_BACKEND_FAILURE_MARKERS: Final = (
    "needs updating",
    "wsl/callmsi",
    "regdb_e_classnotreg",
    "wsl_e_",
    "wsl command not found",
    "timed out",
)

WINGET_WSL_REPAIR_MARKERS: Final = (
    "class not registered",
    "wsl/callmsi",
    "regdb_e_classnotreg",
)

WINGET_WSL_UPGRADE_COMMAND: Final = (
    "winget",
    "upgrade",
    "--id",
    "Microsoft.WSL",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--silent",
)


@dataclass(frozen=True, slots=True)
class WindowsDockerDiagnostics:
    """Windows Docker Desktop backend diagnosis."""

    blocked: bool
    lines: tuple[str, ...]


def collect_windows_backend_diagnostics() -> WindowsDockerDiagnostics:
    """Collect Docker Desktop and WSL diagnostics for a Windows Docker context."""
    endpoint = docker_context_endpoint()
    diagnostics: list[str] = []
    wsl_output = ""

    if endpoint is not None:
        diagnostics.append(f"Docker context endpoint: {endpoint}")
        pipe_path = _npipe_endpoint_path(endpoint)
        if pipe_path is not None:
            diagnostics.append(_named_pipe_status(pipe_path))

    desktop_status = _probe_text("Docker Desktop status", ["docker", "desktop", "status"])
    if desktop_status is not None:
        diagnostics.append(desktop_status)

    engine_status = _probe_text("Docker Desktop engine", ["docker", "desktop", "engine", "ls"])
    if engine_status is not None:
        diagnostics.append(engine_status)

    if endpoint is not None and "dockerDesktopLinuxEngine" in endpoint:
        _, wsl_output = probe_command(["wsl", "--status"], timeout=20.0)
        diagnostics.append(f"WSL status:\n{wsl_output}")

    return WindowsDockerDiagnostics(
        blocked=bool(wsl_output and contains_wsl_backend_failure(wsl_output)),
        lines=tuple(diagnostics),
    )


def contains_wsl_backend_failure(output: str) -> bool:
    """Return whether command output proves Docker Desktop's WSL backend is blocked."""
    return _contains_marker(output, WSL_BACKEND_FAILURE_MARKERS)


def winget_wsl_repair_is_relevant(output: str) -> bool:
    """Return whether failed `wsl --update` output should fall back to winget."""
    return _contains_marker(output, WINGET_WSL_REPAIR_MARKERS)


def run_wsl_update() -> tuple[int | None, str]:
    """Run the standard WSL update command."""
    return probe_command(["wsl", "--update"], timeout=300.0)


def run_winget_wsl_upgrade() -> tuple[int | None, str]:
    """Upgrade the Store/MSI WSL package through winget."""
    return probe_command(WINGET_WSL_UPGRADE_COMMAND, timeout=600.0)


def restart_docker_desktop() -> tuple[int | None, str]:
    """Restart Docker Desktop through Docker's Desktop CLI."""
    return probe_command(["docker", "desktop", "restart"], timeout=180.0)


def docker_context_endpoint() -> str | None:
    """Return the active Docker context endpoint when the CLI can report it."""
    status, output = probe_command(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        timeout=10.0,
    )
    if status != 0 or not output:
        return None
    return output.splitlines()[0].strip()


def _probe_text(label: str, command: list[str]) -> str | None:
    """Return formatted diagnostic command output when a probe provides evidence."""
    _, output = probe_command(command, timeout=10.0)
    if not output:
        return None
    return f"{label}:\n{output}"


def _npipe_endpoint_path(endpoint: str) -> str | None:
    """Translate a Docker npipe endpoint into a Windows named-pipe path."""
    prefix = "npipe:////./pipe/"
    if not endpoint.startswith(prefix):
        return None
    pipe_name = endpoint.removeprefix(prefix).replace("/", "\\")
    return f"\\\\.\\pipe\\{pipe_name}"


def _named_pipe_status(pipe_path: str) -> str:
    """Return a diagnostic message for a Windows named-pipe endpoint."""
    try:
        os.stat(pipe_path)
    except FileNotFoundError:
        return f"Engine named pipe missing: {pipe_path}"
    except OSError as error:
        return f"Engine named pipe unavailable: {pipe_path} ({error})"
    return f"Engine named pipe present: {pipe_path}"


def _contains_marker(output: str, markers: tuple[str, ...]) -> bool:
    normalized = output.lower().replace("\\", "/")
    return any(marker in normalized for marker in markers)
