from pathlib import Path

import pytest

from pysymex._internal.config.sandbox.types import SandboxConfig
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
)


class TestWindowsAppContainerBoundary:
    @pytest.mark.timeout(30)
    def test_reset_workspace_preserves_runtime_and_removes_transient_files(
        self,
        tmp_path: Path,
    ) -> None:
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        runtime_path = tmp_path / "cache" / "__pysymex_python_runtime__"
        transient_dir = jail_path / "target_output"
        jail_path.mkdir()
        runtime_path.mkdir(parents=True)
        transient_dir.mkdir()
        (runtime_path / "python.exe").write_bytes(b"runtime")
        (jail_path / "_pysymex_sandbox_worker.py").write_text("worker", encoding="utf-8")
        (transient_dir / "artifact.txt").write_text("artifact", encoding="utf-8")
        backend.set_jail_path_for_test(jail_path)
        backend.set_runtime_path_for_test(runtime_path)
        backend.mark_verified_for_test()

        backend.reset_workspace()

        assert (runtime_path / "python.exe").read_bytes() == b"runtime"
        assert not (jail_path / "_pysymex_sandbox_worker.py").exists()
        assert not transient_dir.exists()

    @pytest.mark.timeout(30)
    def test_appcontainer_environment_uses_staged_pythonhome(self, tmp_path: Path) -> None:
        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                environment={
                    "PYTHONHOME": r"C:\host-python",
                    "PYTHONPATH": r"C:\host-python\Lib",
                    "CUSTOM_FLAG": "must-not-leak",
                    "DB_CONNECTION_STRING": "must-not-leak",
                }
            )
        )
        jail_path = tmp_path / "jail"
        runtime_path = jail_path / "__pysymex_python_runtime__"
        runtime_path.mkdir(parents=True)
        backend.set_jail_path_for_test(jail_path)
        backend.set_runtime_path_for_test(runtime_path)

        env = backend.appcontainer_environment_for_test()

        assert env["PYTHONHOME"] == str(runtime_path)
        assert env["PYSYMEX_SANDBOX_JAIL"] == str(jail_path)
        assert "PYTHONPATH" not in env
        assert "CUSTOM_FLAG" not in env
        assert "DB_CONNECTION_STRING" not in env
        assert str(runtime_path) in env["PATH"]

    @pytest.mark.timeout(30)
    def test_appcontainer_process_starts_from_immutable_runtime_cwd(
        self,
        tmp_path: Path,
    ) -> None:
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        runtime_path = tmp_path / "cache" / "__pysymex_python_runtime__"
        jail_path.mkdir()
        runtime_path.mkdir(parents=True)
        backend.set_jail_path_for_test(jail_path)
        backend.set_runtime_path_for_test(runtime_path)

        assert backend.appcontainer_process_cwd_for_test() == runtime_path
        assert backend.appcontainer_process_cwd_for_test() != jail_path

    @pytest.mark.timeout(30)
    def test_strips_only_staged_python_startup_warning(self, tmp_path: Path) -> None:
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        runtime_path = tmp_path / "__pysymex_python_runtime__"
        runtime_path.mkdir()
        backend.set_runtime_path_for_test(runtime_path)
        startup_warning = (
            f"Failed to find real location of {runtime_path / 'python.exe'}\n".encode()
        )

        filtered = backend.strip_staged_python_startup_warning_for_test(
            startup_warning + b"target stderr\n"
        )
        unrelated = backend.strip_staged_python_startup_warning_for_test(b"target stderr\n")

        assert filtered == b"target stderr\n"
        assert unrelated == b"target stderr\n"
