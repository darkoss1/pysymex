from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from pysymex._internal.config.sandbox.types import (
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SecurityCapabilities,
)
from pysymex._internal.sandbox.errors import SandboxError, SandboxSetupError
from pysymex._internal.sandbox.runner import SandboxRunner
from pysymex._internal.sandbox.types import (
    ExecutionStatus,
    SandboxBackendStrength,
    SandboxResult,
)


class _FakeStrongBackend:
    name = "FakeStrongBackend"

    def __init__(self) -> None:
        self.is_setup = False
        self.reset_calls = 0

    def setup(self) -> None:
        self.is_setup = True

    def cleanup(self) -> None:
        self.is_setup = False

    def get_capabilities(self) -> SecurityCapabilities:
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=True,
            syscall_filtering=True,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )

    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        _ = filename
        _ = input_data
        _ = extra_files
        return SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0, stdout=code)

    def reset_workspace(self) -> None:
        self.reset_calls += 1


def _fake_backend_patch(backend: _FakeStrongBackend | None = None):
    return patch.object(
        SandboxRunner, "_create_backend", return_value=backend or _FakeStrongBackend()
    )


class TestSandboxRunner:
    """Test suite for pysymex._internal.sandbox.runner.SandboxRunner."""

    @pytest.mark.timeout(30)
    def test_is_active(self) -> None:
        """Test is_active behavior."""
        config = SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER)
        runner = SandboxRunner(config)
        assert runner.is_active is False
        with _fake_backend_patch(), runner:
            assert runner.is_active is True
        assert runner.is_active is False

    @pytest.mark.timeout(30)
    def test_backend_name(self) -> None:
        """Test backend_name behavior."""
        config = SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER)
        runner = SandboxRunner(config)
        assert runner.backend_name == "none"
        with _fake_backend_patch(), runner:
            assert runner.backend_name == "FakeStrongBackend"

    @pytest.mark.timeout(30)
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        config = SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER)
        runner = SandboxRunner(config)
        before_caps = runner.get_capabilities()
        assert before_caps.process_isolation is False

        with _fake_backend_patch(), runner:
            caps = runner.get_capabilities()
            assert caps.process_isolation is True
            assert caps.filesystem_jail is True

    @pytest.mark.timeout(30)
    def test_backend_strength_is_unavailable_before_setup(self) -> None:
        runner = SandboxRunner(SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER))

        assert runner.backend_strength is SandboxBackendStrength.UNAVAILABLE

    @pytest.mark.timeout(30)
    def test_backend_strength_reports_verified_strong_backend(self) -> None:
        with (
            patch("pysymex._internal.sandbox.runner.sys.platform", "win32"),
            patch(
                "pysymex._internal.sandbox.runner.check_windows_appcontainer_support",
                return_value=True,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.setup",
                return_value=None,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.get_capabilities",
                return_value=SecurityCapabilities(
                    process_isolation=True,
                    filesystem_jail=True,
                    network_blocking=True,
                    memory_limits=True,
                    cpu_limits=True,
                    process_limits=True,
                ),
            ),
        ):
            with SandboxRunner() as runner:
                assert runner.backend_strength is SandboxBackendStrength.STRONG

    @pytest.mark.timeout(30)
    def test_backend_strength_reports_partial_backend_as_experimental(self) -> None:
        config = SandboxConfig(
            backend=SandboxBackend.WINDOWS_APPCONTAINER,
            required_capabilities=SecurityCapabilities(process_isolation=True),
        )
        with (
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.setup",
                return_value=None,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.get_capabilities",
                return_value=SecurityCapabilities(process_isolation=True),
            ),
        ):
            with SandboxRunner(config) as runner:
                assert runner.backend_strength is SandboxBackendStrength.EXPERIMENTAL

    @pytest.mark.timeout(30)
    def test_reset_workspace_requires_active_sandbox(self) -> None:
        runner = SandboxRunner(SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER))

        with pytest.raises(SandboxError, match="Sandbox is not active"):
            runner.reset_workspace()

    @pytest.mark.timeout(30)
    def test_reset_workspace_calls_backend_when_supported(self) -> None:
        backend = _FakeStrongBackend()
        runner = SandboxRunner(SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER))

        with _fake_backend_patch(backend), runner:
            runner.reset_workspace()
        assert backend.reset_calls == 1

    @pytest.mark.timeout(30)
    def test_execute(self) -> None:
        """Test execute behavior."""
        config = SandboxConfig(
            backend=SandboxBackend.WINDOWS_APPCONTAINER,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)

        with _fake_backend_patch(), runner:
            with pytest.raises(FileNotFoundError):
                runner.execute(Path("does_not_exist.py"))

    @pytest.mark.timeout(30)
    def test_execute_permitted_operation_succeeds(self, tmp_path: Path) -> None:
        """Permits safe code execution when no forbidden patterns are present."""
        file_path = tmp_path / "safe.py"
        file_path.write_text("print('runner-safe')\n", encoding="utf-8")

        config = SandboxConfig(
            backend=SandboxBackend.WINDOWS_APPCONTAINER,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)
        with _fake_backend_patch(), runner:
            result = runner.execute(file_path)
            assert result.status is ExecutionStatus.SUCCESS
            assert "runner-safe" in result.get_stdout_text()

    @pytest.mark.timeout(30)
    def test_execute_code(self) -> None:
        """Test execute_code behavior."""
        config = SandboxConfig(
            backend=SandboxBackend.WINDOWS_APPCONTAINER,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)
        with _fake_backend_patch(), runner:
            result = runner.execute_code("print('code-safe')\n", filename="safe_code.py")
            assert result.status is ExecutionStatus.SUCCESS
            assert "code-safe" in result.get_stdout_text()

            with pytest.raises(ValueError):
                runner.execute_code("print('x')", filename="../escape.py")

    @pytest.mark.timeout(30)
    @pytest.mark.parametrize(
        "filename",
        ["CON.py", "NUL", "LPT1.txt", "safe.py.", "bad?.py"],
    )
    def test_execute_code_rejects_windows_normalized_target_names(
        self,
        filename: str,
    ) -> None:
        """Runner validation rejects Windows device names before backend staging."""
        config = SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER)
        runner = SandboxRunner(config)
        with _fake_backend_patch(), runner, pytest.raises(ValueError):
            runner.execute_code("print('x')", filename=filename)

    @pytest.mark.timeout(30)
    @pytest.mark.parametrize(
        "rel_path",
        [
            "CON.txt",
            "nested/COM1.log",
            "safe.txt.",
            "bad?.txt",
            "native.pyd",
            "library.dll",
            "tool.exe",
            "module.pyc",
            "startup.pth",
        ],
    )
    def test_execute_code_rejects_windows_normalized_extra_file_paths(
        self,
        rel_path: str,
    ) -> None:
        """Runner extra-file policy matches backend staging policy."""
        config = SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER)
        runner = SandboxRunner(config)
        with _fake_backend_patch(), runner, pytest.raises(ValueError):
            runner.execute_code("print('x')", extra_files={rel_path: b"x"})

    @pytest.mark.timeout(30)
    def test_execute_code_inactive_runner_fails(self) -> None:
        """Execution APIs must fail closed when sandbox context is not active."""
        runner = SandboxRunner(SandboxConfig(backend=SandboxBackend.WINDOWS_APPCONTAINER))
        with pytest.raises(SandboxError):
            runner.execute_code("print('x')")

    @pytest.mark.timeout(30)
    def test_linux_auto_detect_does_not_select_namespace_without_unshare(self) -> None:
        """Linux auto-detection must not claim namespace isolation when unshare is absent."""
        with (
            patch("pysymex._internal.sandbox.runner.sys.platform", "linux"),
            patch("shutil.which", return_value=None),
            patch("builtins.open", mock_open(read_data="1")),
        ):
            with pytest.raises(SandboxSetupError, match="No strong pysymex sandbox backend"):
                with SandboxRunner():
                    pass

    @pytest.mark.timeout(30)
    def test_windows_auto_detect_prefers_native_appcontainer(self) -> None:
        """Windows selects the native strong backend when it is available."""
        with (
            patch("pysymex._internal.sandbox.runner.sys.platform", "win32"),
            patch(
                "pysymex._internal.sandbox.runner.check_windows_appcontainer_support",
                return_value=True,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.setup",
                return_value=None,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.get_capabilities",
                return_value=SecurityCapabilities(
                    process_isolation=True,
                    filesystem_jail=True,
                    network_blocking=True,
                    memory_limits=True,
                    cpu_limits=True,
                    process_limits=True,
                ),
            ),
        ):
            with SandboxRunner() as runner:
                assert runner.backend_name == "AppContainerBackend"

    @pytest.mark.timeout(30)
    def test_windows_appcontainer_setup_failure_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed native strong setup stays visible instead of falling back."""
        monkeypatch.setattr(
            "pysymex._internal.sandbox.backends._windows_appcontainer_auto_disabled_reason",
            None,
        )

        with (
            patch("pysymex._internal.sandbox.runner.sys.platform", "win32"),
            patch(
                "pysymex._internal.sandbox.runner.check_windows_appcontainer_support",
                return_value=True,
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.AppContainerBackend.setup",
                side_effect=SandboxSetupError("native self-check failed"),
            ),
            pytest.raises(SandboxSetupError, match="native self-check failed"),
        ):
            with SandboxRunner():
                pass

    @pytest.mark.timeout(30)
    def test_windows_without_native_backend_fails_closed(self) -> None:
        """Windows has no weak fallback when AppContainer is unavailable."""
        with (
            patch("pysymex._internal.sandbox.runner.sys.platform", "win32"),
            patch(
                "pysymex._internal.sandbox.runner.check_windows_appcontainer_support",
                return_value=False,
            ),
            pytest.raises(SandboxSetupError, match="No strong pysymex sandbox backend"),
        ):
            with SandboxRunner():
                pass
