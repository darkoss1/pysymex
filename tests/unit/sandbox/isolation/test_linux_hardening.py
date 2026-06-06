import signal
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import Mock, patch

import pytest

import pysymex.sandbox.isolation.linux as linux_mod
import pysymex.sandbox.isolation.linux.limits as linux_limits
from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.constants import HARNESS_FILENAME
from pysymex.sandbox.isolation.linux import LinuxNamespaceBackend
from pysymex.sandbox.isolation.linux.shared import SYSCALL_ALLOWLIST_X86_64
from pysymex.sandbox.types import ExecutionStatus, SandboxConfig
from tests.unit.sandbox.isolation.linux_test_helpers import FakeProcess


class TestLinuxNamespaceHardening:
    """Platform-independent checks for Linux backend hardening decisions."""

    def test_seccomp_allowlist_includes_cpython_file_probe_syscalls(self) -> None:
        assert 13 in SYSCALL_ALLOWLIST_X86_64
        assert 16 in SYSCALL_ALLOWLIST_X86_64

    def test_sigsys_exit_is_security_violation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sigsys = 31
        monkeypatch.setattr(linux_limits, "_SIGSYS", sigsys)
        classify_exit = cast(
            "Callable[[int], ExecutionStatus]",
            getattr(LinuxNamespaceBackend, "_classify_exit"),
        )

        assert classify_exit(-sigsys) is ExecutionStatus.SECURITY_VIOLATION

    def test_rejects_target_filename_before_jail_population(self, tmp_path: Path) -> None:
        config = SandboxConfig(working_directory=tmp_path)
        backend = LinuxNamespaceBackend(config)
        with patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True):
            backend.setup()
            try:
                with pytest.raises(SandboxSetupError, match="Invalid Linux sandbox target"):
                    backend.execute(b"print('escape')\n", "../escape.py", b"", {})
            finally:
                backend.cleanup()

    def test_strict_seccomp_uses_in_namespace_launcher(self, tmp_path: Path) -> None:
        config = SandboxConfig(
            working_directory=tmp_path,
            python_executable="/usr/local/bin/python3",
        )
        backend = LinuxNamespaceBackend(config)
        captured_cmd: list[str] = []
        captured_cwd = ""
        launcher_name = "_linux_sandbox_launcher.py"

        def _popen(cmd: list[str], **kwargs: object) -> FakeProcess:
            nonlocal captured_cmd
            nonlocal captured_cwd
            captured_cmd = cmd
            cwd = kwargs.get("cwd")
            captured_cwd = cwd if isinstance(cwd, str) else ""
            return FakeProcess(0, b"ok\n", b"")

        def _trusted_tool(name: str) -> str:
            return f"/usr/bin/{name}"

        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._find_unshare",
                return_value="/usr/bin/unshare",
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=True,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=True,
            ),
            patch.object(
                backend,
                "_find_trusted_tool",
                side_effect=_trusted_tool,
            ),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", side_effect=_popen),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "safe.py", b"", {})
                assert backend.jail_path is not None
                launcher = backend.jail_path / launcher_name
                assert result.status is ExecutionStatus.SUCCESS
                assert launcher_name in captured_cmd
                assert HARNESS_FILENAME in captured_cmd
                assert captured_cmd[-1] == "safe.py"
                assert "/usr" not in captured_cmd
                assert "/usr/local" in captured_cmd
                assert "/usr/lib" in captured_cmd
                assert captured_cwd == str(backend.jail_path)
                launcher_source = launcher.read_text(encoding="utf-8")
                compile(launcher_source, launcher_name, "exec")
                assert "prctl(PR_SET_SECCOMP) failed in launcher" in launcher_source
                assert "_SECCOMP_MODE_FILTER = 2" in launcher_source
                assert "_AUDIT_ARCH_X86_64, 1, 0" in launcher_source
                assert (
                    "Any other arch means this x86_64 syscall table is invalid" in launcher_source
                )
            finally:
                backend.cleanup()

    def test_root_jail_mounts_configured_python_runtime_prefix(self, tmp_path: Path) -> None:
        python_exe = "/opt/hostedtoolcache/Python/3.13.13/x64/bin/python"
        runtime_root = "/opt/hostedtoolcache/Python/3.13.13/x64"
        config = SandboxConfig(working_directory=tmp_path, python_executable=python_exe)
        backend = LinuxNamespaceBackend(config)
        captured_cmd: list[str] = []

        def _popen(cmd: list[str], **kwargs: object) -> FakeProcess:
            nonlocal captured_cmd
            _ = kwargs
            captured_cmd = cmd
            return FakeProcess(0, b"ok\n", b"")

        def _trusted_tool(name: str) -> str:
            return f"/usr/bin/{name}"

        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._find_unshare",
                return_value="/usr/bin/unshare",
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=True,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=False,
            ),
            patch.object(backend, "_find_trusted_tool", side_effect=_trusted_tool),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", side_effect=_popen),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert python_exe in captured_cmd
                assert runtime_root in captured_cmd
                assert "/opt" not in captured_cmd
                assert "/bin" in captured_cmd
                assert any(f"{runtime_root}/lib" in part for part in captured_cmd)
                script = captured_cmd[captured_cmd.index("-c") + 1]
                assert "unset LD_LIBRARY_PATH" in script
                assert "exec \"$_chroot\" \"$_jail\" /bin/sh" in script
            finally:
                backend.cleanup()

    def test_root_jail_library_path_prefers_multiarch_libs(self, tmp_path: Path) -> None:
        config = SandboxConfig(working_directory=tmp_path, python_executable="/usr/local/bin/python")
        backend = LinuxNamespaceBackend(config)
        root_jail_library_path = cast(
            "Callable[[tuple[str, ...]], str]",
            getattr(backend, "_root_jail_library_path"),
        )

        with patch("pysymex.sandbox.isolation.linux.backend.sysconfig.get_config_var") as cfg:
            cfg.return_value = "x86_64-linux-gnu"
            library_path = root_jail_library_path(
                ("/usr/local", "/usr/lib", "/lib", "/lib64", "/bin"),
            )

        paths = library_path.split(":")
        assert paths[:2] == ["/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu"]
        assert paths.index("/usr/lib/x86_64-linux-gnu") < paths.index("/usr/lib")
        assert paths.index("/lib/x86_64-linux-gnu") < paths.index("/lib")

    def test_capabilities_include_root_jail_for_configured_python_runtime(self) -> None:
        config = SandboxConfig(
            python_executable="/opt/hostedtoolcache/Python/3.13.13/x64/bin/python"
        )
        backend = LinuxNamespaceBackend(config)
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=True,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=False,
            ),
        ):
            caps = backend.get_capabilities()

        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is True

    def test_root_jail_rejects_non_runtime_python_path(self) -> None:
        config = SandboxConfig(python_executable="/opt/hostedtoolcache/Python/3.13.13/x64/python")
        backend = LinuxNamespaceBackend(config)
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=True,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=False,
            ),
        ):
            caps = backend.get_capabilities()

        assert caps.filesystem_jail is False
        root_jail_python_cmd = cast(
            "Callable[[], list[str]]", getattr(backend, "_root_jail_python_cmd")
        )
        with pytest.raises(SandboxSetupError, match="mounted read-only runtime root"):
            root_jail_python_cmd()

    def test_execute_without_root_jail_still_runs_harness(self, tmp_path: Path) -> None:
        config = SandboxConfig(working_directory=tmp_path)
        backend = LinuxNamespaceBackend(config)

        def _popen(cmd: list[str], **kwargs: object) -> FakeProcess:
            return FakeProcess(0, b"ok\n", b"")

        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._find_unshare",
                return_value="/usr/bin/unshare",
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=False,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=False,
            ),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", side_effect=_popen),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert backend.jail_path is not None
                assert (backend.jail_path / HARNESS_FILENAME).exists()
            finally:
                backend.cleanup()

    def test_rejects_reserved_extra_file_before_jail_population(self, tmp_path: Path) -> None:
        config = SandboxConfig(working_directory=tmp_path)
        backend = LinuxNamespaceBackend(config)
        with patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True):
            backend.setup()
            try:
                assert backend.jail_path is not None
                with pytest.raises(SandboxSetupError, match="shadows reserved file"):
                    backend.execute(
                        b"print('safe')\n",
                        "safe.py",
                        b"",
                        {"safe.py": b"print('shadowed')\n"},
                    )
                assert not (backend.jail_path / "safe.py").exists()
            finally:
                backend.cleanup()

    def test_uses_trusted_unshare_path_with_poisoned_environment(self, tmp_path: Path) -> None:
        config = SandboxConfig(
            working_directory=tmp_path,
            environment={"PATH": str(tmp_path)},
        )
        backend = LinuxNamespaceBackend(config)
        captured_cmd: list[str] = []

        def _which(name: str, path: str | None = None) -> str | None:
            assert name == "unshare"
            assert path == "/usr/sbin:/usr/bin:/sbin:/bin"
            return "/usr/bin/unshare"

        def _popen(cmd: list[str], **kwargs: object) -> FakeProcess:
            nonlocal captured_cmd
            _ = kwargs
            captured_cmd = cmd
            return FakeProcess(0, b"ok\n", b"")

        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=False,
            ),
            patch("pysymex.sandbox.isolation.linux.shutil.which", side_effect=_which),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", side_effect=_popen),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert captured_cmd[0] == "/usr/bin/unshare"
            finally:
                backend.cleanup()

    def test_rlimit_failure_is_not_silent(self, tmp_path: Path) -> None:
        config = SandboxConfig(
            working_directory=tmp_path,
        )
        backend = LinuxNamespaceBackend(config)

        class _FakeLibc:
            def prctl(self, *_args: object) -> int:
                return 0

        fake_resource = ModuleType("resource")
        setattr(fake_resource, "RLIMIT_AS", 1)
        setattr(fake_resource, "RLIMIT_CPU", 2)
        setattr(fake_resource, "RLIMIT_NPROC", 3)
        setattr(fake_resource, "RLIMIT_FSIZE", 4)
        setattr(fake_resource, "RLIMIT_NOFILE", 5)
        setattr(fake_resource, "RLIMIT_CORE", 6)

        def _setrlimit(limit: int, values: tuple[int, int]) -> None:
            _ = values
            if limit == 1:
                raise OSError("denied")

        setattr(fake_resource, "setrlimit", _setrlimit)

        def _popen(cmd: list[str], **kwargs: object) -> FakeProcess:
            _ = cmd
            preexec_fn = kwargs.get("preexec_fn")
            assert callable(preexec_fn)
            with (
                patch.object(linux_mod.os, "setsid", return_value=None, create=True),
                patch("ctypes.CDLL", return_value=_FakeLibc()),
                patch.dict(sys.modules, {"resource": fake_resource}),
            ):
                preexec_fn()
            return FakeProcess(0, b"ok\n", b"")

        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._find_unshare",
                return_value="/usr/bin/unshare",
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=False,
            ),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", side_effect=_popen),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.CRASH
                assert result.error_message is not None
                assert "Failed to enforce RLIMIT_AS" in result.error_message
            finally:
                backend.cleanup()

    def test_cleanup_kills_process_group_then_falls_back_to_child(self) -> None:
        backend = LinuxNamespaceBackend(SandboxConfig())
        kill = Mock()
        sigkill = int(getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 9)))
        with (
            patch.object(linux_mod.os, "getpgid", return_value=321, create=True),
            patch.object(linux_mod.os, "killpg", side_effect=OSError("no pg"), create=True),
            patch.object(linux_mod.os, "kill", kill),
            patch.object(linux_mod.os, "waitpid", side_effect=ChildProcessError()),
        ):
            setattr(backend, "_child_pid", 123)
            backend.cleanup()
        kill.assert_called_once_with(123, sigkill)

    def test_capabilities_do_not_overstate_unavailable_namespaces(self) -> None:
        backend = LinuxNamespaceBackend(SandboxConfig())
        with patch(
            "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available",
            False,
        ):
            caps = backend.get_capabilities()

        assert caps.process_isolation is False
        assert caps.filesystem_jail is False
        assert caps.network_blocking is False
        assert caps.syscall_filtering is False
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True

    def test_capabilities_require_root_jail_for_filesystem_claim(self) -> None:
        backend = LinuxNamespaceBackend(SandboxConfig())
        with (
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available",
                True,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._supports_unshare_root",
                return_value=False,
            ),
            patch(
                "pysymex.sandbox.isolation.linux.LinuxNamespaceBackend._should_enable_seccomp",
                return_value=True,
            ),
        ):
            caps = backend.get_capabilities()

        assert caps.process_isolation is True
        assert caps.filesystem_jail is False
        assert caps.network_blocking is True
        assert caps.syscall_filtering is True
