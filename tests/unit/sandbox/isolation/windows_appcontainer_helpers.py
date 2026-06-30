import sys
from pathlib import Path

from pysymex._internal.sandbox.isolation.windows.appcontainer.backend import (
    AppContainerBackend,
    has_windows_appcontainer_support,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.cache import (
    RuntimeManifestEntry,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import NativeProcessResult
from pysymex._internal.sandbox.types import ExecutionStatus


class InspectableWindowsAppContainerBackend(AppContainerBackend):
    def set_jail_path_for_test(self, path: Path) -> None:
        self._jail_path = path

    def set_runtime_path_for_test(self, path: Path) -> None:
        self._runtime_path = path

    def stage_python_runtime_for_test(self) -> None:
        self._stage_python_runtime()

    def rename_runtime_cache_for_test(self, temp_path: Path, runtime_path: Path) -> None:
        self._rename_runtime_cache(temp_path, runtime_path)

    def runtime_source_manifest_for_test(self, source_root: Path) -> list[RuntimeManifestEntry]:
        return self._runtime_source_manifest(source_root)

    def runtime_path_for_test(self) -> Path | None:
        return self._runtime_path

    def appcontainer_environment_for_test(self) -> dict[str, str]:
        return self._appcontainer_environment()

    def appcontainer_process_cwd_for_test(self) -> Path:
        return self._appcontainer_process_cwd()

    def strip_staged_python_startup_warning_for_test(self, stderr: bytes) -> bytes:
        return self._strip_staged_python_startup_warning(stderr)

    def validate_combined_self_check_for_test(self, result: NativeProcessResult) -> None:
        self._validate_combined_self_check(result)

    def mark_verified_for_test(self) -> None:
        self._is_setup = True
        self._security_verified = True

    def run_raw_python_for_test(
        self,
        code: str,
        *,
        input_data: bytes = b"",
    ) -> tuple[ExecutionStatus, int | None, bytes, bytes, str | None, tuple[str, ...]]:
        result = self._run_native_process(
            [*self._runtime_python_cmd(), "-c", code],
            input_data=input_data,
        )
        return (
            result.status,
            result.exit_code,
            result.stdout,
            result.stderr,
            result.error_message,
            result.blocked_operations,
        )

    def copy_runtime_cache_for_test(
        self,
        source_root: Path,
        runtime_path: Path,
        entries: list[RuntimeManifestEntry],
    ) -> None:
        self._copy_runtime_cache(source_root, runtime_path, entries)


def has_live_appcontainer_support() -> bool:
    return sys.platform == "win32" and has_windows_appcontainer_support()
