"""Tests for scanner directory traversal behavior."""

from __future__ import annotations

from pathlib import Path
from types import CodeType
from unittest.mock import patch

from pysymex._internal.scanner.directory.scan import scan_directory
from pysymex._internal.scanner.types import ScanResult
from pysymex._internal.sandbox.bridge.blobs import BytecodeBlob
from tests.unit.sandbox.bridge_test_helpers import create_bridge_payload


class TestScanDirectory:
    """Tests for scan_directory behavior."""

    def test_scan_directory_includes_nested_files(self, tmp_path: Path) -> None:
        """Directory scans include nested files recursively."""
        top_file = tmp_path / "top.py"
        top_file.write_text("x = 1\n", encoding="utf-8")
        nested_dir = tmp_path / "pkg"
        nested_dir.mkdir()
        nested_file = nested_dir / "nested.py"
        nested_file.write_text("y = 2\n", encoding="utf-8")

        results = scan_directory(
            tmp_path,
            verbose=False,
            workers=1,
            max_paths=10,
            timeout=5,
            use_sandbox=False,
        )
        scanned_files = {Path(result.file_path).resolve() for result in results}
        assert top_file.resolve() in scanned_files
        assert nested_file.resolve() in scanned_files

    def test_sequential_sandbox_scan_uses_bytecode_session(
        self,
        tmp_path: Path,
    ) -> None:
        target = tmp_path / "top.py"
        target.write_text("x = 1\n", encoding="utf-8")
        entered = 0

        class FakeSession:
            def __enter__(self) -> FakeSession:
                nonlocal entered
                entered += 1
                return self

            def __exit__(
                self,
                exc_type: type[BaseException] | None,
                _exc_val: BaseException | None,
                _exc_tb: object,
            ) -> None:
                return None

        def fake_scan_sequential(*args: object, **kwargs: object) -> list[ScanResult]:
            _ = args
            _ = kwargs
            return [ScanResult(file_path=str(target), timestamp="now")]

        with (
            patch(
                "pysymex._internal.sandbox.bridge.bytecode.bytecode_extraction_session",
                return_value=FakeSession(),
            ),
            patch(
                "pysymex._internal.scanner.directory.scan._scan_sequential",
                side_effect=fake_scan_sequential,
            ),
        ):
            results = scan_directory(
                tmp_path,
                verbose=False,
                workers=1,
                use_sandbox=True,
            )

        assert entered == 1
        assert [result.file_path for result in results] == [str(target)]

    def test_no_sandbox_auto_tiny_directory_uses_sequential_mode(
        self,
        tmp_path: Path,
    ) -> None:
        targets: list[Path] = []
        for index in range(40):
            target = tmp_path / f"case_{index:02d}.py"
            target.write_text("def f(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
            targets.append(target)

        def fake_scan_sequential(*args: object, **kwargs: object) -> list[ScanResult]:
            _ = args
            _ = kwargs
            return [ScanResult(file_path=str(target), timestamp="now") for target in targets]

        def fail_scan_parallel(*args: object, **kwargs: object) -> list[ScanResult]:
            _ = args
            _ = kwargs
            raise AssertionError("tiny no-sandbox auto scan should stay sequential")

        with (
            patch("pysymex._internal.scanner.workers.os.cpu_count", return_value=16),
            patch("pysymex._internal.scanner.directory.planning.os.cpu_count", return_value=16),
            patch(
                "pysymex._internal.scanner.directory.scan._scan_sequential",
                side_effect=fake_scan_sequential,
            ),
            patch(
                "pysymex._internal.scanner.directory.scan._scan_parallel",
                side_effect=fail_scan_parallel,
            ),
        ):
            results = scan_directory(
                tmp_path,
                verbose=False,
                workers=None,
                use_sandbox=False,
            )

        assert len(results) == 40

    def test_default_sandbox_tiny_directory_uses_batch_preloaded_bytecode(
        self,
        tmp_path: Path,
    ) -> None:
        targets: list[Path] = []
        for index in range(40):
            target = tmp_path / f"case_{index:02d}.py"
            target.write_text("def f(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
            targets.append(target)

        batch_calls = 0
        scan_calls = 0

        def fake_extract_batch(
            sources: dict[str, bytes],
            sandbox_config: object = None,
        ) -> dict[str, BytecodeBlob]:
            nonlocal batch_calls
            _ = sandbox_config
            batch_calls += 1
            blobs: dict[str, BytecodeBlob] = {}
            for filename, source in sources.items():
                code_obj = compile(source.decode("utf-8"), filename, "exec")
                blobs[filename] = BytecodeBlob(
                    payload=create_bridge_payload(code_obj, filename),
                    filename=filename,
                )
            return blobs

        def fake_scan_file(file_path: Path, *args: object, **kwargs: object) -> ScanResult:
            nonlocal scan_calls
            _ = args
            scan_calls += 1
            preloaded_code_obj = kwargs.get("preloaded_code_obj")
            preloaded_content = kwargs.get("preloaded_content")
            assert isinstance(preloaded_code_obj, CodeType)
            assert isinstance(preloaded_content, str)
            assert kwargs["use_sandbox"] is True
            return ScanResult(file_path=str(file_path), timestamp="now")

        def fail_scan_parallel(*args: object, **kwargs: object) -> list[ScanResult]:
            _ = args
            _ = kwargs
            raise AssertionError("tiny default sandbox scan should use sequential batch mode")

        with (
            patch("pysymex._internal.scanner.workers.os.cpu_count", return_value=16),
            patch("pysymex._internal.scanner.directory.planning.os.cpu_count", return_value=16),
            patch(
                "pysymex._internal.sandbox.bridge.bytecode.extract_bytecode_batch",
                side_effect=fake_extract_batch,
            ),
            patch(
                "pysymex._internal.scanner.directory.sequential.scan_file",
                side_effect=fake_scan_file,
            ),
            patch(
                "pysymex._internal.scanner.directory.scan._scan_parallel",
                side_effect=fail_scan_parallel,
            ),
        ):
            results = scan_directory(
                tmp_path,
                verbose=False,
                workers=None,
                use_sandbox=True,
            )

        assert batch_calls == 1
        assert scan_calls == 40
        assert len(results) == 40
