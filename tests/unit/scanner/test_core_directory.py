"""Tests for scanner directory traversal behavior."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pysymex.scanner.directory import scan_directory
from pysymex.scanner.types import ScanResult


class TestScanDirectoryRecursiveFlag:
    """Tests for recursive-pattern resolution in scan_directory."""

    def test_recursive_false_skips_nested_files(self, tmp_path: Path) -> None:
        """When recursive=False and default pattern is used, nested files are excluded."""
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
            recursive=False,
            max_paths=10,
            timeout=5,
            use_sandbox=False,
        )
        scanned_files = {Path(result.file_path).resolve() for result in results}
        assert top_file.resolve() in scanned_files
        assert nested_file.resolve() not in scanned_files

    def test_recursive_true_includes_nested_files(self, tmp_path: Path) -> None:
        """When recursive=True and default pattern is used, nested files are included."""
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
            recursive=True,
            max_paths=10,
            timeout=5,
            use_sandbox=False,
        )
        scanned_files = {Path(result.file_path).resolve() for result in results}
        assert top_file.resolve() in scanned_files
        assert nested_file.resolve() in scanned_files

    def test_windows_sequential_sandbox_scan_uses_bytecode_session(
        self,
        tmp_path: Path,
    ) -> None:
        target = tmp_path / "top.py"
        target.write_text("x = 1\n", encoding="utf-8")
        entered = 0

        class FakeSession:
            def __enter__(self) -> "FakeSession":
                nonlocal entered
                entered += 1
                return self

            def __exit__(
                self,
                exc_type: type[BaseException] | None,
                exc_val: BaseException | None,
                exc_tb: object,
            ) -> None:
                return None

        def fake_scan_sequential(*args: object, **kwargs: object) -> list[ScanResult]:
            _ = args
            _ = kwargs
            return [ScanResult(file_path=str(target), timestamp="now")]

        with (
            patch("pysymex.scanner.directory.sys.platform", "win32"),
            patch(
                "pysymex.sandbox.bridge.bytecode.sandbox_bytecode_extraction_session",
                return_value=FakeSession(),
            ),
            patch("pysymex.scanner.directory.scan_sequential", side_effect=fake_scan_sequential),
        ):
            results = scan_directory(
                tmp_path,
                verbose=False,
                workers=1,
                recursive=False,
                use_sandbox=True,
            )

        assert entered == 1
        assert [result.file_path for result in results] == [str(target)]
