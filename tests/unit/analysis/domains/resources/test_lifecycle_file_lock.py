"""Tests for resource lifecycle convenience checkers."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.file import FileResourceChecker
from pysymex.analysis.domains.resources.lifecycle.lock import LockResourceChecker
from pysymex.analysis.domains.resources.types import ResourceKind, ResourceState


class TestFileResourceChecker:
    """Test suite for pysymex.analysis.domains.resources.lifecycle.FileResourceChecker."""

    def test_open_file(self) -> None:
        checker = FileResourceChecker()
        resource, _ = checker.open_file("f", "w")
        assert resource.state == ResourceState.FILE_OPEN_WRITE

    def test_read_file(self) -> None:
        checker = FileResourceChecker()
        checker.open_file("f", "r")
        assert checker.read_file("f") is None

    def test_write_file(self) -> None:
        checker = FileResourceChecker()
        checker.open_file("f", "w")
        assert checker.write_file("f") is None

    def test_close_file(self) -> None:
        checker = FileResourceChecker()
        checker.open_file("f", "r")
        assert checker.close_file("f") is None


class TestLockResourceChecker:
    """Test suite for pysymex.analysis.domains.resources.lifecycle.LockResourceChecker."""

    def test_create_lock(self) -> None:
        checker = LockResourceChecker()
        resource = checker.create_lock("l")
        assert resource.kind == ResourceKind.LOCK

    def test_acquire_lock(self) -> None:
        checker = LockResourceChecker()
        checker.create_lock("l")
        assert checker.acquire_lock("l") is None

    def test_release_lock(self) -> None:
        checker = LockResourceChecker()
        checker.create_lock("l")
        checker.acquire_lock("l")
        assert checker.release_lock("l") is None

    def test_set_lock_order(self) -> None:
        checker = LockResourceChecker()
        checker.set_lock_order(["l1"])
        assert checker.lock_order == ["l1"]

    def test_check_current_lock_order(self) -> None:
        checker = LockResourceChecker()
        checker.create_lock("l1")
        checker.create_lock("l2")
        checker.set_lock_order(["l1", "l2"])
        checker.acquire_lock("l2")
        checker.acquire_lock("l1")
        checker.held_locks = {"l1", "l2"}
        assert checker.check_lock_ordering(["l2", "l1"], ["l1", "l2"]) is not None
