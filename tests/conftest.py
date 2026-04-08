"""Pytest configuration and fixtures for pysymex tests."""

import os
import shutil
import sys
import tempfile
import uuid
import getpass
from pathlib import Path

import pytest

# Add the parent directory to path for imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_TEST_RUNTIME_ROOT_ENV = "PYSYMEX_TEST_RUNTIME_ROOT"
sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.fixture(autouse=True)
def clear_all_caches():
    """Clear all global caches before every test to prevent state leakage."""
    try:
        from pysymex.core.solver import clear_solver_caches
        clear_solver_caches()
    except ImportError:
        pass

    try:
        from pysymex.core.types import FROM_CONST_CACHE, SYMBOLIC_CACHE
        FROM_CONST_CACHE.clear()
        SYMBOLIC_CACHE.clear()
    except ImportError:
        pass


@pytest.fixture
def simple_int_params():
    """Simple integer parameter specification."""
    return {"x": "int"}


@pytest.fixture
def two_int_params():
    """Two integer parameters."""
    return {"x": "int", "y": "int"}


@pytest.fixture
def three_int_params():
    """Three integer parameters."""
    return {"x": "int", "y": "int", "z": "int"}


@pytest.fixture
def mixed_params():
    """Mixed parameter types."""
    return {"x": "int", "s": "str", "b": "bool"}


@pytest.fixture
def unsafe_division():
    """A function with unsafe division."""

    def divide(x, y):
        return x / y

    return divide


@pytest.fixture
def safe_division():
    """A function with safe (guarded) division."""

    def divide(x, y):
        if y != 0:
            return x / y
        return 0

    return divide


@pytest.fixture
def failing_assertion():
    """A function with a potentially failing assertion."""

    def check(x):
        assert x > 0
        return x * 2

    return check


@pytest.fixture
def complex_branching():
    """A function with complex branching logic."""

    def branch(x, y, z):
        result = 0
        if x > 0:
            result += 1
        if y > 0:
            result += 2
        if z > 0:
            result += 4
        return result

    return branch


class AnalysisHelper:
    """Helper class for common analysis operations."""

    @staticmethod
    def count_issues_by_kind(result, kind):
        """Count issues of a specific kind."""
        return len([i for i in result.issues if i.kind == kind])

    @staticmethod
    def get_all_counterexamples(result):
        """Get all counterexamples from issues."""
        return [i.get_counterexample() for i in result.issues]

    @staticmethod
    def has_issue_for_var(result, var_name, value):
        """Check if any issue has a counterexample with given variable value."""
        for issue in result.issues:
            ce = issue.get_counterexample()
            if ce.get(var_name) == value:
                return True
        return False


@pytest.fixture
def analysis_helper():
    """Provide analysis helper instance."""
    return AnalysisHelper()


# Markers for different test categories
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "unit: marks unit tests")

    runtime_root = _PROJECT_ROOT / ".pytest_runtime" / f"_tmp_rt_{uuid.uuid4().hex}"
    runtime_root.mkdir(parents=True, exist_ok=True)
    runtime_root_str = str(runtime_root.resolve())

    # Windows temp ACL handling with multiprocess workers is fragile across
    # Python/pytest versions; run serially for deterministic behavior.
    if os.name == "nt" and getattr(config.option, "numprocesses", None):
        config.option.numprocesses = 0
        if hasattr(config.option, "dist"):
            config.option.dist = "no"

    os.environ[_TEST_RUNTIME_ROOT_ENV] = runtime_root_str


def pytest_sessionstart(session):
    """Use a unique workspace-local temp root for this pytest process."""
    temp_root_str = os.environ.get(_TEST_RUNTIME_ROOT_ENV)
    if not temp_root_str:
        runtime_root = _PROJECT_ROOT / ".pytest_runtime" / f"_tmp_rt_{uuid.uuid4().hex}"
        runtime_root.mkdir(parents=True, exist_ok=True)
        temp_root_str = str(runtime_root.resolve())
        os.environ[_TEST_RUNTIME_ROOT_ENV] = temp_root_str

    os.environ["TMP"] = temp_root_str
    os.environ["TEMP"] = temp_root_str
    os.environ["TMPDIR"] = temp_root_str
    tempfile.tempdir = temp_root_str

    if os.name == "nt":
        user = (
            os.environ.get("PYTEST_XDIST_WORKER_USER")
            or os.environ.get("USERNAME")
            or os.environ.get("USER")
            or os.environ.get("LOGNAME")
        )
        if not user:
            try:
                user = getpass.getuser() or "unknown"
            except Exception:
                user = "unknown"
        (Path(temp_root_str) / f"pytest-of-{user}").mkdir(parents=True, exist_ok=True)

        def _workspace_mkdtemp(
            suffix: str | None = None,
            prefix: str | None = None,
            dir: str | os.PathLike[str] | None = None,
        ) -> str:
            base = Path(dir) if dir is not None else Path(temp_root_str)
            base.mkdir(parents=True, exist_ok=True)
            name_prefix = "tmp" if prefix is None else prefix
            name_suffix = "" if suffix is None else suffix
            while True:
                candidate = base / f"{name_prefix}{uuid.uuid4().hex}{name_suffix}"
                try:
                    candidate.mkdir(parents=False, exist_ok=False)
                    return str(candidate)
                except FileExistsError:
                    continue

        class _WorkspaceTemporaryDirectory:
            def __init__(
                self,
                suffix: str | None = None,
                prefix: str | None = None,
                dir: str | os.PathLike[str] | None = None,
                ignore_cleanup_errors: bool = False,
                delete: bool = True,
            ) -> None:
                self.name = _workspace_mkdtemp(suffix=suffix, prefix=prefix, dir=dir)
                self._ignore_cleanup_errors = ignore_cleanup_errors
                self._delete = delete

            def __enter__(self) -> str:
                return self.name

            def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
                self.cleanup()

            def cleanup(self) -> None:
                if not self._delete:
                    return
                try:
                    shutil.rmtree(self.name, ignore_errors=self._ignore_cleanup_errors)
                except Exception:
                    if not self._ignore_cleanup_errors:
                        raise

        tempfile.mkdtemp = _workspace_mkdtemp  # type: ignore[assignment]
        tempfile.TemporaryDirectory = _WorkspaceTemporaryDirectory  # type: ignore[assignment]

        try:
            import _pytest.pathlib as _pytest_pathlib
            import _pytest.tmpdir as _pytest_tmpdir

            _orig_make_numbered_dir = _pytest_pathlib.make_numbered_dir
            _orig_make_numbered_dir_with_cleanup = _pytest_pathlib.make_numbered_dir_with_cleanup
            _orig_cleanup_dead_symlinks = _pytest_pathlib.cleanup_dead_symlinks

            def _patched_make_numbered_dir(root, prefix, mode):  # noqa: ANN001
                return _orig_make_numbered_dir(root, prefix, 0o777)

            def _patched_make_numbered_dir_with_cleanup(*args, **kwargs):  # noqa: ANN002, ANN003
                kwargs["mode"] = 0o777
                return _orig_make_numbered_dir_with_cleanup(*args, **kwargs)

            def _patched_cleanup_dead_symlinks(root):  # noqa: ANN001
                try:
                    _orig_cleanup_dead_symlinks(root)
                except PermissionError:
                    return

            def _patched_getbasetemp(self):  # noqa: ANN001
                if self._basetemp is not None:
                    return self._basetemp
                if self._given_basetemp is not None:
                    base = Path(self._given_basetemp)
                else:
                    base = Path(temp_root_str) / "pytest-basetemp"
                base.mkdir(parents=True, exist_ok=True)
                self._basetemp = base.resolve()
                return self._basetemp

            _pytest_pathlib.make_numbered_dir = _patched_make_numbered_dir
            _pytest_pathlib.make_numbered_dir_with_cleanup = _patched_make_numbered_dir_with_cleanup
            _pytest_pathlib.cleanup_dead_symlinks = _patched_cleanup_dead_symlinks
            _pytest_tmpdir.TempPathFactory.getbasetemp = _patched_getbasetemp

            def _patched_mktemp(self, basename: str, numbered: bool = True):  # noqa: ANN001
                basename = self._ensure_relative_to_basetemp(basename)
                base = self.getbasetemp()
                if not numbered:
                    p = base.joinpath(basename)
                    p.mkdir(parents=True, exist_ok=True)
                    return p
                while True:
                    p = base / f"{basename}-{uuid.uuid4().hex}"
                    try:
                        p.mkdir(parents=False, exist_ok=False)
                        break
                    except FileExistsError:
                        continue
                self._trace("mktemp", p)
                return p

            _pytest_tmpdir.TempPathFactory.mktemp = _patched_mktemp
        except Exception:
            pass


def pytest_sessionfinish(session, exitstatus):  # noqa: ANN001
    """Best-effort cleanup for workspace runtime temp roots."""
    runtime_root = os.environ.get(_TEST_RUNTIME_ROOT_ENV)
    if runtime_root:
        shutil.rmtree(runtime_root, ignore_errors=True)
