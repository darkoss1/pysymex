import time

import pytest
from pysymex.sandbox.execution import (
    ExecutionTimeout,
    ResourceLimitError,
    SecurityError,
    create_sandbox_namespace,
    get_hardened_builtins,
    get_safe_builtins,
    hardened_exec,
    make_restricted_import,
    resource_limits,
    safe_exec,
    timeout_context,
)

class TestExecutionTimeout:
    """Test suite for pysymex.sandbox.execution.ExecutionTimeout."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = ExecutionTimeout("timed out")
        assert isinstance(err, Exception)
        assert str(err) == "timed out"


class TestSecurityError:
    """Test suite for pysymex.sandbox.execution.SecurityError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SecurityError("security violation")
        assert isinstance(err, Exception)
        assert str(err) == "security violation"


class TestResourceLimitError:
    """Test suite for pysymex.sandbox.execution.ResourceLimitError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = ResourceLimitError("too big")
        assert isinstance(err, SecurityError)
        assert str(err) == "too big"


@pytest.mark.timeout(30)
def test_get_safe_builtins() -> None:
    """Test get_safe_builtins behavior."""
    safe = get_safe_builtins()
    assert "len" in safe
    assert "eval" in safe
    eval_fn = safe["eval"]
    assert callable(eval_fn)
    with pytest.raises(SecurityError):
        eval_fn("1+1")


@pytest.mark.timeout(30)
def test_create_sandbox_namespace() -> None:
    """Test create_sandbox_namespace behavior."""
    ns = create_sandbox_namespace(extra_globals={"x": 7})
    assert "__builtins__" in ns
    assert ns["x"] == 7

    no_builtins = create_sandbox_namespace(allow_builtins=False)
    assert no_builtins["__builtins__"] == {}


@pytest.mark.timeout(30)
def test_make_restricted_import() -> None:
    """Test make_restricted_import behavior."""
    restricted_import = make_restricted_import(frozenset({"math"}))
    allowed_ns = {"__builtins__": {"__import__": restricted_import}}
    exec("import math\nresult = math.sqrt(4)\n", allowed_ns)
    assert allowed_ns["result"] == 2.0

    with pytest.raises(SecurityError):
        blocked_ns = {"__builtins__": {"__import__": restricted_import}}
        exec("import os\n", blocked_ns)


@pytest.mark.timeout(30)
def test_timeout_context() -> None:
    """Test timeout_context behavior."""
    with timeout_context(0.5):
        time.sleep(0.01)

    with pytest.raises(ExecutionTimeout):
        with timeout_context(0.05):
            time.sleep(0.2)


@pytest.mark.timeout(30)
def test_resource_limits() -> None:
    """Test resource_limits behavior."""
    with resource_limits(max_memory_mb=64, max_cpu_seconds=2):
        x = 1 + 1
    assert x == 2


@pytest.mark.timeout(30)
def test_safe_exec() -> None:
    """Test safe_exec behavior."""
    ns = safe_exec("value = 41 + 1\n")
    assert ns["value"] == 42

    with pytest.raises(SecurityError):
        safe_exec("import os\n")


@pytest.mark.timeout(30)
def test_get_hardened_builtins() -> None:
    """Test get_hardened_builtins behavior."""
    hardened = get_hardened_builtins(import_allowlist=frozenset({"math"}))
    assert "getattr" in hardened
    assert "__import__" in hardened

    open_fn = hardened["open"]
    assert callable(open_fn)
    with pytest.raises(SecurityError):
        open_fn("x.txt", "w")

    import_fn = hardened["__import__"]
    assert callable(import_fn)
    with pytest.raises(SecurityError):
        import_fn("os")


@pytest.mark.timeout(30)
def test_hardened_exec() -> None:
    """Test hardened_exec behavior."""
    ns = hardened_exec("result = 40 + 2\n", "safe.py")
    assert ns["result"] == 42

    with pytest.raises(SecurityError):
        hardened_exec("x = '__globals__'\n", "blocked.py")
