"""Scanner regressions for coroutine protocol edge cases."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file

_FORBIDDEN_KINDS = {
    "ATTRIBUTE_ERROR",
    "TYPE_ERROR",
    "NAME_ERROR",
    "UNBOUND_VARIABLE",
    "UNHANDLED_EXCEPTION",
    "NULL_DEREFERENCE",
}


def test_modeled_coroutine_import_has_no_cycle() -> None:
    from pysymex._internal.execution.opcodes.common.coroutines.objects import ModeledCoroutine

    assert ModeledCoroutine.__name__ == "ModeledCoroutine"


def test_scan_file_coroutine_close_before_run_without_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "coroutine_close_before_run.py"
    target.write_text(
        "def target() -> int:\n"
        "    async def coro():\n"
        "        return 3\n"
        "\n"
        "    coroutine = coro()\n"
        "    coroutine.close()\n"
        "    result = 5\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") in _FORBIDDEN_KINDS for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_coroutine_send_none_stopiteration_value_without_unhandled(
    tmp_path: Path,
) -> None:
    target = tmp_path / "coroutine_send_stopiteration.py"
    target.write_text(
        "def target() -> int:\n"
        "    async def coro():\n"
        "        return 3\n"
        "\n"
        "    coroutine = coro()\n"
        "    try:\n"
        "        coroutine.send(None)\n"
        "    except StopIteration as exc:\n"
        "        result = exc.value + 2\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") in _FORBIDDEN_KINDS for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_coroutine_throw_into_suspended_await_without_unhandled(
    tmp_path: Path,
) -> None:
    target = tmp_path / "coroutine_throw_suspended.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Pause:\n"
        "        def __await__(self):\n"
        "            yield None\n"
        "            return 1\n"
        "\n"
        "    async def coro():\n"
        "        try:\n"
        "            await Pause()\n"
        "        except ValueError:\n"
        "            return 5\n"
        "        return 1\n"
        "\n"
        "    coroutine = coro()\n"
        "    coroutine.send(None)\n"
        "    try:\n"
        "        coroutine.throw(ValueError)\n"
        "    except StopIteration as exc:\n"
        "        result = exc.value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") in _FORBIDDEN_KINDS for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_custom_await_preserves_symbolic_yield_and_return(tmp_path: Path) -> None:
    target = tmp_path / "custom_await_exact_yield_return.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    class Pause:\n"
        "        def __init__(self, marker: int) -> None:\n"
        "            self.marker = marker\n"
        "        def __await__(self):\n"
        "            checkpoint = ('pause', self.marker)\n"
        "            yield checkpoint\n"
        "            return self.marker\n"
        "\n"
        "    async def worker(current: int) -> int:\n"
        "        observed = await Pause(current)\n"
        "        return observed + 1\n"
        "\n"
        "    coroutine = worker(value)\n"
        "    first = coroutine.send(None)\n"
        "    if first != ('pause', value):\n"
        "        raise AssertionError('unexpected suspension')\n"
        "    try:\n"
        "        coroutine.send(None)\n"
        "    except StopIteration as exc:\n"
        "        result = int(exc.value)\n"
        "    else:\n"
        "        raise AssertionError('coroutine did not finish')\n"
        "    if result != value + 1:\n"
        "        raise AssertionError('unexpected await result')\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=50,
        max_depth=400,
        max_iterations=10000,
        timeout=8,
    )

    assert result.error is None
    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("kind") in _FORBIDDEN_KINDS | {"ASSERTION_ERROR"} for issue in result.issues
    )


def test_scan_file_async_with_unsupported_enter_does_not_report_body_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "async_with_enter_unsupported_body_control.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    class Gate:\n"
        "        async def __aenter__(self):\n"
        "            raise ValueError('async enter failed')\n"
        "        async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "            return False\n"
        "\n"
        "    async def worker() -> int:\n"
        "        async with Gate():\n"
        "            return 10 // (value - value)\n"
        "\n"
        "    coroutine = worker()\n"
        "    coroutine.send(None)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=30,
        max_depth=400,
        max_iterations=10000,
        timeout=8,
    )

    assert result.error is None
    assert "unsupported_generator" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_async_for_incomplete_end_async_for_is_unsupported_not_unknown(
    tmp_path: Path,
) -> None:
    target = tmp_path / "async_for_end_async_for_precision.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Counter:\n"
        "        def __init__(self) -> None:\n"
        "            self.index = 0\n"
        "        def __aiter__(self):\n"
        "            return self\n"
        "        async def __anext__(self) -> int:\n"
        "            self.index += 1\n"
        "            if self.index > 1:\n"
        "                raise StopAsyncIteration\n"
        "            return self.index\n"
        "\n"
        "    async def worker() -> int:\n"
        "        total = 0\n"
        "        async for item in Counter():\n"
        "            total += item\n"
        "        return total\n"
        "\n"
        "    coroutine = worker()\n"
        "    try:\n"
        "        coroutine.send(None)\n"
        "    except StopIteration as exc:\n"
        "        return int(exc.value)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=600,
        max_iterations=12000,
        timeout=10,
    )

    assert result.error is None
    assert "unsupported_generator" in result.degraded_passes
    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") == "UNKNOWN"
        for issue in result.issues
    )


def test_scan_file_async_for_havoc_divisor_is_not_high_confidence(
    tmp_path: Path,
) -> None:
    target = tmp_path / "async_for_havoc_divisor_confidence.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Counter:\n"
        "        def __init__(self) -> None:\n"
        "            self.index = 0\n"
        "        def __aiter__(self):\n"
        "            return self\n"
        "        async def __anext__(self) -> int:\n"
        "            self.index += 1\n"
        "            if self.index > 1:\n"
        "                raise StopAsyncIteration\n"
        "            return 1\n"
        "\n"
        "    async def worker() -> int:\n"
        "        total = 8\n"
        "        async for item in Counter():\n"
        "            total //= item\n"
        "        return total\n"
        "\n"
        "    coroutine = worker()\n"
        "    try:\n"
        "        coroutine.send(None)\n"
        "    except StopIteration as exc:\n"
        "        return int(exc.value)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=600,
        max_iterations=12000,
        timeout=10,
    )

    assert result.error is None
    assert "unsupported_generator" in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("confidence") == 1.0
        for issue in result.issues
    )
