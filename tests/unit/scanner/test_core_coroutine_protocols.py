"""Scanner regressions for coroutine protocol edge cases."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex
from pysymex.scanner.file import scan_file


_FORBIDDEN_KINDS = {
    "ATTRIBUTE_ERROR",
    "TYPE_ERROR",
    "NAME_ERROR",
    "UNBOUND_VARIABLE",
    "UNHANDLED_EXCEPTION",
    "NULL_DEREFERENCE",
}


def test_modeled_coroutine_import_has_no_cycle() -> None:
    from pysymex.execution.opcodes.common.coroutines import ModeledCoroutine

    assert ModeledCoroutine.__name__ == "ModeledCoroutine"


def test_analyze_code_coroutine_close_before_run_without_attribute_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "async def coro():\n"
            "    return 3\n"
            "\n"
            "coroutine = coro()\n"
            "coroutine.close()\n"
            "result = 5\n",
            max_paths=50,
            max_depth=150,
            max_iterations=3500,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) in _FORBIDDEN_KINDS for issue in result.issues
    )
    assert "unsupported_generator" not in result.degraded_passes


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


def test_analyze_code_coroutine_send_none_stopiteration_value_without_unhandled() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "async def coro():\n"
            "    return 3\n"
            "\n"
            "coroutine = coro()\n"
            "try:\n"
            "    coroutine.send(None)\n"
            "except StopIteration as exc:\n"
            "    result = exc.value + 2\n",
            max_paths=50,
            max_depth=150,
            max_iterations=3500,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) in _FORBIDDEN_KINDS for issue in result.issues
    )
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


def test_analyze_code_coroutine_send_non_none_before_start_reports_type_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "async def coro():\n    return 3\n\ncoroutine = coro()\ncoroutine.send(1)\n",
            max_paths=50,
            max_depth=150,
            max_iterations=3500,
            timeout=2.0,
        )
    )

    assert any(getattr(issue.kind, "name", issue.kind) == "TYPE_ERROR" for issue in result.issues)


def test_analyze_code_coroutine_throw_into_suspended_await_without_unhandled() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class Pause:\n"
            "    def __await__(self):\n"
            "        yield None\n"
            "        return 1\n"
            "\n"
            "async def coro():\n"
            "    try:\n"
            "        await Pause()\n"
            "    except ValueError:\n"
            "        return 5\n"
            "    return 1\n"
            "\n"
            "coroutine = coro()\n"
            "coroutine.send(None)\n"
            "try:\n"
            "    coroutine.throw(ValueError)\n"
            "except StopIteration as exc:\n"
            "    result = exc.value\n",
            max_paths=50,
            max_depth=150,
            max_iterations=3500,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) in _FORBIDDEN_KINDS for issue in result.issues
    )
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
