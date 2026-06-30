"""Scanner regressions for generator protocol edge cases."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file


def test_modeled_generator_import_has_no_cycle() -> None:
    from pysymex._internal.core.types.containers.generators import ModeledGenerator

    assert ModeledGenerator.__name__ == "ModeledGenerator"


def test_scan_file_unpacks_literal_generator_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "literal_generator_unpack.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        yield 1\n"
        "        yield 2\n"
        "\n"
        "    left, right = gen()\n"
        "    return left + right\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_yield_from_literal_list_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "yield_from_literal_list.py"
    target.write_text(
        "def target() -> int:\n"
        "    def make_items():\n"
        "        yield from [2, 3]\n"
        "\n"
        "    total = 0\n"
        "    for item in make_items():\n"
        "        total += item\n"
        "    result = total\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_preserves_generator_return_stopiteration_value(tmp_path: Path) -> None:
    target = tmp_path / "generator_return_value.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        yield 1\n"
        "        return 4\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    try:\n"
        "        next(generator)\n"
        "    except StopIteration as exc:\n"
        "        result = first + exc.value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_generator_close_models_finally_without_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "generator_close.py"
    target.write_text(
        "def target() -> int:\n"
        "    events = []\n"
        "\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        finally:\n"
        "            events.append('closed')\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    generator.close()\n"
        "    return first + len(events)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert not result.issues
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_generator_close_reports_ignored_generatorexit_runtime_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_close_ignored_generatorexit.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except GeneratorExit:\n"
        "            yield 2\n"
        "\n"
        "    generator = gen()\n"
        "    next(generator)\n"
        "    generator.close()\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "generator ignored GeneratorExit" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_generator_throw_degrades_without_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "generator_throw.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except ValueError:\n"
        "            yield 3\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    second = generator.throw(ValueError)\n"
        "    return first + second\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert "unsupported_generator" in result.degraded_passes


def test_scan_file_does_not_enter_generator_helper_as_plain_callable(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_helper_callable_entry.py"
    target.write_text(
        "class Ledger:\n"
        "    def __init__(self, seed: int) -> None:\n"
        "        self.seed = seed\n"
        "        self.events: list[object] = []\n"
        "\n"
        "    def mark(self, label: str, value: int) -> int:\n"
        "        self.events.append((label, value, len(self.events)))\n"
        "        return self.seed + value + len(self.events)\n"
        "\n"
        "def helper(values: tuple[int, ...], ledger: Ledger):\n"
        "    for index, value in enumerate(values):\n"
        "        yield ledger.mark('helper-yield', value + index)\n"
        "\n"
        "def target(left: int, right: int) -> int:\n"
        "    ledger = Ledger(0)\n"
        "    first = next(helper((left, right), ledger))\n"
        "    return first\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("function_name") == "helper"
        and issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def test_scan_file_yield_from_modeled_subgenerator_without_havoc(
    tmp_path: Path,
) -> None:
    target = tmp_path / "yield_from_modeled_subgenerator.py"
    target.write_text(
        "def source(values: tuple[int, ...]):\n"
        "    for value in values:\n"
        "        yield value\n"
        "\n"
        "def relay(values: tuple[int, ...]):\n"
        "    yield from source(values)\n"
        "\n"
        "def target(left: int, right: int) -> int:\n"
        "    total = 0\n"
        "    for item in relay((left, right, 1)):\n"
        "        total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") in {"TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def _counterexample_mode(issue: dict[str, object]) -> object:
    """Return a scanner issue's ``mode`` counterexample value, when present."""
    counterexample = issue.get("counterexample")
    if not isinstance(counterexample, dict):
        return None
    typed_counterexample = cast("dict[object, object]", counterexample)
    return typed_counterexample.get("mode")


def test_scan_file_generator_cleanup_does_not_replace_caller_arg_with_cell(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_cleanup_cell_alias.py"
    target.write_text(
        "class Ledger:\n"
        "    def __init__(self, seed: int) -> None:\n"
        "        self.seed = seed\n"
        "        self.events: list[object] = []\n"
        "\n"
        "    def mark(self, label: str, value: int) -> int:\n"
        "        self.events.append((label, value, len(self.events)))\n"
        "        return self.seed + value + len(self.events)\n"
        "\n"
        "def _leaf(values: tuple[int, ...], ledger: Ledger):\n"
        "    total = 0\n"
        "    try:\n"
        "        for index, value in enumerate(values):\n"
        "            try:\n"
        "                incoming = yield ledger.mark('leaf-yield', value + index)\n"
        "                if incoming is None:\n"
        "                    incoming = index\n"
        "                total += incoming + value\n"
        "                yield total\n"
        "            finally:\n"
        "                ledger.events.append(('leaf', index, total))\n"
        "    finally:\n"
        "        ledger.events.append(('leaf-close', len(values), total))\n"
        "    return total\n"
        "\n"
        "def _relay(values: tuple[int, ...], ledger: Ledger):\n"
        "    try:\n"
        "        shifted = tuple(item + ledger.seed for item in values)\n"
        "        result = yield from _leaf(shifted, ledger)\n"
        "    except ValueError as exc:\n"
        "        ledger.events.append(('relay-value', len(exc.args), len(ledger.events)))\n"
        "        yield len(exc.args) + ledger.seed\n"
        "        return ledger.seed\n"
        "    finally:\n"
        "        ledger.events.append(('relay-finally', len(values), len(ledger.events)))\n"
        "    return result\n"
        "\n"
        "def _drive(mode: int, left: int, right: int, pivot: int) -> tuple[int, Ledger]:\n"
        "    ledger = Ledger(pivot)\n"
        "    iterator = _relay((left, right, left - right, pivot), ledger)\n"
        "    first = next(iterator)\n"
        "    try:\n"
        "        if mode == 1:\n"
        "            return (iterator.throw(ValueError('x')), ledger)\n"
        "        if mode == 2:\n"
        "            iterator.close()\n"
        "            return (iterator.send(1), ledger)\n"
        "        if mode == 3:\n"
        "            return (iterator.send('bad'), ledger)\n"
        "        second = iterator.send(first % 3)\n"
        "        return (first + second, ledger)\n"
        "    finally:\n"
        "        ledger.events.append(('drive', mode, len(ledger.events)))\n"
        "\n"
        "def target(mode: int, left: int, right: int, pivot: int) -> int:\n"
        "    value, ledger = _drive(mode, left, right, pivot)\n"
        "    lookup = {name: index for index, (name, *_rest) in enumerate(ledger.events)}\n"
        "    match (mode, bool(ledger.events), len(ledger.events)):\n"
        "        case (1, True, _):\n"
        "            return lookup['missing-event']\n"
        "        case (3, True, _):\n"
        "            return value\n"
        "        case _:\n"
        "            return value + len(lookup)\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=500,
        max_depth=8000,
        max_iterations=120000,
        timeout=20,
        trace_enabled=False,
    )

    assert result.error is None
    assert not any(
        issue.get("kind") in {"NULL_DEREFERENCE", "TYPE_ERROR", "UNKNOWN"}
        and (
            "cell_ledger.events" in str(issue.get("message"))
            or "object of type 'object' has no len()" in str(issue.get("message"))
        )
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "Cannot concatenate 'str' with non-'str' operand" in str(issue.get("message"))
        and issue.get("counterexample")
        for issue in result.issues
    )

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "KEY_ERROR"
        and _counterexample_mode(issue) == 1
        and "subscript key may be missing" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("message") == "Possible TypeError"
        and not issue.get("counterexample")
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "TYPE_ERROR"
        and issue.get("line") == 44
        for issue in result.issues
    )
