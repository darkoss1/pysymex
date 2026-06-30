"""Scanner regressions for generators retained through modeled attributes."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_generator_loaded_from_instance_attribute(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_instance_attribute_next.py"
    target.write_text(
        "class Holder:\n"
        "    def __init__(self, gen):\n"
        "        self.gen = gen\n"
        "\n"
        "    def pull(self):\n"
        "        return next(self.gen)\n"
        "\n"
        "def target() -> int:\n"
        "    def gen():\n"
        "        yield 4\n"
        "\n"
        "    holder = Holder(gen())\n"
        "    return 10 // (holder.pull() - 4)\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=80,
        max_depth=500,
        max_iterations=10000,
        timeout=5.0,
    )

    assert any(
        issue.get("function_name") == "target" and issue.get("kind") == "DIVISION_BY_ZERO"
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "TYPE_ERROR"
        and "not an iterator" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_generator_close_via_exit_replaces_body_exception(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_close_from_exit.py"
    target.write_text(
        "class Manager:\n"
        "    def __init__(self, gen):\n"
        "        self.gen = gen\n"
        "\n"
        "    def __enter__(self):\n"
        "        return None\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        self.gen.close()\n"
        "        return False\n"
        "\n"
        "def target() -> None:\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except GeneratorExit:\n"
        "            yield 2\n"
        "\n"
        "    generator = gen()\n"
        "    with Manager(generator):\n"
        "        next(generator)\n"
        "        raise ValueError('body')\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=80,
        max_depth=500,
        max_iterations=10000,
        timeout=5.0,
    )

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "generator ignored GeneratorExit" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "VALUE_ERROR"
        and "body" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_generator_close_via_symbolic_dict_replaces_body_exception(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_close_from_symbolic_dict.py"
    target.write_text(
        "REG = {}\n"
        "\n"
        "class Manager:\n"
        "    def __init__(self, token):\n"
        "        self.token = token\n"
        "\n"
        "    def __enter__(self):\n"
        "        return None\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        REG[self.token].close()\n"
        "        return False\n"
        "\n"
        "def target() -> None:\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except GeneratorExit:\n"
        "            yield 2\n"
        "\n"
        "    token = 1\n"
        "    generator = gen()\n"
        "    REG[token] = generator\n"
        "    with Manager(token):\n"
        "        next(generator)\n"
        "        raise ValueError('body')\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=500,
        max_iterations=10000,
        timeout=5.0,
    )

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "generator ignored GeneratorExit" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "VALUE_ERROR"
        and "body" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_generator_close_via_symbolic_dict_get_replaces_body_exception(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_close_from_symbolic_dict_get.py"
    target.write_text(
        "REG = {}\n"
        "\n"
        "class Manager:\n"
        "    def __init__(self, box, token):\n"
        "        self.box = box\n"
        "        self.token = token\n"
        "\n"
        "    def __enter__(self):\n"
        "        return self.box\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        generator = REG.get(self.token)\n"
        "        if generator is not None:\n"
        "            try:\n"
        "                generator.close()\n"
        "            except RuntimeError:\n"
        "                if self.box.get('propagate_close', 0):\n"
        "                    raise\n"
        "        return False\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    if value != 2:\n"
        "        return None\n"
        "    box = {\n"
        "        'illegal_yield_on_close': int(value == 2),\n"
        "        'propagate_close': int(value == 2),\n"
        "    }\n"
        "    token = 200 + value\n"
        "\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except GeneratorExit:\n"
        "            if box.get('illegal_yield_on_close', 0):\n"
        "                yield 2\n"
        "            raise\n"
        "\n"
        "    generator = gen()\n"
        "    REG[token] = generator\n"
        "    with Manager(box, token):\n"
        "        next(generator)\n"
        "        raise ValueError('body')\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=120,
        max_depth=700,
        max_iterations=20000,
        timeout=10.0,
    )

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "generator ignored GeneratorExit" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "VALUE_ERROR"
        and "body" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_generator_close_swallows_normal_generatorexit_reraise(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_close_swallows_generatorexit.py"
    target.write_text(
        "def target(value: int) -> None:\n"
        "    ledger = {'closed': 0, 'illegal': int(value == 2)}\n"
        "\n"
        "    def gen():\n"
        "        try:\n"
        "            yield ledger['illegal'] + 1\n"
        "        except GeneratorExit:\n"
        "            ledger['closed'] = ledger.get('closed', 0) + 1\n"
        "            if ledger.get('illegal', 0):\n"
        "                yield 'bad close'\n"
        "            raise\n"
        "\n"
        "    generator = gen()\n"
        "    next(generator)\n"
        "    generator.close()\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=600,
        max_iterations=12000,
        timeout=10.0,
    )

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "generator ignored GeneratorExit" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "UNHANDLED_EXCEPTION"
        and str(issue.get("message")) == "Path raises unhandled exception: GeneratorExit"
        for issue in result.issues
    )
