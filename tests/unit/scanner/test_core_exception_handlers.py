"""Scanner regressions for exception-handler execution paths."""

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_modeled_method_call_in_handler_does_not_corrupt_cleanup_stack(tmp_path: Path) -> None:
    """A resolved list method cannot branch as a synthetic non-callable value."""
    target = tmp_path / "handler_method_call.py"
    target.write_text(
        "def target(values: list) -> int:\n"
        "    errors = []\n"
        "    for value in values:\n"
        "        try:\n"
        "            10 // value\n"
        "        except ZeroDivisionError as exc:\n"
        "            errors.append(exc)\n"
        "    return len(errors)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, auto_tune=False)

    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "UNKNOWN"
        and isinstance(message := issue.get("message"), str)
        and "COPY" in message
        for issue in result.issues
    )


def test_for_loop_inside_with_cleanup_preserves_return_stack(tmp_path: Path) -> None:
    """CPython 3.12+ ``END_FOR; POP_TOP`` cleanup must not consume ``with`` stack items."""
    target = tmp_path / "with_loop_return_cleanup.py"
    target.write_text(
        "class Scope:\n"
        "    def __enter__(self):\n"
        "        self.events = [1]\n"
        "        return self\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        self.events.append(len(self.events))\n"
        "        return False\n"
        "\n"
        "\n"
        "def target(a: int, b: int, c: int, d: int, e: int) -> int:\n"
        "    total = 0\n"
        "    with Scope() as scope:\n"
        "        for value in (a, b, c):\n"
        "            if value > 0:\n"
        "                total += value\n"
        "            else:\n"
        "                total -= value\n"
        "        return total + 100 // 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=120,
        max_iterations=5000,
        timeout=5,
        no_cache=True,
    )

    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "UNKNOWN"
        and isinstance(message := issue.get("message"), str)
        and ("SWAP" in message or "POP_TOP" in message or "END_FOR" in message)
        for issue in result.issues
    )


def test_subscript_exception_inside_with_enters_handler_with_exception_stack(
    tmp_path: Path,
) -> None:
    """Handled ``BINARY_SUBSCR`` errors must populate CPython exception stack items."""
    target = tmp_path / "with_subscript_exception_stack.py"
    target.write_text(
        "class Scope:\n"
        "    def __enter__(self):\n"
        "        return self\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        return False\n"
        "\n"
        "\n"
        "def target(key: str) -> int:\n"
        "    data = {'present': 1}\n"
        "    with Scope():\n"
        "        return data[key]\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=80,
        max_iterations=5000,
        timeout=8,
        no_cache=True,
    )

    assert any(issue.get("kind") == "KEY_ERROR" for issue in result.issues)
    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "UNKNOWN"
        and isinstance(message := issue.get("message"), str)
        and ("COPY" in message or "POP_TOP" in message or "PUSH_EXC_INFO" in message)
        for issue in result.issues
    )


def test_compare_exception_inside_with_enters_handler_with_exception_stack(
    tmp_path: Path,
) -> None:
    """Handled ``COMPARE_OP`` TypeError paths must not jump to handlers bare."""
    target = tmp_path / "with_compare_exception_stack.py"
    target.write_text(
        "class Scope:\n"
        "    def __enter__(self):\n"
        "        return self\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        return False\n"
        "\n"
        "\n"
        "def target(value: object) -> int:\n"
        "    with Scope():\n"
        "        if value > 0:\n"
        "            return 1\n"
        "        return 2\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=80,
        max_iterations=5000,
        timeout=8,
        no_cache=True,
    )

    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "UNKNOWN"
        and isinstance(message := issue.get("message"), str)
        and ("COPY" in message or "POP_TOP" in message or "PUSH_EXC_INFO" in message)
        for issue in result.issues
    )


def test_scan_file_reports_bare_reraise_of_caught_zero_division(tmp_path: Path) -> None:
    target = tmp_path / "bare_reraise.py"
    target.write_text(
        "def target(value: int) -> None:\n"
        "    try:\n"
        "        1 // value\n"
        "    except ZeroDivisionError:\n"
        "        raise\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "ZeroDivisionError" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_key_error_class_is_caught_by_lookup_error(tmp_path: Path) -> None:
    target = tmp_path / "subclass_exception_handler.py"
    target.write_text(
        "def target() -> int:\n"
        "    try:\n"
        "        raise KeyError\n"
        "    except LookupError:\n"
        "        result = 5\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"UNHANDLED_EXCEPTION", "UNBOUND_VARIABLE", "NAME_ERROR"}
        for issue in result.issues
    )


def test_scan_file_local_custom_exception_class_is_caught(tmp_path: Path) -> None:
    target = tmp_path / "local_custom_exception_caught.py"
    target.write_text(
        "def target() -> int:\n"
        "    class MyError(Exception):\n"
        "        pass\n"
        "\n"
        "    try:\n"
        "        raise MyError\n"
        "    except MyError:\n"
        "        result = 4\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert result.degraded_passes == []


def test_scan_file_mismatched_local_custom_exception_is_reported(tmp_path: Path) -> None:
    target = tmp_path / "local_custom_exception_mismatch.py"
    target.write_text(
        "def target() -> int:\n"
        "    class MyError(Exception):\n"
        "        pass\n"
        "\n"
        "    class OtherError(Exception):\n"
        "        pass\n"
        "\n"
        "    try:\n"
        "        raise OtherError\n"
        "    except MyError:\n"
        "        result = 4\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "OtherError" in str(issue.get("message", ""))
        for issue in result.issues
    )


def test_scan_file_explicit_value_error_is_specific_issue_kind(tmp_path: Path) -> None:
    target = tmp_path / "explicit_value_error_method.py"
    target.write_text(
        "class Handle:\n"
        "    def __init__(self) -> None:\n"
        "        self.closed = False\n"
        "\n"
        "    def close(self) -> None:\n"
        "        self.closed = True\n"
        "\n"
        "    def read(self) -> int:\n"
        "        if self.closed:\n"
        "            raise ValueError('closed handle')\n"
        "        return 3\n"
        "\n"
        "\n"
        "def target(mode: int) -> int:\n"
        "    handle = Handle()\n"
        "    if mode == 1:\n"
        "        handle.close()\n"
        "        return handle.read()\n"
        "    return handle.read()\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=300,
        max_iterations=5000,
        timeout=8,
    )

    assert any(
        issue.get("kind") == "VALUE_ERROR" and "closed handle" in str(issue.get("message", ""))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "ValueError" in str(issue.get("message", ""))
        for issue in result.issues
    )


def test_scan_file_explicit_attribute_error_is_specific_issue_kind(tmp_path: Path) -> None:
    target = tmp_path / "explicit_attribute_error_getattr.py"
    target.write_text(
        "class Node:\n"
        "    def __getattr__(self, name: str) -> int:\n"
        "        if name == 'soft':\n"
        "            return 3\n"
        "        raise AttributeError(name)\n"
        "\n"
        "\n"
        "def target(mode: int) -> int:\n"
        "    node = Node()\n"
        "    if mode == 1:\n"
        "        return node.missing_hard\n"
        "    return node.soft\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=300,
        max_iterations=5000,
        timeout=8,
    )

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and "missing_hard" in str(issue.get("message", ""))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "AttributeError" in str(issue.get("message", ""))
        for issue in result.issues
    )
