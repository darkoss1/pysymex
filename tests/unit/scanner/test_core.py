"""Tests for pysymex.scanner.core — source analysis and scanning helpers."""

from __future__ import annotations

from pathlib import Path

from pysymex.config import is_object_dict as _is_object_dict
from pysymex.scanner.core import (
    _auto_worker_count,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _build_symbolic_vars,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _collect_bytearray_modulo_index_diagnostics,  # type: ignore[reportPrivateUsage]  # white-box scanner heuristic regression
    _collect_masked_zero_division_diagnostics,  # type: ignore[reportPrivateUsage]  # white-box scanner heuristic regression
    _collect_top_level_function_names,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _descending_issue_count,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _effective_worker_count,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _is_safe_stdlib_import,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    _scanner_solver_timeout_ms,  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
    get_code_objects_with_context,
    scan_directory,
    scan_file,
)


def test_scanner_solver_timeout_caps_z3_query_budget() -> None:
    """Large file scans should keep each SMT query bounded below the file/function timeout."""
    assert _scanner_solver_timeout_ms(30.0) == 1000
    assert _scanner_solver_timeout_ms(0.25) == 250
    assert _scanner_solver_timeout_ms(0.0) == 1


def test_safe_stdlib_import_rejects_sandbox_blocked_modules() -> None:
    """Scanner must not concrete-bind effectful modules blocked by sandbox policy."""
    assert _is_safe_stdlib_import("subprocess") is False
    assert _is_safe_stdlib_import("socket") is False


def test_safe_stdlib_import_keeps_benign_stdlib_modules() -> None:
    """Ordinary stdlib modules remain concrete-bindable for scanner precision."""
    assert _is_safe_stdlib_import("math") is True


def test_build_symbolic_vars_treats_iterator_hints_as_finite_list_inputs() -> None:
    """Iterator-shaped scanner inputs should use the existing bounded list model."""

    def target(values: object) -> None:
        _ = values

    symbolic_vars = _build_symbolic_vars(
        target.__code__,
        type_hints={"values": "Iterator[CompiledConstraint]"},
        include_collection_heuristics=True,
    )

    assert symbolic_vars == {"values": "list"}


def test_scan_file_reports_explicit_assertion_error_diagnostics_without_impossible_path(
    tmp_path: Path,
) -> None:
    """The buggy_file-style diagnostic should report feasible AssertionError bugs only."""
    target = tmp_path / "buggy_file.py"
    target.write_text(
        "def test_01_basic_math(a: int, b: int):\n"
        "    if a > 1000 and b <= 500:\n"
        "        if a - b == 3333:\n"
        "            raise AssertionError('BUG 1 FOUND')\n"
        "\n"
        "def test_02_diamond_flow(x: int, y: int, z: int):\n"
        "    val = 0\n"
        "    if x == 10:\n"
        "        val += 1\n"
        "    if y == 20:\n"
        "        val += 10\n"
        "    if z == 30:\n"
        "        val += 100\n"
        "    if val == 111:\n"
        "        raise AssertionError('BUG 2 FOUND')\n"
        "\n"
        "def test_03_impossible_path(m: int):\n"
        "    if m > 10:\n"
        "        if m < 5:\n"
        "            raise AssertionError('FATAL BUG')\n"
        "    if m == 7:\n"
        "        raise AssertionError('BUG 3 FOUND')\n",
        encoding="utf-8",
    )

    result = scan_file(target)
    assertion_lines = {
        issue.get("line") for issue in result.issues if issue.get("kind") == "ASSERTION_ERROR"
    }

    assert assertion_lines == {4, 15, 22}


def test_scan_file_deduplicates_runtime_and_range_warning_for_same_site(
    tmp_path: Path,
) -> None:
    """Runtime counterexample should dominate same-site abstract/range warning."""
    target = tmp_path / "duplicate_division.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    if x > -2 and x < 2:\n"
        "        q = x // 2\n"
        "        if q == 0:\n"
        "            return 1 // 0\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target)
    matching = [
        issue
        for issue in result.issues
        if issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 5
    ]

    assert len(matching) == 1
    assert not str(matching[0].get("message", "")).startswith("[Abstract Interpreter]")


def test_scan_file_does_not_merge_fixed_range_loop_into_false_zero_division(
    tmp_path: Path,
) -> None:
    """State merging must preserve fixed-loop history closely enough to avoid false bugs."""
    target = tmp_path / "fixed_range_loop_guard.py"
    target.write_text(
        "def target(z: int) -> int:\n"
        "    total = 0\n"
        "    for _ in range(3):\n"
        "        total += 1\n"
        "    if total == 3 and z == 0:\n"
        "        z = 1\n"
        "    return 1 // z\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_reports_user_object_attribute_missing_on_feasible_path(
    tmp_path: Path,
) -> None:
    """User-object attributes assigned on only one branch must not be silently invented."""
    target = tmp_path / "object_attribute_missing.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record()\n"
        "    if flag:\n"
        "        record.extra = 5\n"
        "    return record.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_does_not_report_user_object_attribute_set_on_all_paths(
    tmp_path: Path,
) -> None:
    """Alias writes on both branches should make the attribute read safe."""
    target = tmp_path / "object_attribute_all_paths.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(flag: bool) -> int:\n"
        "    left = Record()\n"
        "    right = left\n"
        "    if flag:\n"
        "        left.extra = 1\n"
        "    else:\n"
        "        right.extra = 2\n"
        "    return right.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_does_not_report_constructor_initialized_attribute(
    tmp_path: Path,
) -> None:
    """Straight-line __init__ assignments should initialize instance attributes."""
    target = tmp_path / "object_attribute_init_const.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.ready = 1\n\n"
        "def target() -> int:\n"
        "    record = Record()\n"
        "    return record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_binds_private_constructor_class_for_getattr(
    tmp_path: Path,
) -> None:
    """Private helper classes have normal CPython class semantics during scans."""
    target = tmp_path / "private_object_getattr.py"
    target.write_text(
        "class _Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.ready = 1\n\n"
        "def target() -> int:\n"
        "    record = _Record()\n"
        "    return getattr(record, 'ready')\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_reports_constructor_parameter_attribute_zero_division(
    tmp_path: Path,
) -> None:
    """Constructor parameter assignments should preserve downstream bug detection."""
    target = tmp_path / "object_attribute_init_param.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.ready = value\n\n"
        "def target(value: int) -> int:\n"
        "    record = Record(value)\n"
        "    return 10 // record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_does_not_report_attribute_initialized_in_constructor_branches(
    tmp_path: Path,
) -> None:
    """Both constructor branches assigning an attribute should make the read safe."""
    target = tmp_path / "object_attribute_init_branches.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, flag: bool) -> None:\n"
        "        if flag:\n"
        "            self.ready = 1\n"
        "        else:\n"
        "            self.ready = 2\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record(flag)\n"
        "    return record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    )


def test_scan_file_reports_constructor_branch_zero_division_without_attr_noise(
    tmp_path: Path,
) -> None:
    """Conditional constructor values should keep branch-dependent zero feasible."""
    target = tmp_path / "object_attribute_init_branch_zero.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, flag: bool) -> None:\n"
        "        if flag:\n"
        "            self.ready = 0\n"
        "        else:\n"
        "            self.ready = 2\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record(flag)\n"
        "    return 10 // record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    ), result.issues
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    )


def test_scan_file_reports_forbidden_slotted_attribute_store(tmp_path: Path) -> None:
    """Writes outside literal __slots__ should be reported as AttributeError."""
    target = tmp_path / "slotted_forbidden_store.py"
    target.write_text(
        "class Slotted:\n"
        "    __slots__ = ('ready',)\n\n"
        "def target() -> int:\n"
        "    obj = Slotted()\n"
        "    obj.extra = 1\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_allows_declared_slotted_attribute_store(tmp_path: Path) -> None:
    """Declared slots should allow writes and later reads."""
    target = tmp_path / "slotted_allowed_store.py"
    target.write_text(
        "class Slotted:\n"
        "    __slots__ = ('ready',)\n\n"
        "def target() -> int:\n"
        "    obj = Slotted()\n"
        "    obj.ready = 1\n"
        "    return obj.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {6, 7}
        for issue in result.issues
    )


def test_scan_file_reports_readonly_property_store(tmp_path: Path) -> None:
    """Read-only property descriptors should reject STORE_ATTR."""
    target = tmp_path / "readonly_property_store.py"
    target.write_text(
        "class Record:\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return 4\n\n"
        "def target() -> int:\n"
        "    obj = Record()\n"
        "    obj.value = 3\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_allows_settable_property_store(tmp_path: Path) -> None:
    """Property setters should prevent read-only property false positives."""
    target = tmp_path / "settable_property_store.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self._value = 1\n\n"
        "    @property\n"
        "    def value(self) -> int:\n"
        "        return self._value\n\n"
        "    @value.setter\n"
        "    def value(self, new_value: int) -> None:\n"
        "        self._value = new_value\n\n"
        "def target() -> int:\n"
        "    obj = Record()\n"
        "    obj.value = 3\n"
        "    return obj.value\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {15, 16}
        for issue in result.issues
    )


def test_scan_file_reports_instance_method_returned_zero(tmp_path: Path) -> None:
    """Enhanced method bodies should preserve returned zero bugs."""
    target = tmp_path / "instance_method_returned_zero.py"
    target.write_text(
        "class Record:\n"
        "    def echo(self, x: int) -> int:\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    obj = Record()\n"
        "    return 10 // obj.echo(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_does_not_report_method_normalized_zero(tmp_path: Path) -> None:
    """Instance, static, and class methods should avoid havoc-return false positives."""
    target = tmp_path / "method_normalized_zero.py"
    target.write_text(
        "class Record:\n"
        "    def normalize(self, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @staticmethod\n"
        "    def static_normalize(x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @classmethod\n"
        "    def class_normalize(cls, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    obj = Record()\n"
        "    return (\n"
        "        10 // obj.normalize(x)\n"
        "        + 10 // obj.static_normalize(x)\n"
        "        + 10 // obj.class_normalize(x)\n"
        "    )\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") in {22, 23, 24}
        for issue in result.issues
    )


def test_scan_file_does_not_report_class_level_method_normalized_zero(tmp_path: Path) -> None:
    """Class-level static/class method access should not become havoc-return bugs."""
    target = tmp_path / "class_level_method_normalized_zero.py"
    target.write_text(
        "class Record:\n"
        "    @staticmethod\n"
        "    def static_normalize(x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "    @classmethod\n"
        "    def class_normalize(cls, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    return 10 // Record.static_normalize(x) + 10 // Record.class_normalize(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 15
        for issue in result.issues
    )


def test_scan_file_reports_class_level_instance_method_missing_self(tmp_path: Path) -> None:
    """Calling an instance method through the class without self should report TypeError."""
    target = tmp_path / "class_level_instance_method_missing_self.py"
    target.write_text(
        "class Record:\n"
        "    def normalize(self, x: int) -> int:\n"
        "        if x == 0:\n"
        "            return 1\n"
        "        return x\n\n"
        "def target(x: int) -> int:\n"
        "    return Record.normalize(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        and "missing required argument 'x'" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_direct_blocked_module_call_as_unknown(tmp_path: Path) -> None:
    """Direct calls through sandbox-blocked modules must be visible in diagnostics."""
    target = tmp_path / "blocked_call.py"
    target.write_text(
        "import subprocess\n\n"
        "def target(cmd: str) -> int:\n"
        "    completed = subprocess.run([cmd], check=False)\n"
        "    return completed.returncode\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.run is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_blocked_module_alias_call_as_unknown(tmp_path: Path) -> None:
    """Simple aliases of blocked callables must remain visible as unsupported boundaries."""
    target = tmp_path / "blocked_alias.py"
    target.write_text(
        "import subprocess\n\n"
        "runner = subprocess.run\n\n"
        "def target(cmd: str) -> int:\n"
        "    completed = runner([cmd], check=False)\n"
        "    return completed.returncode\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.run is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_does_not_report_overwritten_blocked_alias_call(tmp_path: Path) -> None:
    """Local overwrites must shadow blocked aliases to avoid stale-alias false positives."""
    target = tmp_path / "blocked_alias_overwrite.py"
    target.write_text(
        "import subprocess\n\n"
        "runner = subprocess.run\n\n"
        "def target(cmd: str) -> int:\n"
        "    runner = len\n"
        "    return runner([cmd])\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.run is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_constant_getattr_blocked_call_as_unknown(tmp_path: Path) -> None:
    """Constant getattr aliases of blocked callables must be visible in diagnostics."""
    target = tmp_path / "blocked_getattr.py"
    target.write_text(
        "import subprocess\n\n"
        "def target(cmd: str) -> int:\n"
        "    runner = getattr(subprocess, 'run')\n"
        "    completed = runner([cmd], check=False)\n"
        "    return completed.returncode\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.run is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_dynamic_getattr_blocked_call_as_unknown(tmp_path: Path) -> None:
    """Called dynamic getattr results from blocked modules must be visible as unknown."""
    target = tmp_path / "blocked_dynamic_getattr.py"
    target.write_text(
        "import subprocess\n\n"
        "def target(cmd: str, name: str) -> int:\n"
        "    runner = getattr(subprocess, name)\n"
        "    completed = runner([cmd], check=False)\n"
        "    return completed.returncode\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.<dynamic> is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_does_not_report_unused_dynamic_getattr_blocked_value(tmp_path: Path) -> None:
    """Unused dynamic getattr values are not reported as executed sandbox boundaries."""
    target = tmp_path / "blocked_dynamic_getattr_unused.py"
    target.write_text(
        "import subprocess\n\n"
        "def target(name: str) -> int:\n"
        "    runner = getattr(subprocess, name)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target)

    assert not any(
        issue.get("kind") == "UNKNOWN"
        and "subprocess.<dynamic> is blocked by sandbox policy" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_bytearray_modulo_index_diagnostic_reports_unguarded_oversized_modulo() -> None:
    """The bytearray fallback reports simple modulo ranges wider than the concrete buffer."""
    issues = _collect_bytearray_modulo_index_diagnostics(
        "def target(x: int) -> int:\n"
        "    table = bytearray([1, 2, 3, 4])\n"
        "    idx = x % 13\n"
        "    return table[idx]\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "INDEX_ERROR"
    assert issues[0]["function_name"] == "target"


def test_bytearray_modulo_index_diagnostic_ignores_guarded_modulo_index() -> None:
    """An explicit upper-bound guard prevents the syntactic fallback report."""
    issues = _collect_bytearray_modulo_index_diagnostics(
        "def target(x: int) -> int:\n"
        "    table = bytearray([1, 2, 3, 4])\n"
        "    idx = x % 13\n"
        "    if idx < 4:\n"
        "        return table[idx]\n"
        "    return 0\n"
    )

    assert issues == []


def test_masked_zero_division_diagnostic_reports_guarded_zero_divisor() -> None:
    """The masked-zero fallback reports division inside a proven zero branch."""
    issues = _collect_masked_zero_division_diagnostics(
        "def target(x: int) -> int:\n"
        "    masked = x & 7\n"
        "    if masked == 0:\n"
        "        return 10 // masked\n"
        "    return 1\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "DIVISION_BY_ZERO"
    assert issues[0]["function_name"] == "target"


def test_masked_zero_division_diagnostic_ignores_reassigned_divisor() -> None:
    """Reassigning the guarded variable before division clears the syntactic zero fact."""
    issues = _collect_masked_zero_division_diagnostics(
        "def target(x: int) -> int:\n"
        "    masked = x & 7\n"
        "    if masked == 0:\n"
        "        masked = 1\n"
        "        return 10 // masked\n"
        "    return 1\n"
    )

    assert issues == []


class TestDescendingIssueCount:
    """Tests for _descending_issue_count sort key."""

    def test_returns_negative(self) -> None:
        """Returns negated count for descending sort."""
        assert _descending_issue_count(("file.py", 5)) == -5

    def test_zero(self) -> None:
        """Zero count returns zero."""
        assert _descending_issue_count(("file.py", 0)) == 0


class TestBuildSymbolicVars:
    """Tests for _build_symbolic_vars parameter inference."""

    def test_simple_function(self) -> None:
        """Simple function parameters become 'int'."""
        code = compile("def f(x, y): return x + y", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {"x": "int", "y": "int"}

    def test_self_becomes_object(self) -> None:
        """'self' parameter becomes 'object'."""
        code = compile("class C:\n def m(self, x): pass\n", "<test>", "exec")
        # Navigate to method code
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["self"] == "object"

    def test_cls_becomes_object(self) -> None:
        """'cls' parameter becomes 'object'."""
        code = compile("class C:\n @classmethod\n def m(cls, x): pass\n", "<test>", "exec")
        class_code = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        method_code = [c for c in class_code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(method_code, include_collection_heuristics=False)
        assert result["cls"] == "object"

    def test_collection_heuristics_list(self) -> None:
        """Parameter containing 'list' becomes 'list' with heuristics."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["items"] == "list"

    def test_collection_heuristics_dict(self) -> None:
        """Parameter containing 'config' becomes 'dict' with heuristics."""
        code = compile("def f(config): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=True)
        assert result["config"] == "dict"

    def test_no_heuristics_fallback(self) -> None:
        """Without heuristics, 'items' becomes 'int'."""
        code = compile("def f(items): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result["items"] == "int"

    def test_no_args(self) -> None:
        """Function with no args returns empty dict."""
        code = compile("def f(): pass", "<test>", "exec")
        inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]
        result = _build_symbolic_vars(inner, include_collection_heuristics=False)
        assert result == {}


class TestIsObjectDict:
    """Tests for _is_object_dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """Dict passes."""
        assert _is_object_dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """List fails."""
        assert _is_object_dict([1]) is False


class TestAutoWorkerCount:
    """Tests for _auto_worker_count."""

    def test_without_sandbox(self) -> None:
        """Without sandbox, cap is 4."""
        count = _auto_worker_count(use_sandbox=False)
        assert 1 <= count <= 8

    def test_with_sandbox(self) -> None:
        """With sandbox, cap is 2."""
        count = _auto_worker_count(use_sandbox=True)
        assert 1 <= count <= 4

    def test_with_file_count_clamps_to_useful_parallelism(self) -> None:
        """Auto worker selection should avoid over-parallelizing tiny file sets."""
        count = _auto_worker_count(use_sandbox=False, file_count=2)
        assert count == 1

    def test_with_trace_enabled_reduces_workers(self) -> None:
        """Trace-heavy scans should not increase worker count relative to baseline."""
        baseline = _auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=False)
        traced = _auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=True)
        assert traced <= baseline


class TestEffectiveWorkerCount:
    """Tests for _effective_worker_count."""

    def test_single_file_forces_sequential(self) -> None:
        """One file should always resolve to one worker."""
        assert _effective_worker_count(1, 16) == 1

    def test_file_limited_parallelism(self) -> None:
        """Large worker counts should be clamped by useful file-level parallelism."""
        assert _effective_worker_count(6, 10) == 3


class TestGetCodeObjectsWithContext:
    """Tests for get_code_objects_with_context."""

    def test_module_level(self) -> None:
        """Module code has None path."""
        code = compile("x = 1", "<test>", "exec")
        items = get_code_objects_with_context(code)
        assert len(items) >= 1
        _, parent, full_path = items[0]
        assert parent is None
        assert full_path is None

    def test_nested_functions(self) -> None:
        """Nested functions have dotted paths."""
        src = """
def outer():
    def inner():
        return 1
    return inner()
"""
        code = compile(src, "<test>", "exec")
        items = get_code_objects_with_context(code)
        paths = {full for _, _, full in items if full is not None}
        assert "outer" in paths
        assert "outer.inner" in paths

    def test_nested_classes(self) -> None:
        """Nested classes have dotted paths."""
        src = """
class Outer:
    def method(self):
        def inner():
            return 1
        return inner()
"""
        code = compile(src, "<test>", "exec")
        items = get_code_objects_with_context(code)
        paths = {full for _, _, full in items if full is not None}
        assert "Outer" in paths
        assert "Outer.method" in paths
        assert "Outer.method.inner" in paths


class TestCollectTopLevelFunctionNames:
    """Tests for helper binding discovery."""

    def test_excludes_top_level_classes(self) -> None:
        """Class code objects must not be bound as helper functions."""
        src = """
class Kind:
    VALUE = 1

def helper(x: int) -> int:
    return x + 1
"""
        names = _collect_top_level_function_names(src, Path("sample.py"))
        assert names == {"helper"}


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
        )
        scanned_files = {Path(result.file_path).resolve() for result in results}
        assert top_file.resolve() in scanned_files
        assert nested_file.resolve() in scanned_files
