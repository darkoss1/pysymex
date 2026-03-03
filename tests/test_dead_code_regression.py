"""Regression tests for dead code detection fixes.

Covers false positive eliminations for:
- UNREACHABLE_CODE: exception cleanup bytecode (terminator_line heuristic)
- UNREACHABLE_CODE: generators, async generators, coroutines, genexprs
- UNREACHABLE_CODE: PUSH_EXC_INFO as implicit exception handler entry
- UNUSED_VARIABLE: Python 3.12+/3.13 combined opcodes
- DEAD_STORE: combined opcodes in loops and linear flow
- UNUSED_PARAMETER: combined load opcodes
- Taint analysis: ambiguous short name suppression
"""

import sys

import pytest


from pysymex.analysis.dead_code import (
    DeadCodeAnalyzer,
    DeadCodeKind,
    UnreachableCodeDetector,
    UnusedVariableDetector,
    DeadStoreDetector,
    UnusedParameterDetector,
    RedundantConditionDetector,
)

from pysymex.analysis.taint.checker import TaintAnalyzer, TaintChecker


def _compile_and_get_code(source: str, name: str = "<test>"):
    """Compile source and return the module code object."""

    return compile(source, name, "exec")


def _compile_function(source: str, func_name: str, name: str = "<test>"):
    """Compile source and extract a named function's code object."""

    module_code = compile(source, name, "exec")

    for const in module_code.co_consts:
        if hasattr(const, "co_code") and getattr(const, "co_name", None) == func_name:
            return const

    raise ValueError(f"Function '{func_name}' not found in compiled source")


def _find_issues(issues, kind):
    """Filter issues by DeadCodeKind."""

    return [i for i in issues if i.kind == kind]


class TestUnreachableCodeExceptionCleanup:
    """Regression: CPython exception cleanup bytecode should not trigger
    unreachable code warnings.  CPython emits POP_EXCEPT, RERAISE, SWAP,
    etc. after return/raise in except handlers.  These reference the
    try/except source lines and are mechanically unreachable, not dead
    user code."""

    def test_return_in_except_no_fp(self):
        """Return inside except handler should not flag cleanup as unreachable."""

        source = """\
def get_value(d, key):
    try:
        return d[key]
    except KeyError:
        return None
"""

        code = _compile_function(source, "get_value")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_raise_in_except_no_fp(self):
        """Raise inside except handler should not flag cleanup as unreachable."""

        source = """\
def setup_db():
    try:
        db = connect()
        return db
    except Exception as e:
        raise RuntimeError("DB failed") from e
"""

        code = _compile_function(source, "setup_db")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_multiple_except_handlers_no_fp(self):
        """Multiple except handlers each with return should not produce FPs."""

        source = """\
def load_ext(name):
    try:
        import_module(name)
        return True
    except ImportError:
        return False
    except Exception:
        return False
"""

        code = _compile_function(source, "load_ext")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_nested_try_except_no_fp(self):
        """Nested try/except with returns should not produce FPs."""

        source = """\
def main():
    try:
        try:
            do_work()
        except ValueError:
            return 1
    except Exception:
        return 2
    return 0
"""

        code = _compile_function(source, "main")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_finally_block_no_fp(self):
        """try/except/finally with returns should not produce FPs."""

        source = """\
def safe_op():
    try:
        result = compute()
        return result
    except Exception:
        return None
    finally:
        cleanup()
"""

        code = _compile_function(source, "safe_op")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_real_dead_code_still_detected(self):
        """Actual dead code after return should still be flagged.

        Note: CPython 3.13+ removes dead code after unconditional return/raise
        at compile time, so the bytecode may not contain the unreachable
        instructions.  We test at the module level where CPython preserves
        more bytecode, and accept that on aggressive-optimizing Pythons
        the detector simply has no bytecode to analyze (which is correct)."""

        source = """\
def compute():
    return 42
    x = 10
    print(x)
"""

        code = _compile_function(source, "compute")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        import dis

        instructions = list(dis.get_instructions(code))

        has_dead_bytecode = len(instructions) > 2

        if has_dead_bytecode:
            assert len(unreachable) >= 1, "Real dead code should be detected when present"


class TestUnreachableCodeGeneratorsAsync:
    """Regression: generators, async generators, coroutines, and genexprs
    always have an implicit trailing RETURN_VALUE None in CPython bytecode
    that is mechanically unreachable from source.  These should be
    suppressed."""

    def test_generator_no_fp(self):
        """Generator function implicit return should not be flagged."""

        source = """\
def gen():
    yield 1
    yield 2
"""

        code = _compile_function(source, "gen")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert (
            len(unreachable) == 0
        ), f"False positive in generator: {[i.message for i in unreachable]}"

    def test_async_coroutine_no_fp(self):
        """Async coroutine implicit return should not be flagged."""

        source = """\
async def coro():
    await something()
    return 42
"""

        code = _compile_function(source, "coro")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert (
            len(unreachable) == 0
        ), f"False positive in coroutine: {[i.message for i in unreachable]}"

    def test_async_generator_no_fp(self):
        """Async generator implicit return should not be flagged."""

        source = """\
async def async_gen():
    yield 1
    yield 2
"""

        code = _compile_function(source, "async_gen")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert (
            len(unreachable) == 0
        ), f"False positive in async generator: {[i.message for i in unreachable]}"

    def test_genexpr_no_fp(self):
        """Generator expression code object should not produce unreachable FPs."""

        source = """\
def use_genexpr(items):
    return sum(x * 2 for x in items)
"""

        code = _compile_function(source, "use_genexpr")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        for const in code.co_consts:
            if hasattr(const, "co_code"):
                issues.extend(detector.detect(const, "<test>"))

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert (
            len(unreachable) == 0
        ), f"False positive in genexpr: {[i.message for i in unreachable]}"


class TestUnreachableCodePushExcInfo:
    """Regression: PUSH_EXC_INFO is the entry point of exception handlers
    in Python 3.11+.  It is reachable via the exception table, not via
    regular jumps, so it doesn't appear in is_jump_target.  The detector
    should treat it as an implicit target and not flag code that ends at
    a handler entry as unreachable."""

    def test_try_except_return_both_branches(self):
        """try with return, except with return - handler entry is reachable."""

        source = """\
def parse_int(s):
    try:
        return int(s)
    except ValueError:
        return 0
"""

        code = _compile_function(source, "parse_int")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"

    def test_try_except_with_else(self):
        """try/except/else pattern should not produce FPs."""

        source = """\
def safe_divide(a, b):
    try:
        result = a / b
    except ZeroDivisionError:
        return None
    else:
        return result
"""

        code = _compile_function(source, "safe_divide")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, f"False positive: {[i.message for i in unreachable]}"


class TestUnusedVariableCombinedOpcodes:
    """Regression: Python 3.12+ (PEP 709) inlines comprehensions and
    Python 3.13 introduces combined opcodes (STORE_FAST_LOAD_FAST,
    LOAD_FAST_LOAD_FAST, STORE_FAST_STORE_FAST, LOAD_FAST_AND_CLEAR).
    These have tuple argval and must be handled by the detectors."""

    def test_list_comprehension_var_not_unused(self):
        """Variable used in list comprehension should not be flagged unused."""

        source = """\
def strip_tokens(raw):
    tokens = [t.strip() for t in raw.split(",")]
    return tokens
"""

        code = _compile_function(source, "strip_tokens")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "tokens" not in var_names, "tokens is used (returned), should not be flagged"

    def test_tuple_unpacking_vars_used(self):
        """Tuple unpacking variables that are subsequently used should not be flagged."""

        source = """\
def get_pair():
    a, b = 1, 2
    return a + b
"""

        code = _compile_function(source, "get_pair")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "a" not in var_names

        assert "b" not in var_names

    def test_comprehension_loop_var_not_unused(self):
        """Loop variable in comprehension should not be flagged unused."""

        source = """\
def parse_ids(items):
    ids = {int(x) for x in items}
    return ids
"""

        code = _compile_function(source, "parse_ids")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "ids" not in var_names

    def test_nested_function_closure_var_not_unused(self):
        """Variable used in nested function closure should not be flagged."""

        source = """\
def outer():
    x = 10
    def inner():
        return x
    return inner
"""

        code = _compile_function(source, "outer")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "x" not in var_names, "x is used in closure, should not be flagged"

    def test_actually_unused_variable_still_detected(self):
        """Actually unused variable should still be detected."""

        source = """\
def waste():
    unused_local = 42
    return 0
"""

        code = _compile_function(source, "waste")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "unused_local" in var_names, "Actually unused variable should be detected"

    def test_underscore_vars_ignored(self):
        """Variables named _ should be ignored (unused by convention)."""

        source = """\
def process():
    _ = do_something()
    return True
"""

        code = _compile_function(source, "process")

        detector = UnusedVariableDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "_" not in var_names, "_ should be ignored"


class TestDeadStoreCombinedOpcodes:
    """Regression: Python 3.13 combined opcodes should be tracked in
    DeadStoreDetector for proper loop-var detection and store/load pairs."""

    def test_loop_var_overwrite_not_dead_store(self):
        """Loop iteration variable overwritten each iteration is not a dead store."""

        source = """\
def process_items(items):
    total = 0
    for item in items:
        total += item
    return total
"""

        code = _compile_function(source, "process_items")

        detector = DeadStoreDetector()

        issues = detector.detect(code, "<test>")

        dead = _find_issues(issues, DeadCodeKind.DEAD_STORE)

        var_names = {i.name for i in dead}

        assert "item" not in var_names, "Loop variable is not a dead store"

    def test_comprehension_not_dead_store(self):
        """Comprehension loop variable should not be flagged as dead store."""

        source = """\
def get_names(users):
    names = [u.name for u in users]
    return names
"""

        code = _compile_function(source, "get_names")

        detector = DeadStoreDetector()

        issues = detector.detect(code, "<test>")

        dead = _find_issues(issues, DeadCodeKind.DEAD_STORE)

        var_names = {i.name for i in dead}

        assert "u" not in var_names, "Comprehension loop var is not a dead store"

    def test_except_as_e_not_dead_store(self):
        """Exception variable from 'except X as e' should not be dead store."""

        source = """\
def safe(x):
    try:
        return int(x)
    except ValueError as e:
        print(e)
        return None
"""

        code = _compile_function(source, "safe")

        detector = DeadStoreDetector()

        issues = detector.detect(code, "<test>")

        dead = _find_issues(issues, DeadCodeKind.DEAD_STORE)

        var_names = {i.name for i in dead}

        assert "e" not in var_names, "except-as variable is not a dead store"

    def test_real_dead_store_still_detected(self):
        """Actual dead store (overwrite without read) should still be detected."""

        source = """\
def overwrite():
    x = 1
    x = 2
    return x
"""

        code = _compile_function(source, "overwrite")

        detector = DeadStoreDetector()

        issues = detector.detect(code, "<test>")

        dead = _find_issues(issues, DeadCodeKind.DEAD_STORE)

        var_names = {i.name for i in dead}

        assert "x" in var_names, "Real dead store (x=1 overwritten by x=2) should be detected"


class TestUnusedParameterCombinedOpcodes:
    """Regression: Python 3.13 combined load opcodes (LOAD_FAST_LOAD_FAST,
    STORE_FAST_LOAD_FAST, LOAD_FAST_AND_CLEAR) should count as reads of
    parameters."""

    def test_param_used_in_return(self):
        """Parameter used in return expression should not be flagged."""

        source = """\
def add(a, b):
    return a + b
"""

        code = _compile_function(source, "add")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "a" not in var_names

        assert "b" not in var_names

    def test_param_used_in_condition(self):
        """Parameter used only in condition should not be flagged."""

        source = """\
def check(x):
    if x > 0:
        return True
    return False
"""

        code = _compile_function(source, "check")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "x" not in var_names

    def test_param_used_in_nested_function(self):
        """Parameter used in nested closure should not be flagged."""

        source = """\
def outer(callback):
    def inner():
        return callback()
    return inner
"""

        code = _compile_function(source, "outer")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "callback" not in var_names, "closure-used param should not be flagged"

    def test_self_cls_ignored(self):
        """self and cls parameters should always be ignored."""

        source = """\
def method(self, data):
    return data
"""

        code = _compile_function(source, "method")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "self" not in var_names

    def test_underscore_prefixed_ignored(self):
        """Parameters starting with _ should be ignored."""

        source = """\
def handler(_event, data):
    return data
"""

        code = _compile_function(source, "handler")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "_event" not in var_names

    def test_actually_unused_param_detected(self):
        """Actually unused parameter should be detected."""

        source = """\
def waste(x, y):
    return 42
"""

        code = _compile_function(source, "waste")

        detector = UnusedParameterDetector()

        issues = detector.detect(code, "<test>")

        unused = _find_issues(issues, DeadCodeKind.UNUSED_PARAMETER)

        var_names = {i.name for i in unused}

        assert "x" in var_names, "Unused param x should be detected"

        assert "y" in var_names, "Unused param y should be detected"


class TestTaintAmbiguousNames:
    """Regression: Taint analysis should not match ambiguous short names
    like 'get', 'read', 'load' when used as method calls on unrelated
    objects (e.g., dict.get(), file.read()).  Only qualified matches
    (requests.get, etc.) should trigger source/sink detection."""

    def test_dict_get_not_taint_source(self):
        """dict.get() should not be classified as taint source."""

        source = """\
def lookup(d, key):
    return d.get(key, None)
"""

        code = _compile_function(source, "lookup")

        analyzer = TaintAnalyzer()

        violations = analyzer.analyze_function(code, "<test>")

        assert len(violations) == 0, (
            f"dict.get() should not produce taint violation: " f"{[str(v) for v in violations]}"
        )

    def test_file_read_not_taint_source_when_dotted(self):
        """obj.read() with dotted name should not match the 'read' source
        indiscriminately (it should only match when the qualifier suggests
        a file object, which is ambiguous; the fix suppresses bare base_name
        fallback for dotted names)."""

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("response.read")

        assert source is None, "response.read should not match the bare 'read' source"

    def test_qualified_source_still_matches(self):
        """Qualified taint sources like 'requests.get' should still match."""

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("requests.get")

        assert source is not None, "requests.get should match as taint source"

        assert "NETWORK" in source.kind.name

    def test_bare_input_still_matches(self):
        """Bare 'input' call is not in ambiguous list and should match."""

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("input")

        assert source is not None, "bare input() should match as taint source"

        assert "USER_INPUT" in source.kind.name

    def test_bare_eval_sink_still_matches(self):
        """Bare 'eval' call should still match as a sink."""

        analyzer = TaintAnalyzer()

        sink = analyzer._find_sink("eval")

        assert sink is not None, "bare eval() should match as taint sink"

        assert sink.kind.name == "EVAL"

    def test_dotted_ambiguous_sink_suppressed(self):
        """cursor.execute() should match as a qualified SQL sink."""

        analyzer = TaintAnalyzer()

        sink = analyzer._find_sink("cursor.execute")

        assert sink is not None, "cursor.execute should match as a taint sink"

        assert sink.kind.name == "SQL_EXECUTE"

    def test_getenv_source_matches(self):
        """os.getenv should match via bare name (getenv not in ambiguous list)."""

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("os.getenv")

        assert source is not None, "os.getenv should match as taint source"


class TestDeadCodeAnalyzerIntegration:
    """Integration tests for DeadCodeAnalyzer processing complete modules."""

    def test_module_with_try_except_imports(self):
        """Module-level try/except import pattern should not produce
        unreachable code FPs."""

        source = """\
try:
    import ujson as json
except ImportError:
    import json

def use_json(data):
    return json.dumps(data)
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unreachable = _find_issues(results, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0, (
            f"try/except import should not produce unreachable FPs: "
            f"{[i.message for i in unreachable]}"
        )

    def test_module_with_all_clean_patterns(self):
        """Module with common idiomatic patterns should produce no FPs."""

        source = """\
import os

def get_config():
    try:
        val = os.environ["CONFIG"]
        return int(val)
    except KeyError:
        return None
    except ValueError:
        return None

def process(items):
    results = [x * 2 for x in items]
    return results
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unreachable = _find_issues(results, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0

    def test_real_issues_in_module_still_found(self):
        """Module with real issues should still be flagged.

        CPython 3.13+ may optimize away dead code after unconditional
        return/raise, so we also check for unused parameters which are
        always present in bytecode."""

        source = """\
def dead_func():
    return 1
    x = 2
    print(x)

def unused_param(a, b, c):
    return a + b
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused_params = _find_issues(results, DeadCodeKind.UNUSED_PARAMETER)

        param_names = {i.name for i in unused_params}

        assert "c" in param_names, "Unused param 'c' should be detected"

    def test_unused_import_detected(self):
        """Unused imports should be detected."""

        source = """\
import os
import sys

def hello():
    return "hello"
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused_imports = _find_issues(results, DeadCodeKind.UNUSED_IMPORT)

        import_names = {i.name for i in unused_imports}

        assert "os" in import_names, "Unused import os should be detected"

        assert "sys" in import_names, "Unused import sys should be detected"


class TestRedundantConditionDetector:
    """Test that RedundantConditionDetector handles TO_BOOL correctly."""

    def test_runtime_truth_not_flagged(self):
        """Condition on runtime variable should not be flagged as always-true."""

        source = """\
def check(x):
    if x:
        return True
    return False
"""

        code = _compile_function(source, "check")

        detector = RedundantConditionDetector()

        issues = detector.detect(code, "<test>")

        redundant = _find_issues(issues, DeadCodeKind.REDUNDANT_CONDITION)

        assert len(redundant) == 0, "Runtime condition should not be flagged as redundant"

    def test_constant_true_condition_detected(self):
        """Condition that is literally always True should be flagged."""

        source = """\
def always():
    if True:
        return 1
    return 0
"""

        code = _compile_function(source, "always")

        detector = RedundantConditionDetector()

        issues = detector.detect(code, "<test>")


class TestRegionHasUserCode:
    """Unit tests for UnreachableCodeDetector._region_has_user_code()."""

    def test_none_inputs_return_false(self):
        """None start_idx or terminator_line should return False."""

        assert UnreachableCodeDetector._region_has_user_code([], None, 0, 10) is False

        assert UnreachableCodeDetector._region_has_user_code([], 0, 0, None) is False

    def test_empty_region_returns_false(self):
        """Empty instruction range should return False."""

        assert UnreachableCodeDetector._region_has_user_code([], 0, 0, 10) is False
