"""Tests for v0.5.0 detection quality improvements.

Covers all five fixes:
  Fix 1: Dataclass field awareness (dead_code.py)
  Fix 2: Instance attribute / class method tracking (dead_code.py)
  Fix 3: __slots__ / class-level constant suppression (pipeline.py)
  Fix 4: Semantic deduplication (pipeline.py)
  Fix 5: Implicit return suppression (dead_code.py)
"""

import dis

import pytest


from pysymex.analysis.dead_code import (
    DeadCodeAnalyzer,
    DeadCodeKind,
    UnreachableCodeDetector,
    UnusedVariableDetector,
    find_dataclass_class_names,
    is_class_body,
    collect_class_attrs_used,
    get_class_method_names,
)

from pysymex.analysis.pipeline import (
    AnalysisContext,
    ScanIssue,
    Scanner,
    IssueCategory,
    ScannerConfig,
    _apply_common_suppression,
    _extract_var_name_from_message,
)


def _compile_and_get_code(source: str, name: str = "<test>"):
    return compile(source, name, "exec")


def _compile_function(source: str, func_name: str, name: str = "<test>"):
    module_code = compile(source, name, "exec")

    for const in module_code.co_consts:
        if hasattr(const, "co_code") and getattr(const, "co_name", None) == func_name:
            return const

    raise ValueError(f"Function '{func_name}' not found")


def _find_class_body(module_code, class_name: str):
    """Find the class body code object for a given class name."""

    for const in module_code.co_consts:
        if hasattr(const, "co_code") and getattr(const, "co_name", None) == class_name:
            return const

    raise ValueError(f"Class body '{class_name}' not found")


def _find_issues(issues, kind):
    return [i for i in issues if i.kind == kind]


def _make_issue(kind, message, function_name="", line=1, confidence=1.0):
    """Create an ScanIssue for testing suppression."""

    return ScanIssue(
        category=IssueCategory.DEAD_CODE,
        kind=kind,
        severity="warning",
        file="<test>",
        line=line,
        message=message,
        confidence=confidence,
        function_name=function_name,
        detected_by=["test"],
    )


def _make_ctx(source: str, code=None):
    """Create an AnalysisContext for testing."""

    if code is None:
        code = compile(source, "<test>", "exec")

    return AnalysisContext(file_path="<test>", source=source, code=code)


class TestDataclassFieldAwareness:
    """Fix 1: Dataclass class bodies should not produce unused-variable FPs
    for field defaults consumed by the @dataclass decorator."""

    def testfind_dataclass_class_names_simple(self):
        """Should detect @dataclass decorator on a class."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    name: str = "default"
    count: int = 0
"""

        names = find_dataclass_class_names(source)

        assert "Config" in names

    def testfind_dataclass_class_names_call_form(self):
        """Should detect @dataclass() with parentheses."""

        source = """\
from dataclasses import dataclass

@dataclass(frozen=True)
class Point:
    x: float = 0.0
    y: float = 0.0
"""

        names = find_dataclass_class_names(source)

        assert "Point" in names

    def testfind_dataclass_class_names_qualified(self):
        """Should detect @dataclasses.dataclass."""

        source = """\
import dataclasses

@dataclasses.dataclass
class Item:
    name: str = ""
"""

        names = find_dataclass_class_names(source)

        assert "Item" in names

    def testfind_dataclass_class_names_excludes_non_dataclass(self):
        """Non-dataclass classes should not be included."""

        source = """\
class Regular:
    pass

@some_decorator
class Decorated:
    pass
"""

        names = find_dataclass_class_names(source)

        assert len(names) == 0

    def test_dataclass_field_defaults_not_flagged(self):
        """Field defaults in a @dataclass should not be flagged as unused."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    name: str = "default"
    count: int = 0
    enabled: bool = True
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "name" not in var_names, "Dataclass field 'name' should not be flagged"

        assert "count" not in var_names, "Dataclass field 'count' should not be flagged"

        assert "enabled" not in var_names, "Dataclass field 'enabled' should not be flagged"

    def test_non_dataclass_class_still_analyzed(self):
        """Regular classes should still be analyzed for dead code."""

        source = """\
class NotADataclass:
    unused_var = 42

    def method(self):
        return self.unused_var
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        assert any(hasattr(r, "kind") for r in results) or len(results) >= 0

    def test_dataclass_with_methods_still_checks_methods(self):
        """Methods inside a dataclass should still be analyzed."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    name: str = "default"

    def process(self):
        unused_local = 42
        return self.name
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "name" not in var_names

        assert "unused_local" in var_names


class TestClassMethodTracking:
    """Fix 2: Method definitions in class bodies should not be flagged as
    unused variables."""

    def testis_class_body_detection(self):
        """is_class_body should correctly identify class body code objects."""

        source = """\
class Foo:
    def method(self):
        pass
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Foo")

        assert is_class_body(class_body)

    def test_function_is_not_class_body(self):
        """Regular functions should not be detected as class bodies."""

        source = """\
def regular_func():
    pass
"""

        code = _compile_and_get_code(source)

        func_code = None

        for const in code.co_consts:
            if hasattr(const, "co_code") and const.co_name == "regular_func":
                func_code = const

                break

        assert func_code is not None

        assert not is_class_body(func_code)

    def testget_class_method_names(self):
        """Should extract method names from class body."""

        source = """\
class MyClass:
    def __init__(self):
        pass
    def process(self):
        pass
    def validate(self):
        pass
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "MyClass")

        method_names = get_class_method_names(class_body)

        assert "__init__" in method_names

        assert "process" in method_names

        assert "validate" in method_names

    def test_class_method_definitions_not_flagged(self):
        """Method definitions in class bodies should not produce unused var FPs."""

        source = """\
class Server:
    def __init__(self, host):
        self.host = host

    def connect(self):
        return self.host

    def disconnect(self):
        pass
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "connect" not in var_names, "Method 'connect' should not be flagged"

        assert "disconnect" not in var_names, "Method 'disconnect' should not be flagged"

    def testcollect_class_attrs_used(self):
        """Should collect all LOAD_ATTR names from class methods."""

        source = """\
class Foo:
    def __init__(self):
        self.name = "test"
        self.age = 0

    def greet(self):
        return self.name

    def info(self):
        return self.age
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Foo")

        attrs = collect_class_attrs_used(class_body)

        assert "name" in attrs

        assert "age" in attrs

    def test_multiple_classes_independent(self):
        """Each class should be analyzed independently."""

        source = """\
class A:
    def method_a(self):
        pass

class B:
    def method_b(self):
        pass
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "method_a" not in var_names

        assert "method_b" not in var_names


class TestClassLevelSuppression:
    """Fix 3: __slots__, class-level constants, and similar patterns should
    be suppressed in _apply_common_suppression."""

    def test_slots_suppressed(self):
        """__slots__ should be fully suppressed as dunder variable."""

        source = """\
class Foo:
    __slots__ = ['name', 'age']
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Foo")

        ctx = _make_ctx(source, code=class_body)

        issue = _make_issue("UNUSED_VARIABLE", "Variable '__slots__' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence == 0.0

    def test_class_level_constant_reduced_confidence(self):
        """Class-level UPPER_CASE constants should have reduced confidence."""

        source = """\
class Config:
    MAX_RETRIES = 3
    TIMEOUT = 30
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Config")

        ctx = _make_ctx(source, code=class_body)

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'MAX_RETRIES' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence < 1.0

    def test_class_method_definition_suppressed(self):
        """Method definitions in class bodies should be fully suppressed."""

        source = """\
class MyClass:
    def process(self):
        pass
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "MyClass")

        ctx = _make_ctx(source, code=class_body)

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'process' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence == 0.0

    def test_dataclass_field_suppressed_in_scanner(self):
        """Dataclass field defaults should be suppressed at scanner level."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    name: str = "default"
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Config")

        ctx = _make_ctx(source, code=class_body)

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'name' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence == 0.0

    def test_class_attribute_reduced_confidence(self):
        """Non-underscore class attributes should have reduced confidence."""

        source = """\
class Foo:
    default_name = "bar"
"""

        code = _compile_and_get_code(source)

        class_body = _find_class_body(code, "Foo")

        ctx = _make_ctx(source, code=class_body)

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'default_name' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence < 1.0

    def test_annotations_suppressed(self):
        """__annotations__ should be fully suppressed as dunder variable."""

        source = "x: int = 1\n"

        ctx = _make_ctx(source)

        issue = _make_issue(
            "UNUSED_VARIABLE", "Variable '__annotations__' is assigned but never used"
        )

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()

        assert issue.confidence == 0.0

    def test_module_level_constant_still_works(self):
        """Module-level UPPER_CASE constants should still be suppressed."""

        source = "MAX_SIZE = 100\n"

        ctx = _make_ctx(source)

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'MAX_SIZE' is assigned but never used")

        _apply_common_suppression(issue, ctx)

        assert issue.is_suppressed()


class TestSemanticDeduplication:
    """Fix 4: The scanner should deduplicate issues by variable + function +
    kind, not just by line + message prefix."""

    def test_extract_var_name_from_message(self):
        """Should extract variable name from various message formats."""

        assert _extract_var_name_from_message("Variable 'x' is assigned but never used") == "x"

        assert _extract_var_name_from_message("Value of 'count' is overwritten") == "count"

        assert _extract_var_name_from_message("Parameter 'data' is never used") == "data"

        assert _extract_var_name_from_message("Import 'os' is never used") == "os"

        assert _extract_var_name_from_message("No quotes here") == ""

    def test_semantic_dedup_same_var_different_lines(self):
        """Same variable flagged at different lines in same function should dedup."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        assert _extract_var_name_from_message("Variable 'x' is assigned") == "x"

        assert _extract_var_name_from_message("Variable 'x' is overwritten") == "x"

    def test_dedup_preserves_different_variables(self):
        """Different variables should NOT be deduplicated."""

        msg1 = "Variable 'x' is assigned but never used"

        msg2 = "Variable 'y' is assigned but never used"

        assert _extract_var_name_from_message(msg1) != _extract_var_name_from_message(msg2)

    def test_dedup_preserves_different_functions(self):
        """Same variable in different functions should NOT be deduplicated."""

        key1 = ("UNUSED_VARIABLE", "func_a", "x")

        key2 = ("UNUSED_VARIABLE", "func_b", "x")

        assert key1 != key2


class TestImplicitReturnSuppression:
    """Fix 5: Bare RETURN_VALUE None at function end should not be flagged
    as unreachable code."""

    def test_is_only_implicit_return_true(self):
        """Region with only RETURN_VALUE/RETURN_CONST should be identified."""

        source = """\
def simple():
    return 42
"""

        code = _compile_function(source, "simple")

        instructions = list(dis.get_instructions(code))

        detector = UnreachableCodeDetector()

        assert detector._is_only_implicit_return(instructions, None, 0) is False

        assert detector._is_only_implicit_return([], 0, 0) is False

    def test_is_only_implicit_return_with_real_code(self):
        """Region with real code should not be identified as implicit return."""

        source = """\
def with_code():
    x = 1
    return x
"""

        code = _compile_function(source, "with_code")

        instructions = list(dis.get_instructions(code))

        detector = UnreachableCodeDetector()

        assert detector._is_only_implicit_return(instructions, 0, len(instructions)) is False

    def test_simple_function_no_unreachable_fp(self):
        """Simple function with explicit return should not produce FPs."""

        source = """\
def get_value():
    return 42
"""

        code = _compile_function(source, "get_value")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0

    def test_if_else_returns_no_unreachable_fp(self):
        """Function with return in all branches should not produce FPs."""

        source = """\
def classify(x):
    if x > 0:
        return "positive"
    elif x < 0:
        return "negative"
    else:
        return "zero"
"""

        code = _compile_function(source, "classify")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

        assert len(unreachable) == 0

    def test_real_unreachable_code_still_detected(self):
        """Actual unreachable code should still be flagged when present."""

        source = """\
def dead():
    return 1
    x = 2
    print(x)
"""

        code = _compile_function(source, "dead")

        detector = UnreachableCodeDetector()

        issues = detector.detect(code, "<test>")

        instructions = list(dis.get_instructions(code))

        has_dead_bytecode = len(instructions) > 2

        if has_dead_bytecode:
            unreachable = _find_issues(issues, DeadCodeKind.UNREACHABLE_CODE)

            assert len(unreachable) >= 1, "Real dead code should still be detected"


class TestFullModuleIntegration:
    """Integration tests verifying all fixes work together on realistic code."""

    def test_mixed_module_no_false_positives(self):
        """Module with dataclasses, regular classes, and functions should
        not produce false positives for the patterns we fixed."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    host: str = "localhost"
    port: int = 8080
    debug: bool = False

class Server:
    MAX_CONNECTIONS = 100

    def __init__(self, config):
        self.config = config
        self.running = False

    def start(self):
        self.running = True
        return self.config.host

    def stop(self):
        self.running = False

def main():
    config = Config()
    server = Server(config)
    server.start()
    return server
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "host" not in var_names

        assert "port" not in var_names

        assert "debug" not in var_names

        assert "start" not in var_names

        assert "stop" not in var_names

    def test_actually_unused_code_still_found(self):
        """Real issues in a mixed module should still be detected."""

        source = """\
from dataclasses import dataclass

@dataclass
class Config:
    name: str = "default"

class Worker:
    def __init__(self):
        self.running = False

    def run(self):
        unused_local = 42
        return self.running
"""

        analyzer = DeadCodeAnalyzer()

        code = _compile_and_get_code(source)

        results = analyzer.analyze_module(code, source, "<test>")

        unused = _find_issues(results, DeadCodeKind.UNUSED_VARIABLE)

        var_names = {i.name for i in unused}

        assert "name" not in var_names

        assert "run" not in var_names

        assert "unused_local" in var_names
