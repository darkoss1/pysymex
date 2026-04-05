import pytest
import dis
import ast
from pysymex.analysis.exceptions.analysis import ExceptionAnalyzer, ExceptionASTAnalyzer
from pysymex.analysis.exceptions.handler import ExceptionHandlerAnalyzer

def test_stage2_ast_bare_exception_swallow():
    """
    Adversarial test demonstrating that the AST exception analyzer fails to flag
    a bare 'except:' if the block contains anything other than a literal `pass` or string,
    allowing severe exception swallowing to go undetected.
    """
    source = '''
def bad_func():
    try:
        1 / 0
    except:
        x = 1  # Not a pass, not a string constant. Just an assignment.
'''
    analyzer = ExceptionASTAnalyzer("test.py")
    warnings = analyzer.analyze(source)
    
    # We expect a BARE_EXCEPT warning, but do we get an EXCEPTION_NOT_LOGGED warning?
    swallowed_warnings = [w for w in warnings if w.kind.name == "EXCEPTION_NOT_LOGGED"]
    
    # If the logic is unsound, it will NOT flag this as swallowed.
    assert len(swallowed_warnings) > 0, "AST Analyzer failed to detect swallowed exception due to assignment!"

def test_stage3_uncaught_exception_analyzer_leak():
    """
    Adversarial test demonstrating that UncaughtExceptionAnalyzer crashes or fails
    when encountering standard Python 3.11+ bytecode for exception handling.
    """
    def target_func():
        try:
            x = 1 / 0
        except ZeroDivisionError:
            pass
            
    code = target_func.__code__
    analyzer = ExceptionAnalyzer()
    
    # Analyze the bytecode
    potential_exceptions = analyzer.get_potential_exceptions(code)
    
    # If the bytecode analysis correctly models Python 3.11+ PUSH_EXC_INFO and CHECK_EXC_MATCH,
    # ZeroDivisionError should NOT leak out of the function.
    # However, the logic for `_build_protected_ranges` is highly suspect.
    
    # We assert that the vulnerability exists: ZeroDivisionError incorrectly leaks out.
    leaked = any("ZeroDivisionError" in excs for excs in potential_exceptions.values())
    assert leaked is False, "UncaughtExceptionAnalyzer leaked a caught exception!"

def test_stage4_handler_analyzer_ast_recursion_limit():
    """
    Adversarial test demonstrating that ExceptionHandlerAnalyzer's AST parser
    can be bypassed or corrupted by deep nesting or specific AST structures.
    """
    analyzer = ExceptionHandlerAnalyzer()
    source = '''
def func():
    try:
        try:
            pass
        except Exception:
            pass
    except Exception as e:
        pass
    finally:
        pass
'''
    # The AST visit logic in `_visit_ast` does:
    # `for child in ast.walk(node): if isinstance(child, ast.Try): ...`
    # Wait, ast.walk() is flat! It doesn't track depth natively.
    # But it passes `nesting_depth=depth`, which is hardcoded to 0 in `_visit_ast`.
    # This means nested exception handlers will ALWAYS have a depth of 0!
    
    handlers = analyzer.analyze_source(source)
    
    assert len(handlers) > 0
    # At least one handler (the inner one) should have depth > 0
    has_nested = any(h.nesting_depth > 0 for h in handlers)
    assert has_nested, "Vulnerability: nesting_depth is hardcoded to 0 for all handlers!"

if __name__ == "__main__":
    pytest.main(["-v", __file__])
