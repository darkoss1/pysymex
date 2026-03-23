import sys
import pytest
from pysymex import analyze

@pytest.mark.skipif(sys.version_info < (3, 11), reason="Requires Python 3.11+")
def test_resume_opcode():
    def dummy_resume(x):
        # A simple generator triggers generator opcodes
        yield x
    
    result = analyze(dummy_resume, {"x": "int"})
    assert result.paths_explored > 0

@pytest.mark.skipif(sys.version_info < (3, 11), reason="Requires Python 3.11+")
def test_binary_slice():
    def dummy_slice(x):
        # BINARY_SLICE
        lst = [1, 2, 3]
        return lst[x:x+1]
        
    result = analyze(dummy_slice, {"x": "int"})
    assert result.paths_explored > 0

@pytest.mark.skipif(sys.version_info < (3, 11), reason="Requires Python 3.11+")
def test_kw_names():
    def dummy_kw(x):
        # KW_NAMES
        def inner(**kwargs):
            return len(kwargs)
        return inner(a=x, b=1)
        
    result = analyze(dummy_kw, {"x": "int"})
    assert result.paths_explored > 0
