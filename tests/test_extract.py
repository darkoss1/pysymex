import inspect

def extract_init_params(func_obj: object) -> list:
    """
    Extract __init__ parameters from a function object.
    """
    code_obj = getattr(func_obj, "__code__", None)
    if not code_obj or not hasattr(code_obj, "co_varnames"):
        return []
    
    params = []
    arg_count = getattr(code_obj, "co_argcount", 0)
    varnames = code_obj.co_varnames[:arg_count]
    defaults = getattr(func_obj, "__defaults__", ()) or ()
    
    default_offset = arg_count - len(defaults)
    for i, name in enumerate(varnames):
        is_self = i == 0 and name in ("self", "cls")
        has_default = i >= default_offset
        default = defaults[i - default_offset] if has_default else None
        params.append((name, is_self, has_default, default))
    return params

def sample_func(a, b=2, c=3):
    pass

class TestClass:
    def __init__(self, x, y=4):
        pass



def test_extract_init_params_function():
    params = extract_init_params(sample_func)
    assert params == [
        ("a", False, False, None),
        ("b", False, True, 2),
        ("c", False, True, 3),
    ]


def test_extract_init_params_class_init():
    params = extract_init_params(TestClass.__init__)
    assert params == [
        ("self", True, False, None),
        ("x", False, False, None),
        ("y", False, True, 4),
    ]
