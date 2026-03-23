from pysymex import analyze

def test_reflective_execution():
    class Dummy:
        def __init__(self):
            self.safe_attr = 42
            self.dangerous_attr = 0
            
    def reflective_access(attr_name):
        obj = Dummy()
        return getattr(obj, attr_name, None)

    res = analyze(reflective_access, {"attr_name": "str"})
    assert res.paths_explored > 0, "Should explore paths involving reflective getattr access"
