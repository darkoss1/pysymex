from pysymex.core.exceptions_analyzer import ExceptionAnalyzer
from pysymex.core.symbolic_types import SymbolicString

def test_analyze_division_crash():
    analyzer = ExceptionAnalyzer()
    sym_str = SymbolicString.symbolic("my_str")
    
    # This should crash because to_z3() returns SeqRef and it does == 0
    try:
        analyzer.analyze_division(sym_str, pc=10)
        print("No crash!")
    except Exception as e:
        print(f"Crashed with: {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_analyze_division_crash()