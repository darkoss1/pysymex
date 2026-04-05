import z3

def test_extract():
    s = z3.Const('s', z3.SeqSort(z3.IntSort()))
    # `z3.Extract` takes (high, low, a) where a is BitVec
    # In pysymex/core/symbolic_types_containers.py:
    # z3.Extract(self.z3_seq, start.z3_int, length.z3_int)
    # Let's try what it actually does:
    try:
        start = z3.IntVal(0)
        length = z3.IntVal(1)
        z3.Extract(s, start, length)
        print("Success")
    except Exception as e:
        print(f"Exception: {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_extract()