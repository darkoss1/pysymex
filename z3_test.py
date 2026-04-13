import z3
import time

s = z3.Solver()
s.set("timeout", 5000)
z3.set_param("timeout", 5000)

input_val = z3.Int('input_val')
bv_in = z3.Int2BV(input_val, 64)

# hash_val = (input_val * 31) ^ 0xDEADBEEF
mul = input_val * 31
hash_1 = z3.BV2Int(z3.Int2BV(mul, 64) ^ z3.Int2BV(z3.IntVal(0xDEADBEEF), 64), True)

# hash_val = hash_val + (hash_val << 3)
shifted = z3.BV2Int(z3.Int2BV(hash_1, 64) << z3.Int2BV(z3.IntVal(3), 64), True)
hash_2 = hash_1 + shifted

# hash_val = hash_val ^ (hash_val >> 5)
hash_3 = z3.BV2Int(z3.Int2BV(hash_2, 64) ^ (z3.Int2BV(hash_2, 64) >> z3.Int2BV(z3.IntVal(5), 64)), True)

s.add(hash_3 == 12345678)

print("Starting solver check...")
start = time.time()
res = s.check()
print(f"Result: {res} in {time.time()-start:.2f}s")
