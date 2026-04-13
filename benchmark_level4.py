"""
Level 4 Benchmark Test for PySyMex
The Math Wall - Non-Linear Math & Cryptography

Tests solver bottlenecks with non-linear arithmetic and bit-level mixing.
"""

def level4_simple_hash(input_val: int) -> int:
    """
    Simplified hashing algorithm with multiplication and bit operations.
    Tests non-linear arithmetic.
    """
    # Simple hash: multiply by prime, XOR with constant, add shift
    hash_val = (input_val * 31) ^ 0xDEADBEEF
    hash_val = hash_val + (hash_val << 3)
    hash_val = hash_val ^ (hash_val >> 5)

    if hash_val == 12345678:
        assert True, "Hash collision found!"
        return hash_val
    return hash_val


def level4_crc_like(data: int) -> int:
    """
    CRC-like calculation with bit operations.
    Tests bit-level constraint solving.
    """
    crc = data ^ 0xFFFFFFFF
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc = crc >> 1

    if crc == 0x12345678:
        assert True, "CRC target reached!"
        return crc
    return crc


def level4_nonlinear_equation(x: int, y: int) -> int:
    """
    Non-linear equation: x^2 + y^2 = target
    Tests quadratic constraint solving.
    """
    result = x * x + y * y

    if result == 1000:
        assert True, "Nonlinear equation solved!"
        return result
    return result


def level4_multiplicative_inverse(x: int) -> int:
    """
    Find multiplicative inverse modulo prime.
    Tests modular arithmetic constraints.
    """
    prime = 101
    # Find y such that (x * y) % prime == 1
    for y in range(1, prime):
        if (x * y) % prime == 1:
            if y == 42:
                assert True, "Inverse found!"
                return y
    return 0
