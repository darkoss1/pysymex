"""
Level 5 Benchmark Test for PySyMex
The Turing Tarpit - Concurrency & One-Way Functions

Tests theoretical limits - deep crypto and unbounded concurrency.
These are expected to fail or timeout.
"""

def level5_sha256_reversal(target_hash: int) -> int:
    """
    Attempt to reverse a hash-like operation.
    This is computationally intractable for SMT solvers.
    """
    # Simplified hash reversal - find input that produces target
    for x in range(1000000):
        hash_val = (x * 31 + 17) ^ 0xDEADBEEF
        if hash_val == target_hash:
            assert True, "Hash reversed!"
            return x
    return 0


def level5_aes_like_block(block: int, key: int) -> int:
    """
    Simplified AES-like block cipher.
    Finding the key from plaintext/ciphertext is intractable.
    """
    # Very simplified "encryption"
    encrypted = block ^ key
    encrypted = ((encrypted << 3) | (encrypted >> 29)) ^ 0x9E3779B9
    encrypted = encrypted + key

    if encrypted == 0x12345678:
        assert True, "Cipher broken!"
        return encrypted
    return encrypted


def level5_shared_state_race(counter: int) -> int:
    """
    Simulated race condition with shared state.
    Symbolic execution struggles with unbounded concurrency.
    """
    # Simulate two threads incrementing a counter
    # Race condition: final value depends on interleaving
    thread1_result = counter + 1
    thread2_result = counter + 1

    # Without proper synchronization, final value is non-deterministic
    if thread1_result == thread2_result and counter == 100:
        assert True, "Race condition detected!"
        return thread1_result
    return counter


def level5_infinite_loop_potential(x: int) -> int:
    """
    Loop with termination condition that depends on complex state.
    Tests if engine can prove termination.
    """
    while x > 0:
        x = x - 1
        if x == 50:
            # Potential exit point
            break

    if x == 50:
        assert True, "Loop terminated at target!"
        return x
    return x
