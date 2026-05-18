from pysymex.accel.types import CompressedBitmap


def test_compressed_bitmap_contains():
    b1 = CompressedBitmap(frozenset({1, 2, 3}))
    b2 = CompressedBitmap(frozenset({1, 2}))
    b3 = CompressedBitmap(frozenset({4}))

    assert b1.contains(b2) is True
    assert b2.contains(b1) is False
    assert b1.contains(b3) is False


def test_compressed_bitmap_intersection():
    b1 = CompressedBitmap(frozenset({1, 2, 3}))
    b2 = CompressedBitmap(frozenset({2, 3, 4}))
    b3 = b1.intersection(b2)
    assert b3.native_atoms == frozenset({2, 3})


def test_compressed_bitmap_rarest_atom():
    b1 = CompressedBitmap(frozenset({5, 2, 8}))
    assert b1.rarest_atom == 2
    b2 = CompressedBitmap(frozenset())
    assert b2.rarest_atom is None
