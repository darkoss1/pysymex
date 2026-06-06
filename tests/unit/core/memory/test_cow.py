from pysymex.core.memory.cow.collections import CowDict, CowSet


class TestCowDict:
    """Test suite for copy-on-write dictionaries."""

    def test_hash_value(self) -> None:
        """Scenario: hash on populated dict; expected integer hash output."""
        d: CowDict[str, int] = CowDict({"a": 1})
        assert isinstance(d.hash_value(), int)

    def test_setdefault(self) -> None:
        """Scenario: absent key setdefault; expected inserted default value returned."""
        d: CowDict[str, int] = CowDict()
        assert d.setdefault("x", 9) == 9

    def test_pop(self) -> None:
        """Scenario: pop existing key; expected removed value returned."""
        d: CowDict[str, int] = CowDict({"a": 1})
        assert d.pop("a") == 1

    def test_copy(self) -> None:
        """Scenario: copy then mutate child; expected parent unchanged."""
        parent: CowDict[str, int] = CowDict({"a": 1})
        child = parent.copy()
        child["a"] = 2
        assert parent["a"] == 1

    def test_to_dict(self) -> None:
        """Scenario: plain dict export; expected equivalent mapping."""
        d: CowDict[str, int] = CowDict({"a": 1})
        assert d.to_dict() == {"a": 1}


class TestCowSet:
    """Test suite for CowSet."""

    def test_add(self) -> None:
        """Scenario: add value to set; expected membership after insertion."""
        s: CowSet[int] = CowSet()
        s.add(3)
        assert 3 in s

    def test_discard(self) -> None:
        """Scenario: discard existing value; expected value no longer present."""
        s: CowSet[int] = CowSet({2})
        s.discard(2)
        assert 2 not in s

    def test_hash_value(self) -> None:
        """Scenario: hash on populated set; expected integer hash output."""
        s = CowSet({1, 2})
        assert isinstance(s.hash_value(), int)
