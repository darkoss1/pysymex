import pysymex.core.memory.cow
import z3

class TestCowDict:
    """Test suite for pysymex.core.memory.cow.CowDict."""
    def test_hash_value(self) -> None:
        """Scenario: hash on populated dict; expected integer hash output."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert isinstance(d.hash_value(), int)

    def test_get(self) -> None:
        """Scenario: get existing key; expected associated value."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert d.get("a") == 1

    def test_keys(self) -> None:
        """Scenario: key iteration view; expected key present in keys view."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert list(d.keys()) == ["a"]

    def test_values(self) -> None:
        """Scenario: values view from single-entry dict; expected one value."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert list(d.values()) == [1]

    def test_items(self) -> None:
        """Scenario: items view from single-entry dict; expected one key/value tuple."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert list(d.items()) == [("a", 1)]

    def test_setdefault(self) -> None:
        """Scenario: absent key setdefault; expected inserted default value returned."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict()
        assert d.setdefault("x", 9) == 9

    def test_update(self) -> None:
        """Scenario: update with mapping; expected new key materialized."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        d.update({"b": 2})
        assert d["b"] == 2

    def test_pop(self) -> None:
        """Scenario: pop existing key; expected removed value returned."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert d.pop("a") == 1

    def test_cow_fork(self) -> None:
        """Scenario: CoW fork then mutate child; expected parent unchanged."""
        parent: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        child = parent.cow_fork()
        child["a"] = 2
        assert parent["a"] == 1

    def test_copy(self) -> None:
        """Scenario: copy delegates to fork; expected copied data equality."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert d.copy().to_dict() == {"a": 1}

    def test_to_dict(self) -> None:
        """Scenario: plain dict export; expected equivalent mapping."""
        d: pysymex.core.memory.cow.CowDict[str, int] = pysymex.core.memory.cow.CowDict({"a": 1})
        assert d.to_dict() == {"a": 1}


class TestCowSet:
    """Test suite for pysymex.core.memory.cow.CowSet."""
    def test_add(self) -> None:
        """Scenario: add value to set; expected membership after insertion."""
        s = pysymex.core.memory.cow.CowSet()
        s.add(3)
        assert 3 in s

    def test_discard(self) -> None:
        """Scenario: discard existing value; expected value no longer present."""
        s = pysymex.core.memory.cow.CowSet({2})
        s.discard(2)
        assert 2 not in s

    def test_hash_value(self) -> None:
        """Scenario: hash on populated set; expected integer hash output."""
        s = pysymex.core.memory.cow.CowSet({1, 2})
        assert isinstance(s.hash_value(), int)

    def test_cow_fork(self) -> None:
        """Scenario: set fork then child mutation; expected parent remains unchanged."""
        parent = pysymex.core.memory.cow.CowSet({1})
        child = parent.cow_fork()
        child.add(2)
        assert 2 not in parent

    def test_to_set(self) -> None:
        """Scenario: export to plain set; expected equivalent set members."""
        s = pysymex.core.memory.cow.CowSet({1, 2})
        assert s.to_set() == {1, 2}


class TestBranchRecord:
    """Test suite for pysymex.core.memory.cow.BranchRecord."""
    def test_initialization(self) -> None:
        """Scenario: branch record stores pc/condition/decision fields."""
        rec = pysymex.core.memory.cow.BranchRecord(1, z3.BoolVal(True), True)
        assert rec.pc == 1


class TestBranchChain:
    """Test suite for pysymex.core.memory.cow.BranchChain."""
    def test_append(self) -> None:
        """Scenario: append one record to empty chain; expected length one."""
        chain = pysymex.core.memory.cow.BranchChain.empty()
        chain = chain.append(pysymex.core.memory.cow.BranchRecord(1, z3.BoolVal(True), True))
        assert len(chain) == 1

    def test_to_list(self) -> None:
        """Scenario: convert chain with one record; expected one-item list."""
        rec = pysymex.core.memory.cow.BranchRecord(1, z3.BoolVal(True), True)
        chain = pysymex.core.memory.cow.BranchChain.empty().append(rec)
        assert chain.to_list() == [rec]

    def test_empty(self) -> None:
        """Scenario: empty chain factory; expected zero length."""
        assert len(pysymex.core.memory.cow.BranchChain.empty()) == 0


class TestConstraintChain:
    """Test suite for pysymex.core.memory.cow.ConstraintChain."""
    def test_append(self) -> None:
        """Scenario: append one constraint; expected chain length one."""
        chain = pysymex.core.memory.cow.ConstraintChain.empty().append(z3.Bool("c"))
        assert len(chain) == 1

    def test_to_list(self) -> None:
        """Scenario: materialize chain list; expected original constraint order."""
        c = z3.Bool("c")
        chain = pysymex.core.memory.cow.ConstraintChain.empty().append(c)
        assert chain.to_list() == [c]

    def test_newest(self) -> None:
        """Scenario: newest on non-empty chain; expected last appended constraint."""
        c = z3.Bool("c")
        chain = pysymex.core.memory.cow.ConstraintChain.empty().append(c)
        assert chain.newest() == c

    def test_hash_value(self) -> None:
        """Scenario: chain hash query; expected integer hash."""
        chain = pysymex.core.memory.cow.ConstraintChain.empty().append(z3.Bool("c"))
        assert isinstance(chain.hash_value(), int)

    def test_empty(self) -> None:
        """Scenario: empty chain evaluates false; expected boolean false."""
        assert bool(pysymex.core.memory.cow.ConstraintChain.empty()) is False

    def test_from_list(self) -> None:
        """Scenario: build chain from list; expected same number of constraints."""
        constraints = [z3.Bool("a"), z3.Bool("b")]
        chain = pysymex.core.memory.cow.ConstraintChain.from_list(constraints)
        assert len(chain.to_list()) == 2
