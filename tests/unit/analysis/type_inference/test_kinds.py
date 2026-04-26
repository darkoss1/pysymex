from pysymex.analysis.type_inference.kinds import TypeKind, PyType


class TestTypeKind:
    """Test suite for pysymex.analysis.type_inference.kinds.TypeKind."""

    def test_int_type(self) -> None:
        """Test int_type behavior."""
        t = TypeKind.int_type()
        assert t.kind == TypeKind.INT

    def test_str_type(self) -> None:
        """Test str_type behavior."""
        t = TypeKind.str_type()
        assert t.kind == TypeKind.STR

    def test_bool_type(self) -> None:
        """Test bool_type behavior."""
        t = TypeKind.bool_type()
        assert t.kind == TypeKind.BOOL

    def test_float_type(self) -> None:
        """Test float_type behavior."""
        t = TypeKind.float_type()
        assert t.kind == TypeKind.FLOAT

    def test_list_type(self) -> None:
        """Test list_type behavior."""
        t = TypeKind.list_type(PyType.int_())
        assert t.kind == TypeKind.LIST
        assert t.params[0].kind == TypeKind.INT

    def test_dict_type(self) -> None:
        """Test dict_type behavior."""
        t = TypeKind.dict_type(PyType.str_(), PyType.int_())
        assert t.kind == TypeKind.DICT
        assert t.params[0].kind == TypeKind.STR
        assert t.params[1].kind == TypeKind.INT

    def test_tuple_type(self) -> None:
        """Test tuple_type behavior."""
        t = TypeKind.tuple_type(PyType.int_(), PyType.str_())
        assert t.kind == TypeKind.TUPLE
        assert len(t.params) == 2

    def test_set_type(self) -> None:
        """Test set_type behavior."""
        t = TypeKind.set_type(PyType.int_())
        assert t.kind == TypeKind.SET

    def test_none_type(self) -> None:
        """Test none_type behavior."""
        t = TypeKind.none_type()
        assert t.kind == TypeKind.NONE

    def test_int_(self) -> None:
        """Test int_ behavior."""
        assert TypeKind.int_().kind == TypeKind.INT

    def test_str_(self) -> None:
        """Test str_ behavior."""
        assert TypeKind.str_().kind == TypeKind.STR

    def test_bool_(self) -> None:
        """Test bool_ behavior."""
        assert TypeKind.bool_().kind == TypeKind.BOOL

    def test_float_(self) -> None:
        """Test float_ behavior."""
        assert TypeKind.float_().kind == TypeKind.FLOAT

    def test_list_(self) -> None:
        """Test list_ behavior."""
        assert TypeKind.list_().kind == TypeKind.LIST

    def test_dict_(self) -> None:
        """Test dict_ behavior."""
        assert TypeKind.dict_().kind == TypeKind.DICT

    def test_tuple_(self) -> None:
        """Test tuple_ behavior."""
        assert TypeKind.tuple_().kind == TypeKind.TUPLE

    def test_set_(self) -> None:
        """Test set_ behavior."""
        assert TypeKind.set_().kind == TypeKind.SET

    def test_none(self) -> None:
        """Test none behavior."""
        assert TypeKind.none().kind == TypeKind.NONE


class TestPyType:
    """Test suite for pysymex.analysis.type_inference.kinds.PyType."""

    def test_none(self) -> None:
        """Test none behavior."""
        assert PyType.none().kind == TypeKind.NONE

    def test_none_type(self) -> None:
        """Test none_type behavior."""
        assert PyType.none_type().kind == TypeKind.NONE

    def test_bool_(self) -> None:
        """Test bool_ behavior."""
        assert PyType.bool_().kind == TypeKind.BOOL

    def test_int_(self) -> None:
        """Test int_ behavior."""
        assert PyType.int_().kind == TypeKind.INT

    def test_float_(self) -> None:
        """Test float_ behavior."""
        assert PyType.float_().kind == TypeKind.FLOAT

    def test_str_(self) -> None:
        """Test str_ behavior."""
        assert PyType.str_().kind == TypeKind.STR

    def test_bytes_(self) -> None:
        """Test bytes_ behavior."""
        assert PyType.bytes_().kind == TypeKind.BYTES

    def test_list_(self) -> None:
        """Test list_ behavior."""
        assert PyType.list_().kind == TypeKind.LIST

    def test_dict_(self) -> None:
        """Test dict_ behavior."""
        assert PyType.dict_().kind == TypeKind.DICT

    def test_defaultdict_(self) -> None:
        """Test defaultdict_ behavior."""
        assert PyType.defaultdict_().kind == TypeKind.DEFAULTDICT

    def test_set_(self) -> None:
        """Test set_ behavior."""
        assert PyType.set_().kind == TypeKind.SET

    def test_tuple_(self) -> None:
        """Test tuple_ behavior."""
        assert PyType.tuple_().kind == TypeKind.TUPLE

    def test_deque_(self) -> None:
        """Test deque_ behavior."""
        assert PyType.deque_().kind == TypeKind.DEQUE

    def test_union_(self) -> None:
        """Test union_ behavior."""
        u = PyType.union_(PyType.int_(), PyType.str_())
        assert u.kind == TypeKind.UNION
        assert len(u.union_members) == 2
        assert PyType.union_(PyType.int_(), PyType.int_()).kind == TypeKind.INT

    def test_optional_(self) -> None:
        """Test optional_ behavior."""
        o = PyType.optional_(PyType.int_())
        assert o.kind == TypeKind.UNION
        assert any(m.kind == TypeKind.NONE for m in o.union_members)

    def test_literal_(self) -> None:
        """Test literal_ behavior."""
        lit = PyType.literal_("a", "b")
        assert lit.kind == TypeKind.LITERAL
        assert "a" in lit.literal_values

    def test_any_(self) -> None:
        """Test any_ behavior."""
        assert PyType.any_().kind == TypeKind.ANY

    def test_unknown(self) -> None:
        """Test unknown behavior."""
        assert PyType.unknown().kind == TypeKind.UNKNOWN

    def test_bottom(self) -> None:
        """Test bottom behavior."""
        assert PyType.bottom().kind == TypeKind.BOTTOM

    def test_bytes_type(self) -> None:
        """Test bytes_type behavior."""
        assert PyType.bytes_type().kind == TypeKind.BYTES

    def test_is_optional(self) -> None:
        """Test is_optional behavior."""
        assert PyType.optional_(PyType.int_()).is_optional() is True
        assert PyType.int_().is_optional() is False
        assert PyType.none().is_optional() is True

    def test_instance(self) -> None:
        """Test instance behavior."""
        inst = PyType.instance("MyClass")
        assert inst.kind == TypeKind.INSTANCE
        assert inst.class_name == "MyClass"

    def test_callable_(self) -> None:
        """Test callable_ behavior."""
        c = PyType.callable_([PyType.int_()], PyType.str_())
        assert c.kind == TypeKind.CALLABLE
        assert c.get_return_type().kind == TypeKind.STR

    def test_is_numeric(self) -> None:
        """Test is_numeric behavior."""
        assert PyType.int_().is_numeric() is True
        assert PyType.str_().is_numeric() is False

    def test_is_collection(self) -> None:
        """Test is_collection behavior."""
        assert PyType.list_().is_collection() is True
        assert PyType.int_().is_collection() is False

    def test_is_mapping(self) -> None:
        """Test is_mapping behavior."""
        assert PyType.dict_().is_mapping() is True
        assert PyType.list_().is_mapping() is False

    def test_is_sequence(self) -> None:
        """Test is_sequence behavior."""
        assert PyType.list_().is_sequence() is True
        assert PyType.str_().is_sequence() is True

    def test_is_subscriptable(self) -> None:
        """Test is_subscriptable behavior."""
        assert PyType.dict_().is_subscriptable() is True
        assert PyType.int_().is_subscriptable() is False

    def test_is_nullable(self) -> None:
        """Test is_nullable behavior."""
        assert PyType.none().is_nullable() is True
        assert PyType.optional_(PyType.int_()).is_nullable() is True
        assert PyType.int_().is_nullable() is False

    def test_is_definitely_not_none(self) -> None:
        """Test is_definitely_not_none behavior."""
        assert PyType.int_().is_definitely_not_none() is True
        assert PyType.none().is_definitely_not_none() is False

    def test_get_element_type(self) -> None:
        """Test get_element_type behavior."""
        assert PyType.list_(PyType.int_()).get_element_type().kind == TypeKind.INT
        assert PyType.list_().get_element_type().kind == TypeKind.ANY

    def test_get_key_type(self) -> None:
        """Test get_key_type behavior."""
        d = PyType.dict_(PyType.str_(), PyType.int_())
        assert d.get_key_type().kind == TypeKind.STR

    def test_get_value_type(self) -> None:
        """Test get_value_type behavior."""
        d = PyType.dict_(PyType.str_(), PyType.int_())
        assert d.get_value_type().kind == TypeKind.INT

    def test_get_return_type(self) -> None:
        """Test get_return_type behavior."""
        c = PyType.callable_([], PyType.bool_())
        assert c.get_return_type().kind == TypeKind.BOOL

    def test_without_none(self) -> None:
        """Test without_none behavior."""
        assert PyType.none().without_none().kind == TypeKind.BOTTOM
        opt = PyType.optional_(PyType.int_())
        assert opt.without_none().kind == TypeKind.INT

    def test_join(self) -> None:
        """Test join behavior."""
        j = PyType.int_().join(PyType.str_())
        assert j.kind == TypeKind.UNION
        assert PyType.int_().join(PyType.int_()).kind == TypeKind.INT
        assert PyType.list_(PyType.int_()).join(PyType.list_(PyType.str_())).kind == TypeKind.LIST

    def test_meet(self) -> None:
        """Test meet behavior."""
        assert PyType.int_().meet(PyType.int_()).kind == TypeKind.INT
        assert PyType.int_().meet(PyType.str_()).kind == TypeKind.BOTTOM
        assert PyType.int_().meet(PyType.any_()).kind == TypeKind.INT

    def test_is_subtype_of(self) -> None:
        """Test is_subtype_of behavior."""
        assert PyType.int_().is_subtype_of(PyType.int_()) is True
        assert PyType.int_().is_subtype_of(PyType.float_()) is True
        assert PyType.int_().is_subtype_of(PyType.str_()) is False
        assert PyType.int_().is_subtype_of(PyType.any_()) is True
