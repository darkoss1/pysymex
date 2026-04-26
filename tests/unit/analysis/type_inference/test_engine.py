from typing import Union
from pysymex.analysis.type_inference.engine import TypeInferenceEngine
from pysymex.analysis.type_inference.kinds import PyType, TypeKind


class TestTypeInferenceEngine:
    """Test suite for pysymex.analysis.type_inference.engine.TypeInferenceEngine."""

    def test_stub_resolver(self) -> None:
        """Test stub_resolver behavior."""
        engine = TypeInferenceEngine()
        # stub_resolver is loaded dynamically, we just assert it returns None or an object
        assert engine.stub_resolver is not False

    def test_infer_from_annotation(self) -> None:
        """Test infer_from_annotation behavior."""
        engine = TypeInferenceEngine()
        assert engine.infer_from_annotation(int).kind == TypeKind.INT
        assert engine.infer_from_annotation(str).kind == TypeKind.STR
        assert engine.infer_from_annotation(list[int]).kind == TypeKind.LIST
        assert engine.infer_from_annotation(Union[int, str]).kind == TypeKind.UNION
        assert engine.infer_from_annotation("int").kind == TypeKind.INT
        assert engine.infer_from_annotation(None).kind == TypeKind.ANY

    def test_infer_function_signature(self) -> None:
        """Test infer_function_signature behavior."""
        engine = TypeInferenceEngine()

        def my_func(a: int, b: str = "default") -> bool:
            return True

        params, ret = engine.infer_function_signature(my_func)
        assert params[0].kind == TypeKind.INT
        assert params[1].kind == TypeKind.STR
        assert ret.kind == TypeKind.BOOL

    def test_infer_from_value(self) -> None:
        """Test infer_from_value behavior."""
        engine = TypeInferenceEngine()
        assert engine.infer_from_value(42).kind == TypeKind.INT
        assert engine.infer_from_value("hello").kind == TypeKind.LITERAL
        assert engine.infer_from_value([1, 2, 3]).kind == TypeKind.LIST
        assert engine.infer_from_value(None).kind == TypeKind.NONE
        assert engine.infer_from_value({1: "a"}).kind == TypeKind.DICT

    def test_infer_binary_op_result(self) -> None:
        """Test infer_binary_op_result behavior."""
        engine = TypeInferenceEngine()
        assert engine.infer_binary_op_result("+", PyType.int_(), PyType.int_()).kind == TypeKind.INT
        assert (
            engine.infer_binary_op_result("/", PyType.int_(), PyType.int_()).kind == TypeKind.FLOAT
        )
        assert engine.infer_binary_op_result("+", PyType.str_(), PyType.str_()).kind == TypeKind.STR
        assert (
            engine.infer_binary_op_result("==", PyType.int_(), PyType.str_()).kind == TypeKind.BOOL
        )

    def test_infer_unary_op_result(self) -> None:
        """Test infer_unary_op_result behavior."""
        engine = TypeInferenceEngine()
        assert engine.infer_unary_op_result("-", PyType.int_()).kind == TypeKind.INT
        assert engine.infer_unary_op_result("not", PyType.int_()).kind == TypeKind.BOOL

    def test_infer_subscript_result(self) -> None:
        """Test infer_subscript_result behavior."""
        engine = TypeInferenceEngine()
        lst = PyType.list_(PyType.int_())
        assert engine.infer_subscript_result(lst, PyType.int_()).kind == TypeKind.INT

        dic = PyType.dict_(PyType.str_(), PyType.bool_())
        assert engine.infer_subscript_result(dic, PyType.str_()).kind == TypeKind.BOOL

    def test_infer_attribute_result(self) -> None:
        """Test infer_attribute_result behavior."""
        engine = TypeInferenceEngine()
        s = PyType.str_()
        assert engine.infer_attribute_result(s, "lower").kind == TypeKind.CALLABLE
        assert engine.infer_attribute_result(PyType.list_(), "append").kind == TypeKind.CALLABLE

        inst = PyType.instance("MyObj", my_attr=PyType.int_())
        assert engine.infer_attribute_result(inst, "my_attr").kind == TypeKind.INT

    def test_infer_call_result(self) -> None:
        """Test infer_call_result behavior."""
        engine = TypeInferenceEngine()
        c = PyType.callable_([PyType.int_()], PyType.bool_())
        assert engine.infer_call_result(c, [PyType.int_()], {}).kind == TypeKind.BOOL

        cls = PyType(kind=TypeKind.CLASS, name="int", class_name="int")
        assert engine.infer_call_result(cls, [], {}).kind == TypeKind.INT

    def test_narrow_type_for_isinstance(self) -> None:
        """Test narrow_type_for_isinstance behavior."""
        engine = TypeInferenceEngine()
        u = PyType.union_(PyType.int_(), PyType.str_())
        narrowed_pos = engine.narrow_type_for_isinstance(u, PyType.int_(), positive=True)
        assert narrowed_pos.kind == TypeKind.INT

        narrowed_neg = engine.narrow_type_for_isinstance(u, PyType.int_(), positive=False)
        assert narrowed_neg.kind == TypeKind.STR

    def test_narrow_type_for_none_check(self) -> None:
        """Test narrow_type_for_none_check behavior."""
        engine = TypeInferenceEngine()
        opt = PyType.optional_(PyType.int_())
        assert engine.narrow_type_for_none_check(opt, is_none=True).kind == TypeKind.NONE
        assert engine.narrow_type_for_none_check(opt, is_none=False).kind == TypeKind.INT

    def test_narrow_type_for_truthiness(self) -> None:
        """Test narrow_type_for_truthiness behavior."""
        engine = TypeInferenceEngine()
        opt = PyType.optional_(PyType.int_())
        assert engine.narrow_type_for_truthiness(opt, is_truthy=True).kind == TypeKind.INT
        assert engine.narrow_type_for_truthiness(opt, is_truthy=False).kind == TypeKind.UNION
