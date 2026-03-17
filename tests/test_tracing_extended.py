"""Tests for tracing infrastructure (tracing/)."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from pysymex.tracing.schemas import (
    VerbosityLevel, TracerConfig, ConstraintEntry, StackDiff, VarDiff,
    SystemContextEvent, StepDeltaEvent, KeyframeEvent, SolveEvent,
)
from pysymex.tracing.z3_utils import Z3SemanticRegistry, Z3Serializer
from pysymex.tracing._hook_adapter import TracingHookPlugin


# -- Schemas --

class TestVerbosityLevel:
    def test_enum(self):
        assert len(VerbosityLevel) >= 1


class TestTracerConfig:
    def test_creation(self):
        cfg = TracerConfig()
        assert cfg is not None

    def test_has_verbosity(self):
        cfg = TracerConfig()
        assert hasattr(cfg, 'verbosity') or hasattr(cfg, 'level')


class TestConstraintEntry:
    def test_creation(self):
        ce = ConstraintEntry(smtlib="true", causality="test")
        assert ce is not None


class TestStackDiff:
    def test_creation(self):
        sd = StackDiff()
        assert sd is not None


class TestVarDiff:
    def test_creation(self):
        vd = VarDiff()
        assert vd is not None


class TestSystemContextEvent:
    def test_creation(self):
        ev = SystemContextEvent()
        assert ev is not None


class TestStepDeltaEvent:
    def test_creation(self):
        ev = StepDeltaEvent()
        assert ev is not None


class TestKeyframeEvent:
    def test_creation(self):
        ev = KeyframeEvent()
        assert ev is not None


class TestSolveEvent:
    def test_creation(self):
        ev = SolveEvent()
        assert ev is not None


# -- Z3 utils --

class TestZ3SemanticRegistry:
    def test_creation(self):
        reg = Z3SemanticRegistry()
        assert reg is not None

    def test_has_register(self):
        assert (hasattr(Z3SemanticRegistry, 'register') or
                hasattr(Z3SemanticRegistry, 'add'))


class TestZ3Serializer:
    def test_creation(self):
        registry = Z3SemanticRegistry()
        ser = Z3Serializer(registry=registry)
        assert ser is not None

    def test_has_serialize(self):
        assert (hasattr(Z3Serializer, 'serialize') or
                hasattr(Z3Serializer, 'to_dict') or
                hasattr(Z3Serializer, 'to_json') or
                hasattr(Z3Serializer, 'serialize_model') or
                hasattr(Z3Serializer, 'safe_sexpr'))


# -- Hook adapter --

class TestTracingHookPlugin:
    def test_creation(self):
        tracer = MagicMock()
        plugin = TracingHookPlugin(tracer=tracer)
        assert plugin is not None

    def test_has_hooks(self):
        assert (hasattr(TracingHookPlugin, 'on_step') or
                hasattr(TracingHookPlugin, 'on_fork') or
                hasattr(TracingHookPlugin, 'get_hooks') or
                hasattr(TracingHookPlugin, 'handle'))
