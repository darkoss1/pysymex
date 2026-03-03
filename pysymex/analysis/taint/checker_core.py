"""Taint analysis core — TaintAnalyzer, TaintFlowAnalysis, TaintChecker."""

from __future__ import annotations


import dis

from typing import Any


from pysymex._compat import get_starts_line

from pysymex.analysis.flow_sensitive import (
    BasicBlock,
    CFGBuilder,
    ControlFlowGraph,
    DataFlowAnalysis,
)

from pysymex.analysis.taint.checker_types import (
    Sanitizer,
    SinkKind,
    TaintDefinitions,
    TaintKind,
    TaintLabel,
    TaintSource,
    TaintSink,
    TaintState,
    TaintViolation,
    TaintedValue,
)

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

__all__ = ["TaintAnalyzer", "TaintFlowAnalysis", "TaintChecker"]


class TaintAnalyzer:
    """
    Analyzes bytecode for taint flow violations.
    Tracks how tainted data flows through the program and
    reports when it reaches sensitive sinks.
    """

    _AMBIGUOUS_SHORT_NAMES: frozenset[str] = frozenset(
        {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "read",
            "readline",
            "readlines",
            "write",
            "call",
            "run",
            "open",
            "load",
            "loads",
            "execute",
            "system",
            "log",
        }
    )

    def __init__(self) -> None:
        self.sources = {s.name: s for s in TaintDefinitions.SOURCES}

        self.sinks = {s.name: s for s in TaintDefinitions.SINKS}

        self.sanitizers = {s.name: s for s in TaintDefinitions.SANITIZERS}

        self.violations: list[TaintViolation] = []

        self._register_qualified_names()

    def _register_qualified_names(self) -> None:
        """Register common qualified source/sink names.

        The ambiguity filter in ``_find_source``/``_find_sink`` blocks
        short-name fallback for names like ``"get"``, ``"execute"`` etc.
        Registering the fully-qualified forms here ensures that calls like
        ``requests.get()`` and ``cursor.execute()`` resolve correctly.
        """

        _QUALIFIED_SOURCES: dict[str, str] = {
            "file.read": "read",
            "file.readline": "readline",
            "file.readlines": "readlines",
            "urllib.request.urlopen": "urlopen",
        }

        for qual_name, short_name in _QUALIFIED_SOURCES.items():
            if short_name in self.sources and qual_name not in self.sources:
                self.sources[qual_name] = self.sources[short_name]

        _QUALIFIED_SINKS: dict[str, str] = {
            "cursor.execute": "execute",
            "cursor.executemany": "executemany",
            "cursor.executescript": "executescript",
            "os.system": "system",
            "os.popen": "popen",
            "subprocess.call": "call",
            "subprocess.run": "run",
            "subprocess.Popen": "Popen",
        }

        for qual_name, short_name in _QUALIFIED_SINKS.items():
            if short_name in self.sinks and qual_name not in self.sinks:
                self.sinks[qual_name] = self.sinks[short_name]

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Analyze a function for taint violations."""

        self.violations = []

        instructions = _cached_get_instructions(code)

        if not instructions:
            return []

        state = TaintState()

        current_line = code.co_firstlineno

        for instr in instructions:
            line = get_starts_line(instr)

            if line is not None:
                current_line = line

            self._process_instruction(instr, state, current_line, file_path)

        return self.violations

    def _process_instruction(
        self,
        instr: dis.Instruction,
        state: TaintState,
        line: int,
        file_path: str,
    ) -> None:
        """Process a single instruction for taint analysis."""

        opname = instr.opname

        arg = instr.argval

        if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
            var_name = arg

            tainted = state.get_taint(var_name)

            state.push(TaintedValue(var_name, set(tainted.labels), tainted.confidence))

        elif opname == "LOAD_CONST":
            state.push(TaintedValue(f"const_{arg}"))

        elif opname == "LOAD_ATTR":
            attr_name = arg

            obj_taint = state.pop()

            full_name = f"{obj_taint.value_name}.{attr_name}"

            source = self._find_source(full_name)

            if source:
                label = TaintLabel(
                    kind=source.kind,
                    source=source.description or source.name,
                    source_line=line,
                )

                result = TaintedValue(full_name)

                result.add_label(label)

                state.push(result)

            else:
                result = TaintedValue(full_name)

                for label in obj_taint.labels:
                    result.add_label(label.propagate(f".{attr_name}"))

                state.push(result)

        elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            var_name = arg

            if state.stack:
                tainted = state.pop()

                tainted.value_name = var_name

                state.set_taint(var_name, tainted)

        elif opname == "BINARY_OP":
            if len(state.stack) >= 2:
                right = state.pop()

                left = state.pop()

                result = TaintedValue(f"({left.value_name} {instr.argrepr} {right.value_name})")

                for label in left.labels:
                    result.add_label(label.propagate(f"op:{instr.argrepr}"))

                for label in right.labels:
                    result.add_label(label.propagate(f"op:{instr.argrepr}"))

                state.push(result)

        elif opname == "FORMAT_VALUE":
            if state.stack:
                value = state.pop()

                result = TaintedValue(f"format({value.value_name})")

                for label in value.labels:
                    result.add_label(label.propagate("format"))

                state.push(result)

        elif opname == "BUILD_STRING":
            count = arg or 0

            parts: list[TaintedValue] = []

            for _ in range(count):
                if state.stack:
                    parts.append(state.pop())

            result = TaintedValue("string")

            for part in parts:
                for label in part.labels:
                    result.add_label(label.propagate("concat"))

            state.push(result)

        elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            self._handle_call(instr, state, line, file_path)

        elif opname == "BINARY_SUBSCR":
            if len(state.stack) >= 2:
                index = state.pop()

                container = state.pop()

                result = TaintedValue(f"{container.value_name}[{index.value_name}]")

                for label in container.labels:
                    result.add_label(label.propagate("subscript"))

                state.push(result)

        elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
            count = arg or 0

            elements: list[TaintedValue] = []

            for _ in range(count):
                if state.stack:
                    elements.append(state.pop())

            result = TaintedValue(opname.replace("BUILD_", "").lower())

            for elem in elements:
                for label in elem.labels:
                    result.add_label(label.propagate("collect"))

            state.push(result)

        elif opname == "BUILD_MAP":
            count = arg or 0

            for _ in range(count * 2):
                if state.stack:
                    state.pop()

            state.push(TaintedValue("dict"))

        elif opname == "POP_TOP":
            if state.stack:
                state.pop()

        elif opname == "DUP_TOP":
            if state.stack:
                top = state.peek()

                if top:
                    state.push(TaintedValue(top.value_name, set(top.labels), top.confidence))

        elif opname == "ROT_TWO":
            if len(state.stack) >= 2:
                a = state.pop()

                b = state.pop()

                state.push(a)

                state.push(b)

        elif opname == "RETURN_VALUE":
            pass

    def _handle_call(
        self,
        instr: dis.Instruction,
        state: TaintState,
        line: int,
        file_path: str,
    ) -> None:
        """Handle function call for taint analysis."""

        arg_count = instr.argval if instr.argval is not None else instr.arg or 0

        args: list[TaintedValue] = []

        for _ in range(arg_count):
            if state.stack:
                args.insert(0, state.pop())

        func_taint = state.pop() if state.stack else TaintedValue("unknown_func")

        func_name = func_taint.value_name

        source = self._find_source(func_name)

        if source:
            label = TaintLabel(
                kind=source.kind,
                source=source.description or source.name,
                source_line=line,
            )

            result = TaintedValue(f"{func_name}()")

            result.add_label(label)

            state.push(result)

            return

        sink = self._find_sink(func_name)

        if sink:
            for idx in sink.arg_indices:
                if idx < len(args) and args[idx].is_tainted:
                    for label in args[idx].labels:
                        violation = TaintViolation(
                            source=label,
                            sink=sink,
                            sink_line=line,
                            sink_pc=instr.offset,
                            file=file_path,
                            variable_name=args[idx].value_name,
                            path_description=" -> ".join(label.path),
                        )

                        self.violations.append(violation)

        sanitizer = self._find_sanitizer(func_name)

        if sanitizer and args:
            idx = sanitizer.sanitizes_arg

            if idx < len(args):
                arg = args[idx]

                new_labels: set[TaintLabel] = set()

                for label in arg.labels:
                    if not (label.kind & sanitizer.removes_kinds):
                        new_labels.add(label)

                result = TaintedValue(f"{func_name}({arg.value_name})")

                result.labels = new_labels

                state.push(result)

                return

        result = TaintedValue(f"{func_name}()")

        for arg in args:
            for label in arg.labels:
                result.add_label(label.propagate(f"call:{func_name}"))

        for label in func_taint.labels:
            result.add_label(label.propagate(f"call:{func_name}"))

        state.push(result)

    def _find_source(self, name: str) -> TaintSource | None:
        """Find a taint source by name."""

        if name in self.sources:
            return self.sources[name]

        base_name = name.split(".")[-1]

        if "." in name and base_name in self._AMBIGUOUS_SHORT_NAMES:
            return None

        if base_name in self.sources:
            return self.sources[base_name]

        return None

    def _find_sink(self, name: str) -> TaintSink | None:
        """Find a taint sink by name."""

        if name in self.sinks:
            return self.sinks[name]

        base_name = name.split(".")[-1]

        if "." in name and base_name in self._AMBIGUOUS_SHORT_NAMES:
            return None

        if base_name in self.sinks:
            return self.sinks[base_name]

        return None

    def _find_sanitizer(self, name: str) -> Sanitizer | None:
        """Find a sanitizer by name."""

        if name in self.sanitizers:
            return self.sanitizers[name]

        base_name = name.split(".")[-1]

        if base_name in self.sanitizers:
            return self.sanitizers[base_name]

        return None

    def add_source(self, source: TaintSource) -> None:
        """Add a custom taint source."""

        self.sources[source.name] = source

    def add_sink(self, sink: TaintSink) -> None:
        """Add a custom taint sink."""

        self.sinks[sink.name] = sink

    def add_sanitizer(self, sanitizer: Sanitizer) -> None:
        """Add a custom sanitizer."""

        self.sanitizers[sanitizer.name] = sanitizer


class TaintFlowAnalysis(DataFlowAnalysis[TaintState]):
    """
    Flow-sensitive taint analysis using the data flow framework.
    """

    def __init__(
        self,
        cfg: ControlFlowGraph,
        analyzer: TaintAnalyzer,
        file_path: str = "<unknown>",
    ) -> None:
        super().__init__(cfg)

        self.analyzer = analyzer

        self.file_path = file_path

    def initial_value(self) -> TaintState:
        return TaintState()

    def boundary_value(self) -> TaintState:
        return TaintState()

    def transfer(self, block: BasicBlock, in_fact: TaintState) -> TaintState:
        """Transfer function: process block for taint."""

        state = in_fact.copy()

        current_line = block.start_pc

        for instr in block.instructions:
            line = get_starts_line(instr)

            if line is not None:
                current_line = line

            self.analyzer._process_instruction(instr, state, current_line, self.file_path)

        return state

    def meet(self, facts: list[TaintState]) -> TaintState:
        """Merge taint states from multiple paths."""

        if not facts:
            return TaintState()

        result = facts[0].copy()

        for state in facts[1:]:
            result = result.merge_with(state)

        return result


class TaintChecker:
    """
    High-level interface for taint checking.
    """

    def __init__(self) -> None:
        self.analyzer = TaintAnalyzer()

    def check_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Check a function for taint violations."""

        return self.analyzer.analyze_function(code, file_path)

    def check_flow_sensitive(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Check with flow-sensitive analysis."""

        builder = CFGBuilder()

        cfg = builder.build(code)

        analysis = TaintFlowAnalysis(cfg, self.analyzer, file_path)

        analysis.analyze()

        return self.analyzer.violations

    def add_source(self, name: str, kind: TaintKind, description: str = "") -> None:
        """Add a custom taint source."""

        self.analyzer.add_source(TaintSource(name, kind, description=description))

    def add_sink(
        self, name: str, kind: SinkKind, arg_indices: set[int], description: str = ""
    ) -> None:
        """Add a custom taint sink."""

        self.analyzer.add_sink(TaintSink(name, kind, arg_indices, description=description))

    def add_sanitizer(self, name: str, removes_kinds: TaintKind, description: str = "") -> None:
        """Add a custom sanitizer."""

        self.analyzer.add_sanitizer(Sanitizer(name, removes_kinds, description=description))
