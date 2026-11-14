import importlib
import sys
import types

from ghidra_ai.models import CalleeContext, FunctionContext


def _load_context_extractor_without_ghidra():
    module_names = (
        "ghidra",
        "ghidra.app",
        "ghidra.app.decompiler",
        "ghidra.program",
        "ghidra.program.model",
        "ghidra.program.model.block",
        "ghidra.program.model.data",
        "ghidra.program.model.pcode",
        "ghidra.program.model.symbol",
        "ghidra.util",
        "ghidra.util.task",
    )
    previous = {name: sys.modules.get(name) for name in module_names}
    stubs = {name: types.ModuleType(name) for name in module_names}
    for name in module_names:
        if name in {
            "ghidra", "ghidra.app", "ghidra.program", "ghidra.program.model",
            "ghidra.util",
        }:
            stubs[name].__path__ = []
    for module_name, class_names in {
        "ghidra.app.decompiler": ("DecompInterface", "DecompileOptions"),
        "ghidra.program.model.block": ("BasicBlockModel",),
        "ghidra.program.model.data": (
            "StringDataInstance", "TypeDef", "Undefined", "VoidDataType",
        ),
        "ghidra.program.model.pcode": ("HighGlobal", "HighLocal", "HighParam", "PcodeOp"),
        "ghidra.program.model.symbol": ("SourceType",),
        "ghidra.util.task": ("TaskMonitor",),
    }.items():
        for class_name in class_names:
            setattr(stubs[module_name], class_name, type(class_name, (), {}))
    sys.modules.update(stubs)
    extractor_module = "ghidra_ai.context_extractor"
    original_extractor = sys.modules.pop(extractor_module, None)
    try:
        return importlib.import_module(extractor_module).ContextExtractor
    finally:
        sys.modules.pop(extractor_module, None)
        if original_extractor is not None:
            sys.modules[extractor_module] = original_extractor
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


ContextExtractor = _load_context_extractor_without_ghidra()


class FakeFunction:
    def __init__(self, name, address, *, external=False, thunk_target=None, program=None):
        self.name = name
        self.address = address
        self.external = external
        self.thunk_target = thunk_target
        self.program = program

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.address

    def isExternal(self):
        return self.external

    def isThunk(self):
        return self.thunk_target is not None

    def getThunkedFunction(self, _recursive):
        return self.thunk_target

    def getProgram(self):
        return self.program


class FakeProgram:
    def __init__(self, functions):
        self.functions = {function.address: function for function in functions}

    def getFunctionManager(self):
        return self

    def getAddressFactory(self):
        return self

    def getAddress(self, address):
        return address

    def getFunctionAt(self, address):
        return self.functions.get(str(address))


def _make_extractor(functions, *, extracted):
    extractor = ContextExtractor.__new__(ContextExtractor)
    extractor.program = FakeProgram(functions)

    def mark_extracted(support, _function, _monitor):
        support.decompilation_succeeded = True
        extracted.append(support.address)

    extractor._extract_supporting_function = mark_extracted
    return extractor


def test_supporting_selection_accepts_only_direct_internal_callees():
    root = FakeFunction("root", "1000")
    internal = FakeFunction("internal", "2000")
    external = FakeFunction("external", "3000", external=True)
    unrelated = FakeFunction("unrelated", "4000")
    extracted = []
    extractor = _make_extractor([root, internal, external, unrelated], extracted=extracted)
    context = FunctionContext(
        name="root",
        address="1000",
        decompiled_code="root implementation",
        callee_contexts=[
            CalleeContext(name="internal", address="2000"),
            CalleeContext(name="external", address="3000", is_external=True),
        ],
    )

    extractor._add_supporting_functions(
        context, ["2000", "3000", "4000", "1000", "9999", "2000"], None
    )

    assert [support.address for support in context.supporting_functions] == ["2000"]
    assert extracted == ["2000"]
    assert len(context.supporting_selection_errors) == 5
    assert any("external functions cannot" in error for error in context.supporting_selection_errors)
    assert any("not a direct resolved internal callee" in error
               for error in context.supporting_selection_errors)
    assert any("root cannot be selected" in error for error in context.supporting_selection_errors)
    assert any("no Function at exact entry address" in error
               for error in context.supporting_selection_errors)
    assert any("duplicate supporting implementation" in error
               for error in context.supporting_selection_errors)


def test_thunk_and_implementation_selections_share_one_support_identity():
    root = FakeFunction("root", "1000")
    implementation = FakeFunction("implementation", "2000")
    thunk = FakeFunction("thunk", "2100", thunk_target=implementation)
    extracted = []
    extractor = _make_extractor([root, implementation, thunk], extracted=extracted)
    context = FunctionContext(
        name="root",
        address="1000",
        decompiled_code="root implementation",
        callee_contexts=[
            CalleeContext(
                name="thunk",
                address="2100",
                is_thunk=True,
                thunk_target_address="2000",
                thunk_target_is_external=False,
            ),
        ],
    )

    extractor._add_supporting_functions(context, ["2100", "2000"], None)

    assert len(context.supporting_functions) == 1
    support = context.supporting_functions[0]
    assert support.address == "2000"
    assert support.selected_address == "2100"
    assert support.called_addresses == ["2100"]
    assert extracted == ["2000"]
    assert len(context.supporting_selection_errors) == 1
    assert "duplicate supporting implementation" in context.supporting_selection_errors[0]


def test_supporting_selection_enforces_the_maximum_count():
    root = FakeFunction("root", "1000")
    supports = [FakeFunction(f"support_{i}", f"{2000 + i}") for i in range(6)]
    extracted = []
    extractor = _make_extractor([root, *supports], extracted=extracted)
    context = FunctionContext(
        name="root",
        address="1000",
        decompiled_code="root implementation",
        callee_contexts=[
            CalleeContext(name=support.name, address=support.address)
            for support in supports
        ],
    )

    extractor._add_supporting_functions(
        context, [support.address for support in supports], None
    )

    assert len(context.supporting_functions) == ContextExtractor.MAX_SUPPORTING_FUNCTIONS
    assert len(extracted) == ContextExtractor.MAX_SUPPORTING_FUNCTIONS
    assert len(context.supporting_selection_errors) == 1
    assert "maximum 5 supporting functions" in context.supporting_selection_errors[0]
