from ghidra.app.decompiler import DecompInterface, DecompileOptions

from .models import FunctionContext


class ContextExtractor:

    def __init__(self, program):
        self.program = program

        self.decompiler = DecompInterface()
        self.decompiler.setOptions(DecompileOptions())
        self.decompiler.toggleCCode(True)
        self.decompiler.toggleSyntaxTree(True)
        self.decompiler.setSimplificationStyle("decompile")

        if not self.decompiler.openProgram(program):
            raise RuntimeError("Could not open program in decompiler.")

    def get_decompiled_code(self, function, monitor):
        result = self.decompiler.decompileFunction(
            function,
            30,
            monitor
        )

        if not result.decompileCompleted():
            raise RuntimeError(result.getErrorMessage())

        return result.getDecompiledFunction().getC()

    def get_called_functions(self, function, monitor):
        called_functions = function.getCalledFunctions(monitor)

        return [
            str(func.getName())
            for func in called_functions
        ]

    def get_calling_functions(self, function, monitor):
        calling_functions = function.getCallingFunctions(monitor)

        return [
            str(func.getName())
            for func in calling_functions
        ]

    def extract(self, function, monitor):
        code = self.get_decompiled_code(function, monitor)

        callees = self.get_called_functions(
            function,
            monitor
        )

        callers = self.get_calling_functions(
            function,
            monitor
        )

        return FunctionContext(
            name=str(function.getName()),
            address=str(function.getEntryPoint()),
            decompiled_code=code,
            callers=callers,
            callees=callees
        )

    def close(self):
        self.decompiler.dispose()