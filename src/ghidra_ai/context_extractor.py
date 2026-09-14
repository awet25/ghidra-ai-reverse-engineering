from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import StringDataInstance

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
            raise RuntimeError(
                "Could not open program in decompiler."
            )

    def get_decompiled_code(self, function, monitor):
        result = self.decompiler.decompileFunction(
            function,
            30,
            monitor
        )

        if not result.decompileCompleted():
            raise RuntimeError(
                result.getErrorMessage()
            )

        return result.getDecompiledFunction().getC()

    def get_called_functions(self, function, monitor):
        called_functions = function.getCalledFunctions(
            monitor
        )

        return [
            str(func.getName())
            for func in called_functions
        ]

    def get_calling_functions(self, function, monitor):
        calling_functions = function.getCallingFunctions(
            monitor
        )

        return [
            str(func.getName())
            for func in calling_functions
        ]

    def get_strings(self, function):
        listing = self.program.getListing()

        strings = set()

        instructions = listing.getInstructions(
            function.getBody(),
            True
        )

        while instructions.hasNext():
            instruction = instructions.next()

            for operand_index in range(
                instruction.getNumOperands()
            ):

                references = (
                    instruction.getOperandReferences(
                        operand_index
                    )
                )

                for reference in references:

                    if not (
                        reference
                        .getReferenceType()
                        .isData()
                    ):
                        continue

                    target_address = (
                        reference.getToAddress()
                    )

                    # Try exact address first
                    data = listing.getDataAt(
                        target_address
                    )

                    # The reference may point inside
                    # a larger data object
                    if data is None:
                        data = listing.getDataContaining(
                            target_address
                        )

                    if data is None:
                        continue

                    if not StringDataInstance.isString(
                        data
                    ):
                        continue

                    string_instance = (
                        StringDataInstance
                        .getStringDataInstance(data)
                    )

                    value = (
                        string_instance
                        .getStringValue()
                    )

                    if value:
                        strings.add(str(value))

        return sorted(strings)

    def find_function_with_strings(self):
        function_manager = (
            self.program.getFunctionManager()
        )

        for function in (
            function_manager.getFunctions(True)
        ):

            if function.isExternal():
                continue

            strings = self.get_strings(function)

            if strings:
                return function, strings

        return None, []
    
    

    def extract(self, function, monitor):
        code = self.get_decompiled_code(
            function,
            monitor
        )

        callees = self.get_called_functions(
            function,
            monitor
        )

        callers = self.get_calling_functions(
            function,
            monitor
        )

        strings = self.get_strings(
            function
        )

        return FunctionContext(
            name=str(function.getName()),
            address=str(
                function.getEntryPoint()
            ),
            decompiled_code=code,
            callers=callers,
            callees=callees,
            strings=strings
        )

    def close(self):
        self.decompiler.dispose()