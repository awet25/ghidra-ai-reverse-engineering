import pyghidra

GHIDRA_INSTALL = r"C:\ghidra_12.1.3_PUBLIC"
PROJECT_FOLDER = r"C:\GhidraProjects"
PROJECT_NAME = "CapstoneAI"

pyghidra.start(install_dir=GHIDRA_INSTALL)

from ghidra_ai.context_extractor import ContextExtractor


with pyghidra.open_project(
    PROJECT_FOLDER,
    PROJECT_NAME
) as project:

    with pyghidra.program_context(
        project,
        "/notepad.exe"
    ) as program:

        functions = program.getFunctionManager().getFunctions(True)

        selected_function = None

        for function in functions:
            if not function.isExternal():
                selected_function = function
                break

        if selected_function is None:
            raise RuntimeError("No function found.")

        extractor = ContextExtractor(program)

        context = extractor.extract(
            selected_function,
            pyghidra.task_monitor()
        )

        print("Function:", context.name)
        print("Address:", context.address)
        print("\nCallers:")
        for caller in context.callers:
            print(" ", caller)
        print("\nCallees:")
        for callee in context.callees:
            print(" ",callee)   

        print("\n===== DECOMPILED CODE =====\n")

        print(context.decompiled_code)

        extractor.close()