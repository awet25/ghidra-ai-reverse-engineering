import pyghidra
from pathlib import Path
GHIDRA_INSTALL = r"C:\ghidra_12.1.3_PUBLIC"
PROJECT_FOLDER = r"C:\GhidraProjects"
PROJECT_NAME = "CapstoneAI"
BASE_DIR= Path(__file__).resolve().parent
BINARY_PATH= BASE_DIR /"samples"/"harmless.exe"
pyghidra.start(install_dir=GHIDRA_INSTALL)

from ghidra_ai.context_extractor import ContextExtractor


with pyghidra.open_project(
    PROJECT_FOLDER,
    PROJECT_NAME,
    create=True
) as project:
    monitor=pyghidra.task_monitor()
    loader=(pyghidra.program_loader().project(project).source(str(BINARY_PATH)))
    with loader.load() as load_results:
 
        loaded=load_results.getPrimary()
        program= loaded.getDomainObject()
        print("Loaded program:", program.getName())
        print("Analyzing binary......")
        pyghidra.analyze(program, monitor)
        print("Analysis completed")

        # functions = program.getFunctionManager().getFunctions(True)

        selected_function = None

        # for function in functions:
        #     if not function.isExternal():
        #         selected_function = function
        #         break

        # if selected_function is None:
        #     raise RuntimeError("No function found.")

        extractor = ContextExtractor(program)
        selected_function,found_strings=extractor.find_function_with_strings()
        if selected_function is None:
            print("No Function with strings found.")
            extractor.close()
            raise SystemExit
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
        print("\nstrings:")
        for string in context.strings:
            print(" ", repr(string))

        print("\n===== DECOMPILED CODE =====\n")

        print(context.decompiled_code)

        extractor.close()