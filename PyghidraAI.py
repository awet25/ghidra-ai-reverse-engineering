import pyghidra
from pathlib import Path
GHIDRA_INSTALL = r"C:\ghidra_12.1.3_PUBLIC"
PROJECT_FOLDER = r"C:\GhidraProjects"
PROJECT_NAME = "CapstoneAI"
BASE_DIR= Path(__file__).resolve().parent
BINARY_PATH= BASE_DIR /"samples"/"harmless.exe"
pyghidra.start(install_dir=GHIDRA_INSTALL)

from ghidra_ai.context_extractor import ContextExtractor
from ghidra_ai.prompt_builder import PromptBuilder
from ghidra_ai.ai_service import AIService
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
        selected_function = None
        extractor = ContextExtractor(program)
        selected_function,_=extractor.find_function_with_strings()
        if selected_function is None:
            print("No Function with strings found.")
            extractor.close()
            raise SystemExit
        context = extractor.extract(
            selected_function,
           monitor
        )
        prompt_builder= PromptBuilder()
        ai_service= AIService()
        prompt= prompt_builder.build_prompt(context)
        
        print("\n ====== AI PROMPT=========\n")
        print(prompt)
        response=ai_service.analyze(prompt)
        print("\n====== Qwen Response======\n")
        print(response)
        extractor.close()