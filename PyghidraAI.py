import pyghidra
from pathlib import Path


GHIDRA_INSTALL = r"C:\ghidra_12.1.3_PUBLIC"

PROJECT_FOLDER = r"C:\GhidraProjects"
PROJECT_NAME = "CapstoneAI"

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "samples" / "harmless.exe"


pyghidra.start(
    install_dir=GHIDRA_INSTALL
)


from ghidra_ai.context_extractor import ContextExtractor
from ghidra_ai.function_analyzer import FunctionAnalyzer


with pyghidra.open_project(
    PROJECT_FOLDER,
    PROJECT_NAME,
    create=True
) as project:

    monitor = pyghidra.task_monitor()

    loader = (
        pyghidra.program_loader()
        .project(project)
        .source(str(BINARY_PATH))
    )

    with loader.load() as load_results:

        loaded = load_results.getPrimary()
        program = loaded.getDomainObject()

        print("Loaded program:", program.getName())

        print("Analyzing binary...")
        pyghidra.analyze(program, monitor)
        print("Analysis completed.")

        # Temporary function selection
        extractor = ContextExtractor(program)

        selected_function, _ = (
            extractor.find_function_with_strings()
        )

        if selected_function is None:
            print("No function with strings found.")
            extractor.close()
            raise SystemExit

        print(
            "Selected function:",
            selected_function.getName()
        )

        # Full AI analysis pipeline
        analyzer = FunctionAnalyzer(program)

        analysis = analyzer.analyze(
            selected_function,
            monitor
        )

        print("\n===== ANALYSIS RESULT =====\n")

        print("Summary:")
        print(analysis.summary)

        print("\nSuggested Name:")
        print(analysis.suggested_name)

        print("\nSuspicious Behaviors:")
        for behavior in analysis.suspicious_behaviors:
            print("-", behavior)

        print("\nEvidence:")
        for evidence in analysis.evidence:
            print("-", evidence)

        print("\nConfidence:")
        print(analysis.confidence)

        print("\nLimitations:")
        for limitation in analysis.limitations:
            print("-", limitation)

        analyzer.close()
        extractor.close()