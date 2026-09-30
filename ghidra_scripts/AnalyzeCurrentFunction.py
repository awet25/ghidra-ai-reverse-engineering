#@runtime PyGhidra
#@category AI
#@menupath Tools.AI.Analyze Current Function
#@author Awet

from ghidra_ai.function_analyzer import FunctionAnalyzer


def main():

    if currentProgram is None:
        print("No program is currently open.")
        return

    if currentAddress is None:
        print("Place the cursor inside a function.")
        return

    function_manager = currentProgram.getFunctionManager()

    function = function_manager.getFunctionContaining(
        currentAddress
    )

    if function is None:
        print(
            "No function found at address:",
            currentAddress
        )
        return

    print("\n==============================")
    print("AI FUNCTION ANALYSIS")
    print("==============================")

    print("\nFunction:")
    print(function.getName())

    print("\nAddress:")
    print(function.getEntryPoint())

    analyzer = FunctionAnalyzer(
        currentProgram
    )

    try:

        print("\nSending function to Qwen...")

        analysis = analyzer.analyze(
            function,
            monitor
        )

        print("\n===== ANALYSIS RESULT =====\n")

        print("Summary:")
        print(analysis.summary)

        print("\nSuggested Name:")
        print(analysis.suggested_name)

        print("\nSuspicious Behaviors:")
        if analysis.suspicious_behaviors:
            for behavior in analysis.suspicious_behaviors:
                print("-", behavior)
        else:
            print("None")

        print("\nEvidence:")
        if analysis.evidence:
            for evidence in analysis.evidence:
                print("-", evidence)
        else:
            print("None")

        print("\nConfidence:")
        print(analysis.confidence)

        print("\nLimitations:")
        if analysis.limitations:
            for limitation in analysis.limitations:
                print("-", limitation)
        else:
            print("None")

    except Exception as error:

        print("\nAI analysis failed:")
        print(error)

    finally:
        analyzer.close()


main()