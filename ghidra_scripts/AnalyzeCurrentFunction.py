#@runtime PyGhidra
#@category AI
#@menupath Tools.AI.Analyze Current Function
#@author Awet

from ghidra_ai.function_analyzer import FunctionAnalyzer


def parse_supporting_functions(arguments, program, diagnostic=print):
    """Resolve explicit entry addresses only; backend validation remains authoritative."""
    selections = []
    manager = program.getFunctionManager()
    for argument in arguments:
        text = str(argument)
        key, separator, value = text.partition("=")
        if key != "support" or not separator or not value.strip():
            diagnostic(f"Ignored script argument {text!r}: expected support=<entry address>.")
            continue
        try:
            address = program.getAddressFactory().getAddress(value.strip())
            if address is None:
                raise ValueError("invalid address")
            function = manager.getFunctionAt(address)
            if function is None:
                raise ValueError("no function at exact entry address")
            selections.append(function)
        except Exception as error:
            diagnostic(f"Ignored support argument {text!r}: {error}.")
    return selections


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

    supporting_functions = parse_supporting_functions(getScriptArgs(), currentProgram)

    print("\n==============================")
    print("AI FUNCTION ANALYSIS")
    print("==============================")

    print("\nFunction:")
    print(function.getName())

    print("\nAddress:")
    print(function.getEntryPoint())

    analyzer = FunctionAnalyzer(currentProgram)

    try:

        print("\nSending function to Qwen...")

        if supporting_functions:
            analysis = analyzer.analyze(
                function, monitor, supporting_functions=supporting_functions
            )
        else:
            analysis = analyzer.analyze(function, monitor)

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
        validation = analyzer.last_evidence_validation
        diagnostics = [] if validation is None else validation.errors + validation.confidence_diagnostics
        verification = analyzer.last_verification
        verification_unavailable = verification is not None and verification.status != "completed"
        if analysis.limitations or diagnostics or verification_unavailable:
            for limitation in analysis.limitations:
                print("-", limitation)
            # Display system diagnostics separately; never rewrite the model's AnalysisResult.
            for diagnostic in diagnostics:
                print("- Provenance validation (syntax only):", diagnostic)
            if verification_unavailable:
                print("- Semantic verification unavailable; showing unverified draft:", verification.failure)
        else:
            print("None")

    except Exception as error:

        print("\nAI analysis failed:")
        print(error)

    finally:
        analyzer.close()


main()
