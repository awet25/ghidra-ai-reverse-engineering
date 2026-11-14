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

        print("\nSending function to the local model...")

        if supporting_functions:
            analysis = analyzer.analyze(
                function, monitor, supporting_functions=supporting_functions
            )
        else:
            analysis = analyzer.analyze(function, monitor)

        print("\n===== ANALYSIS RESULT =====\n")
        for heading, content in (
            ("Vulnerability Classification", analysis.vulnerability_classification),
            ("Vulnerable Code Isolation", analysis.vulnerable_code_isolation),
            ("Root Cause & Impact Analysis", analysis.root_cause_impact_analysis),
            ("Remediation & Patch Verification", analysis.remediation_patch_verification),
        ):
            print(f"{heading}:")
            print(content)

    except Exception as error:

        print("\nAI analysis failed:")
        print(error)

    finally:
        analyzer.close()


main()
