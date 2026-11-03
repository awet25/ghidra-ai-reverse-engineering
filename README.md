# Ghidra AI

The project currently supports single-function analysis using Ghidra and local
Qwen through Ollama. Whole-program analysis is not currently supported.

## Analyze the current function

1. Start Ollama with your Qwen model available under the configured model name
   `ghidra-re`. The Python service connects to `http://localhost:11434`.
2. Open a binary in Ghidra and let Ghidra's normal analysis finish.
3. Place the cursor inside the function you want to analyze.
4. Run `ghidra_scripts/AnalyzeCurrentFunction.py` from Script Manager using PyGhidra.

The script uses `FunctionAnalyzer` and `ContextExtractor` to collect decompiled C,
the function name and address, callers, callees, and referenced strings into a
`FunctionContext`. `PromptBuilder` creates the prompt, `AIService` sends it to local
Ollama, and `ResponseParser` converts the JSON reply into an `AnalysisResult`.
The script prints the summary, suggested name, suspicious behaviors, evidence,
confidence, and limitations. Suggested names are not applied to the program.

## Standalone single-function test

`PyghidraAI.py` exercises the same pipeline outside Ghidra's Script Manager.
Review its `GHIDRA_INSTALL`, `PROJECT_FOLDER`, `PROJECT_NAME`, and `BINARY_PATH`
settings for your machine, and provide the configured `samples/harmless.exe`.
The sample C source is in `samples/harmless.c`.

Run it in the Python environment where this project is installed:

```powershell
python PyghidraAI.py
```

It loads the sample, runs Ghidra's normal analysis, then sends only the first
non-external function with a referenced string to the AI for explanation.

## Requirements

- Windows 10/11 or Linux
- Python 3.11+
- Ghidra 12.1.3
- JDK required by Ghidra
- Ollama
- Qwen 7B model ( qwen2.5-coder:7b-instruct)  / ghidra-re

The Gradle Wrapper is included in the repository, so a separate Gradle installation is not required.

## Setup

1. Install Ghidra 12.1.3.
2. Clone this repository.
3. Create a Python virtual environment:

   python -m venv .venv

4. Activate the environment:

   .\.venv\Scripts\Activate.ps1

5. Install the project:

   pip install -e .
6.  Set `GHIDRA_INSTALL_DIR`
    Set the `GHIDRA_INSTALL_DIR` environment variable to your local Ghidra installation.


## Build the Ghidra Extension

Navigate to the Java extension directory:
   cd ghidra_extension\GhidraAI

### Compile the Java Code

Windows:

powershell:
.\gradlew.bat compileJava



### Build the Installable Extension

Windows:

.\gradlew.bat buildExtension

The generated extension ZIP will be placed inside:
ghidra_extension/GhidraAI/dist/

## Install the Extension in Ghidra

1. Start Ghidra.
2. Open:
File → Install Extensions

3. Add or select the generated `GhidraAI` ZIP file.
4. Enable the extension.
5. Restart Ghidra if requested.
6. Open a project and launch CodeBrowser.
7. Open:
File → Configure

8. Find the plugin under **Ghidra Core**.
9. Enable:
AI Reverse Engineering Assistant

The panel can then be opened from:

Window → AI Reverse Engineering Assistant
