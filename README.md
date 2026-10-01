## Requirements

- Windows 10/11 or Linux
- Python 3.11+
- Ghidra 12.1.3
- JDK required by Ghidra
-Ollama
- Qwen 7B model ( qwen2.5-coder:7b-instruct)

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






