# Ghidra AI

A general-purpose reverse-engineering assistant for analyzing an analyst-selected
function in Ghidra using a local Qwen model through Ollama. Analysis is advisory:
review generated claims against the supplied code and evidence.

## Production workflow

Java panel -> selected root + optional direct supports -> bundled Python script
-> FunctionAnalyzer -> ContextExtractor -> PromptBuilder -> one Ollama request
-> ResponseParser -> provenance validation -> formatted Java results.

The analyst chooses every function. Up to **5 direct internal supporting functions**
may be included. There is no automatic selection, ranking, recursive expansion,
or program-wide analysis. Production logic does not depend on executable format,
architecture, API families, particular names, or fixed addresses.

## Requirements

- Ghidra 12.1.3 and its required JDK (JDK 21 or newer for this release).
- Python 3.11+ with PyGhidra and requests, installed through this project's package.
- Ollama with Qwen2.5-Coder-7B-Instruct available under the model name `ghidra-re`.
- A Ghidra session started with PyGhidra using the Python environment containing
  this package.

The Gradle wrapper is included. Windows has been exercised with the desktop
plugin; equivalent Linux/ARM analysis has not yet been validated end to end.

The extension's `gradlew.bat check` (or `./gradlew check`) runs headless function-list
regression checks, including delayed discovery, refresh, filtering and listener cleanup.

## Install and build

From the repository root, create an environment and install the Python backend:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
$env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra_12.1.3_PUBLIC'
```

On Linux, activate with `source .venv/bin/activate` and set
`GHIDRA_INSTALL_DIR` to the installation directory using `export`.

To install the Python test dependency as well, use
`python -m pip install -e ".[test]"` instead of `python -m pip install -e .`.
Run the Python tests from the repository root with `python -m pytest`.
The optional local Ollama smoke test is skipped by default; run it with
`$env:GHIDRA_AI_RUN_OLLAMA_SMOKE = '1'; python -m pytest tests/integration`
in PowerShell, or `GHIDRA_AI_RUN_OLLAMA_SMOKE=1 python -m pytest tests/integration`
on Linux.

Build the Java extension using a JDK supported by Ghidra:

```powershell
cd ghidra_extension/GhidraAI
.\gradlew.bat buildExtension
```

On Linux, use `./gradlew buildExtension`. The installable ZIP is written to
`ghidra_extension/GhidraAI/dist/`.

In Ghidra, open **File > Install Extensions**, install the generated ZIP, and restart
when requested. In CodeBrowser, enable **AI Reverse Engineering Assistant** under
**File > Configure**, then open its panel from **Window**.

Start the GUI with the installed Python environment, for example from the
repository root:

```powershell
python -m pyghidra --gui
```

The ZIP includes Java classes and the matching `AnalyzeCurrentFunction.py` entry
script. The Python package is installed separately. Java resolves the script only
inside its installed extension; it never falls back to a same-named script in
another checkout. Keep the extension and Python backend versions together.

## Ollama configuration

Make the local Qwen model available as `ghidra-re` using your Ollama Modelfile, and
start Ollama before analyzing. The service uses:

| Setting | Default |
| --- | --- |
| Endpoint | `http://localhost:11434/api/generate` |
| Model | `ghidra-re` |
| Model output | Four-section Markdown report |
| Transport | Non-streaming |
| Context window (`num_ctx`) | 16,384 tokens |
| Maximum output (`num_predict`) | 1,024 tokens |
| HTTP timeout | 480 seconds |

Defaults are declared in `src/ghidra_ai/ai_service.py`. Python callers may configure
`AIService(model=..., base_url=..., num_ctx=..., num_predict=..., timeout=...)`.
Sampling settings are left to the model configuration. There are no automatic
retries or additional model requests in normal mode.

`FunctionAnalyzer(program, max_prompt_chars=...)` defaults to a 30,000-character
preflight. Oversized prompts shorten supporting code with an equal per-function
cap and explicit truncation metadata. The root, selected support identities,
relationships, strings and source IDs are preserved. If protected context cannot
fit, analysis stops before sending. Character budgeting is a heuristic, not exact
token counting; adjust it together with the context/output settings.

## Analyze a function

1. Open a binary and allow Ghidra analysis to complete.
2. Search/filter the root function list and select one root, or enable
   **Follow CodeBrowser location**.
   Opening the AI panel also loads the currently active binary, including when
   the binary was opened before the panel was enabled.
   The list refreshes automatically as Ghidra adds, removes, or renames functions.
   Use **Refresh** to reload it manually; your filter and available root selection
   are preserved.
3. Optionally check up to five entries in **Supporting Functions**. Nothing is
   preselected; changing the root or program clears previous choices.
4. Click **Analyze Function**. The button is disabled while analysis runs.
5. Review Vulnerability Classification, Vulnerable Code Isolation, Root Cause &
   Impact Analysis, and Remediation & Patch Verification. No code or program
   edits are applied.

Java passes checked entries as `support=<entry-address>` script arguments. Python
validates exact entries against the root's resolved direct internal callees.
Unrelated, external, root, duplicate and excess selections are skipped with reasons
retained in context metadata. Thunks preserve the called entry while supporting
code comes from the resolved implementation; aliases share one supporting context.

Supporting code is limited to 16,000 characters per implementation before prompt
budgeting. Supporting strings are limited to 12 entries of 160 characters each.
Cuts and extraction failures are explicit. A supporting decompilation failure does
not fail root analysis. External implementations and descendants are not expanded.

The script can also be run directly through Ghidra's PyGhidra Script Manager for
the function containing the cursor, with optional explicit support arguments.

## Context and evidence provenance

ContextExtractor uses Ghidra instruction call references for relationships and
static call-site counts. Root High P-code augments these with argument counts,
shallow provenance and conservative return-use observations. Unresolved CALLIND
sites are recorded without invented targets. Direct internal callee previews use
Listing, raw instruction P-code and optional block/signature metadata; they do not
decompile descendants. Detailed previews and High P-code metadata are not sent to
the model. Only the root and explicitly accepted supporting implementations enter the
prompt.

Source IDs are local to each prompt:

| IDs | Source |
| --- | --- |
| `R0` | Root identity, callers and implementation |
| `RCn` | Root call relationships, including known thunk/support links |
| `RSn` | Root strings |
| `Sn` | Selected supporting implementations and completeness metadata |
| `Sn-STRn` | Supporting strings |

The source catalog is retained for evaluation and traceability. The report parser
checks for the four required headings and non-empty section content; it does not
validate citations or establish that a reported claim is true. If an initial
response has valid, non-empty sections but omits only trailing sections, the
analyzer makes one continuation request and validates the combined report. Other
malformed responses are rejected.

## Limitations and research mode

Decompiler output and recovered signatures can be incomplete. Indirect targets,
conditional execution, runtime effects and unavailable implementations may remain
unknown. Function/API names and strings alone do not establish intent. The model can
still hallucinate. Large prompts can be slow, and output limits can produce an
incomplete Markdown report. Human review remains necessary.

Normal `analyze(function, monitor, supporting_functions=None, verify=False)` makes
one model request, with at most one continuation request for an incomplete report.
An experimental second-pass verifier is retained for capstone evaluation and is
not exposed in the Java UI:

```python
result = analyzer.analyze(function, monitor,
                          supporting_functions=[helper_a, helper_b], verify=True)
```

Research mode makes two requests against the same supplied sources, without extra
extraction. It is disabled by default because evaluation did not improve semantic
correctness and significantly increased latency. Failures return the original
unverified draft with separate verification diagnostics. The experimental verifier
uses the same four-section Markdown response format and remains available for
explicit research use.

For explicit evaluation, inspect `analyzer.last_source_catalog`,
`last_verification`, `last_prompt_budget_diagnostics`, and
`analyzer.ai_service.last_diagnostics`. The latter captures optional Ollama
`prompt_eval_count`, `eval_count`, and `total_duration` (nanoseconds).
An explicit `AIService(diagnostic_output=...)` callback can log token counts.
Evaluation diagnostics are quiet in normal plugin output; Python evaluation
logging can be enabled with an explicit handler on `ghidra_ai.function_analyzer`.
