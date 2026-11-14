import importlib
import sys
import types
from dataclasses import replace

import pytest

from ghidra_ai.models import FunctionContext, SupportingFunctionContext
from ghidra_ai.prompt_builder import PromptBuilder
from ghidra_ai.ai_service import CONTINUATION_SYSTEM_PROMPT
from ghidra_ai.response_parser import ResponseParser


def _load_analyzer_without_ghidra():
    module_name = "ghidra_ai.context_extractor"
    original = sys.modules.get(module_name)
    stub = types.ModuleType(module_name)
    stub.ContextExtractor = object
    sys.modules[module_name] = stub
    try:
        return importlib.import_module("ghidra_ai.function_analyzer").FunctionAnalyzer
    finally:
        if original is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = original


FunctionAnalyzer = _load_analyzer_without_ghidra()


def _analysis_response(
    classification="No vulnerability identified.",
    code="No vulnerable code identified.",
    cause="The available root implementation does not show a vulnerability.",
    remediation="No patch is indicated by the available context.",
):
    return f"""### 1. Vulnerability Classification
{classification}

### 2. Vulnerable Code Isolation
{code}

### 3. Root Cause & Impact Analysis
{cause}

### 4. Remediation & Patch Verification
{remediation}"""


def _analyzer_for_context(context, *, max_prompt_chars=30000):
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.extractor = FakeExtractor(context)
    analyzer.prompt_builder = PromptBuilder()
    analyzer.ai_service = FakeAIService()
    analyzer.response_parser = ResponseParser()
    analyzer.last_source_catalog = {}
    analyzer.last_evidence_validation = None
    analyzer.last_verification = None
    analyzer.max_prompt_chars = max_prompt_chars
    analyzer.last_prompt_budget_diagnostics = []
    return analyzer


class FakeExtractor:
    def __init__(self, context):
        self.context = context

    def extract(self, function, monitor, supporting_functions=None):
        return self.context


class FakeAIService:
    def __init__(self, responses=None):
        self.prompts = []
        self.system_prompts = []
        self.responses = list(
            responses if responses is not None else [_analysis_response()]
        )

    def analyze(self, prompt, *, system_prompt=None):
        self.prompts.append(prompt)
        self.system_prompts.append(system_prompt)
        if not self.responses:
            raise AssertionError("Unexpected additional model request.")
        return self.responses.pop(0)


def test_analyze_makes_one_model_request_and_returns_parsed_result():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)

    result = analyzer.analyze(function=object(), monitor=None)

    assert result.vulnerability_classification == "No vulnerability identified."
    assert len(analyzer.ai_service.prompts) == 1
    assert analyzer.last_source_catalog["R0"]
    assert analyzer.last_evidence_validation is None


def test_analyze_continues_once_when_only_trailing_sections_are_missing():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    partial = """### 1. Vulnerability Classification
No vulnerability identified.

### 2. Vulnerable Code Isolation
No vulnerable code identified.

### 3. Root Cause & Impact Analysis
The available root implementation does not show a vulnerability."""
    analyzer.ai_service = FakeAIService([
        partial,
        """### 4. Remediation & Patch Verification
No patch is indicated by the available context.""",
    ])

    result = analyzer.analyze(function=object(), monitor=None)

    assert result.remediation_patch_verification == (
        "No patch is indicated by the available context."
    )
    assert len(analyzer.ai_service.prompts) == 2
    assert "PARTIAL REPORT (already generated; do not repeat)" in (
        analyzer.ai_service.prompts[1]
    )
    assert analyzer.ai_service.system_prompts == [None, CONTINUATION_SYSTEM_PROMPT]


def test_analyze_does_not_continue_non_partial_malformed_responses():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService(["not a report"])

    with pytest.raises(ValueError, match="four-section Markdown report"):
        analyzer.analyze(function=object(), monitor=None)

    assert len(analyzer.ai_service.prompts) == 1


def test_analyze_verifies_the_draft_when_requested():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService([
        _analysis_response(classification="Draft classification."),
        _analysis_response(classification="Verified classification."),
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.vulnerability_classification == "Verified classification."
    assert analyzer.last_verification.status == "completed"
    assert len(analyzer.ai_service.prompts) == 2
    assert "SOURCE CATALOG" in analyzer.ai_service.prompts[1]


def test_analyze_returns_draft_when_verification_fails():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService([
        _analysis_response(classification="Draft classification."),
        "not a report",
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.vulnerability_classification == "Draft classification."
    assert analyzer.last_verification.status == "unavailable"
    assert analyzer.last_verification.failure.startswith("ValueError:")


def test_analyze_returns_draft_when_verification_report_is_incomplete():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    incomplete_report = """### 1. Vulnerability Classification
Alternative classification.

### 2. Vulnerable Code Isolation
Potentially relevant code.

### 3. Root Cause & Impact Analysis
The remediation section is missing."""
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService([
        _analysis_response(classification="Draft classification."),
        incomplete_report,
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.vulnerability_classification == "Draft classification."
    assert analyzer.last_verification.status == "unavailable"
    assert analyzer.last_verification.failure is not None
    assert "Remediation & Patch Verification" in analyzer.last_verification.failure


def test_analyze_clears_stale_diagnostics_and_does_not_call_model_on_extraction_error():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    analyzer.last_source_catalog = {"STALE": "old source"}
    analyzer.last_evidence_validation = object()
    analyzer.last_verification = object()
    analyzer.last_prompt_budget_diagnostics = ["old warning"]

    def fail_extraction(*args, **kwargs):
        raise RuntimeError("decompilation failed")

    analyzer.extractor.extract = fail_extraction
    with pytest.raises(RuntimeError, match="decompilation failed"):
        analyzer.analyze(function=object(), monitor=None)

    assert analyzer.last_source_catalog == {}
    assert analyzer.last_evidence_validation is None
    assert analyzer.last_verification is None
    assert analyzer.last_prompt_budget_diagnostics == []
    assert analyzer.ai_service.prompts == []


def test_analyze_stops_before_model_call_when_protected_context_exceeds_budget():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context, max_prompt_chars=100)

    with pytest.raises(ValueError, match="Root context was preserved"):
        analyzer.analyze(function=object(), monitor=None)

    assert analyzer.ai_service.prompts == []


def test_prompt_budget_truncates_support_code_but_preserves_root_and_source():
    support = SupportingFunctionContext(
        name="FUN_support",
        address="2000",
        parent_address="1000",
        selected_address="2000",
        decompiled_code="S" * 3000,
        decompilation_succeeded=True,
    )
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="ROOT_IMPLEMENTATION",
        supporting_functions=[support],
    )
    empty_support_context = replace(
        context,
        supporting_functions=[replace(support, decompiled_code="")],
    )
    minimum_prompt_length = len(PromptBuilder().build_prompt_with_sources(
        empty_support_context
    ).prompt)
    budget = minimum_prompt_length + 1000
    analyzer = _analyzer_for_context(context, max_prompt_chars=budget)

    built = analyzer._build_bounded_prompt(context)

    assert len(built.prompt) <= budget
    assert "ROOT_IMPLEMENTATION" in built.source_catalog["R0"]
    assert "Code truncated: yes" in built.source_catalog["S1"]
    assert "S" * 3000 not in built.source_catalog["S1"]
    assert analyzer.last_prompt_budget_diagnostics


def test_prompt_budget_applies_equal_support_code_caps():
    supports = [
        SupportingFunctionContext(
            name=f"support_{index}",
            address=f"{index + 2000}",
            parent_address="1000",
            selected_address=f"{index + 2000}",
            decompiled_code=code * 3000,
            decompilation_succeeded=True,
        )
        for index, code in enumerate(("A", "B"), 1)
    ]
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="ROOT_IMPLEMENTATION",
        supporting_functions=supports,
    )
    empty_context = replace(
        context,
        supporting_functions=[
            replace(support, decompiled_code="") for support in supports
        ],
    )
    minimum_prompt_length = len(PromptBuilder().build_prompt_with_sources(
        empty_context
    ).prompt)
    analyzer = _analyzer_for_context(
        context, max_prompt_chars=minimum_prompt_length + 500
    )

    built = analyzer._build_bounded_prompt(context)

    support_code = [
        source.split("Decompiler output:\n", 1)[1]
        for source_id, source in sorted(built.source_catalog.items())
        if source_id in {"S1", "S2"}
    ]
    assert len(support_code) == 2
    assert len(support_code[0]) == len(support_code[1])
    assert 0 < len(support_code[0]) < 3000
    assert "ROOT_IMPLEMENTATION" in built.source_catalog["R0"]


def test_prompt_budget_rejects_context_when_protected_root_cannot_fit():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="ROOT_IMPLEMENTATION",
    )
    analyzer = _analyzer_for_context(context, max_prompt_chars=100)

    with pytest.raises(ValueError, match="Root context was preserved"):
        analyzer._build_bounded_prompt(context)


def test_constructor_rejects_nonpositive_or_boolean_prompt_budgets():
    for budget in (0, -1, True):
        with pytest.raises(ValueError, match="positive integer"):
            FunctionAnalyzer(program=object(), max_prompt_chars=budget)
