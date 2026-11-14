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
        self.responses = list(responses or [])

    def analyze(self, prompt, *, system_prompt=None):
        self.prompts.append(prompt)
        self.system_prompts.append(system_prompt)
        if self.responses:
            return self.responses.pop(0)
        return """### 1. Vulnerability Classification
No vulnerability identified.

### 2. Vulnerable Code Isolation
No vulnerable code identified.

### 3. Root Cause & Impact Analysis
The available root implementation does not show a vulnerability.

### 4. Remediation & Patch Verification
No patch is indicated by the available context."""


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
