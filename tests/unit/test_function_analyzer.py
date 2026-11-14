import importlib
import json
import sys
import types
from dataclasses import replace

import pytest

from ghidra_ai.models import FunctionContext, SupportingFunctionContext
from ghidra_ai.prompt_builder import PromptBuilder
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


def _analysis_response(summary="Processes the root input."):
    return json.dumps({
        "summary": summary,
        "suggested_name": "process_root_input",
        "suspicious_behaviors": [],
        "evidence": ["[R0] The root implementation processes an input."],
        "confidence": "medium",
        "limitations": [],
    })


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
        self.responses = list(responses if responses is not None else [_analysis_response()])

    def analyze(self, prompt):
        self.prompts.append(prompt)
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

    assert result.summary == "Processes the root input."
    assert len(analyzer.ai_service.prompts) == 1
    assert analyzer.last_source_catalog["R0"]
    assert analyzer.last_evidence_validation.valid


def test_analyze_verifies_the_draft_when_requested():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService([
        _analysis_response("Draft summary."),
        _analysis_response("Verified summary."),
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.summary == "Verified summary."
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
        _analysis_response("Draft summary."),
        "not JSON",
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.summary == "Draft summary."
    assert analyzer.last_verification.status == "unavailable"
    assert analyzer.last_verification.failure.startswith("ValueError:")
    assert analyzer.last_evidence_validation.valid


def test_analyze_returns_draft_when_verification_has_invalid_source_ids():
    context = FunctionContext(
        name="FUN_root",
        address="1000",
        decompiled_code="root implementation",
    )
    invalid_verification = json.loads(_analysis_response("Unsupported verified summary."))
    invalid_verification["evidence"] = ["[R9] This source was not supplied."]
    analyzer = _analyzer_for_context(context)
    analyzer.ai_service = FakeAIService([
        _analysis_response("Draft summary."),
        json.dumps(invalid_verification),
    ])

    result = analyzer.analyze(function=object(), monitor=None, verify=True)

    assert result.summary == "Draft summary."
    assert analyzer.last_verification.status == "invalid_provenance"
    assert analyzer.last_verification.failure is not None
    assert analyzer.last_evidence_validation.valid


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
