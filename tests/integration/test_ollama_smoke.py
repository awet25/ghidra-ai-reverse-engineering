import os

import pytest
import requests

from ghidra_ai.ai_service import AIService
from ghidra_ai.models import FunctionContext
from ghidra_ai.prompt_builder import PromptBuilder
from ghidra_ai.response_parser import ResponseParser


pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.environ.get("GHIDRA_AI_RUN_OLLAMA_SMOKE") != "1",
    reason="Set GHIDRA_AI_RUN_OLLAMA_SMOKE=1 to call a local Ollama model.",
)
def test_local_ollama_returns_parseable_analysis():
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.environ.get("GHIDRA_AI_MODEL", "ghidra-re")
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=3)
    except (requests.ConnectionError, requests.Timeout) as error:
        pytest.skip(f"Local Ollama is unavailable: {error}")
    response.raise_for_status()
    available_models = response.json().get("models", [])
    if not any(item.get("name", "").split(":")[0] == model for item in available_models):
        pytest.skip(f"Ollama model '{model}' is not installed.")

    context = FunctionContext(
        name="add_values",
        address="1000",
        decompiled_code="int add_values(int left, int right) { return left + right; }",
    )
    prompt = PromptBuilder().build_prompt(context)
    response_text = AIService(
        model=model,
        base_url=base_url,
        timeout=240,
    ).analyze(prompt)

    result = ResponseParser().parse(response_text)

    assert result.vulnerability_classification.strip()
    assert result.vulnerable_code_isolation.strip()
    assert result.root_cause_impact_analysis.strip()
    assert result.remediation_patch_verification.strip()
