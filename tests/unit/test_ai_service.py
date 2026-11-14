import pytest
import requests

from ghidra_ai.ai_service import AIService, REPORT_SYSTEM_PROMPT


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


def test_analyze_sends_ollama_payload_and_records_diagnostics(monkeypatch):
    calls = []
    model_response = "### 1. Vulnerability Classification\nNo vulnerability identified."
    monkeypatch.setattr(
        "ghidra_ai.ai_service.requests.post",
        lambda url, *, json, timeout: (
            calls.append((url, json, timeout))
            or FakeResponse({
                "response": model_response,
                "prompt_eval_count": 12,
                "eval_count": 5,
                "total_duration": 99,
            })
        ),
    )
    service = AIService(
        model="local-model",
        base_url="http://ollama.local",
        num_ctx=2048,
        num_predict=256,
        timeout=30,
    )

    result = service.analyze("analyze this function")

    assert result == model_response
    assert calls == [(
        "http://ollama.local/api/generate",
        {
            "model": "local-model",
            "system": REPORT_SYSTEM_PROMPT,
            "prompt": "analyze this function",
            "stream": False,
            "options": {"num_ctx": 2048, "num_predict": 256},
        },
        30,
    )]
    assert service.last_diagnostics == {
        "num_ctx": 2048,
        "num_predict": 256,
        "prompt_chars": 21,
        "prompt_eval_count": 12,
        "eval_count": 5,
        "total_duration": 99,
    }


@pytest.mark.parametrize(
    ("num_ctx", "num_predict"),
    [(0, 0), (100, 100), (100, 101), (True, 1), (100, False), (10.5, 1)],
)
def test_constructor_rejects_invalid_context_limits(num_ctx, num_predict):
    with pytest.raises(ValueError, match="0 < num_predict < num_ctx"):
        AIService(num_ctx=num_ctx, num_predict=num_predict)


def test_analyze_propagates_http_errors(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.HTTPError("server error")

    monkeypatch.setattr("ghidra_ai.ai_service.requests.post", fail)
    service = AIService()

    with pytest.raises(requests.HTTPError, match="server error"):
        service.analyze("prompt")


@pytest.mark.parametrize(
    "data",
    [{}, {"response": None}, {"response": 1}, []],
)
def test_analyze_rejects_missing_or_invalid_response_field(monkeypatch, data):
    monkeypatch.setattr(
        "ghidra_ai.ai_service.requests.post",
        lambda *args, **kwargs: FakeResponse(data),
    )

    with pytest.raises(ValueError, match="string 'response' field"):
        AIService().analyze("prompt")


def test_diagnostic_callback_failure_does_not_fail_successful_request(monkeypatch):
    monkeypatch.setattr(
        "ghidra_ai.ai_service.requests.post",
        lambda *args, **kwargs: FakeResponse({"response": "ok"}),
    )

    def fail(_message):
        raise RuntimeError("diagnostic sink failed")

    service = AIService(diagnostic_output=fail)

    assert service.analyze("prompt") == "ok"


def test_analyze_surfaces_ollama_output_limit(monkeypatch):
    monkeypatch.setattr(
        "ghidra_ai.ai_service.requests.post",
        lambda *args, **kwargs: FakeResponse({
            "response": "partial report",
            "done_reason": "length",
            "eval_count": 1024,
        }),
    )
    service = AIService()

    with pytest.raises(ValueError, match="reached the 1024-token output limit"):
        service.analyze("prompt")

    assert service.last_diagnostics["done_reason"] == "length"
