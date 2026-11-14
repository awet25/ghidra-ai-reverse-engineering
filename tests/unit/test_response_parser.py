import json

import pytest

from ghidra_ai.models import AnalysisResult
from ghidra_ai.response_parser import ResponseParser


def test_parse_returns_all_six_analysis_fields():
    response = json.dumps({
        "summary": "Copies a value.",
        "suggested_name": "copy_value",
        "suspicious_behaviors": ["Writes to a fixed address."],
        "evidence": ["[R0] The function writes to the destination."],
        "confidence": "medium",
        "limitations": ["The destination meaning is unknown."],
    })

    result = ResponseParser().parse(response)

    assert result == AnalysisResult(
        summary="Copies a value.",
        suggested_name="copy_value",
        suspicious_behaviors=["Writes to a fixed address."],
        evidence=["[R0] The function writes to the destination."],
        confidence="medium",
        limitations=["The destination meaning is unknown."],
    )


@pytest.mark.parametrize("response", ["not JSON", None, "[]", "null", '"string"'])
def test_parse_rejects_invalid_json_and_non_object_responses(response):
    with pytest.raises(ValueError):
        ResponseParser().parse(response)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("summary", [], "must be a string"),
        ("suggested_name", None, "must be a string"),
        ("confidence", 1, "must be a string"),
        ("suspicious_behaviors", "not a list", "must be a list of strings"),
        ("evidence", ["valid", 3], "must be a list of strings"),
        ("limitations", [None], "must be a list of strings"),
        ("confidence", "certain", "has an invalid value"),
    ],
)
def test_parse_rejects_fields_with_invalid_types_or_values(field, value, message):
    with pytest.raises(ValueError, match=message):
        ResponseParser().parse(json.dumps({field: value}))


def test_parse_uses_defaults_for_omitted_fields():
    result = ResponseParser().parse("{}")

    assert result == AnalysisResult(summary="", suggested_name="")
