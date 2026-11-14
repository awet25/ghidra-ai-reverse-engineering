import pytest

from ghidra_ai.evidence_provenance import EvidenceProvenanceValidator
from ghidra_ai.models import AnalysisResult


@pytest.mark.parametrize(
    ("evidence", "catalog"),
    [
        ("[R0] The root contains this operation.", {"R0": "root"}),
        ("[RC1][S1-STR2] The root calls a supplied function.", {
            "RC1": "call relationship",
            "S1-STR2": "support string",
        }),
    ],
)
def test_validate_accepts_well_formed_citations_in_catalog(evidence, catalog):
    result = EvidenceProvenanceValidator().validate(
        AnalysisResult(summary="", suggested_name="", evidence=[evidence]),
        catalog,
    )

    assert result.valid
    assert result.valid_evidence == [evidence]
    assert result.invalid_evidence == []
    assert result.errors == []


@pytest.mark.parametrize(
    ("evidence", "catalog", "expected_error"),
    [
        ("Observation without citation.", {"R0": "root"}, "must begin"),
        ("[RC2] Unknown source.", {"R0": "root"}, "unknown source ID"),
        ("[r0] Invalid source format.", {"r0": "root"}, "malformed source ID"),
        ("[R0] claim [unclosed", {"R0": "root"}, "malformed citation brackets"),
        ("claim [R0]", {"R0": "root"}, "must begin"),
    ],
)
def test_validate_marks_invalid_citations(evidence, catalog, expected_error):
    result = EvidenceProvenanceValidator().validate(
        AnalysisResult(summary="", suggested_name="", evidence=[evidence]),
        catalog,
    )

    assert not result.valid
    assert result.invalid_evidence == [evidence]
    assert any(expected_error in error for error in result.errors)


def test_high_confidence_with_invalid_evidence_gets_syntax_only_diagnostic():
    result = EvidenceProvenanceValidator().validate(
        AnalysisResult(
            summary="",
            suggested_name="",
            confidence="high",
            suspicious_behaviors=["unsupported claim"],
            evidence=["[RC8] Missing source."],
        ),
        {"R0": "root"},
    )

    assert len(result.confidence_diagnostics) == 1
    assert "checks syntax" in result.confidence_diagnostics[0]
    assert "not semantic truth" in result.confidence_diagnostics[0]
