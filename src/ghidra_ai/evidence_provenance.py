"""Validate source citations only. A valid citation does not establish a claim's truth."""

from collections.abc import Mapping
import re

from .models import AnalysisResult, EvidenceValidationResult


class EvidenceProvenanceValidator:
    # Square brackets are reserved for citations in evidence strings (not in code sources).
    _citation = re.compile(r"\[([^\[\]]*)\]")
    _source_id = re.compile(r"(?:R0|RC[1-9][0-9]*|RS[1-9][0-9]*|S[1-9][0-9]*(?:-STR[1-9][0-9]*)?)")

    def validate(self, analysis: AnalysisResult, source_catalog: Mapping[str, str]):
        result = EvidenceValidationResult(valid=True)
        for index, evidence in enumerate(analysis.evidence, 1):
            citations = list(self._citation.finditer(evidence))
            errors = []
            if not citations or citations[0].start() != len(evidence) - len(evidence.lstrip()):
                errors.append("must begin with one or more source citations")
            remainder = self._citation.sub("", evidence)
            if "[" in remainder or "]" in remainder:
                errors.append("malformed citation brackets")
            for citation in citations:
                source_id = citation.group(1)
                if not self._source_id.fullmatch(source_id):
                    errors.append(f"malformed source ID {source_id!r}")
                elif source_id not in source_catalog:
                    errors.append(f"unknown source ID {source_id!r}")
            if errors:
                result.invalid_evidence.append(evidence)
                result.errors.extend(f"Evidence {index}: {error}." for error in errors)
            else:
                result.valid_evidence.append(evidence)
        result.valid = not result.invalid_evidence
        if analysis.confidence == "high":
            reasons = []
            if not result.valid:
                reasons.append("evidence provenance validation failed")
            if analysis.suspicious_behaviors and not result.valid_evidence:
                reasons.append("suspicious_behaviors is non-empty with no valid cited evidence")
            if reasons:
                result.confidence_diagnostics.append(
                    "High confidence is poorly supported: " + "; ".join(reasons) + ". "
                    "Citation validation checks syntax and supplied IDs only, not semantic truth."
                )
        return result
