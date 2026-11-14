import re

from .models import AnalysisResult


class IncompleteReportError(ValueError):
    def __init__(self, missing_headings):
        self.missing_headings = tuple(missing_headings)
        super().__init__(
            "AI response is missing required report heading(s): "
            + ", ".join(self.missing_headings)
        )


class ResponseParser:
    _headings = (
        (
            "vulnerability_classification",
            "Vulnerability Classification",
            re.compile(r"^\s*#{1,6}\s*(?:1[.)]\s*)?Vulnerability Classification\s*#*\s*$", re.I),
        ),
        (
            "vulnerable_code_isolation",
            "Vulnerable Code Isolation",
            re.compile(r"^\s*#{1,6}\s*(?:2[.)]\s*)?Vulnerable Code Isolation\s*#*\s*$", re.I),
        ),
        (
            "root_cause_impact_analysis",
            "Root Cause & Impact Analysis",
            re.compile(r"^\s*#{1,6}\s*(?:3[.)]\s*)?Root Cause & Impact Analysis\s*#*\s*$", re.I),
        ),
        (
            "remediation_patch_verification",
            "Remediation & Patch Verification",
            re.compile(r"^\s*#{1,6}\s*(?:4[.)]\s*)?Remediation & Patch Verification\s*#*\s*$", re.I),
        ),
    )

    def parse(self, response):
        if not isinstance(response, str):
            raise ValueError("AI response must be a four-section Markdown report.")

        lines = response.strip().splitlines()
        if len(lines) >= 2 and lines[0].strip().lower() in {
            "```", "```markdown", "```md",
        } and lines[-1].strip() == "```":
            lines = lines[1:-1]

        found = {}
        in_code_fence = False
        for index, line in enumerate(lines):
            if line.strip().startswith("```"):
                in_code_fence = not in_code_fence
                continue
            if in_code_fence:
                continue
            for field, heading, pattern in self._headings:
                if pattern.fullmatch(line):
                    if field in found:
                        raise ValueError(f"AI response has duplicate report heading '{heading}'.")
                    found[field] = (heading, index)
                    break

        if not found:
            raise ValueError("AI response must be a four-section Markdown report.")

        missing = [
            heading for field, heading, _ in self._headings
            if field not in found
        ]
        if missing:
            found_fields = [field for field, _, _ in self._headings if field in found]
            is_trailing_incomplete = (
                found_fields == [field for field, _, _ in self._headings[:len(found_fields)]]
                and not in_code_fence
            )
            if is_trailing_incomplete:
                self._validate_nonempty_sections(lines, found)
                raise IncompleteReportError(missing)
            raise ValueError(
                "AI response is missing required report heading(s): " + ", ".join(missing)
            )
        heading_positions = [found[field][1] for field, _, _ in self._headings]
        if heading_positions != sorted(heading_positions):
            raise ValueError("AI response report headings are out of order.")

        sections = self._extract_sections(lines, found)
        return AnalysisResult(**sections)

    def _validate_nonempty_sections(self, lines, found):
        for field, heading, _ in self._headings:
            if field not in found:
                break
            start = found[field][1] + 1
            next_fields = [item[0] for item in self._headings]
            position = next_fields.index(field)
            end = (found[next_fields[position + 1]][1]
                   if position + 1 < len(next_fields)
                   and next_fields[position + 1] in found else len(lines))
            if not "\n".join(lines[start:end]).strip():
                raise ValueError(f"AI response section '{heading}' is empty.")

    def _extract_sections(self, lines, found):
        sections = {}
        for position, (field, heading, _) in enumerate(self._headings):
            start = found[field][1] + 1
            end = (found[self._headings[position + 1][0]][1]
                   if position + 1 < len(self._headings) else len(lines))
            content = "\n".join(lines[start:end]).strip()
            if not content:
                raise ValueError(f"AI response section '{heading}' is empty.")
            sections[field] = content
        return sections
