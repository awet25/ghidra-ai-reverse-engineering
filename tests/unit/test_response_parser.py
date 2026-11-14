import pytest

from ghidra_ai.models import AnalysisResult
from ghidra_ai.response_parser import IncompleteReportError, ResponseParser


REPORT = """### 1. Vulnerability Classification
Potential out-of-bounds write.

### 2. Vulnerable Code Isolation
```c
buffer[index] = value;
```

### 3. Root Cause & Impact Analysis
The index is not checked against the buffer length.

### 4. Remediation & Patch Verification
Check the index before the write and verify boundary cases."""


def test_parse_extracts_all_four_markdown_sections():
    result = ResponseParser().parse(REPORT)

    assert result == AnalysisResult(
        vulnerability_classification="Potential out-of-bounds write.",
        vulnerable_code_isolation="```c\nbuffer[index] = value;\n```",
        root_cause_impact_analysis="The index is not checked against the buffer length.",
        remediation_patch_verification=(
            "Check the index before the write and verify boundary cases."
        ),
    )


def test_parse_accepts_an_outer_markdown_fence():
    result = ResponseParser().parse(f"```markdown\n{REPORT}\n```")

    assert result.vulnerability_classification == "Potential out-of-bounds write."
    assert result.remediation_patch_verification.endswith("boundary cases.")


def test_heading_like_text_inside_code_fence_is_kept_as_section_content():
    report = REPORT.replace(
        "buffer[index] = value;",
        "buffer[index] = value;\n### 3. Root Cause & Impact Analysis",
    )

    result = ResponseParser().parse(report)

    assert "### 3. Root Cause & Impact Analysis" in result.vulnerable_code_isolation
    assert result.root_cause_impact_analysis.startswith("The index")


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ("not a report", "four-section Markdown report"),
        (None, "four-section Markdown report"),
        (REPORT.replace("### 4. Remediation & Patch Verification", ""),
         "missing required report heading"),
        (REPORT.replace("### 2. Vulnerable Code Isolation", "### 1. Vulnerability Classification"),
         "duplicate report heading"),
        ("### 1. Vulnerability Classification\n\n"
         "### 2. Vulnerable Code Isolation\ncode\n"
         "### 3. Root Cause & Impact Analysis\ncause\n"
         "### 4. Remediation & Patch Verification\nfix",
         "section 'Vulnerability Classification' is empty"),
    ],
)
def test_parse_rejects_malformed_or_incomplete_reports(response, message):
    with pytest.raises(ValueError, match=message):
        ResponseParser().parse(response)


def test_parse_rejects_sections_out_of_order():
    reordered = REPORT.replace(
        "### 2. Vulnerable Code Isolation",
        "### TEMP SECTION",
    ).replace(
        "### 3. Root Cause & Impact Analysis",
        "### 2. Vulnerable Code Isolation",
    ).replace(
        "### TEMP SECTION",
        "### 3. Root Cause & Impact Analysis",
    )

    with pytest.raises(ValueError, match="out of order"):
        ResponseParser().parse(reordered)


def test_parse_marks_only_missing_trailing_sections_as_continuable():
    partial = REPORT.replace(
        "\n### 4. Remediation & Patch Verification\n"
        "Check the index before the write and verify boundary cases.",
        "",
    )

    with pytest.raises(IncompleteReportError) as error:
        ResponseParser().parse(partial)

    assert error.value.missing_headings == ("Remediation & Patch Verification",)

    non_trailing = partial.replace(
        "### 2. Vulnerable Code Isolation\n```c\nbuffer[index] = value;\n```",
        "",
    )
    with pytest.raises(ValueError, match="missing required report heading"):
        ResponseParser().parse(non_trailing)
