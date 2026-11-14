from ghidra_ai.models import (
    CalleeContext,
    FunctionContext,
    SupportingFunctionContext,
)
from ghidra_ai.prompt_builder import PromptBuilder


def test_prompt_assigns_stable_source_ids_to_sorted_supports():
    later = SupportingFunctionContext(
        name="later",
        address="3000",
        decompiled_code="later implementation",
    )
    earlier = SupportingFunctionContext(
        name="earlier",
        address="2000",
        decompiled_code="earlier implementation",
    )
    context = FunctionContext(
        name="root",
        address="1000",
        decompiled_code="root implementation",
        callee_contexts=[
            CalleeContext(name="later", address="3000", call_count=1),
            CalleeContext(name="earlier", address="2000", call_count=2),
        ],
        supporting_functions=[later, earlier],
    )

    result = PromptBuilder().build_prompt_with_sources(context)

    assert "SOURCE S1" in result.prompt
    assert "SOURCE S2" in result.prompt
    assert "earlier implementation" in result.source_catalog["S1"]
    assert "later implementation" in result.source_catalog["S2"]
    assert "Resolved support: S1." in result.source_catalog["RC1"]
    assert "Resolved support: S2." in result.source_catalog["RC2"]
