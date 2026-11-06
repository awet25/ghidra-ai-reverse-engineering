from dataclasses import dataclass, field


@dataclass
class CallSiteContext:
    """Observations from one High P-code CALL/CALLIND, not source-level claims."""

    address: str | None
    call_kind: str
    argument_count: int
    pcode_time: int | None = None
    argument_provenance: list[str] = field(default_factory=list)
    has_output: bool = False
    return_consumed: bool = False
    return_uses: list[str] = field(default_factory=list)
    target_status: str = "unresolved"
    target_address: str | None = None


@dataclass
class CalleePreview:
    """Generic Ghidra metadata for one body; body_size counts address units."""

    name: str
    address: str
    body_size: int
    instruction_count: int = 0
    internal_callee_count: int = 0
    external_callee_count: int = 0
    strings: list[str] = field(default_factory=list)
    strings_truncated: bool = False
    pcode_counts: dict[str, int] | None = None  # Raw instruction P-code, not High P-code.
    decompilation_succeeded: bool | None = None  # None: not attempted for previews.
    errors: list[str] = field(default_factory=list)
    basic_block_count: int | None = None
    direct_call_site_count: int = 0
    parameter_count: int | None = None
    has_return_value: bool | None = None
    signature_source: str | None = None
    is_external: bool = False
    is_thunk: bool = False
    thunk_target_address: str | None = None

    @property
    def metadata_incomplete(self) -> bool:
        return bool(
            self.errors or self.strings_truncated or self.pcode_counts is None
            or self.basic_block_count is None or self.parameter_count is None
            or self.has_return_value is None
            or (self.body_size > 0 and self.instruction_count == 0)
        )

    @property
    def contains_callind(self) -> bool | None:
        return None if self.pcode_counts is None else self.pcode_counts["CALLIND"] > 0


@dataclass
class CalleeContext:
    """A referenced call destination; thunk identity is kept separately from its target."""

    name: str
    address: str
    is_external: bool = False
    is_thunk: bool = False
    call_count: int = 0
    thunk_target_name: str | None = None
    thunk_target_address: str | None = None
    thunk_target_is_external: bool | None = None
    call_sites: list[CallSiteContext] = field(default_factory=list)
    preview: CalleePreview | None = None
    preview_error: str | None = None

    @property
    def pcode_call_count(self) -> int:
        return len(self.call_sites)


@dataclass
class SupportingFunctionContext:
    """Bounded context for an explicitly selected, validated depth-one function."""

    name: str
    address: str
    decompiled_code: str = ""
    depth: int = 1
    parent_address: str | None = None
    selected_address: str | None = None
    called_addresses: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    decompilation_succeeded: bool = False
    code_truncated: bool = False
    strings_truncated: bool = False
    extraction_errors: list[str] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        return bool(
            not self.decompilation_succeeded or self.code_truncated
            or self.strings_truncated or self.extraction_errors
        )


@dataclass
class FunctionContext:
    name: str
    address: str
    decompiled_code: str
    strings: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    callee_contexts: list[CalleeContext] = field(default_factory=list)
    indirect_call_sites: list[CallSiteContext] = field(default_factory=list)
    unmatched_call_sites: list[CallSiteContext] = field(default_factory=list)
    extraction_errors: list[str] = field(default_factory=list)
    depth: int = 0
    supporting_functions: list[SupportingFunctionContext] = field(default_factory=list)
    supporting_selection_errors: list[str] = field(default_factory=list)

@dataclass
class PromptBuildResult:
    """One prompt and its exact source bodies; IDs are local to this prompt."""

    prompt: str
    source_catalog: dict[str, str] = field(default_factory=dict)


@dataclass
class EvidenceValidationResult:
    """Citation syntax/membership diagnostics, never a semantic truth assessment."""

    valid: bool
    valid_evidence: list[str] = field(default_factory=list)
    invalid_evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    confidence_diagnostics: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    summary: str
    suggested_name: str
    suspicious_behaviors:list[str]=field(default_factory=list)
    evidence:list[str]=field(default_factory=list)
    confidence:str="unknown"
    limitations:list[str]=field(default_factory=list)


@dataclass
class AnalysisVerificationResult:
    """Second-pass diagnostics; completion means model review, not proven truth."""

    draft: AnalysisResult
    draft_provenance: EvidenceValidationResult
    status: str = "unavailable"
    verified_result: AnalysisResult | None = None
    verified_provenance: EvidenceValidationResult | None = None
    failure: str | None = None
    latency_seconds: float = 0.0
    raw_response: str | None = None

    @property
    def result(self) -> AnalysisResult:
        return (self.verified_result if self.status == "completed" and self.verified_result is not None
                else self.draft)
