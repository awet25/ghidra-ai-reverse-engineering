import logging
from dataclasses import replace

from .context_extractor import ContextExtractor
from .prompt_builder import PromptBuilder
from .ai_service import AIService
from .response_parser import ResponseParser
from .evidence_provenance import EvidenceProvenanceValidator
from .analysis_verifier import AnalysisVerifier

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
# Opt-in diagnostic handlers can write to a file/Ghidra log; never script stderr.
logger.propagate = False

# A conservative character preflight for decompiler text, not an exact token count.
DEFAULT_MAX_PROMPT_CHARS = 30000

class FunctionAnalyzer:

    def __init__(self,program,*,max_prompt_chars=DEFAULT_MAX_PROMPT_CHARS):
        if not isinstance(max_prompt_chars, int) or isinstance(max_prompt_chars, bool) or max_prompt_chars <= 0:
            raise ValueError("max_prompt_chars must be a positive integer")
        self.extractor=ContextExtractor(program)
        self.prompt_builder=PromptBuilder()
        self.ai_service=AIService()
        self.response_parser=ResponseParser()
        self.last_source_catalog={}
        self.last_evidence_validation=None
        self.last_verification=None
        self.max_prompt_chars=max_prompt_chars
        self.last_prompt_budget_diagnostics=[]
    def analyze(self,function,monitor,supporting_functions=None,*,verify=False):
        # Do not expose stale diagnostics if extraction/transport/parsing fails.
        self.last_source_catalog={}
        self.last_evidence_validation=None
        self.last_verification=None
        self.last_prompt_budget_diagnostics=[]
        # Snapshot explicit selections once for extraction and evaluation logging.
        if supporting_functions is not None:
            supporting_functions=list(supporting_functions)
        if supporting_functions is None:
            context=self.extractor.extract(function,monitor)
        else:
            context=self.extractor.extract(
                function,monitor,supporting_functions=supporting_functions
            )
            # Separate diagnostics from the script's labeled AnalysisResult output.
            logger.info(
                "Supporting context for %s: accepted=%s",
                context.address,
                [(support.selected_address, support.address, support.depth)
                 for support in context.supporting_functions],
            )
            for reason in context.supporting_selection_errors:
                logger.warning("Supporting selection skipped: %s", reason)
            for support in context.supporting_functions:
                for reason in support.extraction_errors:
                    logger.warning("Supporting context %s: %s", support.address, reason)
        built=self._build_bounded_prompt(context)
        self.last_source_catalog=built.source_catalog
        response=self.ai_service.analyze(built.prompt)
        analysis=self.response_parser.parse(response)
        draft_provenance=EvidenceProvenanceValidator().validate(
            analysis,built.source_catalog
        )
        self.last_evidence_validation=draft_provenance
        for diagnostic in draft_provenance.errors + draft_provenance.confidence_diagnostics:
            logger.warning("draft evidence provenance (syntax only): %s",diagnostic)
        if not verify:
            return analysis

        self.last_verification=AnalysisVerifier(self.ai_service,self.response_parser).verify(
            built,analysis,draft_provenance,monitor
        )
        self.last_evidence_validation=(self.last_verification.verified_provenance
            if self.last_verification.status == "completed" else draft_provenance)
        validation=self.last_verification.verified_provenance
        if validation is not None:
            for diagnostic in validation.errors + validation.confidence_diagnostics:
                logger.warning("verification evidence provenance (syntax only): %s",diagnostic)
        if self.last_verification.failure:
            logger.warning("Semantic verification unavailable; showing unverified draft: %s",
                           self.last_verification.failure)
        return self.last_verification.result

    def _build_bounded_prompt(self,context):
        """Bound support code equally; never trim the root, relationships, or source IDs."""
        limit=getattr(self,"max_prompt_chars",DEFAULT_MAX_PROMPT_CHARS)
        built=self.prompt_builder.build_prompt_with_sources(context)
        if len(built.prompt) <= limit:
            return built

        def build_with_cap(cap):
            supports=[]
            for support in context.supporting_functions:
                code=support.decompiled_code[:cap]
                errors=list(support.extraction_errors)
                reduced=len(code) < len(support.decompiled_code)
                if reduced:
                    errors.append(f"Prompt budget: supporting code truncated from "
                                  f"{len(support.decompiled_code)} to {len(code)} characters.")
                supports.append(replace(support,decompiled_code=code,
                                        code_truncated=support.code_truncated or reduced,
                                        extraction_errors=errors))
            bounded=replace(context,supporting_functions=supports)
            return bounded,self.prompt_builder.build_prompt_with_sources(bounded)

        bounded,minimum=build_with_cap(0)
        if len(minimum.prompt) > limit:
            # Refuse the request rather than discard root/identity/string evidence.
            raise ValueError(f"Prompt exceeds the {limit}-character budget even with supporting "
                             "code removed. Root context was preserved; reduce selected context "
                             "or configure a larger prompt budget and Ollama context window.")
        count=max(1,len(context.supporting_functions))
        cap=(limit-len(minimum.prompt))//count
        bounded,built=build_with_cap(cap)
        while len(built.prompt) > limit:
            # Account for diagnostic formatting without assuming characters per token.
            cap=max(0,cap-(len(built.prompt)-limit+count-1)//count)
            bounded,built=build_with_cap(cap)
        for original,support in zip(context.supporting_functions,bounded.supporting_functions):
            if len(support.decompiled_code) < len(original.decompiled_code):
                message=(f"PROMPT BUDGET: {support.name} @ {support.address}: supporting code "
                         f"truncated from {len(original.decompiled_code)} to "
                         f"{len(support.decompiled_code)} characters; root preserved.")
                self.last_prompt_budget_diagnostics.append(message)
                logger.info("%s",message)
        return built

    def close(self):
        self.extractor.close()
