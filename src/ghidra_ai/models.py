from dataclasses import dataclass, field


@dataclass
class FunctionContext:
    name: str
    address: str
    decompiled_code: str
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    
@dataclass
class AnalysisResult:
    summary: str
    suggested_name: str
    suspicious_behaviors:list[str]=field(default_factory=list)
    evidence:list[str]=field(default_factory=list)
    confidence:str="unknown"
    limitations:list[str]=field(default_factory=list)
    