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