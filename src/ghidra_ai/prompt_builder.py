from .models import FunctionContext


class PromptBuilder:
    def build_prompt(self,context:FunctionContext):
        callers=self._format_list(context.callers)
        callees=self._format_list(context.callees)
        strings=self._format_list(context.strings)
        prompt=f"""
        
        You are assisting a reverse engineer analyzing a function
decompiled by Ghidra.

Analyze only the evidence provided below.
Do not invent behavior that is not supported by the evidence.

FUNCTION NAME:
{context.name}

FUNCTION ADDRESS:
{context.address}

CALLERS:
{callers}

CALLEES:
{callees}

REFERENCED STRINGS:
{strings}

DECOMPILED C CODE:
{context.decompiled_code}
        
        """
        
        return  prompt.strip()
    def _format_list(self, values:list[str]):
        if not values:
            return "None"
        
        return "\n".join(f"-{value}" for value in values)