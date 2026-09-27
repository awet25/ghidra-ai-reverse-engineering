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


Return ONLY valid JSON using exactly this structure:
{{
    "summary":"brief explanation of the function",
    "suggested_name":"descriptive_function_name",
    "suspicious_behaviors":[],
    "evidence":[],
    "confidence":"low | medium | high",
    "limitations":[]
    
}}
   Rules:

- Do not return Markdown.
- Do not return text outside the JSON object.
- Base conclusions only on the provided evidence.
- Do not invent APIs, strings, or behaviors.
- If behavior cannot be determined, state that in limitations.
- Do not label behavior malicious merely because system APIs are used.
        
        """
        
        return  prompt.strip()
    def _format_list(self, values:list[str]):
        if not values:
            return "None"
        
        return "\n".join(f"-{value}" for value in values)