import requests


DEFAULT_NUM_CTX = 16384  # Total Ollama context window, including generated output.
DEFAULT_NUM_PREDICT = 1024  # Maximum generated response tokens.
DEFAULT_TIMEOUT_SECONDS = 480  # Allow cold prompt evaluation plus the full output budget.
REPORT_SYSTEM_PROMPT = """You analyze only the source context in the user prompt.
Do not use external or remembered CVEs, code, or facts. Return exactly these four
Markdown sections, in order, and no other text:
### 1. Vulnerability Classification
### 2. Vulnerable Code Isolation
### 3. Root Cause & Impact Analysis
### 4. Remediation & Patch Verification
Keep each narrative section concise. If a vulnerability is not established by the
provided source, say so instead of inventing one."""
CONTINUATION_SYSTEM_PROMPT = """Continue an incomplete four-section Markdown analysis report.
Use only the source context and partial report in the user prompt. Return only the
requested missing trailing section(s), with their exact numbered headings. Do not
repeat existing sections or add a preamble, conclusion, or unsupported claims."""


class AIService:
    def __init__(self,model="ghidra-re",
                 base_url="http://localhost:11434", *,
                 num_ctx=DEFAULT_NUM_CTX, num_predict=DEFAULT_NUM_PREDICT,
                 diagnostic_output=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        if not (isinstance(num_ctx, int) and isinstance(num_predict, int)
                and not isinstance(num_ctx, bool) and not isinstance(num_predict, bool)
                and 0 < num_predict < num_ctx):
            raise ValueError("Ollama requires 0 < num_predict < num_ctx")
        self.model=model
        self.base_url=base_url
        self.num_ctx=num_ctx
        self.num_predict=num_predict
        self.diagnostic_output=diagnostic_output
        self.timeout=timeout
        self.last_diagnostics={}

    def analyze(self,prompt, *, system_prompt=REPORT_SYSTEM_PROMPT):
        self.last_diagnostics={}
        payload = {
            "model": self.model, "system": system_prompt,
            "prompt": prompt, "stream": False,
            "options": {"num_ctx": self.num_ctx, "num_predict": self.num_predict},
        }
        response=requests.post(f"{self.base_url}/api/generate",
                            json=payload,timeout=self.timeout)
        response.raise_for_status()
        data=response.json()
        if not isinstance(data, dict) or not isinstance(data.get("response"), str):
            raise ValueError("Ollama response must contain a string 'response' field.")
        self.last_diagnostics={"num_ctx": self.num_ctx, "num_predict": self.num_predict,
                               "prompt_chars": len(prompt)}
        for key in ("prompt_eval_count", "eval_count", "total_duration"):
            value=data.get(key)
            # Optional transport metadata must not prevent parsing the model response.
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                self.last_diagnostics[key]=value
        done_reason = data.get("done_reason")
        if isinstance(done_reason, str):
            self.last_diagnostics["done_reason"] = done_reason
        if done_reason == "length":
            raise ValueError(
                f"Ollama response reached the {self.num_predict}-token output limit. "
                "Reduce the requested report or increase num_predict."
            )
        if self.diagnostic_output is not None:
            try:
                self.diagnostic_output(
                    f"OLLAMA:\ncontext window: {self.num_ctx}\n"
                    f"prompt tokens evaluated: {self.last_diagnostics.get('prompt_eval_count', 'unavailable')}\n"
                    f"response tokens: {self.last_diagnostics.get('eval_count', 'unavailable')}"
                )
            except Exception:
                pass  # Console diagnostics must not fail an otherwise successful request.
        return data["response"]
