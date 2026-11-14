import requests


DEFAULT_NUM_CTX = 16384  # Total Ollama context window, including generated output.
DEFAULT_NUM_PREDICT = 1024  # Maximum generated response tokens.
DEFAULT_TIMEOUT_SECONDS = 480  # Allow cold prompt evaluation plus the full output budget.


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

    def analyze(self,prompt):
        self.last_diagnostics={}
        payload = {
            "model": self.model, "prompt": prompt, "format": "json", "stream": False,
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
