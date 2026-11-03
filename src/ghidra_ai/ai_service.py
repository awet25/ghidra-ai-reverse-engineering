import requests

class AIService:
    def __init__(self,model="ghidra-re",
                 base_url="http://localhost:11434"):
        self.model=model
        self.base_url=base_url

    def analyze(self,prompt):
        payload = {
            "model": self.model, "prompt": prompt, "format": "json", "stream": False,
        }
        response=requests.post(f"{self.base_url}/api/generate",
                            json=payload,timeout=120)
        response.raise_for_status()
        data=response.json()
        return data["response"]
