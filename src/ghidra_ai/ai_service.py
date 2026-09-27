import requests

class AIService:
    def __init__(self,model="qwen2.5-coder:7b-instruct",
                 base_url="http://localhost:11434"):
        self.model=model
        self.base_url=base_url
        
    def analyze(self,prompt):
        response=requests.post(f"{self.base_url}/api/generate",
                            json={
                                "model":self.model,
                                "prompt":prompt,
                                "format":"json",
                                "stream":False
                            },timeout=120  )
        response.raise_for_status()
        data=response.json()
        return data["response"]
        