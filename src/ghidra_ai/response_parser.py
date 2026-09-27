import json
from .models import AnalysisResult

class ResponseParser:
    def parse(self, response):
        try:
            data=json.loads(response)
        except json.JSONDecodeError as error:
            raise ValueError("AI returned invalid JSON.") from error
        return AnalysisResult(
            
            summary=data.get("summary",""),
            suggested_name=data.get("suggested_name",""),
            suspicious_behaviors=data.get("suspicious_behaviors",[]),
            evidence=data.get("evidence",[]),
            confidence=data.get("confidence","unknown"),
            limitations=data.get("limitations",[])
            
            
            
        )