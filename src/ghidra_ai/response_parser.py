import json
from .models import AnalysisResult

class ResponseParser:
    def parse(self, response):
        try:
            data=json.loads(response)
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("AI returned invalid JSON.") from error
        if not isinstance(data, dict):
            raise ValueError("AI response must be a JSON object.")

        for field in ("summary", "suggested_name", "confidence"):
            if field in data and not isinstance(data[field], str):
                raise ValueError(f"AI response field '{field}' must be a string.")

        for field in ("suspicious_behaviors", "evidence", "limitations"):
            if field in data:
                value = data[field]
                if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value
                ):
                    raise ValueError(
                        f"AI response field '{field}' must be a list of strings."
                    )

        if data.get("confidence", "unknown") not in {"low", "medium", "high", "unknown"}:
            raise ValueError("AI response field 'confidence' has an invalid value.")

        return AnalysisResult(
            
            summary=data.get("summary",""),
            suggested_name=data.get("suggested_name",""),
            suspicious_behaviors=data.get("suspicious_behaviors",[]),
            evidence=data.get("evidence",[]),
            confidence=data.get("confidence","unknown"),
            limitations=data.get("limitations",[])
            
            
            
        )
