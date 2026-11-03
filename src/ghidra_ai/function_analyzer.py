from .context_extractor import ContextExtractor
from .prompt_builder import PromptBuilder
from .ai_service import AIService
from .response_parser import ResponseParser

class FunctionAnalyzer:

    def __init__(self,program):
        self.extractor=ContextExtractor(program)
        self.prompt_builder=PromptBuilder()
        self.ai_service=AIService()
        self.response_parser=ResponseParser()
    def analyze(self,function,monitor):
        context=self.extractor.extract(function,monitor)
        prompt=self.prompt_builder.build_prompt(context)
        response=self.ai_service.analyze(prompt)
        analysis=self.response_parser.parse(response)
        return analysis
    def close(self):
        self.extractor.close()
