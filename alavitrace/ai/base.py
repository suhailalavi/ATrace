from abc import ABC, abstractmethod
from typing import Dict, Any
from alavitrace.ai.models import AIAnalysisResult

class AIProvider(ABC):
    """
    Abstract base class for AI security analysis providers.
    """

    @abstractmethod
    def analyze_security_data(self, structured_input: Dict[str, Any]) -> AIAnalysisResult:
        """
        Analyzes structured security scan data and returns an AIAnalysisResult.
        """
        pass
