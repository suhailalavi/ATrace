from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class AIAnalysisResult:
    """
    Structured response model containing AI-assisted security analysis and guidance.
    """
    executive_summary: str = ""
    attack_surface_summary: str = ""
    key_observations: List[str] = field(default_factory=list)
    investigation_priorities: List[str] = field(default_factory=list)
    remediation_summary: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    is_available: bool = True
    error_message: Optional[str] = None
