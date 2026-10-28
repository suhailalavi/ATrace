from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
from alavitrace.core.models import Confidence

class ValidationStatus(Enum):
    """
    Standardized validation statuses for AlaviTrace finding verification.
    """
    VALIDATED = "VALIDATED"
    NOT_VALIDATED = "NOT_VALIDATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

@dataclass
class ValidationResult:
    """
    Structured outcome of a deterministic, non-destructive validation check.
    Represents technical evidence gathered to confirm or refute a previously identified finding.
    """
    finding_id: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    vulnerability_id: Optional[str] = None
    owasp_category: Optional[str] = None
    status: ValidationStatus = ValidationStatus.INCONCLUSIVE
    confidence: Confidence = Confidence.INFORMATIONAL
    evidence: str = ""
    validation_method: str = "Unknown"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error_message: Optional[str] = None
    remediation_context: Optional[str] = None
    structured_evidence: Optional[Dict[str, Any]] = None
    limitations: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the validation result to a dictionary for reporting and AI integration."""
        data = {
            "finding_id": self.finding_id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "vulnerability_id": self.vulnerability_id,
            "owasp_category": self.owasp_category,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "validation_method": self.validation_method,
            "timestamp": self.timestamp,
            "error_message": self.error_message,
            "remediation_context": self.remediation_context
        }
        if self.structured_evidence:
            data["structured_evidence"] = self.structured_evidence
        if self.limitations:
            data["limitations"] = self.limitations
        return data
