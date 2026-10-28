from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

from alavitrace.core.models import Target, ScanResult, HttpResult, Finding, Severity, Confidence

class OwaspCategory(Enum):
    """
    Standard OWASP Top 10 (2021) categories.
    """
    A01_2021 = "A01:2021 - Broken Access Control"
    A02_2021 = "A02:2021 - Cryptographic Failures"
    A03_2021 = "A03:2021 - Injection"
    A04_2021 = "A04:2021 - Insecure Design"
    A05_2021 = "A05:2021 - Security Misconfiguration"
    A06_2021 = "A06:2021 - Vulnerable and Outdated Components"
    A07_2021 = "A07:2021 - Identification and Authentication Failures"
    A08_2021 = "A08:2021 - Software and Data Integrity Failures"
    A09_2021 = "A09:2021 - Security Logging and Monitoring Failures"
    A10_2021 = "A10:2021 - Server-Side Request Forgery"

    @property
    def code(self) -> str:
        """Returns the category code, e.g. 'A01:2021'."""
        return self.value.split(" - ")[0]

class CategorySupportStatus(Enum):
    """
    Tracks assessment engine support readiness for each OWASP category.
    """
    SUPPORTED = "Supported"
    LIMITED = "Limited / Future"

CATEGORY_SUPPORT_STATUS: Dict[OwaspCategory, CategorySupportStatus] = {
    OwaspCategory.A01_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A02_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A03_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A04_2021: CategorySupportStatus.LIMITED,
    OwaspCategory.A05_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A06_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A07_2021: CategorySupportStatus.SUPPORTED,
    OwaspCategory.A08_2021: CategorySupportStatus.LIMITED,
    OwaspCategory.A09_2021: CategorySupportStatus.LIMITED,
    OwaspCategory.A10_2021: CategorySupportStatus.SUPPORTED,
}

def get_supported_categories() -> List[OwaspCategory]:
    """Returns the list of OWASP categories currently supported or targeted by AlaviTrace."""
    return [cat for cat, status in CATEGORY_SUPPORT_STATUS.items() if status == CategorySupportStatus.SUPPORTED]

def is_category_supported(category: OwaspCategory) -> bool:
    """Checks if a given OWASP category is actively supported by AlaviTrace."""
    return CATEGORY_SUPPORT_STATUS.get(category) == CategorySupportStatus.SUPPORTED

class DetectionType(Enum):
    """
    Identifies how an OWASP assessment finding was identified.
    """
    PASSIVE = "passive"
    ACTIVE = "active"
    CORRELATED = "correlated"

@dataclass
class OWASPFinding(Finding):
    """
    Structured OWASP Web Security Assessment finding extending the core Finding model.
    Maintains full compatibility with core Finding consumers while providing
    OWASP category, endpoint, method, parameter, and detection type attributes.
    """

    @classmethod
    def create(
        cls,
        id: str,
        title: str,
        owasp_category: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        evidence: str,
        affected_asset: str,
        endpoint: Optional[str] = None,
        http_method: Optional[str] = "GET",
        parameter: Optional[str] = None,
        detection_type: str = "passive",
        recommendation: str = "",
        limitations: str = "",
        references: Optional[List[str]] = None,
        source: str = "AlaviTrace OWASP Engine",
        category: str = "OWASP Web Security",
        affected_port: Optional[int] = None,
        affected_service: Optional[str] = None
    ) -> "OWASPFinding":
        """Convenience factory method for constructing an OWASPFinding."""
        derived_port = affected_port
        derived_service = affected_service
        if derived_port is None or derived_service is None:
            url_to_parse = endpoint or affected_asset
            if url_to_parse and (url_to_parse.startswith("http://") or url_to_parse.startswith("https://")):
                try:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(url_to_parse)
                    if derived_port is None:
                        derived_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    if derived_service is None:
                        derived_service = parsed.scheme.upper()
                except Exception:
                    pass

        return cls(
            id=id,
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            affected_asset=affected_asset,
            affected_port=derived_port,
            affected_service=derived_service,
            recommendation=recommendation,
            references=references or [],
            source=source,
            owasp_category=owasp_category,
            endpoint=endpoint,
            http_method=http_method,
            parameter=parameter,
            detection_type=detection_type,
            limitations=limitations
        )

    @property
    def target(self) -> str:
        """Convenience property referencing affected_asset."""
        return self.affected_asset

    @property
    def method(self) -> Optional[str]:
        """Convenience property referencing http_method."""
        return self.http_method

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the OWASP finding to a structured dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "owasp_category": self.owasp_category,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "target": self.affected_asset,
            "affected_asset": self.affected_asset,
            "affected_port": self.affected_port,
            "affected_service": self.affected_service,
            "endpoint": self.endpoint,
            "url": self.url,
            "method": self.http_method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "remediation": self.remediation,
            "limitations": self.limitations,
            "references": self.references,
            "detection_type": self.detection_type,
            "source": self.source,
            "timestamp": self.timestamp,
            "validation": self.validation_result.to_dict() if self.validation_result and hasattr(self.validation_result, "to_dict") else None
        }

@dataclass
class AssessmentContext:
    """
    Supplies contextual evidence collected during early-stage reconnaissance and HTTP enumeration
    to OWASP assessment checks without exposing direct scanner execution.
    """
    target: Target
    scan_result: ScanResult
    http_results: List[HttpResult] = field(default_factory=list)
    existing_findings: List[Finding] = field(default_factory=list)
    vulnerability_records: List[Any] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)

    def has_http_service(self) -> bool:
        """
        Determines whether any reachable HTTP or HTTPS services are present on the target.
        Returns False if no web ports or HTTP services were discovered.
        """
        # 1. Check if any HTTP enumeration result received a valid response status code
        for res in self.http_results:
            if res.status_code is not None:
                return True

        # 2. Check open ports from reconnaissance scan
        for host in self.scan_result.hosts:
            for s in host.open_ports:
                name = s.name.lower()
                if "http" in name or "https" in name or "ssl|http" in name:
                    return True
                if s.port in [80, 443, 8080, 8443, 8000, 8888]:
                    return True

        return False

    def get_open_web_ports(self) -> List[int]:
        """Returns sorted list of open ports recognized as HTTP or HTTPS."""
        web_ports = set()
        for host in self.scan_result.hosts:
            for s in host.open_ports:
                name = s.name.lower()
                if "http" in name or "https" in name or "ssl|http" in name or s.port in [80, 443, 8080, 8443, 8000, 8888]:
                    web_ports.add(s.port)
        for h in self.http_results:
            if h.url:
                try:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(h.url)
                    if parsed.port:
                        web_ports.add(parsed.port)
                    elif parsed.scheme == "http":
                        web_ports.add(80)
                    elif parsed.scheme == "https":
                        web_ports.add(443)
                except Exception:
                    pass
        return sorted(list(web_ports))

    def get_web_urls(self) -> List[str]:
        """Returns list of active target URLs enumerated with HTTP responses."""
        return [h.url for h in self.http_results if h.status_code is not None]

@dataclass
class AssessmentResult:
    """
    Aggregates the outcomes of the OWASP assessment engine.
    """
    is_http_available: bool
    findings: List[OWASPFinding] = field(default_factory=list)
    executed_checks: List[str] = field(default_factory=list)
    supported_categories: List[str] = field(default_factory=list)
    message: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the assessment result to a dictionary for reporting."""
        summary_by_severity = {
            "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
            "informational": sum(1 for f in self.findings if f.severity == Severity.INFO),
        }
        return {
            "is_http_available": self.is_http_available,
            "supported_categories": self.supported_categories,
            "executed_checks": self.executed_checks,
            "findings_count": len(self.findings),
            "summary_by_severity": summary_by_severity,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else {
                "id": f.id,
                "title": f.title,
                "owasp_category": f.owasp_category,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "endpoint": f.endpoint,
                "url": getattr(f, "url", f.endpoint or f.affected_asset),
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "remediation": getattr(f, "remediation", f.recommendation),
                "limitations": getattr(f, "limitations", ""),
                "detection_type": f.detection_type
            } for f in self.findings],
            "message": self.message,
            "notes": self.notes
        }
