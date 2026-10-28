from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

class Severity(Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Confidence(Enum):
    INFORMATIONAL = "Informational"
    POTENTIAL = "Potential"
    PROBABLE = "Probable"
    CONFIRMED = "Confirmed"
    OBSERVED = "Observed"

class ActionImpact(Enum):
    SAFE = "Safe"
    LOW_IMPACT = "Low Impact"
    REQUIRES_APPROVAL = "Requires Approval"
    RESTRICTED = "Restricted"

class FindingLifecycle(Enum):
    DISCOVERED = "Discovered"
    ANALYZED = "Analyzed"
    CORRELATED = "Correlated"
    PRIORITIZED = "Prioritized"
    VALIDATION_ATTEMPTED = "Validation Attempted"
    VALIDATED = "Validated"
    INCONCLUSIVE = "Inconclusive"
    NOT_VALIDATED = "Not Validated"
    REPORTED = "Reported"

@dataclass
class Target:
    raw_input: str
    normalized: str
    target_type: str  # IPv4, Hostname, Domain
    is_valid: bool = True
    error_message: Optional[str] = None

@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str = "Unknown"
    version: str = "Unknown"
    extra_info: str = ""
    cpes: List[str] = field(default_factory=list)
    scripts_output: Dict[str, str] = field(default_factory=dict)

@dataclass
class Host:
    target: Target
    state: str = "unknown"
    ipv4: Optional[str] = None
    hostname: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    open_ports: List[Service] = field(default_factory=list)
    os_matches: List[str] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    target: Target
    hosts: List[Host] = field(default_factory=list)
    raw_xml_path: Optional[str] = None
    scan_args: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class HttpResult:
    url: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    response_time_ms: float = 0.0
    server_header: Optional[str] = None
    powered_by_header: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    redirect_chain: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    body_sample: Optional[str] = None
    forms: List[Dict[str, Any]] = field(default_factory=list)
    insecure_resources: List[str] = field(default_factory=list)
    observed_parameters: List[str] = field(default_factory=list)
    options_methods: List[str] = field(default_factory=list)
    tls_cert_info: Optional[Dict[str, Any]] = None
    robots_txt_disallowed: List[str] = field(default_factory=list)
    security_txt_found: bool = False
    framework_headers: Dict[str, str] = field(default_factory=dict)
    raw_body: Optional[str] = None

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    affected_asset: str
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    source: str = "AlaviTrace Core"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    owasp_category: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    parameter: Optional[str] = None
    detection_type: Optional[str] = None
    limitations: str = ""
    validation_result: Optional[Any] = None
    lifecycle_stage: FindingLifecycle = FindingLifecycle.DISCOVERED
    technical_category: Optional[str] = None
    priority_score: int = 0
    cvss: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        """Returns primary URL or endpoint for the finding."""
        return self.endpoint or self.affected_asset

    @property
    def remediation(self) -> str:
        """Alias for recommendation to support consistent terminology."""
        return self.recommendation

    def advance_lifecycle(self, new_stage: FindingLifecycle) -> None:
        """Transitions the finding to a new stage in the assessment lifecycle."""
        self.lifecycle_stage = new_stage

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the finding into a canonical dictionary representation."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "technical_category": self.technical_category or determine_technical_category(self),
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "lifecycle_stage": self.lifecycle_stage.value if hasattr(self.lifecycle_stage, "value") else str(self.lifecycle_stage),
            "priority_score": self.priority_score,
            "cvss": self.cvss,
            "cve_ids": self.cve_ids,
            "description": self.description,
            "evidence": self.evidence,
            "affected_asset": self.affected_asset,
            "affected_port": self.affected_port,
            "affected_service": self.affected_service,
            "product": self.product,
            "version": self.version,
            "recommendation": self.recommendation,
            "remediation": self.remediation,
            "references": self.references,
            "source": self.source,
            "timestamp": self.timestamp,
            "owasp_category": self.owasp_category,
            "endpoint": self.endpoint,
            "url": self.url,
            "http_method": self.http_method,
            "parameter": self.parameter,
            "detection_type": self.detection_type,
            "limitations": self.limitations,
            "validation": self.validation_result.to_dict() if getattr(self, "validation_result", None) and hasattr(self.validation_result, "to_dict") else None
        }

def determine_technical_category(finding: Finding) -> str:
    """
    Deterministically maps a Finding into one of the canonical technical categories:
    Network, Service, Web, Authentication, Access Control, Injection,
    Misconfiguration, Vulnerability Intelligence, Security Headers, Attack Surface.
    """
    if finding.technical_category:
        return finding.technical_category

    cat_lower = (finding.category or "").strip().lower()
    title_lower = (finding.title or "").lower()
    owasp = (finding.owasp_category or "").upper()

    # 1. High-specificity vulnerability and technical categories
    if "security header" in cat_lower or "missing security header" in title_lower:
        return "Security Headers"
    if "injection" in cat_lower or "injection" in title_lower or "sql" in title_lower or "xss" in title_lower or "command" in title_lower or "a03" in owasp:
        return "Injection"
    if "access control" in cat_lower or "access control" in title_lower or "directory listing" in title_lower or "path traversal" in title_lower or "csrf" in title_lower or "a01" in owasp:
        return "Access Control"
    if "authentication" in cat_lower or "authentication" in title_lower or "cookie" in title_lower or "session" in title_lower or "a07" in owasp:
        return "Authentication"
    if "misconfiguration" in cat_lower or "misconfiguration" in title_lower or "default" in title_lower or "server header" in title_lower or "a05" in owasp:
        return "Misconfiguration"
    if "vulnerability intelligence" in cat_lower or "cve" in title_lower or finding.cve_ids or "a06" in owasp:
        return "Vulnerability Intelligence"
    if "attack surface" in cat_lower or "endpoint" in title_lower or "parameter" in title_lower:
        return "Attack Surface"

    # 2. General application and network tiers
    if "web" in cat_lower or finding.endpoint or owasp:
        return "Web"
    if "service" in cat_lower or finding.affected_port or finding.affected_service:
        return "Service"
    return "Network"

@dataclass
class AssessmentSummary:
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    validated_findings: int = 0
    unvalidated_findings: int = 0
    inconclusive_findings: int = 0
    total_services: int = 0
    total_endpoints: int = 0
    total_forms: int = 0
    attack_surface_score: float = 0.0
    overall_risk_rating: str = "Low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "info_findings": self.info_findings,
            "validated_findings": self.validated_findings,
            "unvalidated_findings": self.unvalidated_findings,
            "inconclusive_findings": self.inconclusive_findings,
            "total_services": self.total_services,
            "total_endpoints": self.total_endpoints,
            "total_forms": self.total_forms,
            "attack_surface_score": self.attack_surface_score,
            "overall_risk_rating": self.overall_risk_rating
        }

@dataclass
class Assessment:
    target: Target
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    hosts: List[Host] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    http_results: List[HttpResult] = field(default_factory=list)
    attack_surface: Optional[Any] = None
    findings: List[Finding] = field(default_factory=list)
    prioritized_findings: List[Finding] = field(default_factory=list)
    validation_results: List[Any] = field(default_factory=list)
    owasp_coverage: Optional[Any] = None
    ai_analysis: Optional[Any] = None
    summary: Optional[AssessmentSummary] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": {
                "raw_input": self.target.raw_input,
                "normalized": self.target.normalized,
                "target_type": self.target.target_type,
                "is_valid": self.target.is_valid
            },
            "scan_metadata": self.scan_metadata,
            "services_count": len(self.services),
            "http_results_count": len(self.http_results),
            "attack_surface": self.attack_surface.to_dict() if self.attack_surface and hasattr(self.attack_surface, "to_dict") else None,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else str(f) for f in self.findings],
            "prioritized_findings": [f.to_dict() if hasattr(f, "to_dict") else str(f) for f in self.prioritized_findings],
            "validation_results": [v.to_dict() if hasattr(v, "to_dict") else str(v) for v in self.validation_results],
            "owasp_coverage": self.owasp_coverage.to_dict() if self.owasp_coverage and hasattr(self.owasp_coverage, "to_dict") else self.owasp_coverage,
            "ai_analysis": self.ai_analysis.to_dict() if self.ai_analysis and hasattr(self.ai_analysis, "to_dict") else None,
            "summary": self.summary.to_dict() if self.summary else None
        }

@dataclass
class ActionRecommendation:
    id: str
    title: str
    reason: str
    action_type: str
    impact_level: ActionImpact
    target_asset: str
    command_preview: Optional[str] = None
