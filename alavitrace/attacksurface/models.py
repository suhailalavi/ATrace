from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from alavitrace.core.models import Confidence

@dataclass
class Technology:
    """
    Represents an identified web technology, server software, or framework.
    """
    name: str
    version: Optional[str] = None
    source: str = "Unknown"
    confidence: Confidence = Confidence.INFORMATIONAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "confidence": self.confidence.value
        }

@dataclass
class Parameter:
    """
    Represents an observed input parameter (URL query parameter or form field).
    STRICT PRIVACY: Parameter names and locations are recorded; sensitive values are never stored.
    """
    name: str
    location: str  # "query", "form_body", "header"
    endpoint: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "endpoint": self.endpoint,
            "evidence": self.evidence
        }

@dataclass
class Endpoint:
    """
    Represents an observable HTTP/HTTPS endpoint on the target application.
    An endpoint represents attack surface inventory, NOT necessarily a vulnerability.
    """
    url: str
    path: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    parameters: List[str] = field(default_factory=list)
    source: str = "root_url"  # "root_url", "html_link", "html_form", "redirect", "robots_txt", "sitemap_xml"
    depth: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "parameters": self.parameters,
            "source": self.source,
            "depth": self.depth
        }

@dataclass
class RedirectEntry:
    """
    Tracks an observed HTTP redirect and whether it remained within the target scope.
    """
    source_url: str
    target_url: str
    status_code: Optional[int] = None
    is_out_of_scope: bool = False
    flag: Optional[str] = None  # None or "OUT_OF_SCOPE_REDIRECT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_url": self.source_url,
            "target_url": self.target_url,
            "status_code": self.status_code,
            "is_out_of_scope": self.is_out_of_scope,
            "flag": self.flag
        }

@dataclass
class AttackSurface:
    """
    Consolidated attack surface inventory for a target application.
    Separates observed attack surface inventory from security findings.
    """
    target: str
    base_urls: List[str] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    redirects: List[RedirectEntry] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "base_urls": self.base_urls,
            "total_endpoints": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "total_technologies": len(self.technologies),
            "technologies": [t.to_dict() for t in self.technologies],
            "total_parameters": len(self.parameters),
            "parameters": [p.to_dict() for p in self.parameters],
            "methods": sorted(self.methods),
            "total_redirects": len(self.redirects),
            "redirects": [r.to_dict() for r in self.redirects],
            "metadata": self.metadata
        }
