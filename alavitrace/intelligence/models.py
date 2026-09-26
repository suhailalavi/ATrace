from dataclasses import dataclass, field
from typing import List, Optional, Dict
from alavitrace.core.models import Severity

@dataclass
class VulnerabilityRecord:
    """
    Provider-independent normalized vulnerability record representing a single CVE.
    """
    cve_id: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_product: Optional[str] = None
    affected_version: Optional[str] = None
    matched_cpe: Optional[str] = None
    source: str = "NVD"

@dataclass
class VulnQueryResult:
    """
    Result container for a vulnerability lookup query.
    """
    query_type: str  # 'cpe' or 'keyword'
    query_value: str
    records: List[VulnerabilityRecord] = field(default_factory=list)
    error_message: Optional[str] = None
    from_cache: bool = False
