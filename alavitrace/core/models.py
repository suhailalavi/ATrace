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

class ActionImpact(Enum):
    SAFE = "Safe"
    LOW_IMPACT = "Low Impact"
    REQUIRES_APPROVAL = "Requires Approval"
    RESTRICTED = "Restricted"

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
    source: str = "ATrace Core"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ActionRecommendation:
    id: str
    title: str
    reason: str
    action_type: str
    impact_level: ActionImpact
    target_asset: str
    command_preview: Optional[str] = None
