"""
AlaviTrace OWASP Web Security Assessment Engine (Phase 6 Foundation).
Provides modular, extensible architecture for OWASP Top 10 web security checks.
"""

from alavitrace.assessment.models import (
    OwaspCategory,
    CategorySupportStatus,
    CATEGORY_SUPPORT_STATUS,
    get_supported_categories,
    is_category_supported,
    DetectionType,
    OWASPFinding,
    AssessmentContext,
    AssessmentResult
)

from alavitrace.assessment.base import (
    BaseAssessmentCheck,
    AccessControlCheckStub,
    CryptographicFailuresCheckStub,
    InjectionCheckStub,
    SecurityMisconfigurationCheckStub,
    VulnerableComponentsCheckStub,
    AuthenticationCheckStub,
    SSRFCheckStub,
    BrokenAccessControlCheck,
    CryptographicFailuresCheck,
    InjectionCheck,
    InsecureDesignCheck,
    SecurityMisconfigurationCheck,
    VulnerableComponentsCheck,
    AuthenticationCheck,
    SoftwareIntegrityCheck,
    LoggingMonitoringCheck,
    SSRFCheck,
    CSRFCheck,
    CookieSecurityCheck,
    register_builtin_checks
)

from alavitrace.assessment.registry import (
    CheckRegistry,
    default_registry,
    get_default_registry
)

from alavitrace.assessment.engine import (
    AssessmentEngine,
    generate_finding_fingerprint,
    deduplicate_findings
)
from alavitrace.assessment.injection_payloads import (
    PayloadType,
    SafePayload,
    get_sqli_payloads,
    generate_xss_canary,
    COMMAND_PARAM_CANDIDATES
)

from alavitrace.assessment.http_probe import (
    InjectionTarget,
    ProbeResponse,
    HttpProber
)

from alavitrace.assessment.response_analysis import (
    XssContext,
    detect_db_error,
    detect_sqli_error_difference,
    classify_xss_context,
    analyze_xss_reflection
)

from alavitrace.assessment.injection_engine import (
    ControlledInjectionDetector,
    discover_injection_targets,
    InjectionAssessmentResult
)

__all__ = [
    "OwaspCategory",
    "CategorySupportStatus",
    "CATEGORY_SUPPORT_STATUS",
    "get_supported_categories",
    "is_category_supported",
    "DetectionType",
    "OWASPFinding",
    "AssessmentContext",
    "AssessmentResult",
    "BaseAssessmentCheck",
    "AccessControlCheckStub",
    "CryptographicFailuresCheckStub",
    "InjectionCheckStub",
    "SecurityMisconfigurationCheckStub",
    "VulnerableComponentsCheckStub",
    "AuthenticationCheckStub",
    "SSRFCheckStub",
    "BrokenAccessControlCheck",
    "CryptographicFailuresCheck",
    "InjectionCheck",
    "InsecureDesignCheck",
    "SecurityMisconfigurationCheck",
    "VulnerableComponentsCheck",
    "AuthenticationCheck",
    "SoftwareIntegrityCheck",
    "LoggingMonitoringCheck",
    "SSRFCheck",
    "CSRFCheck",
    "CookieSecurityCheck",
    "register_builtin_checks",
    "CheckRegistry",
    "default_registry",
    "get_default_registry",
    "AssessmentEngine",
    "generate_finding_fingerprint",
    "deduplicate_findings",
    "PayloadType",
    "SafePayload",
    "get_sqli_payloads",
    "generate_xss_canary",
    "COMMAND_PARAM_CANDIDATES",
    "InjectionTarget",
    "ProbeResponse",
    "HttpProber",
    "XssContext",
    "detect_db_error",
    "detect_sqli_error_difference",
    "classify_xss_context",
    "analyze_xss_reflection",
    "ControlledInjectionDetector",
    "discover_injection_targets",
    "InjectionAssessmentResult"
]
