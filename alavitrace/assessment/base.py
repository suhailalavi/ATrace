import logging
from abc import ABC, abstractmethod
from typing import List

from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)

logger = logging.getLogger("AlaviTrace")

class BaseAssessmentCheck(ABC):
    """
    Abstract contract for all OWASP Web Security Assessment checks.
    Each check receives an AssessmentContext and deterministically generates
    zero or more OWASPFinding records.
    """
    category: OwaspCategory
    name: str
    description: str
    detection_type: DetectionType = DetectionType.PASSIVE

    @abstractmethod
    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        """
        Executes the assessment check against the provided AssessmentContext.

        Args:
            context: AssessmentContext containing target, reconnaissance, and HTTP evidence.

        Returns:
            List[OWASPFinding]: List of identified findings (empty if none identified).
        """
        pass

    def run(self, context: AssessmentContext) -> List[OWASPFinding]:
        """
        Convenience wrapper executing check() with error logging.
        """
        return self.check(context)


# ============================================================================
# Check Hooks & Stubs for Future Phases (Phase 7–10)
# These represent placeholder registration points designed for subsequent phases.
# In Phase 6, they are unpopulated stubs that return no findings.
# ============================================================================

class AccessControlCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 9: A01:2021 - Broken Access Control."""
    category = OwaspCategory.A01_2021
    name = "A01_BrokenAccessControl_Stub"
    description = "Framework hook for broken access control checks (Phase 9)."
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class CryptographicFailuresCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 7: A02:2021 - Cryptographic Failures."""
    category = OwaspCategory.A02_2021
    name = "A02_CryptographicFailures_Stub"
    description = "Framework hook for TLS and cryptographic failure checks (Phase 7)."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class InjectionCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 8: A03:2021 - Injection."""
    category = OwaspCategory.A03_2021
    name = "A03_Injection_Stub"
    description = "Framework hook for active injection vulnerability checks (Phase 8)."
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class SecurityMisconfigurationCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 7: A05:2021 - Security Misconfiguration."""
    category = OwaspCategory.A05_2021
    name = "A05_SecurityMisconfiguration_Stub"
    description = "Framework hook for HTTP security headers and misconfiguration checks (Phase 7)."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class VulnerableComponentsCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 6/11: A06:2021 - Vulnerable and Outdated Components."""
    category = OwaspCategory.A06_2021
    name = "A06_VulnerableComponents_Stub"
    description = "Framework hook consuming Phase 4 vulnerability intelligence for web-facing services."
    detection_type = DetectionType.CORRELATED

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class AuthenticationCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 9: A07:2021 - Identification and Authentication Failures."""
    category = OwaspCategory.A07_2021
    name = "A07_Authentication_Stub"
    description = "Framework hook for authentication and session management checks (Phase 9)."
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []

class SSRFCheckStub(BaseAssessmentCheck):
    """Placeholder hook for Phase 10: A10:2021 - Server-Side Request Forgery (SSRF)."""
    category = OwaspCategory.A10_2021
    name = "A10_SSRF_Stub"
    description = "Framework hook for controlled SSRF probe checks (Phase 10)."
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return []


# ============================================================================
# Phase 7 Concrete OWASP Web Security Assessment Checks
# Connects to deterministic detectors in alavitrace.analysis.owasp
# ============================================================================

from alavitrace.analysis.owasp import (
    detect_broken_access_control,
    detect_cryptographic_failures,
    detect_injection_indicators,
    detect_insecure_design,
    detect_security_misconfiguration,
    detect_vulnerable_components,
    detect_identification_authentication_weakness,
    detect_software_data_integrity_failures,
    detect_security_logging_monitoring_gaps,
    detect_ssrf_indicators,
    detect_csrf_weaknesses,
    detect_cookie_security
)

class BrokenAccessControlCheck(BaseAssessmentCheck):
    category = OwaspCategory.A01_2021
    name = "BrokenAccessControlCheck"
    description = "Inspects directory listings and exposed sensitive administration/configuration paths."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_broken_access_control(context)

class CryptographicFailuresCheck(BaseAssessmentCheck):
    category = OwaspCategory.A02_2021
    name = "CryptographicFailuresCheck"
    description = "Evaluates unencrypted cleartext HTTP transport and missing HSTS over TLS."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_cryptographic_failures(context)

class InjectionCheck(BaseAssessmentCheck):
    category = OwaspCategory.A03_2021
    name = "InjectionCheck"
    description = "Heuristically identifies input parameters and executes controlled non-destructive injection tests."
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        enable_injection = context.options.get("enable_injection", False)
        if enable_injection:
            from alavitrace.assessment.injection_engine import ControlledInjectionDetector
            max_requests = context.options.get("max_injection_requests", 20)
            detector = ControlledInjectionDetector(max_requests=max_requests)
            result = detector.execute(context)
            if result.findings:
                return result.findings
        return detect_injection_indicators(context)

class InsecureDesignCheck(BaseAssessmentCheck):
    category = OwaspCategory.A04_2021
    name = "InsecureDesignCheck"
    description = "Documents architectural threat modeling and design boundaries with zero false positives."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_insecure_design(context)

class SecurityMisconfigurationCheck(BaseAssessmentCheck):
    category = OwaspCategory.A05_2021
    name = "SecurityMisconfigurationCheck"
    description = "Audits standard HTTP security headers and verbose server banner disclosures."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_security_misconfiguration(context)

class VulnerableComponentsCheck(BaseAssessmentCheck):
    category = OwaspCategory.A06_2021
    name = "VulnerableComponentsCheck"
    description = "Correlates web-facing CVEs from Phase 4 vulnerability intelligence without duplicate queries."
    detection_type = DetectionType.CORRELATED

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_vulnerable_components(context)

class AuthenticationCheck(BaseAssessmentCheck):
    category = OwaspCategory.A07_2021
    name = "AuthenticationCheck"
    description = "Detects credential transmission over unencrypted HTTP and cookies missing HttpOnly."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_identification_authentication_weakness(context)

class SoftwareIntegrityCheck(BaseAssessmentCheck):
    category = OwaspCategory.A08_2021
    name = "SoftwareIntegrityCheck"
    description = "Detects external script inclusions missing Subresource Integrity (SRI) and Mixed Content."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_software_data_integrity_failures(context)

class LoggingMonitoringCheck(BaseAssessmentCheck):
    category = OwaspCategory.A09_2021
    name = "LoggingMonitoringCheck"
    description = "Documents security logging, monitoring, and alerting verification boundaries."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_security_logging_monitoring_gaps(context)

class SSRFCheck(BaseAssessmentCheck):
    category = OwaspCategory.A10_2021
    name = "SSRFCheck"
    description = "Heuristically flags candidate URL/redirection parameters commonly associated with SSRF."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_ssrf_indicators(context)

class CSRFCheck(BaseAssessmentCheck):
    category = OwaspCategory.A01_2021
    name = "CSRFCheck"
    description = "Identifies state-changing POST forms lacking anti-CSRF token input fields."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_csrf_weaknesses(context)

class CookieSecurityCheck(BaseAssessmentCheck):
    category = OwaspCategory.A05_2021
    name = "CookieSecurityCheck"
    description = "Evaluates Secure and SameSite attributes on application cookies."
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        return detect_cookie_security(context)

def register_builtin_checks(registry) -> None:
    """
    Registers the complete suite of Phase 7 OWASP checks into the provided CheckRegistry.
    """
    checks = [
        BrokenAccessControlCheck(),
        CryptographicFailuresCheck(),
        InjectionCheck(),
        InsecureDesignCheck(),
        SecurityMisconfigurationCheck(),
        VulnerableComponentsCheck(),
        AuthenticationCheck(),
        SoftwareIntegrityCheck(),
        LoggingMonitoringCheck(),
        SSRFCheck(),
        CSRFCheck(),
        CookieSecurityCheck()
    ]
    for chk in checks:
        registry.register(chk)

