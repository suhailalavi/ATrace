import pytest
from alavitrace.core.models import Target, Host, Service, ScanResult, HttpResult, Finding, Severity, Confidence
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

def test_owasp_category_representation():
    # 1. Verify all 10 standard categories exist
    assert len(OwaspCategory) == 10
    assert OwaspCategory.A01_2021.value == "A01:2021 - Broken Access Control"
    assert OwaspCategory.A02_2021.value == "A02:2021 - Cryptographic Failures"
    assert OwaspCategory.A03_2021.value == "A03:2021 - Injection"
    assert OwaspCategory.A04_2021.value == "A04:2021 - Insecure Design"
    assert OwaspCategory.A05_2021.value == "A05:2021 - Security Misconfiguration"
    assert OwaspCategory.A06_2021.value == "A06:2021 - Vulnerable and Outdated Components"
    assert OwaspCategory.A07_2021.value == "A07:2021 - Identification and Authentication Failures"
    assert OwaspCategory.A08_2021.value == "A08:2021 - Software and Data Integrity Failures"
    assert OwaspCategory.A09_2021.value == "A09:2021 - Security Logging and Monitoring Failures"
    assert OwaspCategory.A10_2021.value == "A10:2021 - Server-Side Request Forgery"

    # Category code property
    assert OwaspCategory.A01_2021.code == "A01:2021"
    assert OwaspCategory.A05_2021.code == "A05:2021"

    # Support status tracking
    supported = get_supported_categories()
    assert len(supported) == 7
    assert OwaspCategory.A01_2021 in supported
    assert OwaspCategory.A02_2021 in supported
    assert OwaspCategory.A03_2021 in supported
    assert OwaspCategory.A05_2021 in supported
    assert OwaspCategory.A06_2021 in supported
    assert OwaspCategory.A07_2021 in supported
    assert OwaspCategory.A10_2021 in supported

    assert is_category_supported(OwaspCategory.A01_2021) is True
    assert is_category_supported(OwaspCategory.A04_2021) is False
    assert CATEGORY_SUPPORT_STATUS[OwaspCategory.A04_2021] == CategorySupportStatus.LIMITED
    assert CATEGORY_SUPPORT_STATUS[OwaspCategory.A08_2021] == CategorySupportStatus.LIMITED
    assert CATEGORY_SUPPORT_STATUS[OwaspCategory.A09_2021] == CategorySupportStatus.LIMITED

def test_severity_and_confidence_reuse():
    # Verify core Severity enum is reused
    assert Severity.CRITICAL.value == "Critical"
    assert Severity.HIGH.value == "High"
    assert Severity.MEDIUM.value == "Medium"
    assert Severity.LOW.value == "Low"
    assert Severity.INFO.value == "Informational"

    # Verify confidence model including OBSERVED
    assert Confidence.OBSERVED.value == "Observed"
    assert Confidence.POTENTIAL.value == "Potential"
    assert Confidence.PROBABLE.value == "Probable"
    assert Confidence.CONFIRMED.value == "Confirmed"

def test_detection_types():
    assert DetectionType.PASSIVE.value == "passive"
    assert DetectionType.ACTIVE.value == "active"
    assert DetectionType.CORRELATED.value == "correlated"

def test_owasp_finding_creation_and_properties():
    finding = OWASPFinding.create(
        id="OWASP-A05-001",
        title="Missing Content-Security-Policy",
        owasp_category=OwaspCategory.A05_2021.value,
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="The web application does not enforce a Content-Security-Policy header.",
        evidence="Content-Security-Policy header was not present in the HTTP response",
        affected_asset="192.168.56.106",
        endpoint="http://192.168.56.106/",
        http_method="GET",
        parameter=None,
        detection_type=DetectionType.PASSIVE.value,
        recommendation="Implement a robust CSP header.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
    )

    # Core Finding compatibility
    assert isinstance(finding, Finding)
    assert finding.id == "OWASP-A05-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.OBSERVED
    assert finding.target == "192.168.56.106"
    assert finding.method == "GET"
    assert finding.endpoint == "http://192.168.56.106/"
    assert finding.detection_type == "passive"

    # Serialization
    data = finding.to_dict()
    assert data["id"] == "OWASP-A05-001"
    assert data["owasp_category"] == "A05:2021 - Security Misconfiguration"
    assert data["severity"] == "Medium"
    assert data["confidence"] == "Observed"
    assert data["endpoint"] == "http://192.168.56.106/"
    assert data["detection_type"] == "passive"
    assert data["target"] == "192.168.56.106"

def test_assessment_context_http_availability():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")

    # Case 1: Only FTP (21) and SSH (22)
    host_no_http = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[
            Service(port=21, protocol="tcp", state="open", name="ftp"),
            Service(port=22, protocol="tcp", state="open", name="ssh")
        ]
    )
    context_no_http = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target, hosts=[host_no_http]),
        http_results=[]
    )
    assert context_no_http.has_http_service() is False
    assert context_no_http.get_open_web_ports() == []
    assert context_no_http.get_web_urls() == []

    # Case 2: Port 80 Open in Nmap
    host_with_http = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[
            Service(port=80, protocol="tcp", state="open", name="http")
        ]
    )
    context_with_port = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target, hosts=[host_with_http]),
        http_results=[]
    )
    assert context_with_port.has_http_service() is True
    assert context_with_port.get_open_web_ports() == [80]

    # Case 3: HttpResult with valid response
    http_res = HttpResult(url="http://192.168.56.106", status_code=200)
    context_with_res = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target, hosts=[host_no_http]),
        http_results=[http_res]
    )
    assert context_with_res.has_http_service() is True
    assert context_with_res.get_web_urls() == ["http://192.168.56.106"]

def test_assessment_result_serialization():
    finding = OWASPFinding.create(
        id="OWASP-A05-001",
        title="Missing CSP",
        owasp_category=OwaspCategory.A05_2021.value,
        severity=Severity.LOW,
        confidence=Confidence.OBSERVED,
        description="CSP missing",
        evidence="No CSP header",
        affected_asset="192.168.56.106",
        endpoint="http://192.168.56.106/"
    )

    res = AssessmentResult(
        is_http_available=True,
        findings=[finding],
        executed_checks=["DummyCheck"],
        supported_categories=["A01:2021 - Broken Access Control"],
        message="Assessment complete.",
        notes=["Note 1"]
    )

    data = res.to_dict()
    assert data["is_http_available"] is True
    assert data["findings_count"] == 1
    assert data["executed_checks"] == ["DummyCheck"]
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "OWASP-A05-001"
